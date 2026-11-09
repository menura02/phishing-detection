import { parse } from 'tldts';
import type { Finding, Span } from './types.ts';

const header = /^(?<name>from|reply-to|kimden|yan[ıi]t[- ]adres[ıi])\s*:[ \t]*(?<value>[^\n]+)$/dgimu;
const mailbox = /(?<![\w.@-])[\w.!#$%&'*+/=?^_{}|~-]+@([\p{L}\p{N}.-]+\.[\p{L}]{2,})(?![\p{L}\p{N}.@-])/giu;

export function inspectHeaders(value: string): { compared: boolean; finding?: Finding; spans: Span[] } {
  const fields = { from: [] as { domain: string; span: Span }[], reply: [] as { domain: string; span: Span }[] };
  const spans: Span[] = [];
  const lines = value.split('\n');
  // Treat only a leading contiguous header block as headers. Forwarded or quoted body text stays prose.
  const first = lines.findIndex((line) => line.trim());
  if (first < 0) return { compared: false, spans };
  const block = lines.slice(first);
  const body = block.findIndex((line) => !/^[\p{L}][\p{L}\d -]{0,30}:[ \t]*/u.test(line));
  const prefix = block.slice(0, body < 0 ? undefined : body).join('\n');
  const offset = first ? lines.slice(0, first).join('\n').length + 1 : 0;
  for (const match of prefix.matchAll(header)) {
    const [start] = match.indices!.groups!.value;
    const candidates = [...match.groups!.value.matchAll(mailbox)];
    const field = /^(?:from|kimden)$/iu.test(match.groups!.name) ? 'from' : 'reply';
    for (const address of candidates) {
      const target = 'https://' + address[1];
      if (!URL.canParse(target)) continue;
      const hostname = new URL(target).hostname.replace(/\.$/u, '');
      const domain = parse(hostname, { allowPrivateDomains: true }).domain ?? hostname;
      fields[field].push({ domain, span: { start: offset + start + address.index, end: offset + start + address.index + address[0].length } });
    }
    spans.push({ start: offset + match.index, end: offset + match.index + match[0].length });
  }
  if (fields.from.length !== 1 || fields.reply.length !== 1) return { compared: false, spans };
  if (fields.from[0].domain === fields.reply[0].domain) return { compared: true, spans };
  return { compared: true, spans, finding: { signal: 'replyMismatch', span: fields.reply[0].span, contextual: false } };
}
