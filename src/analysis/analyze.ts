import { validateText } from './input.ts';
import { inspectLinks } from './links.ts';
import { inspectText, isContextual } from './text.ts';
import { METHOD, type Analysis, type Finding, type Risk, type Signal } from './types.ts';

const strongLinkSignals = new Set<Signal>(['mismatch', 'userinfo', 'subdomain', 'lookalike']);

function assess(findings: Finding[], hasText: boolean): Risk {
  const active = new Set(findings.filter((finding) => !finding.contextual).map((finding) => finding.signal));
  const pressure = active.has('urgency');
  const solicitation = active.has('secrets') || active.has('payment');
  const pretext = active.has('reward') || active.has('impersonation');
  const deceptiveLink = [...active].some((signal) => strongLinkSignals.has(signal));
  if (solicitation && (deceptiveLink || (pressure && pretext))) return 'high';
  if (solicitation || deceptiveLink || (pressure && pretext)) return 'elevated';
  if (!hasText || findings.length) return 'uncertain';
  return 'none';
}

export function analyze(value: string, timestamp = new Date().toISOString()): Analysis {
  const error = validateText(value);
  if (error) throw new RangeError(error);

  const { links, coverage } = inspectLinks(value);
  let position = 0;
  let prose = '';
  for (const span of coverage) {
    prose += value.slice(position, span.start) + value.slice(span.start, span.end).replace(/[^\n]/gu, (character) => ' '.repeat(character.length));
    position = span.end;
  }
  prose += value.slice(position);
  const hasText = /[\p{L}\p{N}]/u.test(prose);
  const findings = hasText ? inspectText(prose).map((finding) => ({
    ...finding,
    contextual: isContextual(value, finding.span),
  })) : [];
  for (const link of links) {
    for (const signal of link.signals) {
      findings.push({ signal, span: link.span, contextual: isContextual(value, link.span) });
    }
  }
  findings.sort((a, b) => Number(a.contextual) - Number(b.contextual) || priority(a.signal) - priority(b.signal) || a.span.start - b.span.start);

  const unavailable: Analysis['unavailable'] = ['linkAccess', 'ai', 'fact', 'source'];
  if (!hasText) unavailable.unshift('text');
  if (!links.length) unavailable.unshift('links');
  return { timestamp, method: METHOD, risk: assess(findings, hasText), findings, links, unavailable };
}

function priority(signal: Signal): number {
  if (signal === 'secrets' || signal === 'payment' || strongLinkSignals.has(signal)) return 0;
  if (signal === 'unparsed' || signal === 'shortener') return 2;
  return 1;
}
