import PostalMime, { addressParser } from 'postal-mime';
import { defaultTreeAdapter as tree, parse, type DefaultTreeAdapterTypes } from 'parse5';
import { MAX_EMAIL_BYTES } from '../config.ts';
import { validateText } from './input.ts';

export type EmailEvidence = {
  subject: string;
  from: string[];
  replyTo: string[];
  bodyFormat: 'html' | 'text';
  attachments: { name: string; mimeType: string }[];
};

const excluded = new Set(['head', 'script', 'style', 'template', 'iframe', 'object', 'svg', 'noscript']);
const blocks = new Set(['div', 'p', 'li', 'tr', 'table', 'section', 'article', 'h1', 'h2', 'h3', 'hr', 'pre']);

function clean(value: string): string {
  return value.replace(/\s+/gu, ' ').trim();
}

function toText(node: DefaultTreeAdapterTypes.Node, depth = 0, includeTargets = true): string {
  if (depth > 100) throw new Error('HTML nesting limit exceeded');
  if (tree.isTextNode(node)) return tree.getTextNodeContent(node).replace(/\s+/gu, ' ');
  if (!('childNodes' in node)) return '';
  if (!tree.isElementNode(node)) return node.childNodes.map((child) => toText(child, depth + 1, includeTargets)).join('');
  const tag = tree.getTagName(node);
  if (excluded.has(tag)) return '';
  if (tag === 'br') return '\n';
  const attrs = tree.getAttrList(node);
  if (tag === 'img') return clean(attrs.find((item) => item.name === 'alt')?.value ?? '');
  const children = node.childNodes.map((child) => toText(child, depth + 1, includeTargets)).join('');
  if (tag === 'a' && includeTargets) {
    const href = attrs.find((item) => item.name === 'href')?.value.trim();
    if (href && !/^(?:#|mailto:|tel:|cid:)/iu.test(href)) {
      const label = clean(children).replaceAll('[', '(').replaceAll(']', ')') || '↗';
      const target = href.replace(/[<>\s]/gu, (character) => encodeURIComponent(character));
      return '[' + label + '](<' + target + '>)';
    }
  }
  if (tag === 'blockquote') return '\n' + children.trim().split('\n').map((line) => '> ' + line).join('\n') + '\n';
  if (blocks.has(tag)) return '\n' + children + '\n';
  return tag === 'td' || tag === 'th' ? children + ' ' : children;
}

export async function extractEmail(bytes: ArrayBuffer | ArrayBufferView) {
  if (bytes.byteLength > MAX_EMAIL_BYTES) throw new RangeError('emailSize');
  const email = await PostalMime.parse(bytes, {
    maxHeadersSize: 128_000, maxNestingDepth: 24, maxPartCount: 200, forceRfc822Attachments: true,
  });
  if (!email.headers.some(({ key }) => ['from', 'to', 'subject', 'date', 'mime-version', 'content-type'].includes(key))) {
    throw new Error('Email headers missing');
  }
  const addresses = (key: string) => email.headers.filter((header) => header.key === key)
    .flatMap((header) => addressParser(header.value, { flatten: true }))
    .flatMap((entry) => entry.address ? [clean(entry.address)] : []);
  const from = addresses('from');
  const replyTo = addresses('reply-to');
  const subject = clean(email.subject ?? '');
  const document = email.html ? parse(email.html) : undefined;
  const html = document ? toText(document).trim() : '';
  const visibleHtml = document ? toText(document, 0, false).trim() : '';
  const plain = (visibleHtml || email.text?.trim() || '').replace(/\r\n?/gu, '\n');
  const body = (html || plain).replace(/[ \t]+\n/gu, '\n').replace(/\n{3,}/gu, '\n\n');
  const headers = [
    from.length ? 'From: ' + from.join(', ') : '',
    replyTo.length ? 'Reply-To: ' + replyTo.join(', ') : '',
    'Subject: ' + subject,
  ].filter(Boolean);
  // Keep the subject and body in the same text coordinate system as the existing analyzer.
  const value = headers.join('\n') + '\n\n' + body;
  const evidence: EmailEvidence = {
    subject, from, replyTo, bodyFormat: html ? 'html' : 'text',
    attachments: email.attachments.map(({ filename, mimeType }) => ({
      name: clean(filename ?? '').slice(0, 260),
      mimeType: clean(mimeType).slice(0, 120),
    })),
  };
  return { value, evidence, plain: [subject, plain].filter(Boolean).join('\n\n') };
}

export async function readEmailFile(file: File) {
  if (file.size > MAX_EMAIL_BYTES) return { error: 'emailSize' as const };
  try {
    const parsed = await extractEmail(await file.arrayBuffer());
    const error = validateText(parsed.value);
    return error ? { error } : { value: parsed.value, evidence: parsed.evidence };
  } catch {
    return { error: 'emailRead' as const };
  }
}
