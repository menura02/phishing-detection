import { validateText } from './input.ts';
import { inspectHeaders } from './headers.ts';
import { inspectLinks } from './links.ts';
import { inspectText, isContextual } from './text.ts';
import { METHOD, type Analysis, type Finding, type Signal, type Span } from './types.ts';

const strongLinkSignals = new Set<Signal>(['mismatch', 'userinfo', 'subdomain', 'lookalike']);
const sensitiveSignals = new Set<Signal>(['secrets', 'payment', 'approval', 'remoteAccess']);

function assess(findings: Finding[], hasText: boolean): Pick<Analysis, 'risk' | 'reason'> {
  const active = new Set(findings.filter((finding) => !finding.contextual).map((finding) => finding.signal));
  const pressure = active.has('urgency');
  const solicitation = [...active].some((signal) => sensitiveSignals.has(signal));
  const pretext = active.has('reward') || active.has('impersonation') || active.has('delivery') || active.has('invoice');
  const deceptiveLink = [...active].some((signal) => strongLinkSignals.has(signal));
  const action = active.has('login') || active.has('attachment') || active.has('callback') || active.has('qr');
  const destinationConcern = active.has('redirect') || active.has('download') || active.has('shortener') ||
    active.has('ip') || active.has('punycode') || active.has('replyMismatch');
  if (solicitation && deceptiveLink) return { risk: 'high', reason: 'requestAndDeception' };
  if (solicitation && pressure && pretext) return { risk: 'high', reason: 'requestAndPressure' };
  if (action && deceptiveLink) return { risk: 'high', reason: 'actionAndDeception' };
  if (solicitation) return { risk: 'elevated', reason: 'sensitiveRequest' };
  if (deceptiveLink) return { risk: 'elevated', reason: 'destinationDeception' };
  if (pressure && pretext) return { risk: 'elevated', reason: 'pressureAndPretext' };
  if (action && (pretext || destinationConcern)) return { risk: 'elevated', reason: 'actionAndPretext' };
  if (!hasText || findings.length) return { risk: 'uncertain', reason: 'limitedEvidence' };
  return { risk: 'none', reason: 'noIndicators' };
}

function mask(value: string, spans: Span[]): string {
  let position = 0;
  let prose = '';
  for (const span of spans) {
    prose += value.slice(position, span.start) + value.slice(span.start, span.end).replace(/[^\n]/gu, (character) => ' '.repeat(character.length));
    position = span.end;
  }
  return prose + value.slice(position);
}

export function analyze(value: string, timestamp = new Date().toISOString()): Analysis {
  const error = validateText(value);
  if (error) throw new RangeError(error);

  const headers = inspectHeaders(value);
  const body = mask(value, headers.spans);
  const { links, coverage } = inspectLinks(body);
  const prose = mask(body, coverage);
  const hasText = /\p{Script=Latin}/u.test(prose);
  const findings = hasText ? inspectText(prose).map((finding) => ({
    ...finding,
    contextual: isContextual(value, finding.span),
  })) : [];
  if (headers.finding) findings.push(headers.finding);
  for (const link of links) {
    for (const signal of link.signals) {
      findings.push({ signal, span: link.span, contextual: isContextual(value, link.span) });
    }
  }
  findings.sort((a, b) => Number(a.contextual) - Number(b.contextual) || priority(a.signal) - priority(b.signal) || a.span.start - b.span.start);

  const unavailable: Analysis['unavailable'] = ['linkAccess', 'senderAuthentication'];
  if (!headers.compared) unavailable.unshift('senderHeaders');
  if (!hasText) unavailable.unshift('text');
  if (!links.length) unavailable.unshift('links');
  return { timestamp, method: METHOD, ...assess(findings, hasText), findings, links, unavailable };
}

function priority(signal: Signal): number {
  if (sensitiveSignals.has(signal) || strongLinkSignals.has(signal)) return 0;
  if (signal === 'unparsed' || signal === 'shortener') return 2;
  return 1;
}
