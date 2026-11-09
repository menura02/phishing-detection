import { validateText } from './input.ts';
import { groupFindings, linksForRequests } from './context.ts';
import { inspectHeaders } from './headers.ts';
import { inspectLinks } from './links.ts';
import { inspectText, isContextual } from './text.ts';
import { METHOD, type Analysis, type Finding, type InspectedLink, type Signal, type Span } from './types.ts';

const strongLinkSignals = new Set<Signal>(['userinfo', 'subdomain', 'lookalike']);
const sensitiveSignals = new Set<Signal>(['secrets', 'payment', 'approval', 'remoteAccess']);
const actionSignals = new Set<Signal>(['login', 'attachment', 'callback', 'qr']);
const linkActions = new Set<Signal>(['login', 'attachment']);
const linkConcerns = new Set<Signal>(['redirect', 'download', 'shortener', 'ip', 'punycode']);
const riskRank = { none: 0, uncertain: 1, elevated: 2, high: 3 };

function assess(
  value: string,
  findings: Finding[],
  links: InspectedLink[],
  coverage: Span[],
  replyMismatch: boolean,
): Pick<Analysis, 'risk' | 'reason'> {
  const active = new Set(findings.map((finding) => finding.signal));
  const pressure = active.has('urgency');
  const solicitation = [...active].some((signal) => sensitiveSignals.has(signal));
  const pretext = active.has('reward') || active.has('impersonation') || active.has('delivery') || active.has('invoice');
  const action = [...active].some((signal) => actionSignals.has(signal));
  const requestTargets = (signals: Set<Signal>) => linksForRequests(value,
    findings.filter((finding) => signals.has(finding.signal)), links, coverage);
  const hasDeception = (link: InspectedLink) => link.crossDomainMismatch || link.signals.some((signal) => strongLinkSignals.has(signal));
  if (solicitation && requestTargets(sensitiveSignals).some(hasDeception)) {
    return { risk: 'high', reason: 'requestAndDeception' };
  }
  if (solicitation && pressure && pretext) return { risk: 'high', reason: 'requestAndPressure' };
  if (action && requestTargets(linkActions).some(hasDeception)) {
    return { risk: 'high', reason: 'actionAndDeception' };
  }
  if (solicitation) return { risk: 'elevated', reason: 'sensitiveRequest' };
  if (links.some(hasDeception)) return { risk: 'elevated', reason: 'destinationDeception' };
  if (pressure && pretext) return { risk: 'elevated', reason: 'pressureAndPretext' };
  const relatedConcern = action && requestTargets(linkActions).some((link) => link.signals.some((signal) => linkConcerns.has(signal)));
  if (action && (pretext || relatedConcern || replyMismatch)) return { risk: 'elevated', reason: 'actionAndPretext' };
  return { risk: 'uncertain', reason: 'limitedEvidence' };
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
  const textFindings = inspectText(prose);
  for (const { labelSpan } of links) {
    if (!labelSpan) continue;
    for (const finding of inspectText(value.slice(labelSpan.start, labelSpan.end))) {
      textFindings.push({
        ...finding, span: { start: labelSpan.start + finding.span.start, end: labelSpan.start + finding.span.end },
      });
    }
  }
  const hasText = /\p{Script=Latin}/u.test(prose) || textFindings.length > 0;
  const findings = textFindings.map((finding) => ({
    ...finding, contextual: isContextual(value, finding.span),
  }));
  if (headers.finding) findings.push(headers.finding);
  for (const link of links) {
    for (const signal of link.signals) {
      findings.push({ signal, span: link.span, contextual: isContextual(value, link.span) });
    }
  }
  const sections = groupFindings(value, findings);
  let assessment: Pick<Analysis, 'risk' | 'reason'> = !hasText || findings.length
    ? { risk: 'uncertain', reason: 'limitedEvidence' }
    : { risk: 'none', reason: 'noIndicators' };
  let linkIndex = 0;
  for (const section of sections) {
    const start = linkIndex;
    while (links[linkIndex] && links[linkIndex].span.start < section.end) linkIndex++;
    const active = section.findings.filter((finding) => !finding.contextual);
    if (!active.length) continue;
    // Keep benign links in the sequence so a later link cannot replace an earlier target.
    const scopedLinks = links.slice(start, linkIndex);
    const scopedCoverage = coverage.slice(start, linkIndex);
    const contextualStarts = new Set(section.findings.filter((finding) => finding.contextual).map((finding) => finding.span.start));
    const candidates = scopedLinks.map((link) => contextualStarts.has(link.span.start)
      ? { ...link, signals: [], crossDomainMismatch: false } : link);
    const result = assess(value, active, candidates, scopedCoverage, Boolean(headers.finding && !headers.finding.contextual));
    if (riskRank[result.risk] > riskRank[assessment.risk]) assessment = result;
  }
  findings.sort((a, b) => Number(a.contextual) - Number(b.contextual) || priority(a.signal) - priority(b.signal) || a.span.start - b.span.start);

  const unavailable: Analysis['unavailable'] = ['linkAccess', 'senderAuthentication'];
  if (!headers.compared) unavailable.unshift('senderHeaders');
  if (!hasText) unavailable.unshift('text');
  if (!links.length) unavailable.unshift('links');
  return { timestamp, method: METHOD, ...assessment, findings, links, unavailable };
}

function priority(signal: Signal): number {
  if (sensitiveSignals.has(signal) || strongLinkSignals.has(signal)) return 0;
  if (signal === 'unparsed' || signal === 'shortener') return 2;
  return 1;
}
