import { messages } from '../i18n/index.ts';
import { getGuidance } from './guidance.ts';
import { INTEL_SOURCE, INTEL_SOURCE_URL, type IntelligenceResult } from './intelligence.ts';
import type { Analysis, Language, Span } from './types.ts';

export function createReport(
  analysis: Analysis, value: string, language: Language, includeContent = false, intelligence?: IntelligenceResult,
) {
  const copy = messages[language];
  return {
    schemaVersion: 2,
    timestamp: analysis.timestamp,
    analysisType: 'phishing',
    language,
    method: analysis.method,
    assessment: {
      level: analysis.risk, label: copy.risk[analysis.risk], scope: copy.scope,
      reason: { id: analysis.reason, explanation: copy.reasons[analysis.reason] },
    },
    findings: analysis.findings.map(({ signal, contextual, span }) => ({
      signal, contextual, title: copy.signals[signal][0], explanation: copy.signals[signal][1],
      ...(includeContent ? { span, excerpt: value.slice(span.start, span.end) } : {}),
    })),
    links: analysis.links.map(({ raw, signals, hostname, domain }, index) => ({
      number: index + 1, signals,
      ...(includeContent ? { url: raw, hostname, domain } : {}),
    })),
    unavailable: analysis.unavailable.map((id) => ({ id, explanation: copy.checks[id] })),
    limitations: [copy.limitText],
    ...getGuidance(analysis, language, intelligence),
    ...(intelligence ? { intelligence: { source: INTEL_SOURCE, sourceUrl: INTEL_SOURCE_URL, ...intelligence } } : {}),
    ...(includeContent ? { originalText: value } : {}),
  };
}

export function mergeSpans(spans: Span[]): Span[] {
  const merged: Span[] = [];
  for (const span of [...spans].sort((a, b) => a.start - b.start)) {
    const last = merged.at(-1);
    if (last && span.start <= last.end) last.end = Math.max(last.end, span.end);
    else merged.push({ ...span });
  }
  return merged;
}
