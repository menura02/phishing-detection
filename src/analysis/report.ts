import { messages } from '../i18n/index.ts';
import type { Analysis, Language, Span } from './types.ts';

export function createReport(analysis: Analysis, value: string, language: Language, includeContent = false) {
  const copy = messages[language];
  return {
    schemaVersion: 1,
    timestamp: analysis.timestamp,
    analysisType: 'phishing',
    language,
    method: analysis.method,
    assessment: { level: analysis.risk, label: copy.risk[analysis.risk], scope: copy.scope },
    findings: analysis.findings.map(({ signal, contextual, span }) => ({
      signal, contextual, title: copy.signals[signal][0], explanation: copy.signals[signal][1],
      ...(includeContent ? { span, excerpt: value.slice(span.start, span.end) } : {}),
    })),
    links: analysis.links.map(({ raw, signals }, index) => ({
      number: index + 1, signals,
      ...(includeContent ? { url: raw } : {}),
    })),
    unavailable: analysis.unavailable.map((id) => ({ id, explanation: copy.checks[id] })),
    limitations: [copy.limitText, copy.aiLimit],
    nextSteps: copy.steps,
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
