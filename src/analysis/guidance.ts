import { messages } from '../i18n/index.ts';
import type { IntelligenceResult } from './intelligence.ts';
import type { Analysis, Language } from './types.ts';

export function getGuidance(analysis: Analysis, language: Language, intelligence?: IntelligenceResult) {
  const copy = messages[language].guidance;
  const signals = new Set(analysis.findings.filter((finding) => !finding.contextual).map((finding) => finding.signal));
  const nextSteps = [
    copy.verify,
    copy.stop,
    ...(signals.has('secrets') || signals.has('approval') || signals.has('login') ? [copy.account] : []),
    ...(signals.has('payment') || signals.has('invoice') ? [copy.payment] : []),
    ...(signals.has('remoteAccess') || signals.has('attachment') || signals.has('download') ? [copy.device] : []),
    ...(signals.has('qr') ? [copy.qr] : []),
    intelligence?.matches.length ? copy.reportedLink : copy.report,
  ];
  return {
    nextSteps,
    recoverySteps: [copy.opened, copy.shared, copy.paid, copy.installed],
  };
}
