import type { Finding, Signal, Span } from './types.ts';

const patterns: [Signal, RegExp][] = [
  ['urgency', /hesab[ıi]n[ıi]z (?:kapat[ıi]lacak|ask[ıi]ya al[ıi]nacak)|hemen (?:t[ıi]klay[ıi]n|doğrulay[ıi]n|gönderin|ödeyin|yan[ıi]tlay[ıi]n)|(?:son|yaln[ıi]zca) \d+ (?:dakika|saat)|(?:act|respond|verify|pay|click) (?:right now|immediately|within \d+ (?:hours?|minutes?))|(?:account|access) (?:will be|is about to be) (?:locked|suspended|closed)|final warning/giu],
  ['secrets', /(?:(?:şifre|parola|doğrulama kodu|sms kodu|tek kullan[ıi]ml[ıi]k kod|kart bilgileri|kimlik numaras[ıi])(?:n[ıi]z|n[ıi]|[ıi]n[ıi]z[ıi]|[ıi]n[ıi])?)[^\n.!?]{0,45}?(?:gönderin|paylaş[ıi]n|yaz[ıi]n|girin|iletin)|(?:send|share|reply with|provide|enter|confirm) (?:me )?(?:your |the )?(?:password|pin\b|(?:one-time|verification|security|sms) code|otp\b|(?:credit )?card (?:details|number)|social security number)|(?:password|verification code) [^\n.!?]{0,30}?(?:is required|must be provided)/giu],
  ['payment', /(?:iban|hesaba|cüzdana)[^\n.!?]{0,35}?(?:para gönderin|havale yap[ıi]n|transfer edin|ödeme yap[ıi]n)|(?:hediye kart[ıi]|kripto para|bitcoin|kapora|işlem ücreti)[^\n.!?]{0,40}?(?:al[ıi]n|ödeyin|gönderin)|(?:wire|transfer|send) (?:the |your |some )?(?:money|funds|bitcoin|crypto(?:currency)?)|(?:pay|send) (?:a |the )?(?:processing fee|release fee|deposit)|(?:buy|send|pay (?:with|in)) (?:\w+ )?gift cards?/giu],
  ['reward', /(?:ödül|hediye|çekiliş)[^\n.!?]{0,35}?(?:kazand[ıi]n[ıi]z|almaya hak kazand[ıi]n[ıi]z)|(?:you (?:have |just )?won|you have been selected for|claim) (?:a |your |the )?(?:prize|lottery|reward|gift)|(?:guaranteed|risk-free) (?:returns?|profits?)/giu],
  ['impersonation', /(?:bankan[ıi]zdan|destek ekibinden|polis merkezinden|vergi dairesinden|kurye şirketinden) (?:ar[ıi]yoruz|yaz[ıi]yoruz|ulaş[ıi]yoruz)|(?:ben|biz) [^\n.!?]{0,30}?(?:destek ekibindeniz|polis memuruyum|bankan[ıi]z[ıi]z)|(?:this is|we are|i am) (?:calling |writing )?(?:from )?(?:your bank|(?:the )?(?:fraud department|support team|tax office|police))|(?:message|notice) from (?:your bank|the fraud department|the tax office)/giu],
];

const contextCue = /(?:\b(?:example|training|simulation|awareness|scammers?|never (?:send|share|enter|provide|pay)|do not (?:send|share|enter|provide|pay))\b|örnek|eğitim|simülasyon|doland[ıi]r[ıi]c[ıi]lar|asla (?:gönder|paylaş|yaz|gir)|(?:gönder|paylaş|girme|ödeme)[a-zçğıöşü]*may[ıi]n|(?:paylaş|gönder|gir)meyin)/iu;

export function isContextual(value: string, span: Span): boolean {
  const lineStart = value.lastIndexOf('\n', span.start - 1) + 1;
  const newline = value.indexOf('\n', span.end);
  const lineEnd = newline < 0 ? value.length : newline;
  const line = value.slice(lineStart, lineEnd);
  const quoted = /"[^"\n]+"|“[^”\n]+”|‘[^’\n]+’|'[^'\n]+'|^>\s.+/gu;
  const context = value.slice(Math.max(0, lineStart - 180), lineStart).trimEnd().split('\n').at(-1) ?? '';
  const before = value.slice(lineStart, span.start);
  const sentencePrefix = before.slice(Math.max(before.lastIndexOf('.'), before.lastIndexOf('!'), before.lastIndexOf('?')) + 1);
  if (contextCue.test(sentencePrefix) || /\b(?:never|do not|don['’]t)\s*$/iu.test(sentencePrefix)) return true;
  return (contextCue.test(line) || contextCue.test(context)) && [...line.matchAll(quoted)].some((match) => (
    lineStart + match.index <= span.start && lineStart + match.index + match[0].length >= span.end
  ));
}

export function inspectText(value: string): Finding[] {
  // Dotted uppercase I folds to one UTF-16 code unit here, preserving the input offsets.
  const searchable = value.replaceAll('İ', 'i');
  return patterns.flatMap(([signal, pattern]) => [...searchable.matchAll(pattern)].map((match) => ({
    signal, span: { start: match.index, end: match.index + match[0].length }, contextual: false,
  })));
}
