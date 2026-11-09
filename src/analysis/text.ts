import type { Finding, Signal, Span } from './types.ts';

const patterns: [Signal, RegExp][] = [
  ['urgency', /hesab[ıi]n[ıi]z (?:kapat[ıi]lacak|ask[ıi]ya al[ıi]nacak)|hemen (?:t[ıi]klay[ıi]n|doğrulay[ıi]n|gönderin|ödeyin|yan[ıi]tlay[ıi]n)|(?:son|yaln[ıi]zca) \d+ (?:dakika|saat)|(?:act|respond|verify|pay|click) (?:right now|immediately|within \d+ (?:hours?|minutes?))|(?:account|access) (?:will be|is about to be) (?:locked|suspended|closed)|final warning/giu],
  ['secrets', /(?:(?:şifre|parola|doğrulama kodu|sms kodu|tek kullan[ıi]ml[ıi]k kod|kart bilgileri|kimlik numaras[ıi])(?:n[ıi]z|n[ıi]|[ıi]n[ıi]z[ıi]|[ıi]n[ıi])?)[^\n.!?]{0,45}?(?:gönderin|paylaş[ıi]n|yaz[ıi]n|girin|iletin)|(?:send|share|reply with|provide|enter|confirm) (?:me )?(?:your |the )?(?:password|pin\b|(?:one-time|verification|security|sms) code|otp\b|(?:credit )?card (?:details|number)|social security number)|(?:password|verification code) [^\n.!?]{0,30}?(?:is required|must be provided)/giu],
  ['payment', /(?:iban|hesaba|cüzdana)[^\n.!?]{0,35}?(?:para gönderin|havale yap[ıi]n|transfer edin|ödeme yap[ıi]n)|(?:hediye kart[ıi]|kripto para|bitcoin|kapora|işlem ücreti)[^\n.!?]{0,40}?(?:al[ıi]n|ödeyin|gönderin)|(?:wire|transfer|send) (?:the |your |some )?(?:money|funds|bitcoin|crypto(?:currency)?)|(?:pay|send) (?:a |the )?(?:processing fee|release fee|deposit)|(?:buy|send|pay (?:with|in)) (?:\w+ )?gift cards?/giu],
  ['reward', /(?:ödül|hediye|çekiliş)[^\n.!?]{0,35}?(?:kazand[ıi]n[ıi]z|almaya hak kazand[ıi]n[ıi]z)|(?:you (?:have |just )?won|you have been selected for|claim) (?:a |your |the )?(?:prize|lottery|reward|gift)|(?:guaranteed|risk-free) (?:returns?|profits?)/giu],
  ['impersonation', /(?:bankan[ıi]zdan|destek ekibinden|polis merkezinden|vergi dairesinden|kurye şirketinden) (?:ar[ıi]yoruz|yaz[ıi]yoruz|ulaş[ıi]yoruz)|(?:ben|biz) [^\n.!?]{0,30}?(?:destek ekibindeniz|polis memuruyum|bankan[ıi]z[ıi]z)|(?:this is|we are|i am) (?:calling |writing )?(?:from )?(?:your bank|(?:the )?(?:fraud department|support team|tax office|police))|(?:message|notice) from (?:your bank|the fraud department|the tax office)/giu],
  ['delivery', /(?:kargonuz|paketiniz|gönderiniz)[^\n.!?]{0,45}?(?:teslim edilemedi|iade edilecek|adres eksik|beklemeye al[ıi]nd[ıi])|(?:your (?:parcel|package|shipment))[^\n.!?]{0,45}?(?:could not be delivered|was not delivered|is on hold|will be returned|incomplete address)/giu],
  ['invoice', /(?:izniniz d[ıi]ş[ıi]nda (?:işlem|ödeme)|(?:faturan[ıi]z|aboneliğiniz) [^\n.!?]{0,30}?(?:ödenmedi|otomatik yenilendi|ask[ıi]ya al[ıi]nacak)|bekleyen borcunuz)|(?:unauthorized (?:charge|transaction)|(?:your )?subscription (?:has |was )?(?:automatically )?renewed|(?:your )?(?:invoice|payment) is overdue)/giu],
  ['login', /(?:hesab[ıi]n[ıi]z[ıi]|ödeme bilgilerinizi|teslimat adresinizi)[^\n.!?]{0,35}?(?:doğrulay[ıi]n|güncelleyin)|(?:oturum aç[ıi]n|giriş yap[ıi]n)[^\n.!?]{0,30}?(?:doğrulamak|güncellemek) için|(?:verify|reactivate|unlock) your account|update your (?:billing information|payment details|delivery address)|(?:sign|log) in to (?:verify|restore|reactivate|unlock|update)/giu],
  ['approval', /(?:oturum açma|giriş|mfa|bildirim) (?:isteğini|talebini|bildirimini) onaylay[ıi]n|(?:approve|accept) (?:the |your )?(?:sign-in|login|mfa|push|authentication) (?:request|prompt|notification)/giu],
  ['remoteAccess', /(?:uzaktan erişim(?:e)? (?:izin verin|sağlay[ıi]n)|(?:anydesk|teamviewer|h[ıi]zl[ıi] yard[ıi]m)[^\n.!?]{0,25}?(?:kurun|yükleyin|aç[ıi]n))|(?:allow|grant|enable) (?:us )?(?:remote access|remote control)|(?:install|open|download) (?:anydesk|teamviewer|quick assist)/giu],
  ['attachment', /(?:ekteki (?:dosyay[ıi]|faturay[ıi]|belgeyi) (?:aç[ıi]n|indirin)|makrolar[ıi] etkinleştirin)|(?:open|download|run) (?:the )?(?:attached (?:invoice|file|document)|attachment)|enable (?:editing|macros)/giu],
  ['callback', /(?:bu (?:işlem|ödeme|sat[ıi]n alma) size ait değilse|iptal etmek için)[^\n.!?]{0,65}?(?:aray[ıi]n|ulaş[ıi]n)|(?:if you (?:did not|didn['’]t) (?:authorize|make|recognize) (?:this|the)[^\n.!?]{0,45}?(?:call|contact)|call [^\n.!?]{0,25}? to cancel)/giu],
  ['qr', /(?:qr kodu(?:nu)? (?:taray[ıi]n|okutun)|(?:scan|use) (?:the |this )?qr code)/giu],
];

const contextCue = /(?:\b(?:phishing example|training example|security training|phishing simulation|security awareness|scammers? (?:may|often|can))\b|eğitim örneği|phishing örneği|kimlik av[ıi] örneği|simülasyon|doland[ıi]r[ıi]c[ıi]lar [^\n.!?]{0,35}?(?:isteyebilir|yazabilir|kullanabilir))/iu;

export function isContextual(value: string, span: Span): boolean {
  const lineStart = value.lastIndexOf('\n', span.start - 1) + 1;
  const newline = value.indexOf('\n', span.end);
  const lineEnd = newline < 0 ? value.length : newline;
  const line = value.slice(lineStart, lineEnd);
  const quoted = /"[^"\n]+"|“[^”\n]+”|‘[^’\n]+’|'[^'\n]+'|^>\s.+/gu;
  const context = value.slice(Math.max(0, lineStart - 180), lineStart).trimEnd().split('\n').at(-1) ?? '';
  const before = value.slice(lineStart, span.start);
  const sentencePrefix = before.slice(Math.max(before.lastIndexOf('.'), before.lastIndexOf('!'), before.lastIndexOf('?')) + 1);
  if (/\b(?:never|do not|don['’]t)\s*$|(?:^|\s)asla\s*$/iu.test(sentencePrefix)) return true;
  return (contextCue.test(line) || contextCue.test(context)) && [...line.matchAll(quoted)].some((match) => (
    lineStart + match.index <= span.start && lineStart + match.index + match[0].length >= span.end
  ));
}

export function inspectText(value: string): Finding[] {
  // Dotted uppercase I folds to one UTF-16 code unit here, preserving the input offsets.
  const searchable = value.replaceAll('İ', 'i').replace(/[^\S\n]/gu, ' ');
  return patterns.flatMap(([signal, pattern]) => [...searchable.matchAll(pattern)].map((match) => ({
    signal, span: { start: match.index, end: match.index + match[0].length }, contextual: false,
  })));
}
