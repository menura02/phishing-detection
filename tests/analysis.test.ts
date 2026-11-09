import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analyze } from '../src/analysis/analyze.ts';
import { extractEmail, readEmailFile } from '../src/analysis/email.ts';
import { exampleEmail } from './email-fixture.ts';
import { messages } from '../src/i18n/index.ts';
import { DAY_MS, digest, matchIntelligence, normalizeIndicator, validateSnapshot, type Snapshot } from '../src/analysis/intelligence.ts';
import { characterCount, readTextFile, validateText } from '../src/analysis/input.ts';
import { createReport, mergeSpans } from '../src/analysis/report.ts';
import { MAX_CHARACTERS, MAX_FILE_BYTES } from '../src/config.ts';

test('extracts email evidence and analyzes the actual destination without exposing private metadata in reports', async () => {
  const { value, plain, evidence } = await extractEmail(new TextEncoder().encode(exampleEmail));
  assert.equal(evidence.subject, 'Hesap kontrolü');
  assert.deepEqual(evidence.from, ['support@example.org']);
  assert.deepEqual(evidence.replyTo, ['help@reply.example']);
  assert.deepEqual(evidence.attachments, [{ name: 'private-invoice.exe', mimeType: 'application/octet-stream' }]);
  assert.ok(!value.includes('pixel.example') && !value.includes('emailCodeExecuted') && !value.includes('ZmFrZQ'));
  const result = analyze(value);
  assert.equal(result.reason, 'actionAndDeception');
  assert.equal(result.links[0].raw, 'https://target.example/check?x=1&y=2');
  assert.ok(result.findings.some(({ signal }) => signal === 'replyMismatch'));
  assert.ok(!analyze(plain).findings.some(({ signal }) => signal === 'mismatch'));
  assert.deepEqual(createReport(result, value, 'tr', false, undefined, evidence).email, {
    bodyFormat: 'html', attachmentCount: 1,
  });
  assert.deepEqual(createReport(result, value, 'tr', true, undefined, evidence).email?.attachments, evidence.attachments);
  assert.deepEqual(await readEmailFile(new File(['not an email'], 'bad.eml')), { error: 'emailRead' });
  assert.deepEqual(await readEmailFile(new File([new Uint8Array(2_000_001)], 'large.eml')), { error: 'emailSize' });
});

test('report suggests independent verification and guidance relevant to active evidence', () => {
  const input = 'Send your password. Pay a processing fee. Scan the QR code. Install AnyDesk.';
  const advice = messages.en.guidance;
  const report = createReport(analyze(input), input, 'en');
  assert.deepEqual(report.nextSteps, [advice.verify, advice.stop, advice.account, advice.payment, advice.device, advice.qr, advice.report]);
  assert.deepEqual(report.recoverySteps, [advice.opened, advice.shared, advice.paid, advice.installed]);
  const quote = 'Security training example: “Send your password.”';
  assert.deepEqual(createReport(analyze(quote), quote, 'en').nextSteps, [advice.verify, advice.stop, advice.report]);
  assert.ok(createReport(analyze(input), input, 'en', false, {
    status: 'fresh', matches: [{ number: 1, kind: 'host' }],
  }).nextSteps.includes(advice.reportedLink));
});

test('matches exact threat indicators without widening a host or URL path', async () => {
  const updatedAt = '2026-11-09T06:00:00.000Z';
  const windowStart = '2026-10-26T06:00:00.000Z';
  const snapshot: Snapshot = {
    schema: 1,
    indicators: {
      updatedAt, windowStart,
      hosts: [await digest('reported.example')],
      urls: [await digest('https://shared.example/bad?case=1')],
    },
  };
  const text = 'hxxps://reported[.]example/ https://sub.reported.example/ https://shared.example/bad?case=1#anchor https://shared.example/clean https://shared.example/bad?case=2';
  const analysis = analyze(text);
  const result = await matchIntelligence(analysis, validateSnapshot(snapshot), Date.parse(updatedAt));
  assert.deepEqual(result.matches, [{ number: 1, kind: 'host' }, { number: 3, kind: 'url' }]);
  assert.equal(result.status, 'fresh');
  assert.equal((await matchIntelligence(analysis, snapshot, Date.parse(updatedAt) + 3 * DAY_MS)).status, 'stale');
  assert.equal((await matchIntelligence(analysis, { schema: 1 })).status, 'unavailable');
  assert.equal((await matchIntelligence(analyze('hello'), snapshot)).status, 'notApplicable');
  assert.equal(normalizeIndicator('https://reported.example@different.example/', 'host'), undefined);
  assert.equal(normalizeIndicator('reported.example/path', 'host'), undefined);
  const report = JSON.stringify(createReport(analysis, text, 'en', false, result));
  assert.ok(!report.includes('reported.example') && !report.includes('case=1'));
  assert.ok(report.includes(windowStart));
});

test('combining independent Turkish phishing signals yields high risk', () => {
  const result = analyze('Bankanızdan yazıyoruz. Hesabınız kapatılacak. DOĞRULAMA KODUNUZU GÖNDERİN.');
  assert.equal(result.risk, 'high');
  assert.deepEqual(new Set(result.findings.map((item) => item.signal)), new Set(['impersonation', 'urgency', 'secrets']));
});

test('English transfer, reward and pressure signals work together', () => {
  const result = analyze('You have won a prize. Respond immediately. Pay a processing fee to claim it.');
  assert.equal(result.risk, 'high');
  assert.ok(result.findings.some((item) => item.signal === 'payment'));
  assert.ok(result.findings.some((item) => item.signal === 'reward'));
});

test('ordinary messages and single or repeated urgency indicators do not become high risk', () => {
  assert.equal(analyze('Öğle arasında buluşalım mı?').risk, 'none');
  assert.equal(analyze('Are you still free for lunch on Friday?').risk, 'none');
  assert.equal(analyze('Final warning').risk, 'uncertain');
  assert.equal(analyze('Final warning. Final warning. Final warning.').risk, 'uncertain');
  assert.equal(analyze('Pay a deposit. Pay a deposit. Pay a deposit.').risk, 'elevated');
});

test('education, quoted examples and warnings reduce false positives in both languages', () => {
  for (const value of [
    'Security training example:\n“Final warning. Send your password to http://192.0.2.1.”',
    'Bu bir eğitim örneği:\n“Bankanızdan yazıyoruz. Hesabınız kapatılacak. Şifrenizi gönderin.”',
    'Never send your verification code.',
    'Şifrenizi asla göndermeyin.',
  ]) {
    const result = analyze(value);
    assert.ok(result.risk === 'uncertain' || result.risk === 'none');
    assert.ok(result.findings.every((finding) => finding.contextual));
  }
  assert.equal(analyze('Security training is tomorrow. Send your password to https://paypal.com@bad.example.').risk, 'high');
});

test('URL parser separates domains, credentials, IPs, international hostnames and shorteners', () => {
  const value = [
    'https://www.paypal.com/confirm',
    'https://paypal.com.bad.example/confirm',
    'https://paypal.com@bad.example/login',
    'http://[2001:db8::1]/confirm',
    '192.0.2.1',
    'https://xn--bcher-kva.example/',
    'https://bücher.example/',
    'https://paypal-secure.example/',
    'https://bit.ly/a',
    'https://notbit.ly/a',
    'https://bit.ly.bad.example/a',
  ].join('\n');
  const result = analyze(value);
  assert.deepEqual(result.links.map((link) => link.signals), [
    [], ['subdomain'], ['userinfo'], ['ip'], ['ip'], ['punycode'], ['punycode'], ['lookalike'], ['shortener'], [], [],
  ]);
  assert.ok(result.unavailable.includes('text'));
  assert.equal(analyze('https://example.org/').risk, 'uncertain');
});

test('visible Markdown and HTML link destinations are compared and point to the original text', () => {
  const value = '🙂 [https://example.org/a](<https://example.org/b>)\n<a title="href=x" href="https://bad.example/">example.org</a>';
  const result = analyze(value);
  assert.equal(result.links.length, 2);
  assert.ok(result.links.every((link) => link.signals.includes('mismatch')));
  for (const link of result.links) assert.equal(value.slice(link.span.start, link.span.end), link.raw);
  assert.equal(analyze('[example.org](https://example.org/path)').links[0].signals.length, 0);
});

test('unsupported and malformed links retain uncertainty', () => {
  for (const value of ['ftp://example.org', '[Open](javascript:alert)', 'https://[oops']) {
    const result = analyze(value);
    assert.equal(result.risk, 'uncertain');
    assert.equal(result.links[0].signals[0], 'unparsed');
    assert.ok(result.unavailable.includes('text'));
  }
});

test('correlates a Turkish delivery pretext, information update and deceptive destination', () => {
  const result = analyze('Kargonuz teslim edilemedi. Teslimat adresinizi güncelleyin. [https://example.org](https://parcel-check.example/update)');
  assert.equal(result.risk, 'high');
  assert.equal(result.reason, 'actionAndDeception');
  assert.deepEqual(new Set(result.findings.map((item) => item.signal)), new Set(['delivery', 'login', 'mismatch']));
  assert.equal(analyze('Kargonuz teslim edilemedi.').risk, 'uncertain');
  assert.equal(analyze('Kargonuz teslim edilemedi. Teslimat adresinizi güncelleyin.').risk, 'elevated');
});

test('links only the nearest explicit target to a request in the same section', () => {
  assert.equal(analyze('Verify your account using this link:\n[example.org](https://bad.example/check)').reason, 'actionAndDeception');
  for (const input of [
    'Verify your account at https://account.example.org. [example.org](https://bad.example/check)',
    'Verify your account. Documentation: [example.org](https://bad.example/check)',
    'Verify your account.\n\n[example.org](https://bad.example/check)',
    'Verify your account.\n----- Forwarded message -----\n[example.org](https://bad.example/check)',
  ]) {
    assert.equal(analyze(input).reason, 'destinationDeception');
  }
});

test('separates same-domain and explained redirect mismatches from unrelated destinations', () => {
  const standalone = analyze('[https://example.org](https://tracking.example/redirect)');
  assert.equal(standalone.risk, 'elevated');
  assert.ok(standalone.findings.some((finding) => finding.signal === 'mismatch'));
  const sameSite = analyze('Verify your account: [https://example.org/start](https://login.example.org/check)');
  assert.equal(sameSite.risk, 'uncertain');
  assert.ok(sameSite.findings.some((finding) => finding.signal === 'mismatch'));
  assert.equal(analyze('Verify your account: [example.org](https://different.example/login)').risk, 'high');
  assert.equal(analyze('https://example.org@different.example/').risk, 'elevated');
  const wrapper = analyze('[https://example.org/start](https://tracking.example/redirect?url=https%3A%2F%2Fexample.org%2Fstart)');
  assert.equal(wrapper.risk, 'uncertain');
  assert.deepEqual(wrapper.links[0].signals, ['mismatch', 'redirect']);
  assert.equal(analyze('[https://example.org/start](https://tracking.example/redirect?url=https%3A%2F%2Fexample.org%2Fother)').risk, 'elevated');
});

test('reads a link label as an action and only associates it with its own target', () => {
  const label = 'Belgeyi görüntülemek için oturum açın';
  const value = '🙂 [' + label + '](https://example.org@different.example/)';
  const result = analyze(value);
  const login = result.findings.find((finding) => finding.signal === 'login')!;
  assert.equal(value.slice(login.span.start, login.span.end), label);
  assert.equal(result.reason, 'actionAndDeception');
  assert.equal(analyze('[Sign in to view the file](https://example.org) https://example.org@different.example/').risk, 'elevated');
});

test('keeps quoted and signature evidence visible and evaluates forwarded requests separately', () => {
  for (const divider of ['-- \n', 'Saygılarımla,\n', '> ']) {
    const result = analyze('Hesabınızı doğrulayın.\n' + divider + '[example.org](https://bad.example/check)');
    assert.equal(result.risk, 'uncertain');
    assert.ok(result.findings.some((finding) => finding.signal === 'mismatch' && finding.contextual));
  }
  const forwarded = analyze('Can you review the email below?\n----- Forwarded message -----\nSend your password: https://example.org@bad.example');
  assert.equal(forwarded.reason, 'requestAndDeception');
  assert.equal(analyze('This is your bank.\n\nYour account will be suspended.\n\nSend your password.').risk, 'elevated');
});

test('identifies English invoice callback and device access tactics', () => {
  const result = analyze('Unauthorized charge. If you did not authorize this purchase, call support. Install AnyDesk and approve the sign-in request. Open the attached invoice. Scan the QR code.');
  const signals = new Set(result.findings.map((item) => item.signal));
  assert.deepEqual(signals, new Set(['invoice', 'callback', 'remoteAccess', 'approval', 'attachment', 'qr']));
  assert.equal(result.reason, 'sensitiveRequest');
  assert.equal(analyze('Do not install AnyDesk.').risk, 'uncertain');
  assert.equal(analyze('Security training example: “Open the attached invoice.”').findings[0].contextual, true);
});

test('compares pasted From and Reply-To addresses within a leading header block', () => {
  const input = 'Kimden: Banka <alerts@notify.example.org>\nYanıt Adresi: case@receiver.example\n\nHesabınızı doğrulayın.';
  const result = analyze(input);
  const match = result.findings.find(({ signal }) => signal === 'replyMismatch')!;
  assert.equal(input.slice(match.span.start, match.span.end), 'case@receiver.example');
  assert.equal(result.reason, 'actionAndPretext');
  assert.ok(!result.unavailable.includes('senderHeaders'));
  assert.ok(result.unavailable.includes('senderAuthentication'));
  assert.equal(analyze('From: a@mail.example.org\nReply-To: b@example.org\n\nHello').findings.length, 0);
  assert.ok(analyze('Hello\n\nFrom: a@example.org\nReply-To: b@other.example').unavailable.includes('senderHeaders'));
  assert.ok(analyze('From: a@example.org, b@example.org\nReply-To: c@other.example\n\nHello').unavailable.includes('senderHeaders'));
});

test('examines encoded parameters and download paths without resolving external destinations', () => {
  const value = 'hxxps://support[.]example/leave?next=https%3A%2F%2Fother.example%2Fsetup https://cdn.example.org/setup%2Eexe example[.]org';
  const result = analyze(value);
  assert.deepEqual(result.links.map((link) => link.signals), [['redirect', 'defanged'], ['download'], ['defanged']]);
  assert.deepEqual(result.links.map((link) => link.hostname), ['support.example', 'cdn.example.org', 'example.org']);
  assert.equal(result.links[1].domain, 'example.org');
  assert.equal(analyze('https://example.org/leave?next=https%3A%2F%2Fcdn.example.org').findings.length, 0);
  assert.equal(result.risk, 'uncertain');
});

test('highlights keep UTF-16 offsets across emoji, Turkish casing and repeated phrases', () => {
  const phrase = 'ŞİFRENİZİ GÖNDERİN';
  const value = '😀 ' + phrase + '\n🔒 ' + phrase;
  const spans = analyze(value).findings.map((finding) => finding.span);
  assert.deepEqual(spans.map((span) => span.start), [value.indexOf(phrase), value.lastIndexOf(phrase)]);
  assert.deepEqual(spans.map((span) => value.slice(span.start, span.end)), [phrase, phrase]);
  assert.deepEqual(mergeSpans([{ start: 3, end: 8 }, { start: 1, end: 5 }, { start: 10, end: 12 }]), [
    { start: 1, end: 8 }, { start: 10, end: 12 },
  ]);
});

test('input and UTF-8 file validation enforce both limits', async () => {
  assert.equal(validateText(' \n\t '), 'empty');
  const limit = '🔒'.repeat(MAX_CHARACTERS);
  assert.equal(characterCount(limit), MAX_CHARACTERS);
  assert.equal(validateText(limit), undefined);
  assert.equal(validateText(limit + 'a'), 'tooLong');
  assert.throws(() => analyze('   '), RangeError);
  assert.deepEqual(await readTextFile(new File(['  '], 'file.txt')), { error: 'empty' });
  assert.deepEqual(await readTextFile(new File(['x'], 'file.pdf')), { error: 'fileType' });
  assert.deepEqual(await readTextFile(new File([new Uint8Array(MAX_FILE_BYTES + 1)], 'file.txt')), { error: 'fileSize' });
  assert.deepEqual(await readTextFile(new File([new Uint8Array([0xff, 0xfe])], 'file.txt')), { error: 'fileEncoding' });
  assert.deepEqual(await readTextFile(new File([new Uint8Array([0, 1])], 'file.txt')), { error: 'fileEncoding' });
  assert.deepEqual(await readTextFile(new File(['Çığ\r\n🧪'], 'file.TXT')), { value: 'Çığ\n🧪' });
});

test('report carries method, time and limitations without leaking content by default', () => {
  const text = 'Send your password. https://example.org/private?token=sensitive';
  const result = analyze(text, '2026-10-01T08:00:00.000Z');
  const report = createReport(result, text, 'tr');
  assert.equal(report.timestamp, '2026-10-01T08:00:00.000Z');
  assert.equal(report.analysisType, 'phishing');
  assert.equal(report.schemaVersion, 2);
  assert.equal(report.method.version, '2.2.0');
  assert.equal(report.assessment.level, 'elevated');
  assert.equal(report.assessment.reason.id, 'sensitiveRequest');
  assert.deepEqual(report.unavailable.map(({ id }) => id), ['senderHeaders', 'linkAccess', 'senderAuthentication']);
  assert.equal(report.limitations.length, 1);
  const json = JSON.stringify(report);
  for (const privateValue of [text, 'token=', 'Send your password', 'excerpt', 'originalText', 'example.org']) {
    assert.ok(!json.includes(privateValue));
  }
  const full = createReport(result, text, 'en', true);
  assert.equal(full.originalText, text);
  assert.equal(full.findings[0].excerpt, 'Send your password');
  assert.equal(full.links[0].url, 'https://example.org/private?token=sensitive');
});
