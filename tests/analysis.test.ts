import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analyze } from '../src/analysis/analyze.ts';
import { characterCount, readTextFile, validateText } from '../src/analysis/input.ts';
import { createReport, mergeSpans } from '../src/analysis/report.ts';
import { MAX_CHARACTERS, MAX_FILE_BYTES } from '../src/config.ts';

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
  assert.equal(report.method.version, '1.0.0');
  assert.equal(report.assessment.level, 'elevated');
  assert.deepEqual(report.unavailable.map(({ id }) => id), ['linkAccess', 'ai', 'fact', 'source']);
  assert.equal(report.limitations.length, 2);
  const json = JSON.stringify(report);
  for (const privateValue of [text, 'token=', 'Send your password', 'excerpt', 'originalText', 'example.org']) {
    assert.ok(!json.includes(privateValue));
  }
  const full = createReport(result, text, 'en', true);
  assert.equal(full.originalText, text);
  assert.equal(full.findings[0].excerpt, 'Send your password');
  assert.equal(full.links[0].url, 'https://example.org/private?token=sensitive');
});
