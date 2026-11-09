import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import { DAY_MS, digest } from '../src/analysis/intelligence.ts';
import { exampleEmail } from './email-fixture.ts';

test('loads an original email locally, shows metadata and clears metadata after editing', async ({ page, context }, testInfo) => {
  const external: string[] = [];
  await context.route('https://**', (route) => {
    external.push(route.request().url());
    return route.abort();
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  const chooser = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: '.txt veya .eml dosyası seç' }).click();
  await (await chooser).setFiles({ name: 'original.eml', mimeType: 'message/rfc822', buffer: Buffer.from(exampleEmail) });
  await expect(page.getByRole('textbox')).toHaveValue(/target\.example/);
  await page.getByRole('button', { name: 'Analiz et' }).click();
  await expect(page.getByRole('heading', { name: 'E-postadan çıkarılan bilgiler' })).toBeVisible();
  await expect(page.locator('#result-body')).toContainText('private-invoice.exe');
  await expect(page.locator('#result-body')).toContainText('Gönderici ve yanıt alan adları farklı');
  await expect(page.locator('#result-body')).toContainText('Görünen adres hedefle uyuşmuyor');
  await expect(page.locator('#print-report')).not.toContainText('private-invoice.exe');
  await expect(page.locator('#print-report')).not.toContainText('help@reply.example');
  await expect(page.locator('img[src*="pixel.example"], [onerror]')).toHaveCount(0);
  await page.getByRole('heading', { name: 'E-postadan çıkarılan bilgiler' }).locator('..')
    .screenshot({ path: testInfo.outputPath('email-evidence-mobile.png') });
  await page.getByRole('textbox').fill('Normal message');
  await page.getByRole('button', { name: 'Analiz et' }).click();
  await expect(page.getByRole('heading', { name: 'E-postadan çıkarılan bilgiler' })).toHaveCount(0);
  expect(external).toEqual([]);
});

test('renders research candidates and matches a reported link without sending the address', async ({ page }, testInfo) => {
  const hostname = 'reported.example';
  const requests: string[] = [];
  page.on('request', (request) => requests.push(request.url()));
  const now = new Date().toISOString();
  const hosts = [await digest(hostname)];
  await page.route('**/intel.json', (route) => route.fulfill({ json: {
    schema: 1,
    indicators: { updatedAt: now, windowStart: new Date(Date.now() - DAY_MS).toISOString(), hosts, urls: [] },
    techniques: {
      updatedAt: now,
      candidates: [
        { title: 'Device-code investigation', url: 'https://www.microsoft.com/en-us/security/blog/2026/04/06/device-code/', published: now, topics: ['deviceCode'] },
        { title: 'Unsafe candidate', url: 'javascript:alert(1)', published: now, topics: [] },
      ],
    },
  } }));
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await page.getByText('Phishing araştırmaları ve test adayları').click();
  await expect(page.getByRole('link', { name: 'Device-code investigation' })).toBeVisible();
  await expect(page.getByText('Unsafe candidate')).toHaveCount(0);
  const afterLoad = requests.slice();
  const input = page.getByRole('textbox');
  await input.fill('https://' + hostname + '/private');
  await page.getByRole('button', { name: 'Analiz et' }).click();
  await expect(page.locator('#result-body .intel-match')).toContainText('Phishing olarak bildirilmiş adres eşleşti');
  await expect(page.locator('#result-body .intel-match')).toContainText('Bağlantı 1 · tam ana makine adı');
  await expect(page.locator('#result-body')).toContainText('Listede eşleşen bağlantıyı açmadan');
  await page.screenshot({ path: testInfo.outputPath('intel-mobile.png'), fullPage: true });
  await input.fill('https://sub.' + hostname + '/private');
  await page.getByRole('button', { name: 'Analiz et' }).click();
  await expect(page.locator('#result-body')).toContainText('Bu listede kayıt bulunamadı');
  expect(requests).toEqual(afterLoad);
});

test('analyzes UTF-8 files locally, changes language, exports JSON and prints a redacted report', async ({ page, context, baseURL }, testInfo) => {
  const errors: string[] = [];
  const requests: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  context.on('request', (request) => requests.push(request.url()));
  await context.route((url) => /^https?:$/u.test(url.protocol) && url.origin !== baseURL, (route) => route.abort());
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Kimlik avı şüphesini incele');
  await page.screenshot({ path: testInfo.outputPath('desktop-start.png') });
  const initialRequests = requests.slice();
  expect(initialRequests.every((url) => new URL(url).origin === baseURL)).toBeTruthy();

  await page.getByRole('button', { name: 'Analiz et' }).click();
  await expect(page.getByRole('alert')).toHaveText('Analiz etmek için bir mesaj veya bağlantı gir.');
  const source = 'From: alerts@example.org\nReply-To: queue@bad.example\n\n🔒 Bankanızdan yazıyoruz. Hesabınız kapatılacak. Şifrenizi gönderin. https://paypal.com@bad.example/private?token=local-test';
  const chooser = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: '.txt veya .eml dosyası seç' }).click();
  await (await chooser).setFiles({ name: 'mesaj.txt', mimeType: 'text/plain', buffer: Buffer.from(source) });
  await expect(page.getByRole('textbox')).toHaveValue(source);
  await page.getByRole('button', { name: 'English' }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await page.getByRole('button', { name: 'Analyze', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'High phishing risk' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Analysis result' })).toBeFocused();
  await expect(page.locator('#result-body').getByText('Sender and reply domains differ')).toBeVisible();
  await expect(page.locator('.risk')).toContainText('alongside a deceptive link pattern');
  await expect(page.locator('.inspected-links')).toContainText('Destination hostname · bad.example');
  await page.getByText('Evidence in the message', { exact: true }).click();
  await expect(page.locator('.evidence mark').filter({ hasText: 'Şifrenizi gönderin' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Safe next steps' })).toBeVisible();
  await expect(page.locator('#result-body')).toContainText('Keep passwords and verification codes private.');
  await page.locator('.recovery summary').click();
  await expect(page.locator('.recovery')).toContainText('contact your bank or payment provider immediately');
  await expect(page.locator('.inspected-links a')).toHaveCount(0);

  const file = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download JSON' }).click();
  const downloaded = await file;
  expect(downloaded.suggestedFilename()).toBe('phishing-report.json');
  const raw = await readFile((await downloaded.path())!, 'utf8');
  expect(JSON.parse(raw)).toMatchObject({ assessment: { level: 'high', reason: { id: 'requestAndDeception' } }, language: 'en' });
  expect(JSON.parse(raw).recoverySteps).toHaveLength(4);
  expect(raw).not.toContain('local-test');
  expect(raw).not.toContain('Şifrenizi gönderin');
  expect(raw).not.toContain('bad.example');

  await page.evaluate(() => {
    window.print = () => { document.body.dataset.printCalled = 'yes'; };
  });
  await page.getByRole('button', { name: 'Print / Save as PDF' }).click();
  await expect(page.locator('body')).toHaveAttribute('data-print-called', 'yes');
  await page.emulateMedia({ media: 'print' });
  const report = page.locator('#print-report');
  await expect(report).toBeVisible();
  await expect(report).toContainText('Analysis time');
  await expect(report).toContainText('local-phishing-rules 2.1.0');
  await expect(report).not.toContainText('local-test');
  await expect(page.locator('#editor')).toBeHidden();
  await page.screenshot({ path: testInfo.outputPath('print-report.png'), fullPage: true });
  const pdf = await page.pdf();
  expect(pdf.subarray(0, 4).toString()).toBe('%PDF');
  await page.emulateMedia({ media: 'screen' });
  await page.getByRole('checkbox').check();
  const fullFile = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download JSON' }).click();
  const fullRaw = await readFile((await (await fullFile).path())!, 'utf8');
  expect(JSON.parse(fullRaw).originalText).toBe(source);
  await page.emulateMedia({ media: 'print' });
  await expect(report).toContainText('token=local-test');
  await page.emulateMedia({ media: 'screen' });

  for (const width of [1440, 1280, 900, 390]) {
    await page.setViewportSize({ width, height: 950 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);
    const editor = (await page.locator('#editor').boundingBox())!;
    const results = (await page.locator('.result-panel').boundingBox())!;
    expect(results.y >= editor.y + editor.height).toBe(width <= 960);
    await expect(page.getByRole('button', { name: 'Download JSON' })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath('result-' + width + '.png'), fullPage: true });
  }
  const clear = page.getByRole('button', { name: 'Clear' });
  await clear.focus();
  await clear.press('Enter');
  await expect(page.getByRole('textbox')).toHaveValue('');
  await expect(page.getByRole('textbox')).toBeFocused();
  await expect(report).toBeEmpty();
  await expect(page.getByRole('button', { name: 'Download JSON' })).toHaveCount(0);
  expect(await page.evaluate(async () => ({
    local: localStorage.length,
    session: sessionStorage.length,
    databases: (await indexedDB.databases()).length,
    serviceWorkers: (await navigator.serviceWorker.getRegistrations()).length,
  }))).toEqual({ local: 0, session: 0, databases: 0, serviceWorkers: 0 });
  expect(requests).toEqual(initialRequests);
  expect(errors).toEqual([]);
});

test('invalid files, XSS strings and URL-only messages produce safe states on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  const file = page.locator('#file');
  await file.setInputFiles({ name: 'example.pdf', mimeType: 'application/pdf', buffer: Buffer.from('test') });
  await expect(page.getByRole('alert')).toHaveText('Bir .txt veya .eml dosyası seç.');
  await file.setInputFiles({ name: 'example.txt', mimeType: 'text/plain', buffer: Buffer.from([0xff, 0xfe]) });
  await expect(page.getByRole('alert')).toContainText('UTF-8');
  const input = page.getByRole('textbox');
  await input.fill('a'.repeat(20_001));
  await page.getByRole('button', { name: 'Analiz et' }).click();
  await expect(page.getByRole('alert')).toContainText('20.000');
  await input.fill('https://bit.ly/private');
  await page.getByRole('button', { name: 'Analiz et' }).click();
  await expect(page.getByRole('heading', { name: 'Belirsiz', exact: true })).toBeVisible();
  await expect(page.locator('#result-body').getByText('Mesaj dili değerlendirilemedi.', { exact: false })).toBeVisible();
  await expect(page.locator('#result-body').getByText('Gönderici kimlik doğrulaması ve alan adı itibarı kontrol edilmedi.')).toBeVisible();
  const payload = '<img src="https://bad.example/x" onerror="window.pwned=1"> Şifrenizi gönderin. [Open](javascript:alert)';
  await input.fill(payload);
  await expect(page.getByRole('button', { name: 'JSON indir' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Analiz et' }).click();
  await page.getByText('Mesajdaki ilgili bölümler', { exact: true }).click();
  await expect(page.locator('.evidence')).toHaveText(payload);
  await expect(page.locator('img, a[href^="javascript:"], [onerror]')).toHaveCount(0);
  await page.getByRole('checkbox').check();
  await page.emulateMedia({ media: 'print' });
  await expect(page.locator('#print-report pre')).toHaveText(payload);
  await expect(page.locator('img, [onerror]')).toHaveCount(0);
});
