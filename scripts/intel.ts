import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { setTimeout } from 'node:timers/promises';
import {
  DAY_MS, INDICATOR_DAYS, MAX_SNAPSHOT_BYTES, digest, microsoftArticle, normalizeIndicator, type Candidate, type Snapshot,
} from '../src/analysis/intelligence.ts';

const cache = new URL('../.intel/intel.json', import.meta.url);
const output = new URL('../dist/intel.json', import.meta.url);
const buildDirectory = new URL('../dist/', import.meta.url);
const sgb = 'https://siberguvenlik.gov.tr/api/address/index';
const researchPage = 'https://www.microsoft.com/en-us/security/blog/threat-intelligence/social-engineering-phishing/';

async function download(url: string, limit = MAX_SNAPSHOT_BYTES): Promise<string> {
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(30_000) });
  if (!response.ok || !response.body) throw new Error('HTTP ' + response.status);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let result = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.length;
      if (bytes > limit) throw new Error('Source response exceeds limit');
      result += decoder.decode(value, { stream: true });
    }
  } finally {
    await reader.cancel();
  }
  return result + decoder.decode();
}

async function indicators(now: Date): Promise<NonNullable<Snapshot['indicators']>> {
  const windowStart = new Date(now.getTime() - INDICATOR_DAYS * DAY_MS);
  const result = { updatedAt: now.toISOString(), windowStart: windowStart.toISOString(), hosts: [] as string[], urls: [] as string[] };
  for (const type of ['domain', 'url'] as const) {
    const values = new Set<string>();
    for (let page = 1; ; page++) {
      const query = new URLSearchParams({
        type, connectiontype: 'PH', page: String(page), 'per-page': '2500',
        date_gte: windowStart.toISOString().slice(0, 19).replace('T', ' '),
        date_lte: now.toISOString().slice(0, 19).replace('T', ' '),
      });
      const data = JSON.parse(await download(sgb + '?' + query));
      if (!Array.isArray(data.models) || !Number.isInteger(data.pageCount) ||
        data.page !== page - 1 || data.count !== data.models.length || data.pageCount < 0 || data.pageCount > 30) {
        throw new Error('Unexpected SGB pagination');
      }
      for (const row of data.models) {
        if (!row || row.type !== type || row.connectiontype !== 'PH' || typeof row.url !== 'string') {
          throw new Error('Unexpected SGB record');
        }
        const value = normalizeIndicator(row.url, type === 'domain' ? 'host' : 'url');
        if (value) values.add(value);
      }
      if (page >= data.pageCount) break;
    }
    result[type === 'domain' ? 'hosts' : 'urls'] = (await Promise.all([...values].map(digest))).sort();
  }
  if (!result.hosts.length && !result.urls.length) throw new Error('Empty SGB snapshot');
  return result;
}

async function techniques(now: Date, previous: Candidate[]): Promise<NonNullable<Snapshot['techniques']>> {
  const page = await download(researchPage);
  const items = [...page.matchAll(/<a\s+href="(https:\/\/www\.microsoft\.com\/en-us\/security\/blog\/\d{4}\/\d{2}\/\d{2}\/[^"]+)"[^>]*data-bi-ct="title link"[^>]*>([^<]+)</giu)];
  if (!items.length) throw new Error('No Microsoft research cards found');
  const articles = new Map(previous.map((item) => [item.url, item]));
  const topicPatterns = {
    deviceCode: /device.code|eviltokens|oauth/iu,
    qr: /qr.code|quishing/iu,
    impersonation: /impersonat|spoof|passkey|social.engineering/iu,
    delivery: /attachment|shared.files|document.sharing/iu,
  };
  for (const [, link, heading] of items) {
    const title = heading.trim().replaceAll('&amp;', '&').replaceAll('&#8217;', '’').replaceAll('&quot;', '"');
    if (!title || !microsoftArticle(link)) continue;
    const url = new URL(link);
    const date = url.pathname.split('/').slice(4, 7).join('-');
    const time = Date.parse(date + 'T00:00:00Z');
    if (!Number.isFinite(time)) continue;
    url.search = '';
    url.hash = '';
    const topics = Object.entries(topicPatterns).filter(([, pattern]) => pattern.test(title)).map(([name]) => name);
    articles.set(url.href, { title: title.slice(0, 300), url: url.href, published: new Date(time).toISOString(), topics });
  }
  return {
    updatedAt: now.toISOString(),
    candidates: [...articles.values()].sort((a, b) => b.published.localeCompare(a.published)).slice(0, 20),
  };
}

async function previousSnapshot(): Promise<Snapshot> {
  try {
    const data: Snapshot = JSON.parse(await readFile(cache, 'utf8'));
    if (data.schema !== 1) throw new Error('Unsupported snapshot schema');
    return data;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { schema: 1 };
    throw error;
  }
}

async function replace(file: URL, contents: string) {
  const temporary = new URL(file.href + '.' + process.pid + '.tmp');
  await writeFile(temporary, contents, 'utf8');
  await rename(temporary, file);
}

async function publish(snapshot: Snapshot) {
  try {
    await stat(buildDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }
  await replace(output, JSON.stringify(snapshot));
}

async function sync(force: boolean): Promise<boolean> {
  const snapshot = await previousSnapshot();
  const now = new Date();
  const jobs = [];
  if (force || !snapshot.indicators || now.getTime() - Date.parse(snapshot.indicators.updatedAt) >= DAY_MS) {
    jobs.push(indicators(now).then((data) => {
      snapshot.indicators = data;
      console.log('SGB: %d hosts, %d URLs', data.hosts.length, data.urls.length);
    }));
  }
  if (force || !snapshot.techniques || now.getTime() - Date.parse(snapshot.techniques.updatedAt) >= DAY_MS * 7) {
    jobs.push(techniques(now, snapshot.techniques?.candidates ?? []).then((data) => {
      snapshot.techniques = data;
      console.log('Microsoft: %d review candidates', data.candidates.length);
    }));
  }
  const results = await Promise.allSettled(jobs);
  for (const result of results) if (result.status === 'rejected') console.error('Intelligence refresh:', result.reason.message);
  if (results.some((result) => result.status === 'fulfilled')) {
    const contents = JSON.stringify(snapshot);
    if (Buffer.byteLength(contents) > MAX_SNAPSHOT_BYTES) throw new Error('Snapshot exceeds limit');
    await mkdir(new URL('./', cache), { recursive: true });
    await replace(cache, contents);
    await publish(snapshot);
  }
  return results.every((result) => result.status === 'fulfilled');
}

switch (process.argv[2]) {
  case 'publish':
    await publish(await previousSnapshot());
    break;
  case 'watch':
    for (;;) {
      try {
        await sync(false);
      } catch (error) {
        console.error('Intelligence refresh:', error);
      }
      await setTimeout(60 * 60 * 1000);
    }
  case 'sync':
    if (!await sync(true)) process.exitCode = 1;
    break;
  default:
    throw new Error('Choose sync, watch or publish.');
}
