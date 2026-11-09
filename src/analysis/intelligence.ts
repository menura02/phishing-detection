import { urlFrom } from './links.ts';
import type { Analysis } from './types.ts';

export const DAY_MS = 86_400_000;
export const INDICATOR_DAYS = 14;
export const MAX_SNAPSHOT_BYTES = 8_000_000;
export const INTEL_SOURCE = 'T.C. Siber Güvenlik Başkanlığı';
export const INTEL_SOURCE_URL = 'https://siberguvenlik.gov.tr/zararli-baglantilar';

export type Candidate = {
  title: string;
  url: string;
  published: string;
  topics: string[];
};

export type Snapshot = {
  schema: 1;
  indicators?: { updatedAt: string; windowStart: string; hosts: string[]; urls: string[] };
  techniques?: { updatedAt: string; candidates: Candidate[] };
};

export type IntelligenceResult = {
  status: 'unavailable' | 'notApplicable' | 'fresh' | 'stale';
  updatedAt?: string;
  windowStart?: string;
  matches: { number: number; kind: 'host' | 'url' }[];
};

const fingerprint = /^[a-f0-9]{64}$/u;

export function validateSnapshot(data: Snapshot): Snapshot {
  if (data?.schema !== 1) return { schema: 1 };
  const result: Snapshot = { schema: 1 };
  const list = data.indicators;
  if (list && Number.isFinite(Date.parse(list.updatedAt)) && Number.isFinite(Date.parse(list.windowStart)) &&
    Array.isArray(list.hosts) && list.hosts.every((item) => typeof item === 'string' && fingerprint.test(item)) &&
    Array.isArray(list.urls) && list.urls.every((item) => typeof item === 'string' && fingerprint.test(item)) &&
    (list.hosts.length || list.urls.length)) result.indicators = list;
  const research = data.techniques;
  if (research && Number.isFinite(Date.parse(research.updatedAt)) && Array.isArray(research.candidates)) {
    const candidates = research.candidates.filter((item) => item && typeof item.title === 'string' &&
      typeof item.url === 'string' && microsoftArticle(item.url) && Number.isFinite(Date.parse(item.published)) &&
      Array.isArray(item.topics) && item.topics.every((topic) => typeof topic === 'string')).slice(0, 20);
    result.techniques = { updatedAt: research.updatedAt, candidates };
  }
  return result;
}

export function normalizeIndicator(raw: string, kind: 'host' | 'url'): string | undefined {
  const url = urlFrom(raw);
  if (!url || url.username || url.password) return;
  url.hostname = url.hostname.replace(/\.$/u, '');
  if (kind === 'host') {
    if (url.pathname !== '/' || url.search || url.hash || url.port) return;
    return url.hostname;
  }
  url.hash = '';
  return url.href;
}

export function microsoftArticle(value: string): boolean {
  if (!URL.canParse(value)) return false;
  const url = new URL(value);
  return url.origin === 'https://www.microsoft.com' && !url.username && !url.password &&
    /^\/en-us\/security\/blog\/\d{4}\/\d{2}\/\d{2}\//u.test(url.pathname);
}

export async function digest(value: string): Promise<string> {
  const buffer = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function matchIntelligence(
  analysis: Analysis,
  snapshot: Snapshot,
  now = Date.now(),
): Promise<IntelligenceResult> {
  if (!analysis.links.some((link) => link.hostname)) return { status: 'notApplicable', matches: [] };
  const data = snapshot.indicators;
  if (!data || !globalThis.crypto?.subtle) return { status: 'unavailable', matches: [] };
  const time = Date.parse(data.updatedAt);
  const start = Date.parse(data.windowStart);
  if (!Number.isFinite(time) || !Number.isFinite(start) || start > time || time > now + 60_000) {
    return { status: 'unavailable', matches: [] };
  }

  const hosts = new Set(data.hosts);
  const urls = new Set(data.urls);
  const matches: IntelligenceResult['matches'] = [];
  for (const [index, link] of analysis.links.entries()) {
    const full = normalizeIndicator(link.raw, 'url');
    if (full && urls.has(await digest(full))) matches.push({ number: index + 1, kind: 'url' });
    else if (link.hostname && hosts.has(await digest(link.hostname))) matches.push({ number: index + 1, kind: 'host' });
  }
  return {
    status: now - time > DAY_MS * 2 ? 'stale' : 'fresh',
    updatedAt: data.updatedAt,
    windowStart: data.windowStart,
    matches,
  };
}
