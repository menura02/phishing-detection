import { parse } from 'tldts';
import type { InspectedLink, Signal, Span } from './types.ts';

const shorteners = new Set(['bit.ly', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd', 'cutt.ly', 'rb.gy', 'goo.gl', 'buff.ly', 'rebrand.ly']);
const brandDomains = ['paypal.com', 'microsoft.com', 'apple.com', 'google.com', 'amazon.com', 'netflix.com', 'turkiye.gov.tr', 'ziraatbank.com.tr'];
const redirectKeys = new Set(['url', 'redirect', 'redirect_url', 'redirect_uri', 'return', 'returnto', 'continue', 'next', 'destination', 'target']);
const riskyExtensions = /\.(?:exe|msi|scr|bat|cmd|ps1|js|vbs|hta|lnk|apk|iso|docm|xlsm|pptm)$/iu;
const hostnamePattern = /^(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?\.)+[\p{L}][\p{L}\p{N}-]*\.?(?=[:/?#]|$)/iu;
const looseLinks = /(?<![\p{L}\p{N}_@./-])(?:[a-z][a-z\d+.-]*:\/\/[^\s<>"']+|\/\/[^\s<>"']+|www\.[^\s<>"']+|(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?(?:\.|\[\.\]))+(?:xn--[\p{L}\p{N}-]+|[\p{L}]{2,63}))(?::\d+)?(?:[/?#][^\s<>"']*)?)(?![\p{L}\p{N}_@-])/giu;

function restoreAddress(raw: string): string {
  return raw.replace(/^hxxp(s?):/iu, 'http$1:').replaceAll('[.]', '.');
}

export function urlFrom(raw: string): URL | undefined {
  const value = restoreAddress(raw.trim());
  if (!value.startsWith('//') && !/^[a-z][a-z\d+.-]*:\/\//iu.test(value) &&
      !hostnamePattern.test(value) && !/^(?:\d{1,3}\.){3}\d{1,3}(?=[:/?#]|$)/u.test(value)) return;
  try {
    const url = new URL(value.startsWith('//') ? 'https:' + value : /^[a-z][a-z\d+.-]*:\/\//iu.test(value) ? value : 'https://' + value);
    if (url.protocol === 'http:' || url.protocol === 'https:') return url;
  } catch {
    return;
  }
}

function cleanTrailing(raw: string): string {
  let value = raw.replace(/[.,!?;:…\]}]+$/u, '');
  const balance = [...value].reduce((count, character) => count + Number(character === ')') - Number(character === '('), 0);
  for (let remaining = balance; remaining > 0 && value.endsWith(')'); remaining--) value = value.slice(0, -1);
  return value;
}

function inspectTarget(raw: string, label?: string): Pick<InspectedLink, 'signals' | 'hostname' | 'domain' | 'crossDomainMismatch'> {
  const restored = restoreAddress(raw);
  const url = urlFrom(restored);
  if (!url) return { signals: ['unparsed'] };

  const host = url.hostname.replace(/\.$/u, '');
  const parts = parse(host, { allowPrivateDomains: true });
  const shown = label && urlFrom(restoreAddress(label));
  const signals: Signal[] = [];
  let crossDomainMismatch = false;
  if (shown) {
    const shownHost = shown.hostname.replace(/\.$/u, '');
    const explicitScheme = /^https?:\/\//iu.test(label);
    const explicitPath = shown.pathname !== '/' || Boolean(shown.search || shown.hash);
    if (shownHost !== host || shown.port !== url.port ||
      (explicitScheme && shown.protocol !== url.protocol) ||
      (explicitPath && shown.pathname + shown.search + shown.hash !== url.pathname + url.search + url.hash)) {
      signals.push('mismatch');
      const shownDomain = parse(shownHost, { allowPrivateDomains: true }).domain ?? shownHost;
      crossDomainMismatch = shownDomain !== (parts.domain ?? host);
    }
  }
  if (parts.isIp) signals.push('ip');
  if (host.split('.').some((part) => part.startsWith('xn--'))) signals.push('punycode');
  if (url.username || url.password) signals.push('userinfo');
  if (shorteners.has(host) || (parts.domain && shorteners.has(parts.domain))) signals.push('shortener');
  if (brandDomains.some((domain) => ('.' + host + '.').includes('.' + domain + '.') &&
    host !== domain && !host.endsWith('.' + domain))) {
    signals.push('subdomain');
  }
  const name = parts.domainWithoutSuffix;
  if (name && brandDomains.some((domain) => {
    const brand = domain.split('.')[0];
    return !host.endsWith('.' + domain) && host !== domain &&
      (name.split('-').includes(brand) || name.replaceAll('0', 'o').replaceAll('1', 'l') === brand);
  })) signals.push('lookalike');
  const redirectTargets = new Set<string>();
  for (const [key, value] of url.searchParams) {
    if (!redirectKeys.has(key.toLowerCase()) || !/^(?:https?:)?\/\//iu.test(value)) continue;
    const target = urlFrom(value);
    if (!target) continue;
    const targetHost = target.hostname.replace(/\.$/u, '');
    const targetDomain = parse(targetHost, { allowPrivateDomains: true }).domain ?? targetHost;
    if (targetDomain !== (parts.domain ?? host)) {
      redirectTargets.add(target.href);
    }
  }
  if (redirectTargets.size) signals.push('redirect');
  // An explicitly embedded matching address can explain the mismatch without proving the redirect behavior.
  if (shown && redirectTargets.size === 1 && redirectTargets.has(shown.href)) crossDomainMismatch = false;
  const path = url.pathname.replace(/%[0-9a-f]{2}/giu, (code) => String.fromCharCode(Number.parseInt(code.slice(1), 16)));
  if (riskyExtensions.test(path)) signals.push('download');
  if (restored !== raw) signals.push('defanged');
  return { signals, hostname: host, domain: parts.domain ?? undefined, ...(crossDomainMismatch ? { crossDomainMismatch } : {}) };
}

function overlaps(a: Span, b: Span): boolean {
  return a.start < b.end && b.start < a.end;
}

export function inspectLinks(value: string): { links: InspectedLink[]; coverage: Span[] } {
  const links: InspectedLink[] = [];
  const coverage: Span[] = [];
  function addMarkup(match: RegExpExecArray, range: [number, number], label: string, base = 0) {
    const outer = { start: match.index, end: match.index + match[0].length };
    if (coverage.some((span) => overlaps(span, outer))) return;
    const span = { start: base + range[0], end: base + range[1] };
    const raw = value.slice(span.start, span.end);
    const [labelStart, labelEnd] = match.indices!.groups!.label;
    const labelSpan = urlFrom(label) ? undefined : { start: labelStart, end: labelEnd };
    coverage.push(outer);
    links.push({ raw, span, labelSpan, ...inspectTarget(raw, label) });
  }

  const anchors = /<a(?=\s|>)(?<attrs>(?:[^<>"'\n]|"[^"\n]*"|'[^'\n]*')*)>(?<label>[^<\n]*)<\/a\s*>/dgiu;
  const attributes = /(?<name>[\w:-]+)(?:\s*=\s*(?:"(?<double>[^"\n]*)"|'(?<single>[^'\n]*)'|(?<unquoted>[^\s"'=<>]+)))?/dgu;
  for (const match of value.matchAll(anchors)) {
    const attr = [...match.groups!.attrs.matchAll(attributes)].find((item) => item.groups!.name.toLowerCase() === 'href');
    const indexes = attr?.indices?.groups;
    const range = indexes?.double ?? indexes?.single ?? indexes?.unquoted;
    if (range) addMarkup(match, range, match.groups!.label, match.indices!.groups!.attrs[0]);
  }

  const markdown = /\[(?<label>[^[\]\n]+)\]\(\s*(?:<(?<angled>[^>\n]+)>|(?<bare>[^\s)<>]+))(?:\s+["'][^"'\n]*["'])?\s*\)/dgu;
  for (const match of value.matchAll(markdown)) {
    const indexes = match.indices!.groups!;
    addMarkup(match, indexes.angled ?? indexes.bare, match.groups!.label);
  }

  for (const match of value.matchAll(looseLinks)) {
    const raw = cleanTrailing(match[0]);
    const span = { start: match.index, end: match.index + raw.length };
    if (!raw || coverage.some((existing) => overlaps(existing, span))) continue;
    if (!urlFrom(restoreAddress(raw)) && !/^(?:[a-z][a-z\d+.-]*:)?\/\//iu.test(raw)) continue;
    coverage.push(span);
    links.push({ raw, span, ...inspectTarget(raw) });
  }

  return { links: links.sort((a, b) => a.span.start - b.span.start), coverage: coverage.sort((a, b) => a.start - b.start) };
}
