import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { analyze } from '../../src/analysis/analyze.ts';
import { extractEmail } from '../../src/analysis/email.ts';
import { validateText } from '../../src/analysis/input.ts';
import type { Risk } from '../../src/analysis/types.ts';

const sampleSize = 80;
const mailbox = '.evaluation/phishing-2025';
const ham = '.evaluation/hard-ham.tar.bz2';
const split = process.argv[2] ?? 'all';
if (split !== 'all' && split !== 'development' && split !== 'holdout') throw new Error('Expected all, development or holdout.');

function pick<T>(items: T[]): T[] {
  const sampled = items.length <= sampleSize ? items :
    Array.from({ length: sampleSize }, (_, index) => items[Math.floor((index + 0.5) * items.length / sampleSize)]);
  return split === 'all' ? sampled : sampled.filter((_, index) => index % 2 === Number(split === 'holdout'));
}

function sha256(data: Buffer) {
  return createHash('sha256').update(data).digest('hex');
}

function mbox(data: Buffer): Buffer[] {
  // Latin-1 maps every input byte to one code unit, keeping the original MIME bytes intact.
  const text = data.toString('latin1');
  const starts = [...text.matchAll(/^From [^\r\n]+\r?\n/gmu)];
  if (!starts.length || starts[0].index !== 0) throw new Error('Expected an mbox archive.');
  return starts.map((match, index) => data.subarray(match.index + match[0].length, starts[index + 1]?.index));
}

async function compare(messages: Buffer[]) {
  const result = {
    selected: messages.length, compared: 0, excluded: 0, html: 0,
    plain: { high: 0, elevated: 0, uncertain: 0, none: 0 },
    eml: { high: 0, elevated: 0, uncertain: 0, none: 0 },
    raisedToHigh: 0, droppedFromHigh: 0, extraLinkTargets: 0, replyMismatch: 0,
    reasons: {} as Record<string, number>,
    activeSignals: {} as Record<string, number>,
    labelMismatches: { sameDomain: 0, crossDomain: 0, sameDomainOnlyMessages: 0 },
  };
  for (const raw of messages) {
    try {
      const extracted = await extractEmail(raw);
      if (validateText(extracted.plain) || validateText(extracted.value)) {
        result.excluded++;
        continue;
      }
      const plain = analyze(extracted.plain);
      const eml = analyze(extracted.value);
      const hit = (risk: Risk) => risk === 'high';
      result.compared++;
      result.html += Number(extracted.evidence.bodyFormat === 'html');
      result.plain[plain.risk]++;
      result.eml[eml.risk]++;
      result.reasons[eml.reason] = (result.reasons[eml.reason] ?? 0) + 1;
      for (const signal of new Set(eml.findings.filter((finding) => !finding.contextual).map((finding) => finding.signal))) {
        result.activeSignals[signal] = (result.activeSignals[signal] ?? 0) + 1;
      }
      const mismatches = eml.links.filter((link) => link.signals.includes('mismatch'));
      for (const link of mismatches) result.labelMismatches[link.crossDomainMismatch ? 'crossDomain' : 'sameDomain']++;
      if (mismatches.length && mismatches.every((link) => !link.crossDomainMismatch)) result.labelMismatches.sameDomainOnlyMessages++;
      result.raisedToHigh += Number(!hit(plain.risk) && hit(eml.risk));
      result.droppedFromHigh += Number(hit(plain.risk) && !hit(eml.risk));
      result.extraLinkTargets += Number(eml.links.length > plain.links.length);
      result.replyMismatch += Number(eml.findings.some((finding) => finding.signal === 'replyMismatch'));
    } catch {
      result.excluded++;
    }
  }
  return result;
}

const phishingBytes = readFileSync(mailbox);
const legitimateBytes = readFileSync(ham);
const names = execFileSync('tar', ['-tf', ham], { encoding: 'utf8' }).split(/\r?\n/u)
  .filter((name) => /^hard_ham\/\d+\.[a-f0-9]{32}$/u.test(name)).sort();
if (!names.length) throw new Error('Expected a SpamAssassin hard_ham archive.');
const [phishing, legitimate] = await Promise.all([
  compare(pick(mbox(phishingBytes))),
  compare(pick(names).map((name) => execFileSync('tar', ['-xOf', ham, name], { maxBuffer: 8_000_000 }))),
]);
console.log(JSON.stringify({
  split,
  phishing: { source: 'Nazario phishing-2025', sha256: sha256(phishingBytes), ...phishing },
  legitimate: { source: 'SpamAssassin 20030228 hard_ham', sha256: sha256(legitimateBytes), ...legitimate },
}, null, 2));
