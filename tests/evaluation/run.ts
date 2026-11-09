import { readFileSync } from 'node:fs';
import { analyze } from '../../src/analysis/analyze.ts';
import type { Language, Risk } from '../../src/analysis/types.ts';

type Fixture = { id: string; language: Language; label: 'phishing' | 'legitimate'; text: string };

const split = process.argv[2] ?? 'development';
if (split !== 'development' && split !== 'holdout') throw new Error('Choose development or holdout.');
const fixtures: Fixture[] = JSON.parse(readFileSync(new URL(split + '.json', import.meta.url), 'utf8'));
const results = fixtures.map(({ id, language, label, text }) => {
  const { risk, reason } = analyze(text);
  return { id, language, label, risk, reason };
});

function summarize(rows: typeof results, threshold: Risk) {
  const flagged = (risk: Risk) => risk === 'high' || (threshold === 'elevated' && risk === 'elevated');
  return {
    phishingCaught: rows.filter((row) => row.label === 'phishing' && flagged(row.risk)).length,
    phishingMissed: rows.filter((row) => row.label === 'phishing' && !flagged(row.risk)).length,
    legitimateFlagged: rows.filter((row) => row.label === 'legitimate' && flagged(row.risk)).length,
    legitimateUnflagged: rows.filter((row) => row.label === 'legitimate' && !flagged(row.risk)).length,
  };
}

console.log(JSON.stringify({
  split,
  metrics: ['all', 'tr', 'en'].map((language) => {
    const rows = results.filter((row) => language === 'all' || row.language === language);
    return { language, elevatedOrHigh: summarize(rows, 'elevated'), highOnly: summarize(rows, 'high') };
  }),
  results,
}, null, 2));
