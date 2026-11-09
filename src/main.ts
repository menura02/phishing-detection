import './styles.css';
import { analyze } from './analysis/analyze.ts';
import type { EmailEvidence } from './analysis/email.ts';
import { getGuidance } from './analysis/guidance.ts';
import {
  INTEL_SOURCE, INTEL_SOURCE_URL, MAX_SNAPSHOT_BYTES, matchIntelligence, validateSnapshot, type IntelligenceResult, type Snapshot,
} from './analysis/intelligence.ts';
import { characterCount, readTextFile, validateText, type InputError } from './analysis/input.ts';
import { createReport, mergeSpans } from './analysis/report.ts';
import type { Analysis, Language } from './analysis/types.ts';
import { MAX_CHARACTERS, PRODUCT_NAME } from './config.ts';
import { messages } from './i18n/index.ts';

const app = document.querySelector<HTMLDivElement>('#app')!;
app.innerHTML = `
  <header class="masthead">
    <div class="frame masthead-inner">
      <div class="identity"><span class="brand-mark" aria-hidden="true">◎</span><strong id="brand"></strong></div>
      <div class="languages" role="group" id="languages">
        <button type="button" id="tr" lang="tr" aria-label="Türkçe">TR</button>
        <button type="button" id="en" lang="en" aria-label="English">EN</button>
      </div>
    </div>
  </header>
  <main class="frame">
    <div class="intro">
      <div><p class="eyebrow" id="kicker"></p><h1 id="title"></h1><p class="intro-copy" id="intro"></p></div>
      <aside class="privacy"><p class="local" id="local"></p><p id="privacy"></p></aside>
    </div>
    <div class="workspace">
      <form class="panel editor" id="editor" novalidate>
        <div class="panel-heading"><label for="message" id="input"></label><span id="count"></span></div>
        <textarea id="message" rows="10" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off" aria-describedby="count error"></textarea>
        <p id="error" class="error" role="alert" hidden></p>
        <div class="file-area">
          <button type="button" class="button subtle" id="upload"></button>
          <input type="file" id="file" accept=".txt,.eml,text/plain,message/rfc822" hidden>
          <small id="limits"></small>
        </div>
        <div class="actions">
          <button class="button primary" id="analyze" type="submit"></button>
          <button class="button subtle" id="clear" type="button"></button>
        </div>
      </form>
      <section class="panel result-panel" aria-labelledby="results">
        <h2 class="panel-heading" id="results" tabindex="-1"></h2>
        <div id="result-body"></div>
      </section>
    </div>
    <details id="research" class="panel research"></details>
    <p class="sr-only" role="status" id="status"></p>
  </main>
  <footer class="frame" id="footer"></footer>
  <article id="print-report" class="print-report"></article>
`;

function element<K extends keyof HTMLElementTagNameMap>(tag: K, content?: string, className?: string) {
  const node = document.createElement(tag);
  if (content !== undefined) node.textContent = content;
  if (className) node.className = className;
  return node;
}

function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

const form = byId<HTMLFormElement>('editor');
const input = byId<HTMLTextAreaElement>('message');
const file = byId<HTMLInputElement>('file');
const resultBody = byId('result-body');
const printReport = byId('print-report');

let language: Language = 'tr';
let analysis: Analysis | undefined;
let email: EmailEvidence | undefined;
let intelligence: IntelligenceResult | undefined;
let includeContent = false;
let revision = 0;
let busy: 'reading' | 'running' | undefined;
let error: keyof typeof messages.en.errors | 'failed' | undefined;
let notice: 'changed' | 'cleared' | 'downloadFailed' | undefined;

async function loadSnapshot(): Promise<Snapshot> {
  try {
    const response = await fetch('./intel.json', { cache: 'no-cache', signal: AbortSignal.timeout(4000) });
    if (!response.ok) return { schema: 1 };
    const body = await response.text();
    if (body.length > MAX_SNAPSHOT_BYTES) return { schema: 1 };
    return validateSnapshot(JSON.parse(body));
  } catch {
    // The core rules still work when the optional snapshot cannot be read.
  }
  return { schema: 1 };
}

const snapshotReady = loadSnapshot();
let snapshot: Snapshot = { schema: 1 };
void snapshotReady.then((data) => {
  snapshot = data;
  renderResearch();
});

function list(values: string[], ordered = false) {
  const node = element(ordered ? 'ol' : 'ul');
  node.append(...values.map((value) => element('li', value)));
  return node;
}

function section(title: string, ...children: HTMLElement[]) {
  const node = element('section', undefined, 'result-section');
  node.append(element('h3', title), ...children);
  return node;
}

function localizedTime(value: string) {
  return new Date(value).toLocaleString(language, { dateStyle: 'medium', timeStyle: 'short' });
}

function renderResearch() {
  const copy = messages[language].intel;
  const panel = byId('research');
  panel.replaceChildren(element('summary', copy.research), element('p', copy.review, 'muted'));
  if (snapshot.techniques?.updatedAt) {
    panel.append(element('p', copy.updated + ' · ' + localizedTime(snapshot.techniques.updatedAt), 'muted'));
  }
  const candidates = snapshot.techniques?.candidates ?? [];
  if (!candidates.length) {
    panel.append(element('p', copy.noResearch));
    return;
  }
  panel.append(element('p', copy.testCandidate, 'muted'));
  const rows = element('ul');
  for (const item of candidates) {
    const row = element('li');
    const link = element('a', item.title);
    link.href = item.url;
    link.rel = 'noreferrer';
    const topics = item.topics.filter((topic) => Object.hasOwn(copy.topics, topic))
      .map((topic) => copy.topics[topic as keyof typeof copy.topics]);
    const date = new Date(item.published).toLocaleDateString(language, { dateStyle: 'medium', timeZone: 'UTC' });
    row.append(link, element('p', [date, ...topics].join(' · '), 'muted'));
    rows.append(row);
  }
  panel.append(rows);
}

function intelligenceSection(result: IntelligenceResult) {
  const copy = messages[language];
  const labels = copy.intel;
  const content = [];
  if (result.status === 'unavailable' || result.status === 'notApplicable') {
    content.push(element('p', labels[result.status]));
  } else {
    if (result.status === 'stale') content.push(element('p', labels.stale));
    content.push(element(result.matches.length ? 'strong' : 'p', result.matches.length ? labels.match : labels.noMatch));
    if (result.matches.length) {
      content.push(list(result.matches.map(({ number, kind }) => copy.linkNumber + ' ' + number + ' · ' + labels[kind])));
    }
    content.push(element('p', labels.updated + ' · ' + localizedTime(result.updatedAt!) +
      ' / ' + labels.since + ' · ' + localizedTime(result.windowStart!), 'muted'));
  }
  const source = element('p', labels.source + ' · ', 'muted');
  const sourceLink = element('a', INTEL_SOURCE);
  sourceLink.href = INTEL_SOURCE_URL;
  sourceLink.rel = 'noreferrer';
  source.append(sourceLink);
  content.push(source);
  const panel = section(labels.title, ...content);
  panel.classList.add('intel-result');
  if (result.matches.length) panel.classList.add('intel-match');
  return panel;
}

function showStatus(message: string) {
  byId('status').textContent = message;
}

function updateEditor() {
  const copy = messages[language];
  const count = characterCount(input.value);
  const format = new Intl.NumberFormat(language);
  byId('count').textContent = `${format.format(count)} / ${format.format(MAX_CHARACTERS)}`;
  byId('count').classList.toggle('over-limit', count > MAX_CHARACTERS);
  const errorText = error === 'failed' ? copy.failed : error ? copy.errors[error] : '';
  byId('error').hidden = !error;
  byId('error').textContent = errorText;
  input.setAttribute('aria-invalid', String(Boolean(error && error !== 'failed')));
  byId<HTMLButtonElement>('analyze').disabled = Boolean(busy);
  byId<HTMLButtonElement>('upload').disabled = Boolean(busy);
  form.setAttribute('aria-busy', String(Boolean(busy)));
}

function makeEvidence(result: Analysis, value: string) {
  const evidence = element('pre', undefined, 'evidence');
  let offset = 0;
  for (const span of mergeSpans(result.findings.map((finding) => finding.span))) {
    evidence.append(value.slice(offset, span.start), element('mark', value.slice(span.start, span.end)));
    offset = span.end;
  }
  evidence.append(value.slice(offset));
  return evidence;
}

function emailSection(data: Partial<EmailEvidence> & Pick<EmailEvidence, 'bodyFormat'> & { attachmentCount: number }) {
  const copy = messages[language].email;
  const fields = [
    copy.format + ' · ' + copy[data.bodyFormat],
    copy.count + ' · ' + new Intl.NumberFormat(language).format(data.attachmentCount),
  ];
  if (data.subject) fields.push(copy.subject + ' · ' + data.subject);
  if (data.from?.length) fields.push(copy.from + ' · ' + data.from.join(', '));
  if (data.replyTo?.length) fields.push(copy.replyTo + ' · ' + data.replyTo.join(', '));
  const panel = section(copy.title, list(fields), element('p', copy.limit, 'muted'));
  if (data.attachments?.length) {
    panel.append(list(data.attachments.map(({ name, mimeType }) => [name || copy.unnamed, mimeType].filter(Boolean).join(' · '))));
  }
  return panel;
}

function renderPrint() {
  printReport.replaceChildren();
  if (!analysis) return;
  const copy = messages[language];
  const report = createReport(analysis, input.value, language, includeContent, intelligence, email);
  printReport.append(
    element('h1', `${PRODUCT_NAME[language]} · ${copy.report}`),
    element('p', copy.mode),
    element('h2', report.assessment.label),
    element('p', report.assessment.reason.explanation),
    element('p', report.assessment.scope),
    element('p', `${copy.reportTime} · ${report.timestamp}`),
    element('p', `${copy.reportMethod} · ${report.method.id} ${report.method.version}`),
    section(copy.findings, report.findings.length
      ? list(report.findings.map((finding) => [
        finding.title, finding.explanation, finding.contextual ? copy.contextual : '', 'excerpt' in finding ? finding.excerpt : '',
      ].filter(Boolean).join(' · ')))
      : element('p', copy.noFindings)),
  );
  if (report.links.length) {
    printReport.append(section(copy.links, list(report.links.map((link) => [
      `${copy.linkNumber} ${link.number}`, link.url,
      link.hostname ? `${copy.destination} · ${link.hostname}` : '',
      link.domain ? `${copy.domain} · ${link.domain}` : '',
      link.signals.map((signal) => copy.signals[signal][0]).join(', ') || copy.linkClean,
    ].filter(Boolean).join(' · ')))));
  }
  if (report.intelligence) printReport.append(intelligenceSection(report.intelligence));
  if (report.email) printReport.append(emailSection(report.email));
  printReport.append(
    section(copy.unavailable, list(report.unavailable.map((item) => item.explanation))),
    section(copy.limitations, list(report.limitations)),
    section(copy.next, list(report.nextSteps, true)),
    section(copy.recovery, list(report.recoverySteps)),
  );
  if (report.originalText !== undefined) printReport.append(section(copy.original, element('pre', report.originalText)));
}

function renderResult() {
  const copy = messages[language];
  resultBody.replaceChildren();
  if (!analysis) {
    const empty = element('div', undefined, 'empty-result');
    const icon = element('span', busy ? '…' : '≋', 'empty-icon');
    icon.setAttribute('aria-hidden', 'true');
    empty.append(icon, element('strong', busy ? copy[busy] : copy.emptyResult), element('p', notice ? copy[notice] : copy.emptyHelp));
    resultBody.append(empty);
    renderPrint();
    return;
  }

  const risk = element('div', undefined, `risk risk-${analysis.risk}`);
  risk.append(
    element('p', copy.mode, 'eyebrow'), element('h3', copy.risk[analysis.risk]),
    element('p', copy.reasons[analysis.reason]), element('p', copy.scope, 'muted'),
  );
  if (intelligence?.matches.length) resultBody.append(intelligenceSection(intelligence));
  resultBody.append(risk);
  if (intelligence && !intelligence.matches.length) resultBody.append(intelligenceSection(intelligence));
  const guidance = getGuidance(analysis, language, intelligence);
  const recovery = element('details', undefined, 'recovery');
  recovery.append(element('summary', copy.recovery), list(guidance.recoverySteps));
  resultBody.append(section(copy.next, list(guidance.nextSteps, true), recovery));
  if (email) resultBody.append(emailSection({ ...email, attachmentCount: email.attachments.length }));
  const findings = element('ul', undefined, 'findings');
  for (const { signal, contextual, span } of analysis.findings) {
    const item = element('li');
    const [title, explanation] = copy.signals[signal];
    item.append(element('strong', title), element('p', explanation));
    if (contextual) item.append(element('span', copy.contextual, 'tag'));
    item.append(element('p', input.value.slice(span.start, span.end), 'snippet'));
    findings.append(item);
  }
  resultBody.append(section(copy.findings, findings.childElementCount ? findings : element('p', copy.noFindings)));
  if (analysis.findings.length) {
    const details = element('details', undefined, 'result-section');
    details.append(element('summary', copy.excerpt), makeEvidence(analysis, input.value));
    resultBody.append(details);
  }

  if (analysis.links.length) {
    const links = element('ol', undefined, 'inspected-links');
    for (const link of analysis.links) {
      const item = element('li');
      item.append(element('code', link.raw));
      if (link.hostname) {
        const target = element('p', undefined, 'muted');
        target.append(copy.destination + ' · ', element('code', link.hostname));
        item.append(target);
      }
      if (link.domain && link.domain !== link.hostname) {
        const domain = element('p', undefined, 'muted');
        domain.append(copy.domain + ' · ', element('code', link.domain));
        item.append(domain);
      }
      const reasons = link.signals.map((signal) => copy.signals[signal][0]);
      item.append(reasons.length ? list(reasons) : element('p', copy.linkClean));
      links.append(item);
    }
    resultBody.append(section(copy.links, links));
  }
  resultBody.append(
    section(copy.unavailable, list(analysis.unavailable.map((check) => copy.checks[check]))),
    section(copy.limitations, element('p', copy.limitText)),
  );

  const checkbox = element('input');
  checkbox.type = 'checkbox';
  checkbox.checked = includeContent;
  checkbox.setAttribute('aria-describedby', 'sensitive');
  checkbox.addEventListener('change', () => {
    includeContent = checkbox.checked;
    renderPrint();
  });
  const label = element('label', undefined, 'opt-in');
  label.append(checkbox, document.createTextNode(copy.include));
  const sensitive = element('p', copy.sensitive, 'muted');
  sensitive.id = 'sensitive';
  const download = element('button', copy.json, 'button primary');
  download.type = 'button';
  download.addEventListener('click', downloadReport);
  const print = element('button', copy.print, 'button subtle');
  print.type = 'button';
  print.addEventListener('click', () => window.print());
  const buttons = element('div', undefined, 'actions');
  buttons.append(download, print);
  const reportError = element('p', notice === 'downloadFailed' ? copy.downloadFailed : '', 'error');
  reportError.id = 'report-error';
  reportError.setAttribute('role', 'alert');
  resultBody.append(section(
    copy.report, label, sensitive, buttons, element('p', copy.printPrompt, 'muted'), reportError,
  ));
  renderPrint();
}

function downloadReport() {
  if (!analysis) return;
  byId('report-error').textContent = '';
  notice = undefined;
  try {
    const report = createReport(analysis, input.value, language, includeContent, intelligence, email);
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
    const anchor = element('a');
    anchor.href = url;
    anchor.download = 'phishing-report.json';
    try {
      anchor.click();
    } finally {
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  } catch {
    notice = 'downloadFailed';
    byId('report-error').textContent = messages[language].downloadFailed;
  }
}

function setLanguage(next: Language) {
  language = next;
  const copy = messages[language];
  document.documentElement.lang = language;
  document.title = PRODUCT_NAME[language];
  byId('brand').textContent = PRODUCT_NAME[language];
  byId('languages').setAttribute('aria-label', copy.language);
  for (const option of ['tr', 'en']) byId(option).setAttribute('aria-pressed', String(option === language));
  for (const id of ['local', 'kicker', 'title', 'intro', 'privacy', 'input', 'upload', 'limits', 'analyze', 'clear', 'results', 'footer'] as const) {
    byId(id).textContent = copy[id];
  }
  input.placeholder = copy.placeholder;
  updateEditor();
  renderResult();
  renderResearch();
}

function resetResult() {
  revision++;
  analysis = undefined;
  intelligence = undefined;
  includeContent = false;
  busy = undefined;
  error = undefined;
  notice = undefined;
}

input.addEventListener('input', () => {
  const hadResult = Boolean(analysis);
  email = undefined;
  resetResult();
  if (hadResult) {
    notice = 'changed';
    showStatus(messages[language].changed);
  }
  updateEditor();
  renderResult();
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  resetResult();
  error = validateText(input.value);
  if (error) {
    updateEditor();
    renderResult();
    input.focus();
    return;
  }
  const current = revision;
  busy = 'running';
  updateEditor();
  renderResult();
  showStatus(messages[language].running);
  await new Promise<void>((resolve) => requestAnimationFrame(() => window.setTimeout(resolve, 0)));
  if (current !== revision) return;
  try {
    const result = analyze(input.value);
    const matched = await matchIntelligence(result, await snapshotReady).catch(() => ({
      status: 'unavailable' as const, matches: [],
    }));
    if (current !== revision) return;
    analysis = result;
    intelligence = matched;
  } catch {
    error = 'failed';
  }
  busy = undefined;
  updateEditor();
  renderResult();
  if (analysis) {
    byId('results').focus();
    showStatus(messages[language].risk[analysis.risk]);
  }
});

byId('upload').addEventListener('click', () => file.click());
file.addEventListener('change', async () => {
  const selected = file.files?.[0];
  file.value = '';
  if (!selected) return;
  resetResult();
  const current = revision;
  busy = 'reading';
  updateEditor();
  renderResult();
  showStatus(messages[language].reading);
  let result: { error: InputError } | { value: string; evidence?: EmailEvidence };
  try {
    result = /\.eml$/iu.test(selected.name)
      ? await (await import('./analysis/email.ts')).readEmailFile(selected)
      : await readTextFile(selected);
  } catch {
    result = { error: 'fileRead' as const };
  }
  if (current !== revision) return;
  busy = undefined;
  if ('error' in result) error = result.error;
  else {
    input.value = result.value;
    email = result.evidence;
  }
  updateEditor();
  renderResult();
  input.focus();
});

byId('clear').addEventListener('click', () => {
  input.value = '';
  email = undefined;
  file.value = '';
  resetResult();
  notice = 'cleared';
  updateEditor();
  renderResult();
  showStatus(messages[language].cleared);
  input.focus();
});

byId('tr').addEventListener('click', () => setLanguage('tr'));
byId('en').addEventListener('click', () => setLanguage('en'));
setLanguage(language);
