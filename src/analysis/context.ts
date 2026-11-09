import type { Finding, InspectedLink, Span } from './types.ts';

type Section = Span & { contextual: boolean; findings: Finding[] };

const forwarded = /^(?:[-_ ]{2,})?(?:forwarded message|original message|begin forwarded message|iletilen ileti|iletilen mesaj|orijinal ileti)(?:[:\s_-]*)$/iu;
const signature = /^(?:--|(?:kind |best )?regards,?|sincerely,?|sayg[ıi]lar[ıi]mla,?|sayg[ıi]lar[ıi]m[ıi]zla,?)$/iu;
const connector = /^[\s.:;–—-]*(?:(?:at|to|via|here|using (?:this|the) link|on (?:this|the) (?:link|page)|(?:bu|aşağ[ıi]daki) bağlant[ıi](?:y[ıi]|dan|ya)|şu adrese|bu adresten)[\s:–—-]*)?$/iu;

export function groupFindings(value: string, findings: Finding[]): Section[] {
  const sections: Section[] = [];
  let offset = 0;
  let inSignature = false;
  let current: Section | undefined;
  for (const raw of value.split('\n')) {
    const line = raw.trim();
    const end = offset + raw.length + 1;
    if (!line || forwarded.test(line)) {
      inSignature = false;
      current = undefined;
    } else {
      const startsSignature = signature.test(line);
      if (startsSignature) inSignature = true;
      const contextual = inSignature || line.startsWith('>');
      if (!current || contextual !== current.contextual || startsSignature) {
        current = { start: offset, end, contextual, findings: [] };
        sections.push(current);
      } else {
        current.end = end;
      }
    }
    offset = end;
  }

  let sectionIndex = 0;
  for (const finding of [...findings].sort((a, b) => a.span.start - b.span.start)) {
    while (sections[sectionIndex] && finding.span.start >= sections[sectionIndex].end) sectionIndex++;
    const section = sections[sectionIndex];
    if (section && finding.span.start >= section.start) {
      finding.contextual ||= section.contextual;
      section.findings.push(finding);
    }
  }
  return sections;
}

export function linksForRequests(value: string, requests: Finding[], links: InspectedLink[], coverage: Span[]): InspectedLink[] {
  const linked = new Set<InspectedLink>();
  let index = 0;
  for (const request of requests.sort((a, b) => a.span.end - b.span.end)) {
    // Coverage starts at the whole link expression, including a Markdown or HTML label.
    while (coverage[index] && coverage[index].end < request.span.end) index++;
    const link = links[index];
    if (!link) break;
    const start = coverage[index].start;
    if (link.labelSpan && request.span.start >= link.labelSpan.start && request.span.end <= link.labelSpan.end) {
      linked.add(link);
      continue;
    }
    if (start < request.span.end) continue;
    const gap = start - request.span.end;
    if (gap <= 90 && connector.test(value.slice(request.span.end, start))) linked.add(link);
  }
  return [...linked];
}
