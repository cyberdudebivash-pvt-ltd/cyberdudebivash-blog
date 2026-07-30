/**
 * Citation & Reference Management
 * Generates citations, manages bibliographies, validates reference URLs
 */

import type { Reference } from '../intelligence/schema';

export interface Citation {
  id: string;
  text: string;
  url?: string;
  source?: string;
  date?: string;
}

export function generateCitations(references: Reference[]): Citation[] {
  return references.map((ref, idx) => ({
    id: `ref-${idx + 1}`,
    text: ref.title || ref.url,
    url: ref.url,
    source: ref.source,
    date: ref.date,
  }));
}

export function formatCitation(citation: Citation): string {
  const parts: string[] = [];
  if (citation.source) parts.push(citation.source);
  if (citation.date) parts.push(new Date(citation.date).toLocaleDateString());
  if (parts.length > 0) return `${citation.text} (${parts.join(', ')})`;
  return citation.text;
}

export function formatBibliography(citations: Citation[]): string {
  return citations
    .map((c, idx) => `[${idx + 1}] ${formatCitation(c)}${c.url ? ` - ${c.url}` : ''}`)
    .join('\n');
}

export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}
