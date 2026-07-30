/**
 * Report Renderers
 * Multi-format rendering (Markdown, HTML, JSON) behind a common interface
 */

import type { MalwareReport } from './report-builder';
import type { MalwareReportMetadata } from './metadata';
import { formatConfidenceLevel, attributionLabel } from './confidence';

export interface Renderer {
  render(report: MalwareReport, metadata: MalwareReportMetadata): string;
  name: string;
}

export class MarkdownRenderer implements Renderer {
  name = 'markdown';

  render(report: MalwareReport, metadata: MalwareReportMetadata): string {
    const lines: string[] = [];

    lines.push(`# ${report.title}\n`);
    lines.push(`**Report ID:** ${metadata.id}`);
    lines.push(`**Confidence:** ${formatConfidenceLevel(metadata.confidence as any)}`);
    lines.push(`**Last Updated:** ${metadata.last_updated}\n`);

    Object.entries(report.sections).forEach(([key, section]) => {
      if (section.isEmpty) {
        lines.push(`## ${section.title}\n`);
        lines.push(`*${section.content}*\n`);
      } else {
        lines.push(`## ${section.title}\n`);
        lines.push(`*Confidence: ${formatConfidenceLevel(section.confidence as any)}*\n`);
        lines.push(section.content);
        if (section.evidence.length > 0) {
          lines.push('\n**Evidence:**');
          section.evidence.forEach(e => {
            lines.push(`- ${e.source} (${attributionLabel(e.attribution)}) - ${formatConfidenceLevel(e.confidence as any)}`);
          });
        }
        lines.push('');
      }
    });

    if (report.citations.length > 0) {
      lines.push('## References\n');
      report.citations.forEach((c, idx) => {
        const url = c.url ? ` [${c.url}]` : '';
        lines.push(`[${idx + 1}] ${c.text}${url}`);
      });
    }

    return lines.join('\n');
  }
}

export class HTMLRenderer implements Renderer {
  name = 'html';

  render(report: MalwareReport, metadata: MalwareReportMetadata): string {
    let html = '';
    html += `<article class="malware-report">\n`;
    html += `<header class="report-header">\n`;
    html += `<h1>${escapeHtml(report.title)}</h1>\n`;
    html += `<div class="report-meta">\n`;
    html += `<span class="report-id">${escapeHtml(metadata.id)}</span>\n`;
    html += `<span class="confidence confidence-${metadata.confidence.toLowerCase()}">${formatConfidenceLevel(metadata.confidence as any)}</span>\n`;
    html += `<time>${metadata.last_updated}</time>\n`;
    html += `</div>\n</header>\n`;

    Object.entries(report.sections).forEach(([key, section]) => {
      html += `<section class="report-section" data-section="${key}">\n`;
      html += `<h2>${escapeHtml(section.title)}</h2>\n`;
      if (section.isEmpty) {
        html += `<p class="empty-section"><em>${escapeHtml(section.content)}</em></p>\n`;
      } else {
        html += `<div class="section-confidence">Confidence: ${formatConfidenceLevel(section.confidence as any)}</div>\n`;
        html += `<div class="section-content">${section.content}</div>\n`;
        if (section.evidence.length > 0) {
          html += `<div class="evidence">\n<h3>Evidence</h3>\n<ul>\n`;
          section.evidence.forEach(e => {
            html += `<li>${escapeHtml(e.source)} (${attributionLabel(e.attribution)}) - ${formatConfidenceLevel(e.confidence as any)}</li>\n`;
          });
          html += `</ul>\n</div>\n`;
        }
      }
      html += `</section>\n`;
    });

    if (report.citations.length > 0) {
      html += `<section class="references">\n<h2>References</h2>\n<ol>\n`;
      report.citations.forEach(c => {
        const link = c.url ? ` <a href="${escapeHtml(c.url)}">${escapeHtml(c.url)}</a>` : '';
        html += `<li>${escapeHtml(c.text)}${link}</li>\n`;
      });
      html += `</ol>\n</section>\n`;
    }

    html += `</article>\n`;
    return html;
  }
}

export class JSONRenderer implements Renderer {
  name = 'json';

  render(report: MalwareReport, metadata: MalwareReportMetadata): string {
    const json = {
      metadata,
      report: {
        id: report.id,
        title: report.title,
        generatedAt: report.generatedAt,
        sections: Object.fromEntries(
          Object.entries(report.sections).map(([key, section]) => [
            key,
            {
              title: section.title,
              content: section.content,
              confidence: section.confidence,
              isEmpty: section.isEmpty,
              evidence: section.evidence.map(e => ({
                source: e.source,
                date: e.date,
                attribution: e.attribution,
                confidence: e.confidence,
                notes: e.notes,
              })),
            },
          ])
        ),
        citations: report.citations.map(c => ({
          id: c.id,
          text: c.text,
          url: c.url,
          source: c.source,
          date: c.date,
        })),
      },
    };
    return JSON.stringify(json, null, 2);
  }
}

function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

export function getRenderer(format: 'markdown' | 'html' | 'json'): Renderer {
  const renderers: Record<string, Renderer> = {
    markdown: new MarkdownRenderer(),
    html: new HTMLRenderer(),
    json: new JSONRenderer(),
  };
  return renderers[format] || renderers.markdown;
}
