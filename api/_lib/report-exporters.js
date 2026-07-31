'use strict';

class ReportExporter {
  static exportToMarkdown(report) {
    let markdown = '';

    markdown += `# ${report.title}\n\n`;
    markdown += `**Report Type:** ${report.reportType}\n`;
    markdown += `**Status:** ${report.status}\n`;
    markdown += `**Classification:** ${report.classification}\n`;
    markdown += `**Version:** ${report.version}\n`;
    markdown += `**Created:** ${report.createdAt}\n`;
    if (report.publishedAt) markdown += `**Published:** ${report.publishedAt}\n`;
    markdown += `\n`;

    if (report.description) {
      markdown += `## Overview\n\n${report.description}\n\n`;
    }

    if (report.sections && report.sections.length > 0) {
      for (const section of report.sections.sort((a, b) => a.sequenceOrder - b.sequenceOrder)) {
        markdown += `## ${section.title}\n\n`;
        markdown += `${section.content}\n\n`;

        if (section.subsections && section.subsections.length > 0) {
          for (const subsection of section.subsections) {
            markdown += `### ${subsection.title}\n\n`;
            markdown += `${subsection.content}\n\n`;
          }
        }

        if (section.evidenceReferences && section.evidenceReferences.length > 0) {
          markdown += `**Evidence References:**\n`;
          for (const ref of section.evidenceReferences) {
            markdown += `- ${ref.sourceTitle} (${ref.confidence})\n`;
          }
          markdown += '\n';
        }

        if (section.sourceReferences && section.sourceReferences.length > 0) {
          markdown += `**Sources:**\n`;
          for (const ref of section.sourceReferences) {
            markdown += `- ${ref.sourceName}\n`;
          }
          markdown += '\n';
        }
      }
    }

    if (report.changeHistory && report.changeHistory.length > 0) {
      markdown += `## Change History\n\n`;
      for (const change of report.changeHistory) {
        markdown += `- **${change.timestamp}:** ${change.changeType} (${change.author})\n`;
        if (change.detail) markdown += `  ${change.detail}\n`;
      }
    }

    return markdown;
  }

  static exportToHTML(report) {
    let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${this.escapeHtml(report.title)}</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 1000px; margin: 0 auto; padding: 20px; }
    h1 { color: #1a1a1a; border-bottom: 3px solid #2c3e50; padding-bottom: 10px; }
    h2 { color: #2c3e50; margin-top: 30px; }
    h3 { color: #34495e; }
    .metadata { background: #ecf0f1; padding: 15px; border-left: 4px solid #3498db; margin: 20px 0; }
    .classification { display: inline-block; padding: 5px 10px; background: #e74c3c; color: white; border-radius: 3px; font-weight: bold; }
    .evidence { background: #f8f9fa; padding: 10px; border-left: 3px solid #27ae60; margin: 10px 0; }
    .section { margin: 20px 0; }
    .subsection { margin-left: 20px; background: #f5f5f5; padding: 15px; border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; margin: 10px 0; }
    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
    th { background: #2c3e50; color: white; }
    .timeline { list-style: none; padding: 0; }
    .timeline li { padding-left: 30px; margin: 10px 0; position: relative; }
    .timeline li:before { content: "▪"; position: absolute; left: 0; }
  </style>
</head>
<body>
  <h1>${this.escapeHtml(report.title)}</h1>

  <div class="metadata">
    <p><strong>Report Type:</strong> ${this.escapeHtml(report.reportType)}</p>
    <p><strong>Status:</strong> ${this.escapeHtml(report.status)}</p>
    <p><strong>Classification:</strong> <span class="classification">${this.escapeHtml(report.classification)}</span></p>
    <p><strong>Version:</strong> ${this.escapeHtml(report.version)}</p>
    <p><strong>Created:</strong> ${new Date(report.createdAt).toLocaleString()}</p>
    ${report.publishedAt ? `<p><strong>Published:</strong> ${new Date(report.publishedAt).toLocaleString()}</p>` : ''}
  </div>
`;

    if (report.description) {
      html += `<div class="section"><p>${this.escapeHtml(report.description)}</p></div>`;
    }

    if (report.sections && report.sections.length > 0) {
      for (const section of report.sections.sort((a, b) => a.sequenceOrder - b.sequenceOrder)) {
        html += `<div class="section">
  <h2>${this.escapeHtml(section.title)}</h2>
  <p>${section.content.replace(/\n/g, '<br>')}</p>
`;

        if (section.subsections && section.subsections.length > 0) {
          for (const subsection of section.subsections) {
            html += `<div class="subsection">
    <h3>${this.escapeHtml(subsection.title)}</h3>
    <p>${subsection.content.replace(/\n/g, '<br>')}</p>
  </div>`;
          }
        }

        if (section.evidenceReferences && section.evidenceReferences.length > 0) {
          html += `<div class="evidence"><strong>Evidence References:</strong><ul>`;
          for (const ref of section.evidenceReferences) {
            html += `<li>${this.escapeHtml(ref.sourceTitle)} <em>(${this.escapeHtml(ref.confidence)})</em></li>`;
          }
          html += `</ul></div>`;
        }

        html += `</div>`;
      }
    }

    if (report.changeHistory && report.changeHistory.length > 0) {
      html += `<div class="section"><h2>Change History</h2><ul class="timeline">`;
      for (const change of report.changeHistory) {
        html += `<li><strong>${new Date(change.timestamp).toLocaleString()}:</strong> ${this.escapeHtml(change.changeType)} (${this.escapeHtml(change.author)})`;
        if (change.detail) html += ` - ${this.escapeHtml(change.detail)}`;
        html += `</li>`;
      }
      html += `</ul></div>`;
    }

    html += `</body></html>`;
    return html;
  }

  static exportToJSON(report) {
    return JSON.stringify(report, null, 2);
  }

  static exportToSTIX(report) {
    const stixObject = {
      type: 'bundle',
      id: `bundle--${this.uuidv4()}`,
      objects: [],
    };

    const reportObject = {
      type: 'report',
      id: `report--${this.uuidv4()}`,
      created: new Date(report.createdAt).toISOString(),
      modified: report.publishedAt ? new Date(report.publishedAt).toISOString() : new Date(report.createdAt).toISOString(),
      name: report.title,
      description: report.description,
      published: report.publishedAt ? new Date(report.publishedAt).toISOString() : undefined,
      labels: ['threat-report'],
      object_refs: [],
    };

    if (report.metadata?.tlp) {
      reportObject.x_tlp = report.metadata.tlp;
    }

    stixObject.objects.push(reportObject);

    if (report.sections) {
      for (const section of report.sections) {
        if (section.sectionType === 'ioc_summary' && section.evidenceReferences) {
          for (const evidence of section.evidenceReferences) {
            const iocObject = {
              type: 'indicator',
              id: `indicator--${this.uuidv4()}`,
              created: new Date().toISOString(),
              modified: new Date().toISOString(),
              labels: ['malicious-activity'],
              pattern: `[file:hashes.MD5 = '${evidence.evidenceId}']`,
              valid_from: new Date().toISOString(),
            };
            stixObject.objects.push(iocObject);
            reportObject.object_refs.push(iocObject.id);
          }
        }
      }
    }

    return JSON.stringify(stixObject, null, 2);
  }

  static escapeHtml(text) {
    if (!text) return '';
    const div = { innerHTML: text };
    return div.innerHTML
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  static uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  static export(report, format) {
    switch (format.toLowerCase()) {
      case 'html':
        return this.exportToHTML(report);
      case 'markdown':
      case 'md':
        return this.exportToMarkdown(report);
      case 'json':
        return this.exportToJSON(report);
      case 'stix':
      case 'stix2':
        return this.exportToSTIX(report);
      default:
        return this.exportToJSON(report);
    }
  }
}

module.exports = { ReportExporter };
