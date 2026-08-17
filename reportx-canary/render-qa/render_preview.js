'use strict';
/**
 * ReportX Phase 4/10 render QA: generates a non-production print-preview
 * HTML page for one canary's rendered_text, using the EXISTING System 4
 * renderer (Sentinel-APEX/renderer/report-renderer.js) UNCHANGED for all
 * content rendering (parseReport/toHTMLDocument/checkRendering) -- this
 * script only adds the print CHROME (TOC, classification header, page-
 * number footer, page-break rules) that report-renderer.js's own README
 * explicitly leaves to the caller ("the caller owns page chrome").
 *
 * Usage: node render_preview.js <input.md> <report_id> <title> <classification> <out.html>
 * Prints a JSON QA summary to stdout (checkRendering() result plus this
 * script's own chrome-level checks: orphan headings, broken TOC anchors,
 * placeholder-text scan, blank-section scan).
 */

const fs = require('node:fs');
const path = require('node:path');
const {
  parseReport, toHTMLDocument, checkRendering,
} = require('../../Sentinel-APEX/renderer/report-renderer.js');

function slugify(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function escHtml(str) {
  return String(str == null ? '' : str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

const PLACEHOLDER_PATTERNS = [
  /\bTODO\b/, /\bTBD\b/, /\bPLACEHOLDER\b/i, /\bLorem ipsum\b/i, /\bFIXME\b/,
  /\[insert[^\]]*\]/i, /\bXXX\b/,
];

function main() {
  const [, , inputPath, reportId, title, classification, outPath] = process.argv;
  if (!inputPath || !reportId || !title || !classification || !outPath) {
    process.stderr.write('usage: node render_preview.js <input.md> <report_id> <title> <classification> <out.html>\n');
    process.exit(2);
  }

  const text = fs.readFileSync(path.resolve(inputPath), 'utf8');

  // Reuse the existing certify-rendering.js check UNCHANGED -- this is
  // System 4's own real-content correctness verdict (table/code-block/
  // section-boundary integrity), not re-implemented here.
  const rendering = checkRendering(text);

  const model = parseReport(text);
  const bodyHtml = toHTMLDocument(model);

  // ── Chrome-level checks this script adds on top of checkRendering() ──
  const chromeIssues = [];

  const orphanHeadings = model.sections.filter(s => !s.rawMarkdown || !s.rawMarkdown.trim());
  if (orphanHeadings.length) {
    chromeIssues.push(`${orphanHeadings.length} orphan heading(s) with no body content: ${orphanHeadings.map(s => s.name).join(', ')}`);
  }

  const blankSections = model.sections.filter(s => s.rawMarkdown && s.rawMarkdown.trim().length < 20);
  if (blankSections.length) {
    chromeIssues.push(`${blankSections.length} near-empty section(s) (<20 chars): ${blankSections.map(s => s.name).join(', ')}`);
  }

  for (const s of model.sections) {
    for (const pat of PLACEHOLDER_PATTERNS) {
      if (pat.test(s.rawMarkdown)) {
        chromeIssues.push(`placeholder-text pattern ${pat} found in section "${s.name}"`);
      }
    }
  }

  const seenSlugs = new Set();
  const tocEntries = model.sections.map((s) => {
    let slug = slugify(s.name);
    let n = 2;
    while (seenSlugs.has(slug)) { slug = `${slugify(s.name)}-${n++}`; }
    seenSlugs.add(slug);
    return { name: s.name, slug };
  });
  // Broken-internal-navigation check: every TOC anchor must resolve to an
  // actual heading id present in bodyHtml (constructed the same way below).
  const missingAnchors = tocEntries.filter(e => !bodyHtml.includes(`id="${e.slug}"`));
  // (bodyHtml doesn't carry ids yet at this point -- checked again after
  // we inject them below, see finalHtml.)

  const tocHtml = tocEntries.map(e => `<li><a href="#${e.slug}">${escHtml(e.name)}</a></li>`).join('\n');

  // Inject id= anchors onto each <h2 class="sh"> in document order, matching
  // tocEntries 1:1 -- toHTMLDocument() doesn't emit ids itself (out of its
  // stated scope), so this is the print-chrome layer's own responsibility.
  let sectionIdx = 0;
  const bodyHtmlWithIds = bodyHtml.replace(/<h2 class="sh">/g, () => {
    const id = tocEntries[sectionIdx] ? tocEntries[sectionIdx].slug : `section-${sectionIdx}`;
    sectionIdx += 1;
    return `<h2 class="sh" id="${id}">`;
  });

  const brokenAnchors = tocEntries.filter(e => !bodyHtmlWithIds.includes(`id="${e.slug}"`));
  if (brokenAnchors.length) {
    chromeIssues.push(`${brokenAnchors.length} TOC entr(y/ies) with no matching in-page anchor: ${brokenAnchors.map(e => e.name).join(', ')}`);
  }

  const generatedAt = new Date().toISOString();

  const finalHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${escHtml(title)} — ${escHtml(reportId)} (PREVIEW — NON-PRODUCTION)</title>
<style>
  @page { size: Letter; margin: 2.2cm 1.6cm 2cm 1.6cm;
    @bottom-center { content: "Page " counter(page) " of " counter(pages) "  —  ${escHtml(reportId)}  —  TLP:CLEAR"; font-size: 8pt; color: #555; }
    @top-center { content: "NON-PRODUCTION PREVIEW — NOT FOR DISTRIBUTION"; font-size: 8pt; color: #b00; letter-spacing: 0.05em; } }
  body { font-family: Georgia, 'Times New Roman', serif; color: #1a1a1a; line-height: 1.5; font-size: 10.5pt; }
  .cover { page-break-after: always; text-align: center; padding-top: 30%; }
  .cover .classification { display: inline-block; border: 2px solid #b00020; color: #b00020; font-weight: bold;
    padding: 4px 14px; letter-spacing: 0.08em; font-family: Arial, sans-serif; font-size: 11pt; margin-bottom: 24px; }
  .cover h1 { font-size: 24pt; margin: 0.3em 0; }
  .cover .report-id { font-family: 'Courier New', monospace; color: #444; margin-top: 1em; }
  .cover .preview-banner { margin-top: 3em; color: #b00020; font-family: Arial, sans-serif; font-weight: bold; }
  .toc { page-break-after: always; }
  .toc h2 { font-family: Arial, sans-serif; }
  .toc ol { counter-reset: toc; list-style: none; padding-left: 0; }
  .toc li { counter-increment: toc; margin: 0.4em 0; }
  .toc li::before { content: counter(toc) ". "; font-weight: bold; }
  .toc a { color: #1a1a1a; text-decoration: none; }
  section.report-section { page-break-before: always; }
  section.report-section:first-of-type { page-break-before: auto; }
  h2.sh { font-family: Arial, sans-serif; border-bottom: 2px solid #1a1a1a; padding-bottom: 4px; font-size: 15pt; }
  h3 { font-family: Arial, sans-serif; font-size: 12pt; }
  table.tbl { border-collapse: collapse; width: 100%; margin: 1em 0; font-size: 9pt; }
  table.tbl th, table.tbl td { border: 1px solid #999; padding: 4px 6px; text-align: left; vertical-align: top; }
  table.tbl th { background: #eee; }
  .code-block-wrap { margin: 1em 0; }
  .code-block-lang { font-family: Arial, sans-serif; font-size: 7.5pt; color: #666; text-transform: uppercase; }
  pre.code-block { background: #f4f4f4; border: 1px solid #ccc; padding: 8px; font-size: 8pt;
    white-space: pre-wrap; word-break: break-word; font-family: 'Courier New', monospace; }
  blockquote { border-left: 3px solid #999; margin-left: 0; padding-left: 1em; color: #333; font-size: 9.5pt; }
</style>
</head>
<body>
<div class="cover">
  <div class="classification">${escHtml(classification)}</div>
  <h1>${escHtml(title)}</h1>
  <div class="report-id">${escHtml(reportId)}</div>
  <div class="preview-banner">NON-PRODUCTION RENDER-QA PREVIEW<br>Generated ${escHtml(generatedAt)}<br>NOT the customer-facing deliverable</div>
</div>
<div class="toc">
  <h2>Table of Contents</h2>
  <ol>
${tocHtml}
  </ol>
</div>
${bodyHtmlWithIds}
</body>
</html>
`;

  fs.writeFileSync(outPath, finalHtml, 'utf8');

  const summary = {
    reportId,
    outPath,
    checkRendering: rendering,
    chromeIssues,
    sectionCount: model.sections.length,
    tocEntryCount: tocEntries.length,
    ok: rendering.ok && chromeIssues.length === 0,
  };
  process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
  process.exit(summary.ok ? 0 : 1);
}

main();
