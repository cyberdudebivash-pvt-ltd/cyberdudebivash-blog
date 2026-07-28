'use strict';
/**
 * SENTINEL APEX — Canonical Report Renderer (EIRE v1)
 *
 * The one place Sentinel-APEX Markdown reports (Sentinel-APEX/reports/,
 * Sentinel-APEX/templates/) get turned into structured, renderable output.
 * Existed as a gap before this: report_parser.py audits already-published
 * pages for the quality gate, but nothing rendered a report for a reader —
 * see platform/open-issues.md Issue 5 for the proof that the one ad-hoc
 * converter in this repo (generate-cve-pages.js's mdToSafeHtml) cannot do
 * this (destroys tables, corrupts fenced code blocks).
 *
 * Design: parseReport() produces a structured model — front-matter metadata
 * plus an ordered list of sections, each pre-rendered to HTML — and that
 * model is the source of truth. Markdown is an input format, not the
 * canonical representation. Any future output surface (PDF, API, portal)
 * should consume the model this returns rather than re-parsing Markdown
 * itself. Today this module has one consumer path, toHTMLDocument(), which
 * assembles the parsed model into a full HTML fragment — kept as a
 * separate function from parseReport() specifically so future consumers
 * don't have to go through it.
 *
 * Section boundaries are `##` (level-2 ATX) headings, matching the fix
 * already made to Sentinel-APEX/engine/sentinel_engine/report_parser.py —
 * same approach, necessarily separate implementation (Python vs Node).
 * A `#` (level-1) heading, if present, is not a section boundary; it
 * renders as ordinary content within whichever section it falls in (see
 * SA-2026-0001-EXEC-*.md, which opens with "# Executive Threat Brief"
 * before its first "##" section — real, not hypothetical).
 */

const yaml = require('js-yaml');
const { marked, Renderer } = require('marked');

function escHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// Neutralizes embedded raw HTML instead of passing it through (marked's
// default behavior, per CommonMark). Reports today are exclusively
// first-party analyst-authored content, but a renderer this many future
// surfaces are meant to depend on shouldn't assume that stays true forever.
function buildRenderer() {
  const renderer = new Renderer();
  renderer.html = (token) => escHtml(token.text != null ? token.text : token.raw);
  // Reuse the existing .tbl / .code-block visual conventions already
  // established in fetch-live-intel.js's generatePostHTML(), rather than
  // introducing a second table/code-block style for the same content.
  renderer.table = (token) => {
    const header = token.header.map(cell => `<th>${cell.tokens ? renderer.parser.parseInline(cell.tokens) : escHtml(cell.text)}</th>`).join('');
    const rows = token.rows.map(row =>
      `<tr>${row.map(cell => `<td>${cell.tokens ? renderer.parser.parseInline(cell.tokens) : escHtml(cell.text)}</td>`).join('')}</tr>`
    ).join('\n');
    return `<table class="tbl">\n<thead><tr>${header}</tr></thead>\n<tbody>${rows}</tbody>\n</table>\n`;
  };
  renderer.code = (token) => {
    const lang = (token.lang || '').trim().split(/\s+/)[0] || '';
    const langLabel = lang ? `<div class="code-block-lang">${escHtml(lang.toUpperCase())}</div>` : '';
    return `<div class="code-block-wrap">${langLabel}<pre class="code-block">${escHtml(token.text)}</pre></div>\n`;
  };
  return renderer;
}

let sharedRenderer = null;
function getRenderer() {
  if (!sharedRenderer) sharedRenderer = buildRenderer();
  return sharedRenderer;
}

function renderMarkdown(md) {
  return marked.parse(md || '', { gfm: true, renderer: getRenderer() });
}

// Splits body text into { preamble, sections } on `##` boundaries. Mirrors
// report_parser.py's _RE_SECTION approach (## only — not # or ###+, see
// that file's comment for why) rather than sharing code across languages.
const RE_SECTION = /^##[ \t]+(.+?)[ \t]*$/gm;

function splitSections(body) {
  const matches = [...body.matchAll(RE_SECTION)];
  const preambleText = matches.length ? body.slice(0, matches[0].index) : body;
  const sections = matches.map((m, i) => {
    const start = m.index + m[0].length;
    const end = i + 1 < matches.length ? matches[i + 1].index : body.length;
    return { name: m[1].trim(), rawMarkdown: body.slice(start, end).trim() };
  });
  return { preambleText: preambleText.trim(), sections };
}

/**
 * Parses a full report file's text (YAML front matter + Markdown body)
 * into the canonical structured model. Never throws on malformed front
 * matter — a report with no/broken front matter still gets its sections
 * parsed; metadata is just empty.
 */
function parseReport(text) {
  const raw = String(text || '');
  const lines = raw.split('\n');
  let metadata = {};
  let bodyStart = 0;

  if (lines[0] != null && lines[0].trim() === '---') {
    const closeIdx = lines.indexOf('---', 1);
    if (closeIdx !== -1) {
      try {
        const parsed = yaml.load(lines.slice(1, closeIdx).join('\n'));
        if (parsed && typeof parsed === 'object') metadata = parsed;
      } catch (e) {
        // Malformed front matter is a content-authoring problem, not a
        // reason to fail rendering — the gate (quality.py) is where that
        // gets caught, not here.
      }
      bodyStart = closeIdx + 1;
    }
  }

  const body = lines.slice(bodyStart).join('\n');
  const { preambleText, sections } = splitSections(body);

  return {
    metadata,
    preamble: { rawMarkdown: preambleText, html: renderMarkdown(preambleText) },
    sections: sections.map(s => ({
      name: s.name,
      rawMarkdown: s.rawMarkdown,
      html: renderMarkdown(s.rawMarkdown),
    })),
  };
}

function section(model, nameFragment) {
  const frag = String(nameFragment || '').toLowerCase();
  return model.sections.find(s => s.name.toLowerCase().includes(frag)) || null;
}

/**
 * Assembles a parsed model into a full HTML fragment (not a complete
 * document — no <html>/<head>; the caller owns page chrome, matching how
 * generatePostHTML() composes its own generated sections into one page).
 */
function toHTMLDocument(model) {
  const parts = [];
  if (model.metadata.title) {
    parts.push(`<h1 class="report-title">${escHtml(model.metadata.title)}</h1>`);
  }
  if (model.preamble.rawMarkdown) parts.push(model.preamble.html);
  for (const s of model.sections) {
    parts.push(`<section class="report-section">\n<h2 class="sh"><span>${escHtml(s.name)}</span></h2>\n${s.html}\n</section>`);
  }
  return parts.join('\n\n');
}

module.exports = { parseReport, toHTMLDocument, section, renderMarkdown };
