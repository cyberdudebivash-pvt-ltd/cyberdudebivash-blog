# Sentinel APEX Report Renderer

The canonical renderer for Sentinel-APEX Markdown reports (`Sentinel-APEX/reports/`,
`Sentinel-APEX/templates/`). Before this module existed, nothing in the repo
rendered them at all — `report_parser.py` audits already-published pages for
the quality gate, and the one Markdown converter that did exist
(`generate-cve-pages.js`'s `mdToSafeHtml()`) cannot handle real report content;
see `platform/open-issues.md` Issue 5 for the tested proof (it destroys every
table and corrupts fenced code blocks via cascading backtick mis-pairing).

## What it does

`report-renderer.js` exposes:

- **`parseReport(text)`** — parses YAML front matter + Markdown body into the
  canonical structured model: `{ metadata, preamble, sections }`. Sections
  are split on `##` (level-2 ATX) headings, mirroring the same fix already
  made to `Sentinel-APEX/engine/sentinel_engine/report_parser.py` (same
  approach; a separate implementation, since one is Python and one is Node).
  A `#` (level-1) heading, if present, is not treated as a section boundary —
  it renders as ordinary preamble content, matching how
  `SA-2026-0001-EXEC-*.md` actually uses one (`# Executive Threat Brief`
  before its first `##` section).
- **`toHTMLDocument(model)`** — assembles a parsed model into an HTML
  fragment (no `<html>`/`<head>` — the caller owns page chrome, same as
  `generatePostHTML()` does today). Kept separate from `parseReport()` on
  purpose: the model is the source of truth, HTML is one consumer of it, and
  a future consumer (PDF, API, portal) should read the model rather than
  re-parsing Markdown.
- **`section(model, fragment)`** — case-insensitive fragment lookup, same
  contract as `report_parser.py`'s `ParsedReport.section()`.
- **`renderMarkdown(md)`** — the underlying Markdown→HTML conversion,
  exposed directly for callers that just need a fragment rendered (e.g. the
  preamble).

Tables and fenced code blocks reuse the `.tbl` / `.code-block` CSS classes
already established in `fetch-live-intel.js`'s `generatePostHTML()`, rather
than introducing a second visual convention for the same content.

## Why `marked` + `js-yaml` instead of hand-rolled parsing

The same lesson Issue 5 already paid for: reinventing a Markdown or YAML
parser is how you end up with a converter that silently corrupts tables and
code fences. Both are new dependencies (see root `package.json`), evaluated
before adoption:

- `marked` — zero transitive dependencies, ~500KB, handles GFM tables and
  fenced code blocks correctly out of the box (verified against real
  SA-2026-0001 content before adoption, not assumed).
- `js-yaml` — one small transitive dependency (`argparse`), the standard
  choice for parsing the nested front-matter structures real reports
  actually use (arrays of objects, e.g. `change_log`).

## Security

`marked` passes through embedded raw HTML by default (standard CommonMark
behavior). Reports today are exclusively first-party, analyst-authored
content, but a renderer this many future surfaces are meant to depend on
shouldn't assume that stays true forever. A custom `Renderer.html` override
neutralizes (HTML-escapes) any embedded raw HTML instead of executing it —
covered by tests, including an HTML-shaped string inside a table cell.

## Validation

Tested against the two structurally different real reports that exist in
this repo (not synthetic examples — see `tests/report-renderer.test.js`):

- `SA-2026-0001-sharepoint-cve-2026-50522-active-exploitation.md` — 24
  sections, nested front-matter arrays, one Sigma YAML fenced code block, 6
  tables. Specifically regression-tested against the exact cascading
  inline-`<code>` corruption found in Issue 5.
- `SA-2026-0001-EXEC-sharepoint-cve-2026-50522.md` — different front-matter
  shape, a `#` heading before the first `##` section, 8 sections, 2 tables.

## Tests

```bash
cd Sentinel-APEX/renderer
node --test
```

Run in CI by `.github/workflows/report-renderer-ci.yml`.

## What this module deliberately does not do

Scoped to HTML rendering of the canonical model only. Not built in this
pass: PDF/email/API/portal output pipelines (`platform/report-experience-audit.md`
Phase 6), reusable UI components beyond plain render functions, or a design
system. Building those before this foundation was validated would have
repeated the exact mistake Issue 5 exists to document.
