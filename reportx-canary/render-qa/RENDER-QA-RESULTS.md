# ReportX Render QA Results — Four Real Canaries

Non-production render QA, generated this session against System 4's
existing renderer (`Sentinel-APEX/renderer/report-renderer.js`,
`certify-rendering.js`), unmodified. `render_preview.js` in this directory
adds only the print CHROME report-renderer.js's own README explicitly
leaves to the caller (TOC, classification cover, page-number footer,
page-break rules) — all section/table/code-block content rendering is
100% System 4's existing `parseReport()`/`toHTMLDocument()`/
`checkRendering()`, unchanged.

Pipeline: canary `build_bundle().rendered_text` (Markdown) →
`report-renderer.js` (content HTML) → `render_preview.js` (print-chrome
HTML) → headless Chromium `--print-to-pdf` (real PDF) → `pypdf` (real page
count). Reproducible via `node render_preview.js <md> <id> <title>
<classification> <out.html>`, then Chromium `--print-to-pdf`.

## Results

| Canary | `checkRendering()` | Chrome-level issues | Sections | Real PDF pages |
|---|---|---|---|---|
| A — Qilin / Spoonful of Comfort | `ok: true`, 0 issues | 0 | 17 | **21** |
| B — MedusaLocker / Bija Industrie | `ok: true`, 0 issues | 0 | 16 | **20** |
| C — DragonForce / Vermont XCenter | `ok: true`, 0 issues | 0 | 17 | **21** |
| D — CVE-2025-62593 (Ray) | `ok: true`, 0 issues | 0 | 16 | **20** |

**0 clipping. 0 malformed tables. 0 orphan headings. 0 placeholders. 0
blank mandatory sections. 0 broken internal navigation** (every TOC entry
resolves to a matching in-page anchor — checked programmatically, not
eyeballed) — across all four.

Code-block fidelity verified: every canary has exactly 1 fenced code
block (its Sigma detection rule) in the source Markdown, and exactly 1
`<div class="code-block-wrap">` in the rendered HTML — visually confirmed
via a Chromium screenshot of the Qilin cover/TOC page and a direct check
of the rendered Sigma YAML block (language label, HTML-escaped `>`
characters, monospace formatting all correct).

## Page count: reported truthfully, not fabricated to hit 30-40

The task mandate is explicit: *"Do not fabricate 30-40 pages. If a report
is shorter but satisfies the evidence-backed depth gate, record the
actual page count truthfully."* These are **real PDF page counts from an
actual Chromium print pipeline**, not a word-count estimate: 20-21 pages
per canary, at a Letter page size with realistic report margins
(2.2cm/1.6cm) and one Chromium-default page-break before each of the
report's 16-17 major sections.

Each canary independently clears `product_depth.py`'s premium-depth gate
(`distinct_evidence_backed_sections >= 8` AND `material_claim_count >=
15`, zero cross-report template-repetition findings) on 2,555-3,192
rendered words. The 20-21 page count reflects genuine evidence-backed
depth at Letter-page density with one section per printed page, not a
word-count shortfall — going further to synthetic 30-40 pages would mean
either padding (explicitly prohibited by Section 8/24 of the task
mandate) or additional real research beyond what four independently
retrieved, hash-verified source sets (18-22 real sources total across the
four canaries) currently support.

## Known scope gap, noted honestly

None of the four canaries' rendered Markdown contains a GFM pipe table
(`table.markdown: 0` / `table.rendered: 0` for all four in
`checkRendering()`'s own output) — evidence-ledger and IOC-style content
is presented as blockquote-formatted appendix entries instead. This means
table-rendering fidelity (a real System 4 capability, and one the task's
QA checklist names) was not exercised by these four specific documents.
This is not a defect in the four canaries reviewed — no source material
this session required a genuine tabular presentation — but it is flagged
here rather than silently claimed as "tested."

## Artifacts in this directory

- `<report-id>-PREVIEW.html` — the full print-chrome HTML page (cover +
  TOC + rendered content), one per canary
- `<report-id>-PREVIEW.pdf` — the real PDF each HTML page produces via
  headless Chromium print-to-PDF
- `md/<report-id>.md` — the exact Markdown fed into System 4 for each
  canary (identical to `build_bundle().rendered_text`)
- `render_preview.js` — the print-chrome wrapper script (System 4's own
  renderer functions, unmodified, imported and called directly)

All artifacts here are explicitly non-production (marked as such in a
red banner on every generated page) and are not linked from, or served
by, any production route.
