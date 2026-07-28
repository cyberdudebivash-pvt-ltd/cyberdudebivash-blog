# Sentinel APEX — Intelligence Report Experience Audit

**Audit framework**: IREX v1 (Intelligence Report Experience Evolution)
**Date**: 2026-07-28
**Scope**: the reader-facing presentation of Sentinel APEX intelligence — what a CISO, SOC analyst, incident responder, or paying customer actually sees when they open a report.
**Method**: direct repository inspection (file:line citations throughout) plus independent spot-verification of every load-bearing claim before inclusion. Nothing below is inferred from documentation alone — where a `.md` file *describes* a capability, the underlying code was checked to confirm the capability is real.

---

## 1. Executive Summary

The report *template* is in reasonable shape. The report *pipeline feeding it* is not, and that single fact dominates this audit.

This repository contains **two entirely disconnected report-production systems**:

- **Pipeline A** — what customers actually see. `fetch-live-intel.js` → `generatePostHTML()` → `posts/*.html`. Populated automatically every ~5 minutes from 28 ingestion sources, including an external API (`intel.cyberdudebivash.com`) whose response schema, by its own documentation, **was never independently verified** (`Sentinel-APEX/docs/SENTINEL-APEX-PROVIDER.md`).
- **Pipeline B** — the analyst-grade engine. `Sentinel-APEX/engine/` (Python) → hand-authored Markdown in `Sentinel-APEX/reports/drafts/`. Capable of real analytical depth — its one real output, SA-2026-0001, correctly identifies a non-obvious operational detail (stolen IIS machine keys surviving a patch) with proper sourcing and an explicitly-documented rejected hypothesis. **Nothing in the codebase renders this output for a reader.** It has no HTML, no PDF, no publish path. It can only be read as raw Markdown source.

The clearest possible demonstration: SA-2026-0001 and `posts/cve-2026-50522-unknown-vendor-unknown-product.html` are both about CVE-2026-50522. The former is a 366-line, well-sourced analyst report. The latter — the one a real visitor or paying customer actually reaches — reads in full:

> "This report analyzes CVE-2026-50522 affecting **Unknown Vendor Unknown Product** (CVSS 9.5, HIGH severity). Active exploitation has been reported in the wild — prioritize accordingly. Corroborated across 1 source(s): sentinel_apex. **Verify all specifics against the primary sources linked below before acting.**"

"Unknown Vendor" / "Unknown Product" appear 15 and 18 times respectively across that live page. This is not a hypothetical edge case — it is the actual content currently live at that URL, and the ingestion cycle that produced it runs continuously.

**Verdict, stated per IREX's own validation standard**: the report experience is not production-ready for the enterprise/CISO audience this platform is built for, and no amount of typography, color, or layout work changes that. The template can carry good content. It is not currently receiving any.

Every recommendation in this audit is sequenced around that fact: fix what reaches the page before improving how the page looks.

---

## 2. Current State Assessment

**What's real and running today:**

| Component | Status | Evidence |
|---|---|---|
| `generatePostHTML()` template | Live, runs every ~5 min | `fetch-live-intel.js:2270-2604` |
| Inline design tokens (11 colors, 2 fonts) | Live | `fetch-live-intel.js:2394` |
| Badge/table/card visual system | Live | `.badge`, `.tbl`, `.stat`, `.sw` classes throughout |
| Sentinel-APEX Python engine (normalize/enrich/correlate/detect/score) | Runs, but output goes nowhere | `pipeline.py:39-65`, output only ever `print()`-ed (`cli.py:92`) |
| Six audience-variant templates (Executive/Board/SOC/DFIR/Hunting/Detection-Engineer) | Written, well-designed, **never programmatically used** | `Sentinel-APEX/templates/*/` — zero code references found repo-wide |
| Quality gate (`quality.py`) | Exists, cannot run against real content | see §4 below |
| D3.js force-directed threat graph | Live, but on an unrelated hub page | `threat-intelligence.html:399-480`, not part of any report page |
| PDF export | **Does not exist** | confirmed via repo-wide dependency and code search |
| Markdown-to-HTML rendering for Sentinel-APEX reports | **Does not exist** | confirmed — no code path reads `reports/drafts/*.md` |
| Report lifecycle (`drafts/` → `final/` → `published/`) | Never used past stage 1 | `final/` and `published/` contain only `.gitkeep` |

**The `►` marker contradiction** (a concrete symptom of the two systems never having talked to each other): `report_parser.py:15` requires every report section to start with a literal `►` character to be recognized. The actual SA-2026-0001 files use standard `## Heading` Markdown and contain **zero** `►` characters. Worse, `normalizer.py:38-39` lists `►` inside `CHROME_PREFIXES` — text to be **stripped as UI noise**, not read as a section marker. The engine's own two modules disagree with each other about what `►` means. Net effect: `quality.py`'s gate has no evidence it has ever successfully parsed a real report in this repository, despite `Sentinel-APEX/quality/quality-gate.md` documenting it as the enforcement mechanism.

---

## 3. Strengths

Worth stating plainly, because the fix is "connect what already works," not "build from nothing":

1. **The template's bones are good.** `generatePostHTML()` already has real visual hierarchy: 24 ordered sections, a two-column grid (content + sidebar), color-coded severity (`cvssColor` computed from real CVSS thresholds, `fetch-live-intel.js:2294`), stat tiles, and badges. This is not a blank slate that needs inventing — it needs better input.
2. **The audience-variant templates show genuine information-architecture competence.** The Executive Brief's "What We Don't Yet Know" section and Decision Matrix, the Detection Engineer brief's Maturity column (Reference → Reviewed → Tested → Production Validated), the Hunting playbook's per-platform query format (KQL/SPL/EQL) — these are the right sections for their audiences. They are simply inert.
3. **When the engine is given real material, it performs well.** SA-2026-0001 documents a resolved cross-source discrepancy and an explicitly-rejected false ATT&CK mapping (T1486) rather than silently presenting either as fact. That is exactly the analytical discipline IREX's "Analyst Quality" criteria ask for — it already happened once, unprompted by this audit.
4. **The data model has more than the template uses.** `models.py`'s `Confidence` enum, `TechniqueMapping.evidence`, and `CVEEnrichment.sources` already carry the raw material for a trust-tier display. The gap is in `generatePostHTML()` not consuming it — not in the data not existing.
5. **A capable visualization library is already a dependency.** D3 v7.8.5 drives a working force-directed graph elsewhere in the codebase (`threat-intelligence.html`). Extending report pages with real visualization is an integration task, not a new-library adoption.
6. **The platform has already been honest with itself once.** `SA-2026-0001-commercial-packaging.md` quotes its own scoring engine giving the report 43/100 (BLOCKED tier) and explains why, rather than hiding it. That self-critical posture is worth preserving as this audit's findings get acted on.

---

## 4. Weaknesses

Ranked by reader-facing severity, not by where they live in the codebase:

1. **Generic, low-trust executive summaries in production** (`fetch-live-intel.js:1025-1026`, live example above). Root cause identified, not just observed: the `sentinel_apex`-sourced construction path tries six reasonable field names (`vendor`, `affected_vendor`, `vendors[0]`, `product`, `affected_product`, `products[0]`) before falling back to the literal string `'Unknown Vendor'` / `'Unknown Product'`. All six missed for this item. The same file already has working CPE-based vendor/product extraction for NVD-sourced items (`fetch-live-intel.js:436-437`, regex against `cpe:2.3:...`) that is never applied as a fallback for `sentinel_apex`-sourced CVEs.
2. **The analyst-grade pipeline has no output path.** `render_draft()` (`pipeline.py:99-189`) produces a flat Markdown string that is only ever `print()`-ed to stdout by `cli.py`. No file write, no HTML render, no HTTP endpoint. Confirmed by grepping the entire engine tree for file-write calls — the only one found writes the knowledge-graph JSON, not a report.
3. **~350 lines of dead, duplicate code inside the live template generator.** `genExecutiveSummary`, `genBusinessImpact`, `genAttackChain`, `genCommentary`, and `genPlaybook` are each declared twice at the same scope (`fetch-live-intel.js:1588`/`1942`, `1604`/`1958`, `1622`/`1974`, `1649`/`2001`, `1672`/`2023`). JavaScript hoisting means the second definition silently wins on every call — the first ~350 lines never execute. This is not a correctness bug today, but it is a maintenance trap: an editor who searches for `genExecutiveSummary`, finds the first (dead) copy at line 1588, and edits it will observe zero effect and reasonably conclude the change failed to deploy.
4. **No trust-tier classification reaches the reader.** IREX's requested taxonomy (Verified Fact / Multi-source Corroborated / Platform Observation / Analyst Assessment / Inference / Hypothesis) doesn't exist anywhere in the live template. The closest analog is a single canned label, "⚡ Analyst Assessment — SENTINEL APEX v4.0," applied uniformly regardless of actual confidence — visible in the same Unknown-Vendor excerpt above. The underlying `Confidence` enum exists in Pipeline B's data model and is simply never surfaced.
5. **CSS is inlined and duplicated in every one of 3,400+ post files**, not linked as an external stylesheet (`fetch-live-intel.js:2393-2451`, verified byte-identical across sampled posts). Two costs: the browser can never cache it once and reuse it across pages (it re-downloads on every post), and there is no single file a designer could edit to restyle the whole report corpus — the source of truth is a JS template literal, not a stylesheet.
6. **No type scale or spacing scale.** The 11-color/2-font token block (`fetch-live-intel.js:2394`) is real, but every font-size and margin/padding value after it is a hardcoded literal (`11px`, `12px`, `13px`, `19px`, etc.) rather than a scale. Small inconsistencies compound across 24 sections with no shared vocabulary to check them against.
7. **Six well-designed audience templates are pure documentation.** No code reads `Sentinel-APEX/templates/*/*.md`. A CISO cannot get an Executive Brief view of a report; a SOC analyst cannot get a SOC-only view. Everyone gets the same 24-section wall, in the same order, mixing a two-sentence executive summary with raw Sigma/YARA code blocks on one continuous scroll — directly working against IREX's own "can a CISO understand this in under two minutes" bar.
8. **The quality gate cannot currently pass judgment on real content**, per the `►` contradiction in §2. This means every report that goes live today does so without ever having been mechanically checked against `quality.py`'s gates, regardless of what `quality-gate.md` documents as the process.
9. **No PDF export exists.** Relevant because IREX explicitly asks about Managed Service Deliverable and Enterprise Report formats, both of which conventionally imply a downloadable, print-stable document — this platform currently has no path to produce one.
10. **The report lifecycle stops at `drafts/`.** Three files exist; zero have ever reached `final/` or `published/`. Whatever process is supposed to promote a draft has never run, or doesn't exist yet.

---

## 5. High-Impact Improvements

In priority order. Each entry states the mechanism, not just the goal, per IREX's "explain how it improves usability" requirement.

1. **Fix the Unknown Vendor/Product fallback** (`fetch-live-intel.js:1025-1026`). Before falling to the literal string, attempt the same CPE-regex extraction already implemented at `fetch-live-intel.js:436-437` for any `sentinel_apex` item that includes CVE data. This reuses existing, working logic in the same file — no new capability required. *Improves: comprehension, confidence, trust.* This is the single highest-leverage fix in this audit: it is live, ongoing, and affects every future `sentinel_apex`-sourced CVE post until corrected.
2. **Give Pipeline B an output path**, even a minimal one. At minimum: have `render_draft()`'s Markdown, or the hand-authored `reports/drafts/*.md` files, pass through *some* renderer (even the existing `mdToSafeHtml()` in `generate-cve-pages.js:37-71`, which already handles headers/bold/inline-code/paragraphs) and land on a real URL. This does not require solving multi-audience rendering or the quality-gate mismatch first — it requires one page to exist that isn't Pipeline A. *Improves: actionability, trust, differentiation from the automated feed.*
3. **Remove the five duplicate dead function declarations** (`fetch-live-intel.js`, ten line numbers cited in §4.3). Deleting the first (dead) copy of each is a zero-risk, zero-behavior-change cleanup — the second copy already wins today and continues to. *Improves: maintainability, reduces future editor confusion.*
4. **Reconcile the `►` vs. `##` marker mismatch** so `quality.py`'s gate can execute against real report content at least once. Either teach `report_parser.py` to also recognize ATX `##` headers, or standardize future Sentinel-APEX Markdown on `►` and remove it from `normalizer.py`'s `CHROME_PREFIXES`. *Improves: trust (an actually-enforced quality gate), maintainability.*
5. **Externalize the CSS** to a single stylesheet referenced by all report pages instead of inlined per-post. *Improves: performance (cacheable across 3,400+ pages), maintainability (one file to restyle the corpus), consistency.*

---

## 6. UX/UI Recommendations

- **Introduce a real type and spacing scale** as CSS custom properties alongside the existing 11-color token set, replacing the hardcoded per-section literals. *Improves: consistency, and makes future audits actually checkable against a standard instead of eyeballing 24 sections individually.*
- **Surface confidence per claim, not once per report.** The `Confidence` enum already exists (`models.py:16-19`); render it as a small inline badge next to individual findings/technique mappings rather than (or in addition to) the single blanket "Analyst Assessment" label. *Improves: trust — a reader can tell which specific statements are solid versus provisional.*
- **Add anchor navigation / a jump-to-section rail** for the 24-section template. Currently a CISO reading a report scrolls past Sigma/YARA code blocks to find recommendations. A sticky in-page nav (Executive Summary / Business Impact / Detections / Response) lets each audience reach their section directly. *Improves: navigation, the two-minute-comprehension bar IREX sets for executives.*
- **Replace ad-hoc emoji icons with a deliberate, accessible icon system** (inline SVG or an icon font) for section headers and badges. Emoji render inconsistently across platforms/screen readers and read as informal for a Fortune-500-CISO audience — which is explicitly this platform's stated bar (root `CLAUDE.md`, Cybersecurity Content Governance). *Improves: accessibility, enterprise credibility.*
- **Turn the existing attack-chain table into a visual timeline/kill-chain strip** for the top of technical sections, keeping the table as supporting detail below it. The data (`attackChain` array, phase/detail/tactic) already exists — this is a presentation change, not a new data requirement. *Improves: comprehension, matches IREX's explicit ask for "Kill chain progression" as a dynamic component.*
- **Verify print/PDF-adjacent CSS** (`@media print`) is present; none was found in the inline stylesheet during this audit. Even before real PDF export exists, browser "Print to PDF" is the de facto save/share path today, and it currently isn't optimized for. *Improves: print quality, a category IREX explicitly asks about.*

---

## 7. Information Architecture Recommendations

- **Make the six audience templates real, not aspirational.** Minimum viable version: don't require full auto-derivation — add explicit anchor-linked sections or tabs on the report page itself ("Executive View" / "SOC View" / "Full Report") that reorder/filter the *same* already-rendered sections by audience, rather than building six separate rendering pipelines. This is achievable without touching Pipeline B at all, since it operates purely on Pipeline A's existing section output.
- **Separate the single continuous scroll into audience-scoped reading paths.** Per `layer-05-multi-audience-output.md:39-40`'s own stated principle ("a template file is a rendering lens, not an independent authoring surface") — the intent was always one underlying report, multiple lenses. Today there is one lens only. This recommendation is the smallest step toward the architecture the platform's own documentation already describes.
- **Establish one canonical rendering surface before adding more report types.** Right now there are three independent page families with no shared rendering code: `posts/*.html` (Pipeline A / `generatePostHTML`), `cve/*.html` (a separate generator, `generate-cve-pages.js`, with its own `mdToSafeHtml()`), and the never-rendered Sentinel-APEX Markdown. Consolidating toward one canonical report renderer (even if `posts/` stays the primary consumer) reduces the risk of the vendor/product-style defect recurring in a second, unaudited code path.

---

## 8. Trust & Evidence Recommendations

- **Implement the six-tier claim classification IREX specifies** (Verified Fact / Multi-source Corroborated Fact / Platform Observation / Analyst Assessment / Inference / Hypothesis), starting narrow: apply it first to the Executive Summary and Key Findings, where a wrong impression costs the most. The underlying signals already exist (`sourceCount`, `Confidence`, `TechniqueMapping.evidence`) — this is a rendering task, not a new-data task.
- **Make source corroboration visible per-claim.** Today a report states "Corroborated across 1 source(s): sentinel_apex" once, globally. A reader cannot tell whether that one source backs the CVSS score, the exploitation claim, or the vendor identification (the last of which, per §4.1, it does not actually back at all). Attaching a source count/list to individual claims — not just the report as a whole — directly prevents the exact failure mode observed live today.
- **Expose the two rejected-hypothesis and resolved-discrepancy patterns from SA-2026-0001 as a reusable template convention**, not a one-off. That report explicitly documents *why* a candidate ATT&CK mapping (T1486) was rejected and *how* a cross-source conflict was resolved. Making "here's what we considered and ruled out" a standard section (not just something one analyst happened to write once) is the most direct way to demonstrate the "acknowledges contradictory evidence" bar IREX's Analyst Quality section asks for.

---

## 9. Commercial Value Assessment

The platform has already produced its own most damning data point: `SA-2026-0001-commercial-packaging.md` records the platform's own scoring engine rating its best real report 43/100 — BLOCKED tier — and explains that the scoring dimensions measure auto-extractable structure (detections, IOCs), not hand-authored analyst quality. That is a scoring-model gap, documented honestly elsewhere in this repo (`platform/open-issues.md`, Issue 3).

This audit adds the more urgent half of the same picture: it isn't only that the *best* report scores low — it's that the *live* report a customer actually reaches isn't the best report at all. Per delivery format, evaluated against what a paying customer would receive **today**:

| Format | Current suitability | What's missing |
|---|---|---|
| Executive Brief | **Not suitable** | Live executive summaries are generic/templated with an explicit "verify everything yourself" disclaimer — the opposite of what an Executive Brief is for |
| Premium Intelligence Bulletin | **Not suitable** | Same root cause; no trust-tier distinction to justify a premium price point over a free feed |
| Enterprise Report | **Not suitable as delivered; content exists but unreachable** | SA-2026-0001 shows the platform can produce this — it simply never reaches a customer-facing page |
| Threat Research | **Partially suitable** | The technical sections (ATT&CK mapping, IOCs, Sigma/YARA) are structurally reasonable when source data is present |
| Managed Service Deliverable | **Not suitable** | No PDF/export path; no lifecycle promotion past `drafts/` |
| Customer Portal | **Partially suitable** | Template renders correctly in-browser; no audience filtering, no trust indicators |
| API Output | **Out of scope for this audit** | Governed separately by `api/_lib`/`Sentinel-APEX/engine` scoring, per `platform/open-issues.md` Issue 1 |

**The commercial risk in plain terms**: an enterprise customer paying for "Sentinel APEX Intelligence" and landing on the live CVE-2026-50522 page receives a lower-quality artifact than a free NVD entry — NVD, at minimum, correctly identifies the vendor and product. That gap is measurable, live, and compounds with every 5-minute ingestion cycle until §5 item 1 is addressed.

---

## 10. Implementation Roadmap

Phased so each phase is independently shippable and none requires waiting on a later one to deliver value.

**Phase 0 — Stop the active wound (days, not weeks)**
Fix the Unknown Vendor/Product fallback (§5.1). This is live and ongoing; every cycle without the fix is more affected content.

**Phase 1 — Give the good content somewhere to go**
Minimal Pipeline B → reader path (§5.2). Doesn't need to be beautiful; needs to exist. Reconcile the `►`/`##` mismatch (§5.4) so the quality gate has something real to check before this content ships.

**Phase 2 — Make trust visible**
Per-claim confidence/source display (§8). Requires Phase 1 to have somewhere to render it, but the data already exists in Pipeline B's models today.

**Phase 3 — Multi-audience views**
Audience-scoped reading paths over the existing single template (§7), extending to real use of the six `templates/` files once Phase 1/2 prove the pattern works on Pipeline A content.

**Phase 4 — Visual system maturation**
Type/spacing scale, externalized CSS, icon system, timeline component (§6). Deliberately last: these are real improvements but, per IREX's own non-negotiable principle, decoration on top of Phase 0-era content would be actively misleading about the product's actual state.

**Phase 5 — Export**
PDF/print-quality output, once there's a stable, trustworthy report to export.

---

## 11. Prioritized Backlog

| # | Item | Section | Rough size |
|---|---|---|---|
| 1 | Fix vendor/product fallback via existing CPE extraction | §5.1 | S |
| 2 | Delete 5 duplicate dead function declarations | §5.3 | S |
| 3 | Reconcile `►`/`##` marker mismatch in engine | §5.4 | S |
| 4 | Externalize inline CSS to a shared stylesheet | §5.5 | M |
| 5 | Minimal render path for Sentinel-APEX Markdown reports | §5.2 | M |
| 6 | Per-claim confidence/source badges | §8 | M |
| 7 | Anchor navigation / jump-to-section rail | §6 | S |
| 8 | Type + spacing scale as CSS custom properties | §6 | M |
| 9 | Audience-scoped reading paths (Exec/SOC/Full toggle) | §7 | L |
| 10 | Icon system replacing ad-hoc emoji | §6 | M |
| 11 | `@media print` styling | §6 | S |
| 12 | PDF export | §4.9, Phase 5 | L |

(S/M/L are relative-effort signals for planning discussion, not committed estimates — no story-pointing exercise was run as part of this audit.)

---

## 12. Risks

- **Polishing the template before fixing the pipeline actively backfires.** A more beautiful "Unknown Vendor Unknown Product" page is a more convincing-looking untrustworthy page. This is the single biggest risk this audit identifies, and it's why the roadmap sequences Phase 4 last.
- **The Unknown Vendor defect is compounding, not static.** It reproduces on every future `sentinel_apex`-sourced CVE post until fixed — the longer Phase 0 is deferred, the larger the corpus of affected live content grows.
- **"Connecting Pipeline B" is a real engineering task, not a config flip.** `render_draft()`'s output shape doesn't even match the hand-authored SA-2026-0001 structure today (§4.2) — Phase 1 needs a real decision about which shape is canonical, not just a rendering step bolted on.
- **Scope creep toward another governance document.** This audit itself should not spawn a Layer 15 or a v2 of itself next cycle; per IREX's own framing, the goal is continuous, evidence-based improvement of the actual reader experience, not a growing stack of assessment documents about it.
- **The audience-template consolidation (§7) risks becoming six parallel maintenance surfaces** if implemented as six independent renderers rather than filtered views over one canonical section set. The recommendation is written specifically to avoid that failure mode — worth re-checking against it at implementation time.

---

## 13. Validation Summary

Per IREX's instruction not to claim production readiness without evidence, here is exactly what was and wasn't checked:

**Validated directly** (read the actual file/line, or ran a command against it):
- The live "Unknown Vendor Unknown Product" content, byte-for-byte, on the actual published post.
- The duplicate function declarations, by line number, in `fetch-live-intel.js`.
- The empty state of `reports/final/` and `reports/published/`.
- The `►`-marker mismatch, by grepping for zero occurrences in the real report and confirming the contradictory treatment in `report_parser.py` vs. `normalizer.py`.
- The root cause of the vendor/product fallback, by reading the exact fallback chain and confirming existing-but-unused CPE extraction logic in the same file.
- The absence of any PDF library in both `package.json` and `requirements.txt`, and the absence of any code path reading the Sentinel-APEX Markdown reports.

**Not validated in this audit** (explicitly flagged, not assumed):
- Actual browser rendering across breakpoints/devices — no live browser test was performed against `posts/*.html`.
- Accessibility (screen-reader behavior, contrast ratios) — assessed only by reading markup/CSS, not tested with assistive tooling.
- Whether `quality.py`'s gates, if pointed at `##`-formatted content instead of `►`, would actually pass SA-2026-0001 — the marker mismatch was confirmed, but the gate was not re-run under a hypothetical fix.
- CI enforcement beyond what `.github/workflows/*.yml` file contents show — confirmed `intelligence-engine-ci.yml` runs `pytest` and a syntax check only, not `cli.py gate` against real content, but did not execute the workflow itself.
- Scale/performance of externalizing CSS across the full 3,400+ post corpus — the recommendation is directionally sound (standard web performance practice) but no before/after measurement was taken.

---

## 14. Recommended Next Sprint

One scoped, shippable unit, consistent with IREX's framing of continuous improvement over one-time redesign:

**Sprint goal: stop the active trust defect and prove one report can travel end-to-end.**

1. Fix the vendor/product fallback (§5.1) — reuse the existing CPE regex extraction, apply it to `sentinel_apex`-sourced CVE items before the literal-string default.
2. Delete the five duplicate dead function declarations (§5.3) — zero-risk cleanup, clears the path for anyone touching those functions next.
3. Decide the canonical Markdown shape for Sentinel-APEX reports (§4.2) and reconcile the `►`/`##` mismatch so the quality gate can evaluate real content at least once.
4. As a proof-of-concept only (not full Phase 1): render SA-2026-0001 through the existing `mdToSafeHtml()` converter to confirm what a minimal Pipeline B → HTML path would actually look like, before committing to a larger rendering investment.

Explicitly out of scope for this sprint: any visual/typography work (Phase 4), multi-audience views (Phase 3), and PDF export (Phase 5) — per this audit's own central finding, none of that should be prioritized ahead of what reaches the page in the first place.

---
*CyberDudeBivash® Sentinel APEX — Intelligence Report Experience Audit (IREX v1)*
