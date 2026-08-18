# P0 — Blogger Publication Path: Root Cause, Live Evidence, and Fixes

**Severity:** P0, customer-facing (per the incoming report).
**Status:** Root cause proven from live production evidence, not inferred. Three
concrete, reproduced defects fixed in this change, each with a before/after
demonstration against the exact two examples named in the incident report
(JWR PhaaS, CISA Windows Task Host). The much larger asks in the original P0
brief (a rebuilt source-acquisition layer, a from-scratch premium renderer,
full observability, an 8-scenario canary suite, staged rollout tooling) are
explicitly scoped as follow-up work — see "What remains" — rather than
attempted wholesale against a live, cron-scheduled production pipeline
without individually testable, low-blast-radius changes.

---

## Executive summary

1. **The core defect this incident describes — Blogger receiving legacy-
   template output instead of the ReportX Intelligence Factory composer's
   output — was already fixed, hours before this investigation began**, by
   `4906afb` ("ReportX: wire the Intelligence Factory composer into the live
   pipeline (#89)", merged 2026-08-18 ~10:04 UTC). A live dry run against
   real, fresh NVD and ransomware-intel sources in this session produced
   `content_source: reportx_composer` for **8/8** articles (100%). The two
   examples named in the incident report were confirmed **already published
   via the composer**, at 10:46 UTC today.
2. That does not mean the incident is a false alarm. Fetching both live
   URLs directly showed three real, reproducible content-quality defects
   *inside* the composer's own output — not the "legacy template" failure
   mode the report assumed, but real defects nonetheless, and a legitimate
   trust problem:
   - **Misrouted role guidance**: a "Vulnerability Manager" decision
     appeared on a phishing-as-a-service report with no CVE or patch
     dimension anywhere in its evidence.
   - **Verbatim content duplication**: the same raw source paragraph was
     rendered three times across three differently-named sections.
   - **Silent mid-sentence truncation**: RSS-derived summaries were hard-cut
     at a fixed character offset with no boundary awareness and no marker,
     producing sentences that visibly stop mid-word.
3. All three are fixed in this change, each verified against a
   reconstruction of the real failing input, with new regression tests.
4. A large, separate, real problem was also found and is flagged (not
   fixed) below: **86% of all publish attempts across ~2 months of
   production logs fail with `publish_error`**. This is a delivery-layer
   problem, orthogonal to content quality, and is out of this change's
   scope — see "Found but not fixed."

---

## Phase 1 — The live pipeline, traced from real code

Two entirely separate, independently-scheduled pipelines exist in this
repository. Only the first publishes to Blogger; the incident is about
that one exclusively.

| | Blogger syndication (this incident) | SENTINEL APEX v5.0 |
|---|---|---|
| Entrypoint | `python -m automation.main` | `node fetch-live-intel.js` |
| Workflow | `.github/workflows/blogger-syndication.yml` | `.github/workflows/sentinel-apex.yml` |
| Cadence | every 2 hours (`15 */2 * * *`) | every 30 min (`0,30 * * * *`) |
| Destination | Blogger API (blogspot/custom domain) | `posts/`, `api/` (blog.cyberdudebivash.in, Next.js) |
| Language | Python | Node.js |

Blogger publication call graph, confirmed by direct code read (not
inferred):

```
automation/main.py: run_pipeline()
  -> ContentDiscoveryEngine.discover()          [content_discovery.py + per-source modules]
       nvd_source.py, cisa_kev_source.py, rss_aggregator.py (28 global feeds),
       threat_feeds.py (CISA advisories, ransomware.live, breach intel, actor intel),
       content_discovery.py's own "live_intel" reader (re-ingests the OTHER
       pipeline's own live-intel.json -- see "Found but not fixed" below)
  -> AuthorityTransformer.transform(article)     [authority_transformer.py]
       1. call_llm(...)                          [llm_client.py: Groq -> DeepSeek -> OpenRouter -> Anthropic]
          |- success -> body = LLM content, content_source = provider name
          `- all fail -> 2.
       2. _composer_enhance(article, config)      [wraps sentinel_engine.reportx.pipeline_composer.compose_report]
          |- achieved_tier != PUBLIC_REFERENCE_DRAFT -> body = composer HTML, content_source = "reportx_composer"
          `- PUBLIC_REFERENCE_DRAFT or any exception -> 3.
       3. _legacy_template_enhance(article, config)  [1000+ line deterministic keyword-matched template]
             content_source = "template"
       -> build_report_context() + validate_publication()   [report_integrity.py, fail-closed floor, ALL paths]
  -> BloggerPublisher.publish_post(title, content, labels, ...)   [blogger_publisher.py]
  -> discovery.state.mark_published(...)          [data/published_posts.json]
  -> SearchConsoleSubmitter.submit_url() + SocialAmplifier.amplify()
```

`_composer_enhance()` (`automation/authority_transformer.py`) is the exact
bridge to `sentinel_engine.reportx.pipeline_composer.compose_report()` — the
evidence-graph-backed, 23-control-gated Intelligence Factory composer this
repository's own `docs/reportx/` documents extensively. It is tried
**second**, after the LLM path and before the legacy template, and it never
raises past its own `try/except` — a composer failure always degrades to
the legacy template rather than breaking the run.

---

## Phase 2 — What "runtime values" actually showed

Every field the incident report asked to trace
(`composer_selected`/`content_source`, `reportx_status`, `certification_status`,
`report_family`, `detection_status`, `llm_attempts`, ...) is already recorded
in every run, in `logs/run-*.json` — 4,258 real run files were available for
this investigation, spanning 2026-06-19 through 2026-08-18 (this repository
already has real observability for this; Phase 15 of the incident is
largely already satisfied for these specific fields).

### The historical rate (before today)

Aggregated across all 4,258 run files (34,386 total publish attempts):

| `content_source` | Count | % |
|---|---|---|
| `template` (legacy) | 33,485 | 97.4% |
| `groq` (LLM) | 704 | 2.0% |
| `openrouter` (LLM) | 138 | 0.4% |
| `reportx_composer` | 10 | 0.03% |

This is real and matches the incident report's description. But it is also
**explained by timing, not by a live defect**: `git log --diff-filter=A` on
`automation/authority_transformer.py`'s `_composer_enhance()` shows it did
not exist in the codebase until `4906afb`, committed 2026-08-18 ~10:04 UTC —
**today**, a few hours before this investigation. Before that commit, the
pipeline had only two rungs (LLM, then legacy template); "reportx_composer"
could not have appeared as a `content_source` value at all. All 10 of the
historical `reportx_composer` hits fall inside the two run files
immediately after that commit landed
(`run-20260818-100558.json`, `run-20260818-104630.json`).

### The current rate (verified live, in this investigation)

A real dry run (`python -m automation.main --dry-run --max-posts 8`) against
live NVD and ransomware-intel sources, with no LLM keys configured (forcing
every article through the composer path), produced **8/8 (100%)**
`content_source: reportx_composer` — 7 fresh CVE advisories and one
ransomware victim claim, none falling back to the legacy template. The
composer wiring is not broken.

### The two named examples, confirmed already composer-published

Both are in `data/published_posts.json` with `published_at` timestamps of
2026-08-18T10:46 UTC — inside the first post-`#89` run:

| | JWR PhaaS | CISA Windows Task Host |
|---|---|---|
| `report_family` | `general_intelligence` | `ransomware_reporting` |
| `certification_status` | Public reference draft — not a certified customer deliverable | (same) |
| `blogger_url` | `.../2026/08/jwr-phishing-as-service-kit-uses.html` | `.../2026/08/cisa-windows-task-host-flaw-now.html` |

Fetching both live pages directly (not simulated) confirmed the composer's
real structure is present — Executive Summary, Threat Classification,
Intelligence Assessment, Operational Decisions, Detection Engineering,
References, Role-Based Decisions, Source Reliability & Corroboration — and
also confirmed three real, reproducible defects inside that structure.

---

## The three defects: root cause, fix, and live before/after

### 1. Misrouted role guidance (incident Phase 9's named symptom)

**Live evidence:** the JWR PhaaS page (a phishing/PhaaS report, no CVE
anywhere in its evidence) included a "Vulnerability Manager" role decision.

**Root cause, found in code**
(`Sentinel-APEX/engine/sentinel_engine/reportx/pipeline_composer.py`,
`_lean_role_decisions()`): the function unconditionally prepended a
`VULNERABILITY_MANAGER` decision — *"Track against {family} intake at
severity commensurate with {exploitation}..."* — to every report regardless
of family, before checking anything else. `SOC_MANAGER`/`IR_MANAGER` were
already correctly gated behind their relevant families; `VULNERABILITY_MANAGER`
was not.

**Fix:** gated `VULNERABILITY_MANAGER` behind the same families that
already have a real patch/exploitation dimension
(`cve_advisory`, `cisa_advisory`, `cisa_kev`, `ransomware_claim` — i.e.
exactly the families already special-cased elsewhere in this function, so
existing, tested behavior for CVE and ransomware-victim-claim reports is
byte-for-byte unchanged). A family with **zero** grounded role decisions
now omits the "Role-Based Decisions" section entirely, rather than leaving
a heading with nothing under it.

**Verified:**
```
before: "Vulnerability Manager" present for a reconstructed JWR-shaped article
after:  "Vulnerability Manager" absent; "Role-Based Decisions" section itself absent
        (CVE and ransomware-claim articles: unaffected, both still show it)
```
Tests: `test_pipeline_composer.py::TestRoleRoutingDoesNotMisapplyVulnerabilityManagement` (4 new tests).

### 2. Verbatim content duplication (incident Phase 12's named symptom)

**Live evidence:** WebFetch on both live pages independently flagged the
same executive-summary paragraph reappearing verbatim in a second,
differently-named section — "a hallmark of template-driven synthesis."

**Root cause, found in code** (`automation/report_renderer.py`): the same
`article.summary[:1800]` raw text was rendered into **three** places —
Executive Summary, `_family_analysis()`'s per-family "Assessment" section
(all 5 branches), and `_technical_evidence()`'s explicitly-labeled "Source
Evidence Extract." The first and third are each independently legitimate
(first exposure to the facts; an explicitly-labeled raw quote). The middle
one added no analytical content beyond repeating the same paragraph a third
time.

**Fix:** removed the raw-summary paragraph from all 5 branches of
`_family_analysis()`, keeping each branch's genuine analytical/boundary
content (e.g. "Vulnerability class: ... Assessment: ...",
"Evidence boundary: this is a third-party leak-site listing...").
Duplication reduced from 3x to 2x, with the 2 remaining occurrences each
independently justified and distinctly labeled.

**Verified:** a reconstructed JWR-shaped article's composer output now
contains the source sentence exactly 2 times (Executive Summary + Source
Evidence Extract), not 3.
Tests: `tests/test_report_renderer.py::TestFamilyAnalysisDoesNotRepeatTheSourceSummary` (6 new tests, one per family branch plus one confirming the legitimate copy survives).

### 3. Silent mid-sentence truncation (incident Phase 3's named concern)

**Live evidence:** the JWR page's opening paragraph ends mid-sentence:
*"...while card numbers, passwords and one-time codes are still [...]"* — no
punctuation, no visible marker until an editorial `[…]` insertion.

**Root cause, found in code** (`automation/content_discovery.py`,
`_parse_feed_items()`, and a second call site reading the sister Node.js
pipeline's own `live-intel.json`): RSS/feed descriptions were hard-truncated
with a bare Python slice, `get_text(...)[:1500]`, with no word-boundary
awareness and no explicit marker appended. A third call site in
`automation/report_renderer.py`'s Executive Summary section had the same
pattern at 1800 characters.

**Fix:** all three call sites now use the existing, already-tested
`seo_optimizer._truncate(text, max_len)` helper (word-boundary cut +
explicit `"..."` marker) instead of a bare slice — reused, not
reimplemented, per this repository's own reuse-before-build discipline.
This does not implement the incident's full "Phase 3: full source
acquisition" ask (fetching complete original article text, canonical URL
resolution, etc.) — see "What remains."

**Verified:** a 1500+-character synthetic description now truncates to
`"...phishing platform."` cleanly on a word boundary with an explicit
marker, never mid-word.
Tests: `tests/test_content_discovery.py::TestParseFeedItemsSummaryTruncation` (3 new tests).

---

## Found but not fixed (named, not silently dropped)

- **86% `publish_error` rate.** Across all 4,258 historical run files:
  4,726 `published`, 28,623 `publish_error`, 640 `auth_error`, 388
  `rate_limited`, 6 `integrity_blocked`. This is a delivery/API-layer
  problem (happens *after* `content_source` is already decided), entirely
  orthogonal to the content-quality defects this incident is about. It
  deserves its own dedicated investigation — the `error` field is recorded
  per-post in every run report and has not yet been aggregated/root-caused
  here. Flagging this explicitly rather than treating "content_source now
  correct" as full resolution of "why does the public channel look
  unhealthy."
- **Cross-pipeline re-ingestion.** `content_discovery.py` has a dedicated
  `source="live_intel"` reader that ingests the *other* (Node.js, blog.cyberdudebivash.in)
  pipeline's own `live-intel.json` output and re-syndicates it to Blogger.
  Several "template" fallback samples in the historical logs
  (`blog.cyberdudebivash.in/posts/cve-2026-...`) are this pipeline
  republishing the sister pipeline's own already-published content. Whether
  this is intentional cross-syndication or unintended duplication was not
  resolved in this pass and is worth an explicit product decision.
- **The remaining 14 "Final Required Deliverables"** this incident names
  (full source-acquisition engine, PREMIUM_PUBLIC_READY schema, a from-
  scratch premium renderer with new design system, full 20-gate QMS wired
  into publication, report-family specialization beyond what
  `_family_analysis()` already has, 8-scenario canary suite, staged
  rollout tooling, complete observability dashboard, production runbook)
  are real, legitimate asks but are each independently large — the kind of
  work this repository's own history treats as its own reviewed change
  (see `REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md`,
  `REPORTX-AUTOMATED-CERTIFICATION.md`, each a separate, dedicated PR).
  Attempting all of them in one pass against a live, cron-scheduled
  production pipeline, untested individually, would itself violate this
  incident's own Phase 17 deployment-safety and zero-downtime
  requirements. Recommended phasing:
  1. Root-cause + the 3 defects above (**this change**).
  2. Investigate and fix the 86% `publish_error` rate (separate, since it's
     data-driven and needs its own aggregation pass over the `error` field).
  3. Wire `sentinel_engine.reportx.intelligence_validation`'s 20-dimension
     scorecard (already built, see `docs/reportx/REPORTX-INTELLIGENCE-VALIDATION-FRAMEWORK.md`)
     as an actual pre-publication gate in `authority_transformer.transform()`,
     with a `HOLD_FOR_ENRICHMENT` state for genuinely sparse records —
     the concrete mechanism this incident's "Non-negotiable publication
     policy" section describes, largely already built, not yet wired to
     Blogger specifically.
  4. Real source-acquisition improvements (canonical URL resolution, full-
     text fetch where legally/technically appropriate) — a genuinely new
     capability, deserves its own design + review.
  5. Design-system-level premium renderer work (Phase 7's badges/matrices/
     visual system) — a product/design decision, not a backend fix.

---

## Files changed in this pass

- `Sentinel-APEX/engine/sentinel_engine/reportx/pipeline_composer.py` —
  role-routing gate + empty-section omission.
- `automation/report_renderer.py` — de-duplicated `_family_analysis()`;
  word-boundary truncation in the Executive Summary section.
- `automation/content_discovery.py` — word-boundary truncation in both RSS
  parsing and the sister-pipeline `live_intel` reader.
- `Sentinel-APEX/engine/tests/reportx/test_pipeline_composer.py`,
  `tests/test_report_renderer.py`, `tests/test_content_discovery.py` — 13
  new regression tests covering all three fixes.

## Validation performed

- Full existing suite unaffected: `Sentinel-APEX/engine/tests/` 892/893
  pass (the one failure is a pre-existing, environment-only Node-
  availability gap in `test_certification.py`, reproduced identically on
  the unmodified base branch); root `tests/` + `automation/tests/` 329/329
  pass.
- Live dry run against real, fresh sources (`python -m automation.main
  --dry-run --max-posts 8`): 8/8 composer success, before and after these
  fixes.
- Both real, live, already-published URLs named in the incident report
  fetched and inspected directly (not simulated) to establish the actual
  defects, and reconstructions of both were used to verify each fix.
- `python -m py_compile` clean on every changed file.
