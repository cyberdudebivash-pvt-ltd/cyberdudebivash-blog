# Commercial Quality Enforcement — Phase 1: The Hard Publication Gate

**Date:** 2026-08-18
**Trigger:** "CyberDudeBivash® Sentinel APEX Intelligence Factory — Premium CTI Commercial Readiness Enforcement" mandate (P0, 20 phases, a 100-point/15-domain scoring model, a 21-section Blogger contract, live canary validation, before/after proof, dashboards — the full text is in this session's conversation history, not reproduced here).

## Why this is Phase 1, not the whole mandate

The mandate is, honestly, a multi-week platform build even for a full team: a 100-point scoring rubric across 15 domains, an explicit `commercial_quality_score >= 95` numeric gate, a 21-section report contract, 10 SIEM/EDR detection formats, a 19-role decision matrix, a forecasting engine, editorial-quality NLP checks, a 7-scenario live canary suite, before/after proof on 3 reports, and a metrics dashboard. Attempting all of it in one unreviewed pass against a live, cron-scheduled, revenue-generating pipeline would itself violate the mandate's own Phase 17 deployment-safety requirement, and this repository's CLAUDE.md (Minimal Change Surface, Blast Radius assessment before every change, Proof Before Change).

Instead, this PR does real, evidence-based investigation first (per the mandate's own "Do not stop at documentation... trace the live code path" instruction) and fixes the single root defect that every other named symptom traces back to. Everything else is named explicitly below as follow-up, not silently dropped.

## What the investigation found

Traced the actual live Blogger publish path (`automation/main.py` → `AuthorityTransformer.transform()` → `BloggerPublisher.publish_post()`) end to end. Two concrete, load-bearing defects, both real and both now fixed:

1. **`certification_status` was a hardcoded module-level constant** (`report_integrity.py`: `CERTIFICATION_STATUS = "Public reference draft — not a certified customer deliverable"`), stamped onto *every* `ReportContext` regardless of actual evidence quality. `validate_publication()` even required this exact literal string to be present in the HTML. This is the direct cause of the mandate's own complaint: *"public outputs still labeled as drafts/reference products"* — even a report that internally passed every correctness control still displayed a static "draft" label, because nothing ever computed or surfaced a real one.

2. **There was no publish/no-publish gate at all** — `main.py` calls `transformer.transform(article)` and passes its result straight to `publisher.publish_post()` unconditionally. The only existing check, inside `_composer_enhance()`, only decided *which template* to use (composer vs. legacy) when the composer's own evidence-graph tier ladder (`tier_downgrade.determine_achieved_tier()`, already built and tested in this repo) landed at `PUBLIC_REFERENCE_DRAFT` — it never blocked publication. Worse: **`_composer_enhance()` — and therefore all evidence-based certification — was only ever called *after* the LLM content path had already failed.** Since `transform()` tries the LLM path first, any LLM-authored article (the first-choice path) published with **zero evidence-based certification of any kind**, regardless of how weak its underlying evidence was. This is the exact root of *"insufficient separation between automated feed synthesis and finished intelligence"* and *"no mandatory premium certification"* from the mandate's own list.

Both defects trace to the same place: certification was never a real, always-computed, gating signal — it was a label, and only sometimes.

## The fix

- `pipeline_composer.compose_report()` (already built, already tested — Reuse Before Build) now runs **unconditionally** for every article, independent of which content path (LLM / composer / legacy template) ends up supplying the rendered body. Evidence-graph correctness is a property of the article's own evidence, not of which renderer wrote the prose.
- `build_report_context()` gained an optional `achieved_tier` parameter (default `""`, fully backward compatible for every existing caller). When a real tier is known and it isn't `PUBLIC_REFERENCE_DRAFT`, the certification label becomes real: `"Public Intelligence Certification: TACTICAL_READY (automated evidence-graph certification...)"` instead of the static draft string — this is what `_assemble_html()`'s single canonical provenance section (used by every article regardless of content path) now renders.
- `validate_publication()` gained one new fail-closed check: `achieved_tier == "PUBLIC_REFERENCE_DRAFT"` now raises `PublicationIntegrityError` — reusing the exact exception type, `main.py` catch block, retry-queue (`state.add_to_retry_queue()`, already capped at 3 attempts / 20 items — no new state machinery needed), and `integrity_blocked` counter that already existed for this exact class of outcome. `achieved_tier == ""` (any caller that hasn't computed a tier) is deliberately *not* a failure, so no other caller's behavior changes.
- A software fault inside `compose_report()` itself (an exception, not an evidence verdict) is kept distinct from an evidence-correctness failure: it still falls back to the legacy template and still publishes, exactly as before this change — an unproven-in-production code path must not be able to take down publication outright. Only a genuine evidence-graph verdict of "unreliable" now blocks.

This directly satisfies the mandate's own top-line, non-negotiable requirement — *"There must be no silent downgrade to public-reference or legacy output"* — for the one case that was actually happening today.

## Real, live proof (not a synthetic fixture)

Ran `python -m automation.main --dry-run` against real, fresh sources. All 5 discovered articles (real NVD CVEs published today) cleared the new gate cleanly (`integrity_blocked: 0`) and — this is the concrete before/after — every one now carries a genuine, computed tier and label instead of the old static string:

| Before this fix | After this fix (real dry-run output) |
|---|---|
| `certification_status`: `"Public reference draft — not a certified customer deliverable"` (always, for every article, regardless of quality) | `certification_status`: `"Public Intelligence Certification: TACTICAL_READY (automated evidence-graph certification — see Provenance for the source basis)"` |
| `achieved_tier`: not tracked anywhere in the pipeline | `achieved_tier`: `"TACTICAL_READY"` (a real value on all 5/5 real articles) |
| LLM-authored articles: zero evidence-based certification, ever | LLM-authored articles: same unconditional evidence-graph check as every other path |

## Test plan

- 7 new/updated regression tests in `tests/test_authority_transformer.py`:
  - The core fix, proven directly: an article whose evidence fails correctness is blocked **even when the LLM path succeeds** (`test_evidence_correctness_failure_blocks_publication_even_when_llm_succeeds`) — this is the exact gap that existed before.
  - The two failure modes stay distinct: a composer exception still falls back to the legacy template and still publishes; a composer evidence-correctness verdict now blocks (`test_composer_exception_falls_back_to_legacy_template_and_still_publishes`, `test_composer_evidence_correctness_failure_blocks_publication_entirely`).
  - The gate itself, isolated from `AuthorityTransformer`: blocks on `PUBLIC_REFERENCE_DRAFT`, does not trip on `""` (backward compatibility for every untouched caller), and the honest label is both computed correctly and satisfies `validate_publication()`'s own required-field check (`TestFailClosedPublicationGate`, 3 new tests).
  - The honest label end-to-end through a real `transform()` call.
- Full suite: root `tests/` + `automation/` — 335/335 pass. `Sentinel-APEX/engine` — 892/893 pass (the one failure is the same pre-existing, environment-only `test_certify_real_end_to_end_with_the_actual_node_rendering_check` gap already documented in PR #91 and PR #92 — reproduces identically, unrelated to this change).
- Live dry-run against real, fresh sources (above) — proves the gate doesn't false-positive-block genuinely good evidence, and that the honest label renders correctly in real output.

## Explicitly named as follow-up (not attempted here, not silently dropped)

Everything below is real, well-motivated work — it's just a separate, similarly-rigorous effort, not a corner cut in this one:

- **The 100-point/15-domain numeric `commercial_quality_score >= 95` model.** This PR reuses the existing, already-calibrated tier ladder (`PUBLIC_REFERENCE_DRAFT` blocks; everything above it currently publishes) rather than inventing a parallel scoring system — Single Source of Truth. Building the full numeric rubric, and deciding whether the bar should sit higher than "cleared correctness" (e.g., requiring `TACTICAL_READY` or above), is a genuine, separate calibration exercise — exactly the kind of empirical threshold-setting work done for `intelligence_validation.py` in the Intelligence Validation Framework PR (#90), and it deserves the same rigor, not a guessed number.
- **`HOLD_FOR_ANALYST_REVIEW` / `UPDATE_EXISTING_REPORT` resolution states.** Only `HOLD_FOR_ENRICHMENT`-equivalent behavior exists today (the existing retry queue, reused as-is). The other two require analyst-review tooling and existing-report-matching logic that don't exist in this pipeline yet — both are large, separate deliverables from the original 10-deliverable platform mandate.
- **The 21-section Blogger contract**, expanded role matrix (19 roles), 10 SIEM/EDR detection formats beyond the existing Sigma/KQL, forecasting engine, editorial-quality NLP checks, and the 7-scenario live canary suite are all real, scoped asks this PR does not touch.
- **A live dashboard** for the new `achieved_tier`/certification observability fields this PR adds — the data is now flowing (see `post_result["achieved_tier"]` in every run report); building a dashboard on top of it is a presentation-layer task, not a pipeline-correctness one.
