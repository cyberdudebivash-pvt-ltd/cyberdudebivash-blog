# REPORTX Phase 1K Remainder — Section 16 (Indicators/Observables) Certification

**Date:** 2026-08-21
**Scope:** One of the five sections named in `REPORTX-PHASE1-RESUME-CHECKPOINT.md` §5 item 2 as Phase 1K's own remainder — Section 16 (Indicators/Observables) had zero real evidence-extraction capability anywhere in this pipeline, unconditionally `WITHHELD` for every article regardless of family. Per explicit user direction, tackled one section at a time (Section 16 this round; Section 20 and Section 4 named as follow-up, not attempted here).
**Format:** Matches `REPORTX-PHASE1N-CERTIFICATION-LADDER-CERTIFICATION.md` / `REPORTX-PHASE1K-24-SECTION-CERTIFICATION.md`.

## Audit first (Reuse Before Build)

Before writing anything, searched for existing capability rather than assuming none existed — the original Phase 1K audit's own claim ("no IOC extraction capability exists") turned out to be incomplete. `Sentinel-APEX/engine/sentinel_engine/ioc_extractor.py` is a real, tested, false-positive-hardened IOC extractor (regex-based, defang/refang, `DEFAULT_ALLOWLIST` for MITRE/NVD/CISA/reference infrastructure) already wired into the separate Sentinel APEX CTI platform (`normalizer.py`, `quality.py`, `report_ingest.py`) — but never imported by `automation/`'s ReportX pipeline at all. This is the fifth instance of the same certified-but-dormant-module defect class this mandate has now found (after `hunt_hypotheses`, `attack_mapping`, `role_decisions`, `forecast`).

## Changed components

- `automation/report_contract.py` — `SECTION_16_INDICATORS_OBSERVABLES` resolution added to `evaluate_section_states()`: new `ioc_count: int = 0` parameter, `COMPLETE if ioc_count > 0 else WITHHELD_INSUFFICIENT_EVIDENCE`, mirroring Section 22's own `forecast_count` pattern exactly.
- `automation/analytical_depth_gate.py` — `ioc_count: int = 0` threaded through `evaluate_product_tier()` to `evaluate_section_states()`. Section 16 is `OPTIONAL` for every family with a reconciled matrix (unlike `forecast_count`, not family-restricted), so this never gates tier eligibility on its own.
- `automation/authority_transformer.py` — new `_extract_article_iocs()` (calls `ioc_extractor.extract_iocs()` against `article.full_content or article.summary`, the same "richest available raw source text" convention `_build_analyst_prompt()` already uses) and `_render_iocs_html()` (renders grouped by type, always defanged via `ioc_extractor.defang()` before publication, per `models.py`'s own IOC docstring requirement). Computed and appended unconditionally in `transform()`, once, regardless of `content_source` — unlike the four prior wirings, IOC extraction has no dependency on the composer's evidence graph, so it needs no `reportx_composer` duplication guard.
- `automation/report_renderer.py` — `_known_publisher_domains()`/`_KNOWN_PUBLISHER_DOMAINS` (derived from `rss_aggregator.py`'s own curated feed list) and `_defang_text()` (new); `_source_lines()` now defangs before quoting. See "Adjacent defect found and fixed" below.
- `reportx-canary/phase1k_section_completeness_representative_fixtures.py` — extended with an IOCs column and `ioc_count` pass-through (one representative case, `KEV (confirmed exploited)`, given realistic indicator-bearing `full_content` to exercise the positive path); new assertions that a `COMPLETE` Section 16 always has real rendered content, a zero `ioc_count` never renders the section, and no extracted URL/IPv4/domain indicator ever reaches the published page un-defanged.
- 24 new tests across `tests/test_report_contract.py` (5), `tests/test_authority_transformer.py` (14), `tests/test_report_renderer.py` (5).

## Adjacent defect found and fixed (not the section-16 wiring itself)

**Found during this round's own real-data validation** (mandate Section 29: "Claude must actively attempt to break its own implementation"), not pre-planned: proving Section 16's own defanging guarantee end-to-end against a real `transform()` call surfaced that `report_renderer.py`'s `_source_lines()` — feeding `_technical_evidence()`, Section 23's "Source Evidence Extract" — has always quoted the article's raw source text **verbatim, HTML-escaped but never defanged**, into the published page. Any live indicator present in an article's own source text (an active C2 URL, for example) was published exactly as written: a real, clickable link to attacker infrastructure.

**Confirmed reachable on the pipeline's primary content path, not a rare edge case**: traced `content_source: "reportx_composer"` output containing the exact leaked, un-defanged URL back to its source — `pipeline_composer.compose_report()` (`Sentinel-APEX/engine`) reuses `automation.report_renderer.render_evidence_report()` (and therefore `_source_lines()`) as its own base HTML for every article, not merely the legacy-template fallback. This means the leak has been reachable on the pipeline's common, no-LLM-configured case (per the resume checkpoint's own prior finding) since `_technical_evidence()` was first written — pre-existing, unrelated to Section 16's own contract wiring, but directly adjacent to it (both concern the exact same hazard: publishing a live indicator) and found in the course of proving Section 16's own guarantee.

**Disposition: fixed in this same round, not deferred** — small, surgical (`_defang_text()`, ~25 lines), reuses this round's own `extract_iocs()`/`defang()` integration rather than a second mechanism, matching the precedent Phase 1M already set (3 real false positives found via that round's own real-data validation, root-caused and fixed inline rather than deferred to a separate round, because each was small and directly adjacent to the work already underway). `_known_publisher_domains()`/`_KNOWN_PUBLISHER_DOMAINS` was relocated from `authority_transformer.py` to `report_renderer.py` (its only prior location) because `_defang_text()` — also in `report_renderer.py` — needs it too, and `authority_transformer.py` already imports from `report_renderer.py` (never the reverse), so this is the one non-circular home for it; `authority_transformer.py` now imports it back, a pure relocation with no behavior change to the callers already using it.

## A second real false positive found and fixed via real-data validation

`ioc_extractor.py`'s own `DEFAULT_ALLOWLIST` covers MITRE/NVD/CISA/social-media/reference infrastructure, but has no way to know this pipeline's own curated news publishers. Real-data testing against ordinary citation prose ("As first reported by SecurityWeek...") confirmed `securityweek.com` was misclassified as a domain indicator. Fixed by deriving a supplementary allowlist from `rss_aggregator.py`'s own real, already-curated 78-feed list (Single Source of Truth — not a second, separately hand-maintained list that could drift), explicitly excluding two multi-tenant platforms (`medium.com`, `feeds.feedburner.com`) that host arbitrary third-party content a genuine indicator could still legitimately be reported on.

## Tests executed

**Unit:** 24 new tests (`TestSectionSixteenIndicators` — contract resolution, family-universality, ×5; `TestIocsWiredIntoTransform` — end-to-end wiring, tier non-gating, LLM-path rendering, live-defanging ×7; `TestKnownPublisherDomainAllowlist` — citation suppression without masking real indicators, multi-tenant exclusion ×4; `TestIocRenderingAndDefanging` — direct render-function unit tests ×3; `TestSourceEvidenceExtractDefanging` — the adjacent Section 23 fix ×5).

**Regression:** `python -m pytest tests/ -q` → **587/587 passed** (563 baseline + 24 new, 0 failures). `Sentinel-APEX/engine`: `python -m pytest tests/ -q` → **1062/1062 passed** (baseline reproduced fresh this round with **zero** pre-existing failures in this environment — `test_certify_real_end_to_end_with_the_actual_node_rendering_check`, documented as environment-dependent in the resume checkpoint, passed cleanly here; not touched by this round's changes either way). `node --test tests-js/*.test.js` → 123/123, unchanged (no JS files touched).

**Adversarial:** Deliberately malformed/documentation-range test inputs (RFC 5737 `203.0.113.0/24`, a truncated 63-char fake hash) confirmed the certified extractor's own false-positive filtering rejects them correctly — not a defect, verified by design. Confirmed extracted IOC values can never carry unescaped HTML into the rendered page: the URL regex's own character class excludes `<`/`>`, and every rendered value is both defanged and `_esc()`-escaped regardless.

**Real-data:** Extended `reportx-canary/phase1k_section_completeness_representative_fixtures.py` (the original Phase 1K certification's own real-data harness — reused, not duplicated) run live against all 8 production families:

```
Case                        Family              ... IOCs  ...
CVE (not KEV)                cve_advisory              0
KEV (confirmed exploited)    cisa_kev                  1   <- real IP extracted from realistic source text
Ransomware claim             ransomware_claim          0
Ransomware reporting (news)  ransomware_reporting      0
Threat actor                 threat_actor              0
AI security                  ai_security               0
Breach notice                breach_notice             0
General intelligence         general_intelligence      0

All assertions passed: every claimed-COMPLETE section's content is genuinely
present in the rendered HTML for every case, and no cross-section
consistency spot-check failed.
```

Manual hand-verification (before the canary extension) additionally confirmed: 5 diverse real indicator types (CVE, email, IPv4, SHA256, URL) extracted correctly from one realistic article; a publisher citation (`securityweek.com`) correctly suppressed while a genuine C2 domain in the same text was still correctly flagged; live URL/domain never appears un-defanged in final published HTML, confirmed by direct string search against the actual rendered page (not merely a unit-level assertion on the render function in isolation).

**Post-publication verification:** Not applicable — nothing published to Blogger this round (no live-publish authorization sought or needed; this is a code/content-generation change, not a publish action).

## Results

- 587/587 root tests pass (24 new, 0 regressions).
- 1062/1062 engine tests pass (0 files touched, baseline reconfirmed).
- 123/123 JS tests pass (0 files touched).
- Real-data canary: 8/8 families, all assertions pass, including the 2 new adversarial assertions this round adds (no `COMPLETE`-without-render, no live-indicator leak anywhere on the page).

## Defects discovered (this round)

1. Section 16 (Indicators/Observables) had zero wiring to a real, existing, certified capability — the primary target of this round.
2. **Adjacent, pre-existing**: `_source_lines()`/Section 23 ("Source Evidence Extract") published live, un-defanged indicators verbatim whenever an article's own source text contained one — reachable on the pipeline's primary (`reportx_composer`) content path, not a rare fallback case.
3. **Adjacent, pre-existing**: `ioc_extractor.py`'s `DEFAULT_ALLOWLIST` had no awareness of this pipeline's own curated publisher domains, producing a real false-positive class (citation text misread as an indicator).

## Defects fixed

All three above.

## Requirements proven

- Section 16 resolves `COMPLETE`/`WITHHELD_INSUFFICIENT_EVIDENCE` correctly and honestly, for every family (not CVE-restricted, unlike `forecast_count`), never fabricating an indicator that isn't literally present in the article's own real source text.
- IOC extraction reaches the published page on every content path (composer, LLM-authored, template-fallback) — proven directly on the LLM path, matching the exact recurring "computed but only rendered on one path" defect class this mandate has repeatedly found and closed.
- Every rendered indicator is genuinely defanged before publication, proven both at the unit level (`_render_iocs_html()` directly) and end-to-end (string search against real `transform()` output) — closing not only Section 16's own guarantee but also the pre-existing Section 23 leak found in the course of proving it.
- The publisher-citation false-positive is suppressed without masking a genuine indicator reported in the same article (both proven together in one test, not separately, since a fix that merely suppressed noise without also confirming real indicators still get through would be an incomplete proof).
- Zero regressions across all three existing suites, confirmed fresh, not assumed from a prior report.

## Requirements NOT yet proven

- Live-Blogger publication of an article whose source text actually contains a real indicator — this round's proof is against `transform()`'s own output (the artifact that gets published), the same evidentiary standard every phase since Phase 0 has used absent explicit owner authorization for a live publish action; not attempted here, consistent with that standing constraint.
- Whether `ioc_extractor.py`'s `DEFAULT_ALLOWLIST` + this round's publisher-domain supplement is fully exhaustive against every publisher this pipeline might ever cite — a determined false-positive could still occur for a publisher not in the curated 78-feed list (e.g., a one-off source cited inline that isn't one of this pipeline's own RSS feeds). Bounded, not zero — the same honest limitation any allowlist-based approach carries.

## Production evidence

- 24 new tests, all passing, spanning contract resolution, end-to-end wiring, adversarial rendering safety, and the adjacent Section 23 fix.
- `python -m pytest tests/ -q` → 587/587. `Sentinel-APEX/engine` → 1062/1062. `node --test tests-js/*.test.js` → 123/123.
- Real-data canary extended and run live: `python reportx-canary/phase1k_section_completeness_representative_fixtures.py` → all assertions pass across all 8 production families, output captured above.

## Known limitations

- **Publisher allowlist is bounded, not exhaustive** — see Requirements NOT yet proven above.
- **Section 16 has no dedicated real-article live-Blogger canary** — same standing constraint as every other content-generation phase; requires explicit owner authorization to trigger, not attempted unilaterally.
- **The remaining Phase 1K sections (20, 4) are unstarted** — named as explicit, separate follow-up in the resume checkpoint, one per round, matching this mandate's own established discipline. Sections 10 (Attack Path) and 17 (Business Impact, for `ransomware_claim` specifically) are deliberately **not** on that list: the original Phase 1K audit concluded `WITHHELD`/`NOT_APPLICABLE` is the honest, permanent, correct state there (inventing an intrusion chain or fabricating unverified-claim business impact would violate this platform's own anti-fabrication governance), not a gap to close.

## Unexecuted tests

- Live Blogger publish canary (see Requirements NOT yet proven / Known limitations).

## Certification

**RELEASE_CERTIFIED**

Section 16's own acceptance bar is fully met: real capability wired (not fabricated), resolves honestly per-article, reaches every content path, renders safely (defanged, escaped), proven against real representative data across all 8 families with zero regressions. The round's own adversarial validation (mandate Section 29) found two real, adjacent defects — a pre-existing live-indicator leak in Section 23 and a publisher-citation false positive — both small, both directly relevant to the same underlying safety property this round's own feature depends on, both fixed inline rather than deferred, matching the precedent Phase 1M already established for exactly this situation.

## Rollback

Every change is additive or corrective, not architectural:
- `report_contract.py`/`analytical_depth_gate.py` changes are backward-compatible optional-parameter additions (`ioc_count: int = 0` preserves every existing caller's behavior exactly, the same pattern `forecast_count` already established).
- `authority_transformer.py`'s new functions are pure additions; the two new lines in `transform()` (compute + conditionally append) and the two parameter threads (`evaluate_product_tier()`, the result dict) are the only touches to existing control flow, and are no-ops when `_extract_article_iocs()` returns `[]`.
- `report_renderer.py`'s `_defang_text()` call inside `_source_lines()` is the only behavior change to existing code; reverting is a one-line removal that restores the pre-existing (leaky) quoting behavior with no other side effects. `_known_publisher_domains`'s relocation is a pure move (same name, same behavior, new file) — no caller-visible change.
- The canary script extension adds columns/assertions without removing or altering any pre-existing case or assertion.

## Next phase

Per the resume checkpoint's own remaining list and this round's explicit scoping (one section at a time, user-directed): **Section 20 (Time-bound Actions)** next — the audit already notes its content (P0/P1/P2-labeled bullets) already exists inside Sections 7/9's "Decisions" sub-blocks, making this likely a promote-to-its-own-section job similar to the four "computed but never rendered" fixes this mandate has now closed, rather than new capability from scratch. **Section 4 (Intelligence Requirements/Scope)** after that — the least-specified of the three remaining sections, needing real design work up front to define what genuine content looks like before implementation begins.
