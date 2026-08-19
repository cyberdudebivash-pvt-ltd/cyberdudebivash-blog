# REPORTX Phase 1 — Product-Tier Gate + Evidence-Graph Wiring
## Release Certification Record

**Date:** 2026-08-19
**Scope of this certification.** This is a continuation of the P0 REPORTX mandate, following Phase 0 (`PHASE-0-RELEASE-CERTIFICATION.md`) and the Phase 1 `related_intelligence[]` slice (`docs/audits/PHASE-1-RELEASE-CERTIFICATION.md`). Per the continuation directive's own instruction ("determine what is already implemented, partially implemented, dormant, disconnected, or genuinely missing" before building anything new), this session's investigation — recorded in full in `docs/audits/REPORTX-PHASE1-CAPABILITY-RECONCILIATION.md` — found that the single highest-leverage, most-repeatedly-named gap across three separate prior certification records was not a missing capability but a **disconnected** one: `report_contract.py` + `analytical_depth_gate.py` (the 24-section contract and FLASH/TACTICAL/PREMIUM_LONG_FORM tier gate) were built, tested, and certified in a prior round, then explicitly left "not wired into `authority_transformer.py`'s live `transform()` call" by that round's own deliberate scope decision. The CTI engine's real, claim-level `EvidenceGraph` (`Sentinel-APEX/engine/sentinel_engine/reportx/claim_model.py`, `discovery_bridge.py`) was in the same state: computed unconditionally for every article by `compose_report()`, then discarded before reaching `transform()`'s return value.

This certification covers **reconciling those disconnections**: wiring both into the live Pipeline A publish path as real, observable production data, plus a real defect (wrong-actor attribution) found and fixed during this work's own real-data verification. It does **not** cover Key Judgements, the contradiction engine, entity resolution beyond ransomware actors, family-specific engines for the remaining 5 report families, ATT&CK semantic validation, hunting hypotheses, certified-artifact-hash binding, the Blogger hard gate's remaining named conditions, or post-publication fetch-back — all tracked as open scope in the reconciliation matrix, not silently dropped.

---

## Changed components

- `automation/authority_transformer.py` — `_ComposerOutcome` extended with `evidence_graph`/`intelligence_gaps` fields; `_composer_enhance()` now captures both from `compose_report()`'s existing return value instead of discarding them; `transform()` now calls `analytical_depth_gate.evaluate_product_tier()` unconditionally and threads its verdict into `validate_publication()` and the returned dict (`product_tier`, `product_tier_reason`, `product_tier_mandatory_withheld`, `evidence_graph`, `intelligence_gaps`).
- `automation/report_integrity.py` — `validate_publication()` gains an optional `product_tier: str = ""` parameter and a hard gate: `product_tier == "FLASH"` blocks publication, mirroring the existing `achieved_tier == "PUBLIC_REFERENCE_DRAFT"` gate immediately above it.
- `Sentinel-APEX/engine/sentinel_engine/reportx/discovery_bridge.py` — fixed a real defect: ransomware actor-attribution (`build_claims()` and `build_threat_product()`) read `article.labels` (site taxonomy tags) instead of `article.ransomware_group` (the canonical, sanitized field every other consumer in this repository already uses). Added `_named_ransomware_actor()` with the same `"Unknown Group"` placeholder guard already established elsewhere.
- `tests/test_authority_transformer.py` — 5 new tests: FLASH-gate isolation test, empty-`product_tier`-is-not-a-failure backward-compatibility test, end-to-end `product_tier` wiring test, `evidence_graph`/`intelligence_gaps` wiring test (including a JSON-round-trip proof), and an adversarial end-to-end test forcing a FLASH verdict through the real `transform()` call.
- `Sentinel-APEX/engine/tests/reportx/test_discovery_bridge.py` — fixture (`_ransomware_article()`) corrected to carry a realistic `ransomware_group` alongside its taxonomy `labels` (matching real production article shape); 2 new regression tests proving the actor-attribution fix and its placeholder guard.
- `docs/audits/REPORTX-PHASE1-CAPABILITY-RECONCILIATION.md` (new) — the full capability matrix this work was scoped from.

## Requirements Traceability

| Directive requirement | Implementation | Verified |
|---|---|---|
| Section 6: "the principal defect to eliminate is capability exists but public report does not benefit from it" | `evaluate_product_tier()` and `EvidenceGraph`/claims now execute against and are returned for every real article `transform()` processes, not merely importable | Real-data run against 2 representative articles (§ below); 406/406 automation-side tests |
| Section 32 / mandate tiers (`HOLD`/`REFERENCE`/`TACTICAL_READY`/`PREMIUM_LONG_FORM`): "integrate with existing repository tiers rather than creating incompatible duplicates" | Reused `analytical_depth_gate.py`'s existing `FLASH`/`TACTICAL`/`PREMIUM_LONG_FORM` verdict unchanged; did **not** collapse it with the CTI engine's separate `achieved_tier` ladder (`PUBLIC_REFERENCE_DRAFT`/.../`PREMIUM_CERTIFIED`) — both are real, independently-computed signals kept under distinct field names, each gated independently, exactly as CLAUDE.md Principle 3 (Single Source of Truth) and mandate Section 11 ("do not collapse into one cosmetic score") require | `validate_publication()`'s new docstring states the reasoning explicitly; `report_integrity.py` diff |
| Section 16: "LLM/provider failure must not silently produce a premium public report" | The `FLASH` gate protects the floor today (mathematically a no-op against the current 2 reconciled families, proven both by hand-derivation and by the existing `REPORTX-24-SECTION-LONG-FORM-RELEASE-CERTIFICATION.md`'s own 9/9 real-data proof) and becomes load-bearing the moment a family-applicability matrix is extended, without a second wiring pass | `test_flash_product_tier_blocks_publication_end_to_end` |
| Section 7/18: claim-level status, ransomware claim-boundary discipline | Already correctly implemented by `discovery_bridge.py::build_claims()` before this session; this session made it *observable* for the first time | Real-data run: `c-victim-claim` status `REPORTED`, never `CONFIRMED` |
| Section 15: entity resolution must not let placeholder values become identity/correlation keys | `discovery_bridge.py` brought into line with `internal_linker.py`/`report_contract.py`'s existing `"Unknown Group"` guard | `test_unknown_group_placeholder_does_not_become_a_named_actor_attribution` |
| Section 45: "do not break existing production ... changes must be backward-compatible" | `validate_publication()`'s new parameter defaults to `""` (not gated); every existing 3-argument call site keeps working unmodified; `_ComposerOutcome`'s new fields default to `None`/`()` | `test_empty_product_tier_is_not_treated_as_a_failure` calls both the old 3-arg and new 4-arg form explicitly |

## Test Environment

Local execution, Python 3.11.15, `pytest 9.1.1`, isolated virtualenv (this sandbox has no system-wide `pytest`; installed via `pip install -r requirements.txt pytest pytest-timeout`, matching `.github/workflows/blogger-syndication.yml`'s own install step exactly).

## Tests Executed

- **Regression, `automation/` pipeline (`tests/ automation/tests/`):** baseline **401/401** (confirmed before any change), **406/406** after (5 new, 0 broken).
- **Regression, CTI engine (`Sentinel-APEX/engine/tests/`):** baseline **927/928** (1 pre-existing failure, confirmed present before any change this session — see Known Limitations), **929/930** after (2 new, 0 broken, same 1 pre-existing failure unchanged).
- **Unit/integration, new:**
  - `test_blocks_flash_product_tier` — isolated gate test, mirrors the existing `achieved_tier` gate test exactly.
  - `test_empty_product_tier_is_not_treated_as_a_failure` — backward compatibility, both call signatures.
  - `test_product_tier_verdict_is_wired_into_transform_output` — end-to-end, real (non-mocked) `transform()` call, asserts the actual `TACTICAL` verdict and its named withheld sections.
  - `test_evidence_graph_and_intelligence_gaps_are_wired_into_transform_output` — end-to-end, asserts real claim content (`c-cve-id` → `CONFIRMED`) and proves JSON round-trip.
  - `test_actor_attribution_uses_ransomware_group_not_the_site_taxonomy_label` / `test_unknown_group_placeholder_does_not_become_a_named_actor_attribution` — the defect regression pair (CTI engine side).
- **Real-data (not synthetic fixtures):** two representative articles run through the actual, unmocked `AuthorityTransformer.transform()` — one clean `cve_advisory` (CVSS 9.8, CWE-78, full vendor/product), one `ransomware_claim` (named actor, sector, country). Full results and a hand-derived cross-check against `report_contract.py`'s real applicability matrix are in `REPORTX-PHASE1-CAPABILITY-RECONCILIATION.md` §3.

## Adversarial Results

**Attempted: force a FLASH verdict through the real, unmocked pipeline and confirm it actually blocks.** `test_flash_product_tier_blocks_publication_end_to_end` patches only `evaluate_product_tier`'s return value (not `validate_publication`, not the gate itself) and confirms `transform()` raises `PublicationIntegrityError` naming the FLASH reason — proving the *live call path*, not merely the isolated gate function, enforces this.

**Attempted: break backward compatibility.** Called `validate_publication()` with its original 3-argument signature (no `product_tier` at all) after the change — confirmed unchanged behavior. All 401 pre-existing tests, none of which know about `product_tier`, continued to pass unmodified.

**Found via real-data testing (not a synthetic adversarial probe — a real defect the new observability surfaced):** the ransomware actor-attribution bug in `discovery_bridge.py`, detailed in the reconciliation matrix §4. This is the same class of defect the mandate's Section 43 names as an automatic release blocker (`fabricated attribution` / `false victim confirmation`-adjacent) — not maliciously fabricated, but structurally capable of naming the wrong entity. **Fixed before this certification, not shipped and flagged as a known issue.** Two regression tests added; full 26-test `test_discovery_bridge.py` file re-run clean, then the full 929-test CTI engine suite re-run clean.

**Checked, no defect found:** whether the new `evidence_graph`/`intelligence_gaps` dict fields are genuinely JSON-serializable end-to-end (not merely dict-shaped, which could still contain a raw `Enum`/`dataclass` instance that `json.dumps()` chokes on downstream, e.g. in `logs/run-*.json` writing). Both `Claim.to_dict()` and `EvidenceGraph.to_dict()` already convert every enum to its `.value` string; `test_evidence_graph_and_intelligence_gaps_are_wired_into_transform_output` calls `json.dumps()` on both fields directly as its final assertion.

## Security Validation

No new untrusted-input path. `evaluate_product_tier()` consumes only `DiscoveredArticle`/`ReportContext` fields already sanitized upstream by `report_integrity.py`/`content_discovery.py`. `EvidenceGraph`'s construction (`discovery_bridge.py`) was already running unconditionally before this session — this change only stops discarding its output; it introduces no new field extraction, parsing, or external call. The one file-I/O path this session's wiring newly exercises in some cases (`evaluate_product_tier`'s optional `state_file` corroboration lookup, via `find_independent_prior_source()`) reuses `internal_linker.py`'s existing, already-tested, read-only access to `data/published_posts.json` — no new I/O capability added.

## Performance

Both `evaluate_product_tier()` and `compose_report()`'s evidence-graph construction were **already executing unconditionally for every article** before this session (per `_composer_enhance()`'s own pre-existing docstring: "Runs ... unconditionally for every article"). This session adds zero new computation — it only stops discarding results that were already being computed. The only new cost is `EvidenceGraph.to_dict()`'s serialization (a handful of small dataclasses per article, O(claims) — typically 4-5) and marginally larger `transform()` return dicts. Not separately load-tested; the complexity class does not warrant it.

## Blogger Validation

**NOT_EXECUTED — BLOCKED BY scope, same as every prior round's own certification.** No live publish occurred this session. The `FLASH` gate's behavior was verified against the real `transform()`/`validate_publication()` call path (not merely unit-tested in isolation), which is the strongest verification available without triggering a production `workflow_dispatch` run — a decision this session did not make unilaterally, consistent with `PHASE-0-RELEASE-CERTIFICATION.md`'s own precedent of treating a live canary as a distinct, explicitly-flagged step.

## Open Defects

None found beyond the one described above, which was fixed prior to this certification.

## Residual Risk

- **LOW** — `product_tier`'s `FLASH` floor is, by construction, unreachable today for the 5 report families with no `report_contract.py` applicability matrix (`get_applicability()` defaults every section to `OPTIONAL`, so `mandatory` is always empty, so `evaluate_product_tier()` returns `TACTICAL` before ever reaching the withheld-count branch that could produce `FLASH`). This is the *correct*, conservative behavior (never falsely gates an unreconciled family) but means the new gate's real protection is currently scoped to `cve_advisory`/`cisa_kev`/`cisa_advisory`/`ransomware_claim` only.
- **LOW** — `evidence_graph`'s multi-source corroboration states (`MULTI_SOURCE_INDEPENDENT`/`MULTI_SOURCE_DEPENDENT`) are unit-tested but were not exercised by this session's own real-data run, which used articles with no matching prior post in the state file. The existing 7-test `TestIndependentSourceCorroboration` suite is the evidence for this path's correctness, not new real-data verification.
- **LOW** — `Claim.contradictions` now reaches production output but is always `[]` (nothing populates it — see reconciliation matrix §5). Not a regression (it was never populated before either), but worth naming so a future reader of `evidence_graph` output does not mistake an always-empty list for "no contradictions were found" rather than "contradiction detection was never run."

## Rollback Readiness

Every change is additive: new dataclass fields with safe defaults (`None`/`()`), one new optional function parameter defaulting to today's exact behavior (`""`, not gated), one new dict-key set on an already-growing return dict, one bug fix confined to two call sites in one file. `git revert` on this session's commit(s) cleanly restores prior behavior with no schema migration, no data deletion, and no other code depending on any of the new fields yet (nothing downstream of `transform()`'s return dict reads `product_tier`/`evidence_graph`/`intelligence_gaps` today — this session made them observable, not yet consumed by anything else in the pipeline).

## Certification Decision

```
RELEASE_CERTIFIED_WITH_LIMITATIONS
```

Certified for the scope stated above: `report_contract.py` + `analytical_depth_gate.py` now execute against and gate every real Pipeline A article; the CTI engine's real claim/evidence graph now reaches production output for the first time; one real, previously-invisible attribution defect was found and fixed in the process, with regression coverage. Named limitations: Blogger validation not executed, the FLASH floor's real protection is currently scoped to 2 of 7 families, and the multi-source corroboration path was not freshly real-data-verified this session. Not a certification of Phase 1's full scope — `docs/audits/REPORTX-PHASE1-CAPABILITY-RECONCILIATION.md` §5 names the next increment explicitly.

## Known Limitations Carried Over (not introduced this session)

- `Sentinel-APEX/engine/tests/test_certification.py::test_certify_real_end_to_end_with_the_actual_node_rendering_check` fails in this environment (`Sentinel-APEX/renderer/certify-rendering.js` — an environment/dependency gap, confirmed present via a full-suite run *before* this session made any change). Unrelated to this certification's scope; not investigated or fixed.

## Next Increment

Per `REPORTX-PHASE1-CAPABILITY-RECONCILIATION.md` §5: wire `contradiction_engine.py` into `discovery_bridge.py`/`pipeline_composer.py` so `Claim.contradictions` is genuinely populated — the identical "certified/implemented but dormant" pattern this session closed twice over, and the mandate's own next-named phase (1D).
