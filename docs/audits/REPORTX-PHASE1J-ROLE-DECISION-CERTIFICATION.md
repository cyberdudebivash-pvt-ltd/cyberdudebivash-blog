# REPORTX Phase 1J — Role Decision Quality: Certification

**Written:** 2026-08-20 (session recovery — a prior session's Phase 1J work was interrupted by a
usage-limit cutoff mid-implementation, before any commit; this round re-audited the architecture
from scratch and re-implemented it, verifying the prior session's own transcript claims against
real code rather than trusting them).

---

## 1. Starting-state verification

- `origin/main` and this branch (`claude/production-session-recovery-036t5a`) were confirmed
  identical (`git merge-base HEAD origin/main == HEAD`) after `git fetch origin main` — the branch
  contains PR #108–#118, all merged, nothing beyond.
- Working tree was clean (`git status`, `git diff`, `git diff --cached`, `git ls-files --others`
  all empty) — the interrupted session's Phase 1J edits were never committed and did not survive
  in this fresh container. `docs/audits/REPORTX-PHASE1-RESUME-CHECKPOINT.md` (written by the
  session that merged #117/#118, immediately before Phase 1J began) independently confirms this:
  its own §3 table lists "Phase 1J onward | Not started."
- `automation/analytical_depth_gate.py` was read directly: `evaluate_product_tier()` had
  `key_judgement_count`, `hunt_hypothesis_count`, `attack_mapping_count` but no
  `role_decision_count` parameter at all — confirming the prior session's transcript claim (it
  stopped mid-read of this exact file, before making any edit to it).
- Baseline reproduced fresh, not inherited: root 486 passed, engine 1026 passed + 1 pre-existing
  unrelated failure (`test_certify_real_end_to_end_with_the_actual_node_rendering_check`, a
  Node-rendering environment issue), JS 123 passed — matching the checkpoint doc exactly.

## 2. Existing architecture reused, not duplicated

No new role system was built. Reused unchanged:
- `RoleAudience` (11-value enum), `pipeline_composer._lean_role_decisions()` (the 7 real,
  family-conditioned decision branches from RX-P1H), `executive_products.RoleDecision`/
  `render_role_decisions()`/`ROLE_DISPLAY_LABELS`.
- The exact wiring pattern already established for `hunt_hypotheses`/`attack_mappings`:
  `ComposedReport` field → `_ComposerOutcome` field → `_composer_enhance()` → duplication-guarded
  render call in `transform()` → count passed to `evaluate_product_tier()`.
- `report_integrity._UNSUPPORTED_COMMERCIAL_PATTERNS`/`_PLACEHOLDER_PATTERNS` in
  `validate_publication()` — these already scan the *full* rendered HTML, so once role-decision
  content is wired into that HTML (§3.3 below), promotional/placeholder language in it is caught
  by the existing gate for free, with zero new regex code.

## 3. Two real production defects found and fixed (mandate's own resume point)

### 3.1 Section 19 could resolve `COMPLETE` with zero role decisions

`report_contract.py`'s `SECTION_19_ROLE_DECISION_MATRIX` sat in `_IMPLEMENTED_TODAY`, dispatched to
`_resolve_implemented_section()`, which has no special case for it and falls through to an
unconditional `return SectionState.COMPLETE`. Every caller, for every family, always saw Section 19
as `COMPLETE` — regardless of whether any role decision existed. This is the exact defect named in
the mandate's resume point.

**Fix:** a new `_resolve_role_decisions()` resolver, dispatched *before* the `_IMPLEMENTED_TODAY`
check (mirroring Sections 3/14's own pattern), gated on a new `role_decision_count` parameter.

**Why `Optional[int] = None`, not `int = 0` like the other three counts:** Sections 3/14/11 were
*already always `WITHHELD`* for every caller before their count parameters existed — so a bare
`int = 0` default correctly preserved old behavior (0 → WITHHELD, unchanged). Section 19 is the
opposite case: it was *already always `COMPLETE`* for every caller. A bare `int = 0` default would
therefore have **silently flipped every unmigrated caller's Section 19 from COMPLETE to WITHHELD**
the moment the parameter was added — including existing tests
(`test_breach_notice_with_llm_content_and_all_mandatory_sections_resolved_reaches_premium`, which
asserts `PREMIUM_LONG_FORM` and passes no role-decision signal at all) and any other caller not yet
updated to measure a real count. Verified empirically: running the full existing suite with a
plain-`int=0` draft of this change reproduced exactly that regression before the sentinel fix was
applied. `Optional[int] = None` distinguishes the three real states cleanly: `None` = "this caller
hasn't been migrated, preserve the prior unconditional COMPLETE" (a deliberate, documented
backward-compatibility carve-out, not an oversight); `0` = "a migrated caller genuinely measured
zero role decisions for this article" (honestly `WITHHELD`); positive = real, gate-passed decisions
exist (`COMPLETE`). This mirrors the `Optional[bool] = None` idiom already used elsewhere in this
exact codebase for the identical "not measured" vs. "measured false" ambiguity
(`content_discovery.DiscoveredArticle.kev_listed`, `authority_transformer._ComposerOutcome.
quality_score_eligible`).

The one production caller that matters (`authority_transformer.transform()`, via
`evaluate_product_tier()`) always passes a real `int` (`len(composer_outcome.role_decisions)`),
never `None` — so on the live pipeline, Section 19 is now honestly `WITHHELD_INSUFFICIENT_EVIDENCE`
whenever a family/article genuinely has zero role decisions, for the first time.

### 3.2 `role_decisions` was computed and counted, but never reached the published HTML on the LLM-authored path

The identical bug class already found and fixed for `hunt_hypotheses` (RX-P1I) and independently
for `attack_mappings` (RX-P1I) had recurred a third time, undetected until this round:
`pipeline_composer._lean_role_decisions()` built real `RoleDecision` objects and used them to
render `role_html` *inside the composer's own HTML*, but that object list was never exposed on
`ComposedReport`, never counted, and never reached `authority_transformer.py`'s `_ComposerOutcome`,
its LLM-authored-path duplication-guarded rendering, or its output dict — despite
`report_contract.py`'s Section 19 sitting in every reconciled family's `MANDATORY` set since RX-P1H.
A report could show Section 19 as `COMPLETE` while the actually-published page (when the LLM path,
not the composer path, authored the narrative) had zero role-decision content at all.

**Fix:** the exact same wiring pattern used for `hunt_hypotheses`/`attack_mappings`, applied a third
time: `ComposedReport.role_decisions` (new field) → `_ComposerOutcome.role_decisions` (new field,
computed in `_composer_enhance()`) → `_render_role_decisions_html()` (new function, mirrors
`_render_hunt_hypotheses_html()`/`_render_attack_mappings_html()` exactly) called in `transform()`
under the identical `content_source != "reportx_composer"` duplication guard → real
`role_decision_count=len(composer_outcome.role_decisions)` passed to `evaluate_product_tier()` →
`"role_decisions"` added to the published output dict.

## 4. Role Decision data contract reconciled (mandate §3/§5)

`RoleDecision` extended additively (all new fields default to `""`/`()`, zero existing call sites
changed): `action`, `priority`, `claim_refs`, `time_horizon`, `deadline_or_trigger`,
`escalation_condition`, `conditions_that_change_decision`, `limitations`. `to_dict()` and
`render_role_decisions()` updated to surface every field, only when populated (no blank
placeholder lines).

**What is populated today, and why:** all 7 production decisions now carry a real, non-fabricated
`limitations` statement (an honest scope caveat already implied by each decision's existing
rationale — e.g. "single third-party source, does not confirm any specific organization was
compromised"). Exactly one (`ransomware_claim`/`IR_MANAGER`) carries a real `escalation_condition`
("Independent corroboration of the victim claim is found."), because that decision's existing
rationale *already states this exact condition in prose* ("absent independent corroboration") —
structured, not invented. `priority`, `action`, `time_horizon`, `deadline_or_trigger`, and
`conditions_that_change_decision` remain unpopulated for all 7 decisions this round: this pipeline
has no real severity/urgency taxonomy or per-decision deadline evidence source today, and inventing
plausible-sounding values for them would violate the mandate's own "no invented deadlines, no
generic filler" constraint directly. The schema supports them and the hard-fail gate (§5) actively
rejects a fabricated value if one is ever introduced; populating them for real is named,
deliberately deferred work (see §8). `reportx-canary/flagship_cve_2025_62593_ray_executive_product.py`
(a separate, hand-authored Phase-4 canary, unaffected by this change) already demonstrates a
genuinely evidence-backed `timeline` value tied to a real CISA BOD due date — a template for what a
real `deadline_or_trigger` source would need to look like if this pipeline ever ingests KEV due
dates structurally.

## 5. Hard-fail semantic gate (mandate §7/§11)

`pipeline_composer._validate_role_decisions()` — mirrors `attack_mapping._apply_semantic_gate()`'s
"drop, never downgrade" discipline, applied at the end of `_lean_role_decisions()`. Rejects:

| Check | Guards against |
|---|---|
| `role` is a real `RoleAudience` | malformed role names |
| non-empty, non-whitespace `decision` | empty decisions |
| `decision` not an exact match of a known bare-generic phrase ("monitor this threat", "track against intake") | regression of the exact defect already fixed once (COMMERCIAL-QUALITY-2026-08-18) |
| non-empty `evidence_claim_ids` | role advice with no evidence basis |
| `(role, decision)` not already seen in this report | duplicate roles/actions |
| `deadline_or_trigger` doesn't match a numeric hour/day/week pattern | unsupported deadlines — this pipeline has no jurisdiction/regulation evidence model in the role-decision path (`regulatory.py`'s real Section-14 engine is separate and unwired here), so any specific numeric deadline reaching a RoleDecision today can only be fabricated |
| decision/rationale/escalation text doesn't match a regulatory-obligation pattern (`must notify`, `legally required`, `GDPR`, `NIS2`, `DORA`, `HIPAA`, etc.) | unsupported legal/regulatory assertions |

Promotional/CTA language is caught downstream for free once rendered (§2 — `validate_publication()`
already scans full HTML), not re-implemented here.

## 6. Adversarial tests (mandate §11)

All added to `Sentinel-APEX/engine/tests/reportx/test_pipeline_composer.py::TestRXP1JRoleDecisionSemanticGate`
and `test_executive_products.py`, run directly against `_validate_role_decisions()`, not just
end-to-end: zero role decisions capping Section 19 at `WITHHELD` (proven at 3 levels — the resolver
directly, the tier-gate, and the real end-to-end pipeline via the real-data script), a malformed
role, an empty decision, a decision with no evidence basis, the exact bare-generic regression
string, a duplicated `(role, decision)` pair, an unsupported numeric deadline, an unsupported
regulatory claim, and — the negative-control case that proves the regulatory-pattern check isn't
over-broad — the real, production `breach_notice`/`LEGAL_COMPLIANCE_PRIVACY` decision (which
deliberately *defers* a regulatory determination rather than asserting one) confirmed to pass
unchanged.

## 7. Real-data results (mandate §12/§18)

`reportx-canary/phase1j_role_decision_representative_fixtures.py` (new, run directly, reproducible)
exercises the real, unmocked `AuthorityTransformer(Config()).transform()` call for all 7 named
families plus `general_intelligence`:

| Case | Family | #Decisions | Roles | Section 19 | Tier | In rendered HTML |
|---|---|---|---|---|---|---|
| CVE (web-exposed RCE) | cve_advisory | 2 | SOC_MANAGER, VULNERABILITY_MANAGER | COMPLETE | TACTICAL | True |
| KEV (confirmed exploited) | cisa_kev | 2 | SOC_MANAGER, VULNERABILITY_MANAGER | COMPLETE | TACTICAL | True |
| Ransomware claim | ransomware_claim | 1 | IR_MANAGER | COMPLETE | TACTICAL | True |
| Ransomware reporting (news) | ransomware_reporting | 1 | SOC_MANAGER | COMPLETE | TACTICAL | True |
| Threat actor | threat_actor | 1 | THREAT_HUNTER | COMPLETE | TACTICAL | True |
| AI security | ai_security | 1 | CISO_CIO | COMPLETE | TACTICAL | True |
| Breach notice | breach_notice | 1 | LEGAL_COMPLIANCE_PRIVACY | COMPLETE | TACTICAL | True |
| General intelligence (no signal) | general_intelligence | 0 | -- | WITHHELD_INSUFFICIENT_EVIDENCE | TACTICAL | False |

Every row's tier is `TACTICAL`, not `PREMIUM_LONG_FORM` — expected and correct: these fixtures use
`content_source="reportx_composer"` (no live LLM provider configured in this environment), and
`evaluate_product_tier()` requires LLM-authored content for Key Judgements regardless of Section 19.
The script asserts programmatically, not just prints: rendered-HTML presence of "Role-Based
Decisions" agrees with the structured decision count for every case (never a heading with nothing
under it, never real content silently dropped), and every decision that exists carries a real
evidence basis. Manual inspection of each case's role/decision text (also exercised by
`test_authority_transformer.py`'s end-to-end tests) confirms the guidance is genuinely
family-specific and non-generic — no case produced "monitor this threat" or an irrelevant
Vulnerability Manager routing.

`reportx-canary/flagship_cve_2025_62593_ray_executive_product.py`'s 7 hand-authored `RoleDecision`
constructions (a separate, real-CVE canary from an earlier phase) were checked statically: every
construction uses keyword arguments only, against fields that all still exist unchanged — confirms
this consumer is unaffected by the additive schema change without needing to execute its separate,
unrelated `ReportBundle` construction path.

## 8. What this round deliberately does not do

- Does not invent new `RoleAudience` values (e.g. a distinct "Detection Engineering" or
  "Asset/Application Owner" role the mandate's own suggested table names) — this codebase's
  established, explicit discipline (RX-P1H's own comment: "no new role invented") is to reuse the
  existing 11 roles; adding new ones is a real, separate decision requiring its own evidence review,
  not a byproduct of this round.
- Does not populate `priority`/`action`/`time_horizon`/`deadline_or_trigger`/
  `conditions_that_change_decision` for any of the 7 production decisions (§4) — the schema and
  hard-fail gate are ready; real population needs a real evidence source this pipeline doesn't have
  yet (e.g. structured KEV due dates for a real `deadline_or_trigger`).
- Does not wire `regulatory.py`'s real Section-14 applicability engine into role decisions — a
  separate, substantially larger capability (jurisdiction/geography evidence mapping) out of this
  round's scope; the hard-fail gate instead denies any regulatory assertion outright, which is the
  correct behavior until that capability exists for real.
- Does not touch Phase 1K/1M/1N/1P/1Q — each requires its own audit-first round per the governing
  checkpoint discipline this session continued rather than overrode.

## 9. Test evidence

| Suite | Before | After | Delta |
|---|---|---|---|
| Root (`tests/`) | 486 passed | 497 passed | +11, 0 regressions |
| Engine (`Sentinel-APEX/engine/tests/`) | 1026 passed + 1 known unrelated failure | 1045 passed + the same 1 known unrelated failure | +19, 0 regressions |
| JS (`tests-js/`) | 123 passed | 123 passed | unchanged (no JS touched) |

The one engine failure (`test_certify_real_end_to_end_with_the_actual_node_rendering_check`) was
reconfirmed present and identical before any Phase 1J code was written, and remains the only
failure after — a Node-rendering environment issue, unrelated to role decisions.

New tests added: `tests/test_report_contract.py::TestSectionNineteenRoleDecisions` (4 — the
`None`/`0`/positive sentinel semantics), `tests/test_analytical_depth_gate.py::
TestRoleDecisionCountGatesSectionNineteen` (3 — the tier-gate end-to-end proof, including the
mandate's own named hard-fail), `tests/test_authority_transformer.py::
TestRoleDecisionsWiredIntoTransform` (4 — the real, unmocked, LLM-path duplication-guard proof),
`Sentinel-APEX/engine/tests/reportx/test_pipeline_composer.py::TestRXP1JRoleDecisionWiring` (6) and
`::TestRXP1JRoleDecisionSemanticGate` (9 — the adversarial gate coverage), `Sentinel-APEX/engine/
tests/reportx/test_executive_products.py::TestRoleDecisions` (+4 — schema/rendering coverage).

## 10. Certification verdict

**`RELEASE_CERTIFIED`**

- Both defects named in the mandate's exact resume point (Section 19 unconditional `COMPLETE`;
  `role_decisions` never reaching `authority_transformer.py`) are fixed, with a documented,
  deliberate backward-compatibility mechanism (the `Optional[int]` sentinel) rather than a silent
  behavior change.
- Zero regressions across root/engine/JS suites (exact counts above).
- Real, evidence-grounded regression and adversarial tests exist for every hard-fail condition the
  mandate names for role decisions specifically.
- Real-data (representative-fixture, real-code-path) validation across all 7 production families
  plus the deliberately-unmapped `general_intelligence` case, with both structural and rendered-HTML
  proof, not unit tests alone.
- What remains deliberately unpopulated or unbuilt is named explicitly (§8), not silently omitted.

This is **not** a claim that Phase 1 is complete. Phase 1K (full 24-section population), 1M
(semantic/factual QA), 1N (premium certification ladder), 1P (Blogger hard gate), and 1Q
(post-publication fetch-back) remain, each requiring its own audit-first round.
