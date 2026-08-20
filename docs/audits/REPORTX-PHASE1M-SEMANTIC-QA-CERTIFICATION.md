# REPORTX Phase 1M — Semantic / Factual QA: Certification

**Written:** 2026-08-20, same session as the Phase 1J/1K recovery rounds, continued after context
compaction (this document covers the full phase, including work completed before and after that
compaction point).

---

## 1. Starting-state verification

- Phase 1K's commit (`b307ba6a8`) confirmed present on this branch, not yet merged to `origin/main`
  as of the Phase 1M audit (`docs/audits/REPORTX-PHASE1M-SEMANTIC-QA-AUDIT.md` §0) — this round
  continues directly on `claude/production-session-recovery-036t5a`, no branch restart needed.
- Baseline reproduced fresh before any Phase 1M edit: root 515 passed, engine 1056 passed + 1
  pre-existing unrelated failure (`test_certify_real_end_to_end_with_the_actual_node_rendering_check`,
  a Node-rendering environment issue), matching Phase 1K's own certified numbers exactly.
- Architecture audit written first, before any implementation: `docs/audits/REPORTX-PHASE1M-SEMANTIC-QA-AUDIT.md`.
  Read `claim_model.py`, `contradiction_engine.py`, `claim_support_matrix.py`, `key_judgements.py`,
  and `report_integrity.py` in full before writing any code this phase.

## 2. What the audit found (summary — full detail in the audit doc)

Three real defects, none fabricated-signal:

1. **Contradiction detection never saw the actually-published page.** `pipeline_composer.compose_report()`
   ran the text-pattern contradiction layer against its own internally-assembled HTML; on the
   LLM-authored and legacy-template content paths, that HTML is never what gets published — the
   real published page (LLM prose or template output, plus appended sections) was never scanned by
   either contradiction layer at all.
2. **Two separate, drifted pattern lists for "confirmed exploitation" language.** `report_integrity.py`'s
   own source-classification patterns (`_CONFIRMED_EXPLOITATION_PATTERNS`) matched paraphrases
   (`"exploitation has been observed"`) that the separate, hand-typed 4-phrase render-side gate did
   not — a classic two-implementations-of-one-concept drift risk.
3. **No general mechanism for the "2,400+" defect class**, only the 4 specific strings already
   observed as hallucinated in the real run #8459 incident
   (`docs/audits/blogger-syndication-run-8459-incident-review-2026-08-20.md`) — no capability to
   catch the *next* invented number.

## 3. Implementation

### 3.1 Unified exploitation-assertion consistency (`automation/report_integrity.py`)

The existing 4-phrase exact-literal `forbidden` list inside `validate_publication()` is kept,
unchanged, as a permanent regression guard. Additively, the same 5 general
`_CONFIRMED_EXPLOITATION_PATTERNS` regexes the module already uses to classify the *source* article
are now also evaluated against rendered output when `context.exploitation_status != "confirmed"`.

**False positive found and fixed while building this:** the legacy template's own honest, hedged
text — *"No confirmed exploitation evidence is available at time of publication"* — matched
`\bconfirmed exploitation\b` even though it explicitly denies the claim. Fixed with a
negation-lookback guard (`_NEGATION_LOOKBACK_RE` / `_is_negated_immediately_before()`): a match is
ignored if a negation word (no/not/never/without/unconfirmed/isn't/hasn't/haven't/doesn't/didn't)
appears within 60 characters immediately before it, in the same sentence.

### 3.2 Contradiction-check reach (`automation/authority_transformer.py`)

`transform()` now re-runs `find_text_contradictions()` against the real, final assembled `html`
(after `_assemble_html()`, not the composer's internal draft), combines the result with
`composer_outcome.contradictions` (the dimension-level findings, unaffected by which prose won),
and passes the combined set into `validate_publication()`. The output dict's `"contradictions"` key
was updated to reflect the same combined set actually gated.

### 3.3 Ransomware-claim confirmed-breach gate (`automation/report_integrity.py`)

New family-scoped hard gate: for `context.family == "ransomware_claim"`, 4 new patterns
(`_RANSOMWARE_CLAIM_CONFIRMED_BREACH_PATTERNS`) block a *definite, unhedged* assertion of confirmed
breach/compromise/data-theft for what this pipeline's evidence model treats as an unverified,
third-party leak-site claim. Reuses the same negation-lookback guard from §3.1.

**False positive found and fixed while building this:** the universal Executive Summary "Decision:"
boilerplate line (*"...before treating this record as an incident, confirmed compromise, or
customer-specific finding"*) is cautionary, nominal framing, not an assertion — the negation-lookback
guard (via "before") together with the exact pattern shapes chosen (requiring a declarative
"confirms"/"is confirmed" construction, not a bare occurrence of "confirmed compromise") avoids this
false-positiving; verified directly with a dedicated regression test
(`test_universal_decision_boilerplate_is_never_a_false_positive`).

### 3.4 General quantitative-claim grounding gate (`automation/report_integrity.py`, `automation/authority_transformer.py`)

Generalizes the run #8459 fix: `_QUANTITATIVE_CLAIM_RE` matches a number in a high-impact
quantitative context (victims/organizations/customers/records/accounts/servers/etc.);
`_check_quantitative_claims_are_grounded()` rejects any such number that does not appear anywhere in
the source article's own text (`_source_text()` — title + summary + full_content), comma-normalized
so a genuinely source-grounded number is never flagged merely because it was reformatted at render
time (`"2400"` in the source vs. `"2,400"` rendered).

**Real false positive found via real-data validation, root-caused, and fixed — not patched around:**
scanning the full assembled `html` (as first wired) flagged real numbers belonging to *other*
articles — `internal_linker.py`'s "Related Intelligence Reports" widget legitimately embeds other
real published articles' headlines (e.g. `"144,520 Accounts"`, `"688,000 Customer Records"`),
appended to the page *outside* the current report's own narrative. Confirmed failing via
`reportx-canary/phase1j_role_decision_representative_fixtures.py` and
`phase1k_section_completeness_representative_fixtures.py`, root-caused to
`internal_linker.py:255-286`'s correlation-block renderer specifically. Fixed by adding a new
`body_content: str = ""` parameter to `validate_publication()` — mirroring the exact safe-default
pattern this same function already uses for `product_tier`/`contradictions` — scoping the
quantitative-claim check to the report's own analytical narrative (`authority_transformer.py`'s
`body_content`, before `_assemble_html()` appends the internal-linking widget, monetization CTAs,
and other page chrome). Default `""` skips the check entirely, so any caller that hasn't computed a
`body_content` keeps its exact current behavior; the one real call site
(`authority_transformer.transform()`) now passes `body_content=body_content` explicitly. Confirmed
`authority_transformer.py` is the *only* real call site of `validate_publication()` in the repo
before making this change (grep-verified; all other matches are comments/docstrings).

### 3.5 Explicit `verification_status` vocabulary on `KeyJudgement` (`automation/key_judgements.py`, `automation/authority_transformer.py`)

Per the audit's own scoping (§3 item 6, §4): a labeling/observability change over already-correct
logic, not a new gate. `KeyJudgement` gained a `verification_status: str` field
(`VERIFICATION_STATUSES = ("SUPPORTED", "ASSESSED_WITH_BASIS", "UNSUPPORTED", "CONTRADICTED")`):

- **SUPPORTED** / **ASSESSED_WITH_BASIS** — computed in `validate_key_judgements()` from the exact
  same `claim_refs` truthiness the pre-existing `UNSUPPORTED_HIGH_IMPACT_CLAIM` rejection gate
  already evaluates; the only two outcomes reachable on an *accepted* `KeyJudgement`.
- **UNSUPPORTED** — exposed via a new `_rejection_verification_status()` helper mapping specific
  rejection reasons (`UNSUPPORTED_HIGH_IMPACT_CLAIM`, `UNKNOWN_{CLAIM,EVIDENCE,SOURCE}_REFERENCE`)
  to the label, wired into `generate_key_judgements()`'s structured logging
  (`verification_statuses` alongside the existing `rejections` list) for observability. Structural/
  format rejections (malformed JSON, missing judgement text, an invalid confidence value) are left
  unclassified (`None`) rather than forced into an epistemic-verdict bucket they were never
  evaluated against.
- **CONTRADICTED** — named for the mandate's own vocabulary completeness, documented explicitly as
  reserved with **no current code path**: nothing in this module cross-references a candidate's
  `claim_refs` against `contradiction_engine.py`'s findings today, and building that check is
  materially new verification logic, explicitly out of this round's scope per the audit's own §4.
  Not faked via a shortcut.

Also rendered (`_render_key_judgements_html()` in `authority_transformer.py`): a `[SUPPORTED]` /
`[ASSESSED_WITH_BASIS]` badge next to each judgement's existing `[CONFIDENCE]` badge, on the
actually-published page — proven with a dedicated end-to-end test
(`test_verification_status_reaches_both_the_output_dict_and_the_rendered_page`), following this
session's own established discipline against the "computed but never rendered" defect class found
four separate times across Phases 1I/1J/1K.

## 4. What this phase did not attempt (named explicitly, per the audit's own §4)

- Wiring `evaluate_claim_support_gate()` into the live pipeline — real, but low marginal value today
  (every claim the live pipeline constructs already carries evidence by construction).
- Full actor/campaign-attribution named-entity verification and a general "customer exposure"/
  "production compromise" assertion detector — deferred; Phase 1K's own false-positive experience
  this session is the direct cautionary precedent against rushing a naive whole-page regex pass here.
- A fully general LLM-prose-to-claim-graph entailment checker (arbitrary sentences, not just
  pattern-matched high-impact phrases) — materially larger scope than one round can build and
  adversarially prove correct with real evidence.
- `CONTRADICTED` on `KeyJudgement` — reserved vocabulary, no code path (§3.5 above).

## 5. Adversarial and regression test evidence

| Gate | Test class | File | Tests |
|---|---|---|---|
| Exploitation-assertion consistency | `TestExploitationAssertionConsistency` | `tests/test_report_integrity.py` | 4 |
| Ransomware-claim confirmed-breach gate | `TestRansomwareClaimConfirmedBreachGate` | `tests/test_report_integrity.py` | 5 |
| Quantitative-claim grounding gate | `TestQuantitativeClaimGroundingGate` | `tests/test_report_integrity.py` | 5 |
| Contradiction reaches the published page | `TestContradictionCheckReachesTheFinalPublishedPage` | `tests/test_authority_transformer.py` | 2 |
| `verification_status` vocabulary | `TestVerificationStatusVocabulary` | `tests/test_key_judgements.py` | 8 |
| `verification_status` reaches the rendered page | (added to `TestKeyJudgementsWiredIntoTransform`) | `tests/test_authority_transformer.py` | 1 |

Every false positive named in §3 (honest negated non-assertion, universal Decision boilerplate,
internal-linker widget numbers) has a dedicated regression test proving it is never blocked, next to
a sibling test proving the real defect it could be confused with *is* still blocked — the same
"found empirically, fixed, then locked in with a regression test" discipline used throughout Phases
1I/1J/1K.

## 6. Real-data validation

All 3 synthetic-fixture canary scripts (Phase 1I ATT&CK, Phase 1J role-decision, Phase 1K
section-completeness) re-run against the real, unmocked `AuthorityTransformer(Config()).transform()`
path — all pass, including after the Task 18 false positive was found and fixed (both
`phase1j_role_decision_representative_fixtures.py` and
`phase1k_section_completeness_representative_fixtures.py` failed with a real `PublicationIntegrityError`
before the `body_content`-scoping fix, and pass cleanly after it).

Additionally, all 5 real-article canary scripts (genuine historical incidents, not synthetic
fixtures) re-run this round with zero regressions: `cve_2025_62593_ray_canary.py`,
`dragonforce_vermont_xcenter_canary.py`, `medusalocker_bija_industrie_canary.py`,
`qilin_spoonful_of_comfort_canary.py`, and `flagship_cve_2025_62593_ray_executive_product.py` — all
exit 0, no new integrity rejections introduced by any Phase 1M gate against real source data.

## 7. Test evidence

| Suite | Before this phase | After this phase | Delta |
|---|---|---|---|
| Root (`tests/`) | 515 passed | 541 passed | +26, 0 regressions |
| Engine (`Sentinel-APEX/engine/tests/`) | 1056 passed + 1 known unrelated failure | 1056 passed + the same 1 known unrelated failure | unchanged — no engine files touched this phase (confirmed via `git diff --stat`) |

The one engine failure (`test_certify_real_end_to_end_with_the_actual_node_rendering_check`) was
reconfirmed present, identical, both before and after this phase's changes — a Node-rendering
environment issue, unrelated to anything Phase 1M touched.

## 8. Reuse Report

| Metric | Result |
|---|---|
| Existing components reused (extended, not replaced) | `_CONFIRMED_EXPLOITATION_PATTERNS`, `validate_publication()`'s existing `forbidden`-list mechanism, `find_text_contradictions()`, the `product_tier`/`contradictions` safe-default parameter pattern, `_source_text()`, `KeyJudgement`'s existing `claim_refs` signal |
| Existing API routes extended (not duplicated) | N/A — no API routes in scope this phase |
| Existing pages/functions extended (not replaced) | `validate_publication()`, `_render_key_judgements_html()`, `validate_key_judgements()`, `generate_key_judgements()`, `transform()` |
| New components introduced (justified by gap analysis) | `_NEGATION_LOOKBACK_RE`/`_is_negated_immediately_before()`, `_RANSOMWARE_CLAIM_CONFIRMED_BREACH_PATTERNS`, `_QUANTITATIVE_CLAIM_RE`/`_grounded_numbers()`/`_check_quantitative_claims_are_grounded()`, `VERIFICATION_STATUSES`/`_rejection_verification_status()` — each maps 1:1 to a named audit finding |
| Duplicate components introduced | **0** |
| Duplicate routes introduced | **0** |
| Backward compatibility preserved | **PASS** — every new parameter (`body_content`, `verification_status`) is additive with a safe default; every existing caller/test kept its exact prior behavior (proven: full pre-existing test suites pass unmodified) |
| Build passing with zero errors | **PASS** — `py_compile` clean on every touched file; full root + engine suites green except the one pre-existing, unrelated, already-documented failure |

## 9. Certification verdict

**`RELEASE_CERTIFIED`**

- All 3 real defects named in the Phase 1M audit are fixed: contradiction-check reach, the
  exploitation-assertion pattern-list drift, and the lack of a general quantitative-claim grounding
  mechanism (the run #8459 defect class generalized, not just re-patched).
- One new hard gate added (ransomware-claim confirmed-breach), matching the mandate's own named
  cross-section example.
- The mandate's own 4-state verification vocabulary is now explicit on `KeyJudgement`, wired into
  both the structured output and the actually-rendered page — with `CONTRADICTED` honestly documented
  as reserved-but-unreachable rather than faked.
- Three real false positives were found empirically during real-data validation (not merely
  theorized), root-caused precisely, fixed, and locked in with dedicated regression tests — never
  silently patched around or dismissed.
- Zero regressions: root suite +26 tests / 0 failures, engine suite byte-for-byte unchanged (no
  engine files touched), all 3 synthetic real-data scripts and all 5 genuine-article canary scripts
  pass cleanly.
- Nothing was weakened to make this pass: the original 4-phrase exploitation-assertion list, the
  4-item `_UNSUPPORTED_COMMERCIAL_PATTERNS` denylist, and every existing gate/section state remain
  intact and additively extended, never loosened or removed.

This is not a claim that semantic/factual QA is now complete or exhaustive — the audit's own §4
names what remains deliberately unbuilt. Phase 1N (premium certification ladder audit), 1P (Blogger
hard gate), and 1Q (post-publication fetch-back) remain, each requiring its own audit-first round;
1P and 1Q additionally require live-publish authorization from the owner before any real Blogger
publish is attempted.
