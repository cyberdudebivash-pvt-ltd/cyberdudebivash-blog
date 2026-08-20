# REPORTX Phase 1I Remainder — Structured ATT&CK Object: Certification

**Date:** 2026-08-20
**Scope:** Mandate Sections 2-5 of the "Phase 1I Remainder → 1J → 1K → 1M → 1N → 1P → 1Q" continuation -- the structured ATT&CK object, its end-to-end survival to the rendered report, multi-tactic/sub-technique semantics, and the semantic quality gate. Phases 1J onward are explicitly NOT attempted this round -- see §7.

---

## 1. Starting-state verification

Per the mandate's own Section 0 instruction, every claim was checked against real `origin/main` before implementation began, not trusted from the prompt:

| Claim | Verified |
|---|---|
| PR #116 merged | **Confirmed** -- `git log origin/main` shows `88f331d1b` as the merge commit |
| Rendered ATT&CK output is still prose, not a structured object | **Confirmed** -- `report_renderer.DetectionPackage.attack_mappings: tuple[str, ...]`, hardcoded per-vulnerability-class prose sentences, unchanged since before PR #116 |
| A structured object already exists somewhere | **False** -- repo-wide grep for `class AttackMapping`/`attack_mapping_id`/`structured_attack` returned nothing before this round |
| T1053/T1053.005 multi-tactic gap is closed | **False.** A CodeRabbit finding on PR #116 flagged this exact gap; the prior round's fix addressed only the sibling finding (T1219's stale label), not the tactic-plurality issue -- confirmed by reading the live `KNOWN_TECHNIQUES["T1053"]` entry, still a single tactic (`"persistence"`) |

## 2. Existing architecture reused, not duplicated

- `attack_mapper.map_techniques()` -- the negation-aware, evidence-anchored text-to-technique mapper (sentence-boundary-scoped negation detection, explicit-citation handling) -- **unchanged**, called as-is.
- `attack_mapper.KNOWN_TECHNIQUES` -- the curated technique registry -- **unchanged** in shape; only new entries and one small, additive lookup added (§4).
- The per-article `EvidenceGraph` REPORTX already builds -- `claim_refs`/`evidence_refs`/`source_refs` point at real, existing graph entries (`c-summary`, `c-cve-id`, `c-exploitation-status`, `e-{claim_id}`, `src-primary`), never fabricated ones.
- `pipeline_composer.compose_report()`'s established "compute unconditionally, append a new rendered section, expose as a new `ComposedReport` field" pattern -- identical to how `canonical_entities` (Phase 1G) and `hunt_hypotheses` (Phase 1I's first round) were wired.
- `authority_transformer._ComposerOutcome`/`_composer_enhance()`'s established "compute once regardless of content path, guard against double-rendering on the composer path" pattern -- identical to the exact fix CodeRabbit's review required for `hunt_hypotheses` on PR #116.

No second mapping engine, no second detection-status vocabulary, no second family registry was created.

## 3. What was built

### 3.1 The structured object (`Sentinel-APEX/engine/sentinel_engine/reportx/attack_mapping.py`, new)

`AttackMapping`: `attack_mapping_id, technique_id, technique_name, tactics (tuple, multi-tactic), status, claim_refs, evidence_refs, source_refs, behavioral_basis, reasoning, confidence, limitations, validation_status` -- every field the mandate's Section 2 names.

`AttackMappingStatus`: `OBSERVED | ASSESSED | CONDITIONAL | NOT_SUPPORTED`, with `OBSERVED` **structurally disallowed** by the semantic gate (§3.3) -- this pipeline only ever sees third-party-reported source text, never the reader's own telemetry, so a mapping can never honestly claim OBSERVED. This mirrors `analytical_depth_gate.py`'s own precedent (`PREMIUM_CUSTOMER` tier: real in the model, honestly unreachable today) rather than omitting the state entirely.

`build_attack_mappings(article, context, graph, package)` merges two real evidence sources, deduplicated by technique_id:
1. `package.attack_mappings`' existing prose sentences (already real, already honestly conditional in their own wording) become structured `CONDITIONAL` entries, with the prose itself as the `reasoning` -- not fabricated, the exact text already written for this purpose.
2. `map_techniques()` run over the article's full source text surfaces additional real signal the single-mapping-per-vulnerability-class system can never catch (e.g. a CVE article that also describes C2 exfiltration in prose). `Confidence.HIGH` matches (explicit technique-ID citation, or an unambiguous phrase) become `ASSESSED`; everything else stays `CONDITIONAL`.

### 3.2 Multi-tactic support (mandate Section 4)

`KNOWN_TECHNIQUES`'s existing single-tactic-per-id shape is **unchanged** -- `normalizer.py`, `report_ingest.py`, and `intelligence_validation.py` all destructure it as `(name, tactic)` today, and widening that shape would be a breaking change to all three for a refinement only the new structured object needs. Instead, an additive `ADDITIONAL_TACTICS: dict[str, tuple[str, ...]]` and a `tactics_for(technique_id)` helper were added to `attack_mapper.py`, populated with the real, verified MITRE data for T1053/T1053.005 (Execution, Persistence, Privilege Escalation -- all three, not just Persistence). `AttackMapping.tactics` is the only consumer; every existing consumer of `KNOWN_TECHNIQUES` is untouched and unaware this exists.

### 3.3 The semantic quality gate (mandate Section 5)

`_apply_semantic_gate()` rejects a candidate (filters it out entirely -- never returned as a customer-visible "NOT_SUPPORTED" badge, matching `map_techniques()`'s own established silent-exclusion discipline for negated matches) when:
- the technique_id is not in the curated registry,
- the technique_name doesn't match the registry,
- the primary tactic isn't in the declared `tactics` tuple,
- `behavioral_basis` is empty,
- no `claim_refs`/`evidence_refs`/`source_refs` exist at all,
- `status == OBSERVED` (structurally disallowed, see §3.1).

"CWE-only reasoning is prohibited" (mandate Section 4/5) is satisfied **structurally**, not by a runtime check: `build_attack_mappings()` never reads `article.cwe_ids` anywhere in its construction, so no mapping's `reasoning` can ever originate from a bare CWE-to-technique inference. `TestBuildAttackMappingsNeverReturnsCweOnlyReasoning` proves this against a real article that does carry CWE IDs.

### 3.4 End-to-end survival (mandate Section 3)

Traced and proven, not assumed:

`EvidenceGraph` + `DetectionPackage` → `build_attack_mappings()` (semantic-gate-passed) → `ComposedReport.attack_mappings` (pipeline_composer.py) → rendered into `ComposedReport.html` as a new "Structured ATT&CK Assessment" section (status/confidence/limitations all visible, not just technique/tactic) → `_ComposerOutcome.attack_mappings` (authority_transformer.py, `.to_dict()`-serialized) → `transform()`'s output dict (`result["attack_mappings"]`) **and** rendered into the actually-published HTML on every content path, including the LLM-authored one (the exact duplication-guard pattern already hardened for `hunt_hypotheses` on PR #116, applied identically here so the same defect class could not silently recur) → threaded into `evaluate_product_tier(..., attack_mapping_count=...)` → `report_contract.py`'s Section 11 (ATT&CK Mapping) state resolution.

No field is lost at any hop -- `status`, `confidence`, and `limitations` are all present in the final rendered HTML and the output dict, not merely computed and discarded (the exact failure class the mandate's Section 3 warns about, and the exact bug CodeRabbit found in the hunt-hypotheses path last round).

### 3.5 Section 11 state truthfulness (mandate Section 10)

`_resolve_attack_mapping()` now checks `attack_mapping_count` first (family-independent -- real for every family with matrix coverage, not only the CVE-vulnerability-class branches `detection_status` represents), falling back to the original `detection_status`-only check for any caller that hasn't computed the count yet (default `0`, fully backward compatible). Critically: **Section 11 never resolves `COMPLETE`, regardless of count** -- every mapping this pipeline can construct is `ASSESSED` or `CONDITIONAL` by structural design, never `OBSERVED`, so `PARTIAL_EVIDENCE` is the honest permanent ceiling (matching Sections 13/21's own `_PARTIAL_SIGNAL_ONLY` precedent for "real but inherently partial" signals). This directly satisfies the mandate's own instruction: *"ATT&CK = only CONDITIONAL mappings → do not claim observed behavior."*

## 4. A real defect found during real-data review (mandate Section 20) and fixed before certification

Running the new pipeline against a `ransomware_claim` fixture with deliberately rich encryption/exfiltration language (mandate Section 18's real-data validation set surfaced this, not a synthetic unit test) showed that `build_attack_mappings()` had no family-awareness: `package.attack_mappings` is already empty for `ransomware_claim` by construction (`report_renderer._detection_package()`'s own branch never sets it), but `map_techniques()` run over raw source text has no such awareness on its own. A richer claim's text could produce real, evidence-anchored `AttackMapping` entries that still bypass `report_contract.py`'s own existing, deliberate policy -- `_FAMILY_APPLICABILITY["ransomware_claim"][SECTION_11_ATTACK_MAPPING] = NOT_APPLICABLE`, the same "never invent an intrusion chain for a third-party leak-site claim" discipline already applied to Attack Path and Technical Analysis for this family.

**Fixed**: `build_attack_mappings()` now checks `report_contract.get_applicability(context.family, SECTION_11_ATTACK_MAPPING)` first and short-circuits to an empty list when it resolves `NOT_APPLICABLE` -- enforcing an existing, already-declared policy, not inventing a new one. Verified against the exact adversarial fixture that surfaced the gap (rich encryption/exfiltration language, still yields zero mappings) and locked in with a permanent regression test.

## 5. Real-data results (mandate Section 18)

Live run through the real, unmocked `AuthorityTransformer.transform()` against 7 representative fixtures:

| Case | Family | # Mappings | Status(es) | Section 11 state | Tier |
|---|---|---|---|---|---|
| Web-exposed CVE (SQLi) | `cve_advisory` | 1 | CONDITIONAL | PARTIAL_EVIDENCE | TACTICAL |
| Network-protocol CVE (DoS) | `cve_advisory` | 1 | ASSESSED | PARTIAL_EVIDENCE | TACTICAL |
| Privilege-escalation CVE | `cve_advisory` | 1 | CONDITIONAL | PARTIAL_EVIDENCE | TACTICAL |
| KEV (confirmed exploited) | `cisa_kev` | 1 | CONDITIONAL | PARTIAL_EVIDENCE | TACTICAL |
| Ransomware claim | `ransomware_claim` | **0** (family-gated) | -- | **NOT_APPLICABLE** | TACTICAL |
| Ransomware reporting (news) | `ransomware_reporting` | 4 | ASSESSED, CONDITIONAL | PARTIAL_EVIDENCE | TACTICAL |
| AI security | `ai_security` | 0 (no text match) | -- | WITHHELD_INSUFFICIENT_EVIDENCE | TACTICAL |

Every tier stays TACTICAL because no fixture had LLM authorship in this sandbox (no live provider access) -- Section 11 is OPTIONAL for every family (never MANDATORY), so it was never capable of gating tier eligibility on its own regardless.

The `ransomware_claim` row is the direct, visible proof the §4 fix works: zero mappings and `NOT_APPLICABLE`, not merely "zero mappings because the fixture happened to have no matching text."

## 6. Test evidence

| Suite | Before this round | After | Notes |
|---|---|---|---|
| Root `tests/` | 479 | **486 passed, 0 failed** | +4 (`TestAttackMappingsWiredIntoTransform`) +3 (`_resolve_attack_mapping` count tests) |
| `Sentinel-APEX/engine/tests/` | 1004 | **1023 passed, 1 pre-existing unrelated failure** | +18 (new `test_attack_mapping.py`) +1 (ransomware_claim family-gate regression) -- reconfirmed: `test_certify_real_end_to_end_with_the_actual_node_rendering_check` fails identically, same Node-rendering environment gap, nothing in this round touches rendering/certification/Node code |
| `tests-js/` | 123 | **123 passed, 0 failed** | Pipeline B untouched |

Adversarial coverage (mandate Section 19), all verified failing safely/downgrading correctly:
- CWE-only mapping basis -- structurally impossible, proven by construction (§3.3).
- Negated phrase / negated explicit citation -- excluded entirely, never reaches the caller.
- Unknown technique_id, technique-name mismatch, tactic not in registry, empty behavioral basis, no evidence/claim/source references, `OBSERVED` status -- each independently proven to reject via `_apply_semantic_gate()` unit tests constructing the exact invalid candidate directly (not relying on the real construction path to ever happen to produce one).
- Family-policy bypass (ransomware_claim rich text) -- the real defect found and fixed in §4.
- LLM-authored-path duplication/silent-drop -- the exact defect class CodeRabbit found in `hunt_hypotheses` last round, proactively guarded against and proven not reintroduced (`test_llm_authored_cve_article_still_renders_the_attack_section_in_published_content`).

Manual semantic review (mandate Section 20) was performed against the real-data table in §5, not only automated assertions -- it is what surfaced the §4 defect.

## 7. What this round deliberately does not do

Per the mandate's own Section 33/34 discipline (per-phase certification, no automatic promotion) and this session's established practice of not rushing comparably-sized work into one PR:

- **Phase 1J (role decision quality)**, **1K (full 24-section population)**, **1M (semantic/factual QA)**, **1N (premium certification ladder audit)** are not started. Each is independently large enough to deserve the same audit-first, evidence-based rigor already applied here and to every prior phase this session.
- **Phase 1P (Blogger hard gate)** and **1Q (post-publication fetch-back)** fundamentally require a live Blogger publish to be meaningfully verified beyond code review -- this repository's own established governance from earlier this session requires explicit owner authorization before any live, customer-visible, hard-to-reverse publish action. Building the fetch-back *verification machinery* without ever triggering a real publish is possible follow-up work; actually publishing is not decided here.
- **Hunting policy beyond `cve_advisory`** (mandate Section 6/8) is not extended this round -- it was already named as real, separate follow-up work in the prior Phase 1I certification, and remains so.
- Multi-family expansion of the multi-tactic registry (`ADDITIONAL_TACTICS` currently covers only the 2 techniques a real, live-verified defect required) is real, bounded follow-up, not attempted speculatively here.

## 8. Certification verdict

**RELEASE_CERTIFIED** for the structured ATT&CK object, its end-to-end survival to the rendered/published report, multi-tactic support, and the semantic quality gate:

- Root cause (prose-only ATT&CK output) fixed with a real structured object, not a workaround.
- Zero regressions across all 3 test suites (1,632 tests total, 1 pre-existing unrelated failure).
- One real defect found via genuine real-data/manual review (not merely unit tests) and fixed before certification, with a permanent regression test.
- No quality/integrity gate weakened -- `ransomware_claim`'s existing "never invent an intrusion chain" policy is now honored by a path that previously bypassed it, strictly strengthening the existing discipline.
- Reuse Before Build honored throughout: zero new mapping engines, zero breaking changes to `KNOWN_TECHNIQUES`'s existing consumers, every addition extends an already-tested mechanism.

**NOT RELEASE CERTIFIED, explicitly incomplete:** Phases 1J through 1Q remain entirely unstarted, per the mandate's own instruction not to claim otherwise.
