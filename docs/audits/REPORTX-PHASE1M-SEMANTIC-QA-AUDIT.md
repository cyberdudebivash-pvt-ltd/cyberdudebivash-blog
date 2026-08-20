# REPORTX Phase 1M — Semantic / Factual QA: Architecture Audit

**Written:** 2026-08-20, before any Phase 1M implementation. Read `claim_model.py`,
`contradiction_engine.py`, `claim_support_matrix.py`, `key_judgements.py`, and
`report_integrity.py` in full.

## 0. Starting-state verification

- Phase 1K's commit (`b307ba6a8`) confirmed present on this branch (`git rev-parse HEAD`); confirmed
  NOT yet on `origin/main` (`git rev-list --left-right --count HEAD...origin/main` → `1  3`, i.e. 1
  commit ahead, 3 bot commits behind) — unlike Phase 1J's PR #119, no auto-PR/merge has landed for
  this branch yet as of this check. Not blocking: this round continues on the same branch.
- Baseline reproduced fresh: root 515 passed, engine 1056 passed + 1 pre-existing unrelated failure
  (Node-rendering environment issue, reconfirmed), matching Phase 1K's own certified numbers exactly.

## 1. What already exists (Reuse Before Build)

This pipeline has substantially more real semantic/evidence infrastructure than either the mandate
or the Phase 1K audit assumed:

| Module | What it does | Live-wired? |
|---|---|---|
| `claim_model.py` | Canonical `Claim`/`EvidenceGraph`/`EpistemicState` (CONFIRMED/REPORTED/CORROBORATED/ASSESSED/HYPOTHESIS/UNKNOWN/NOT_ASSESSED/NOT_APPLICABLE/DISPUTED) — a materially richer vocabulary than the mandate's own 4-state ask, already the single source of truth for claim status everywhere else in this codebase | Yes — the foundation every other module below is built on |
| `contradiction_engine.py` | Two real checkers: dimension-level (same `EpistemicState` dimension, directly-opposed states) and text-pattern (3 hardcoded rule pairs, rendered HTML) | **Partially.** Called inside `pipeline_composer.compose_report()` against the composer's own internally-built HTML only — see §2 finding 1 |
| `claim_support_matrix.py` | `evaluate_claim_support_gate()`: every claim in an assertive `EpistemicState` must show `evidence_refs`/`source_refs`, split out by claim type (statistic/actor-attribution/business-impact/TTP-observed) | **No** — used only by the separate, older `commercial_readiness.py`/`intelligence_validation.py`/`release_certification.py` scorecard, never by `pipeline_composer.py`. Lower marginal value than it first appears: every claim the live pipeline's `discovery_bridge.py` constructs is already built with real evidence attached, so this gate would pass trivially today if wired in — not a live production gap the way the other findings are |
| `key_judgements.py` | The most complete instance of what the mandate is asking for, but scoped to Key Judgements only: LLM output is JSON-structured, every `claim_refs`/`evidence_refs`/`source_refs` entry is checked against the *real* graph (`UNKNOWN_CLAIM_REFERENCE` etc.), and any high-impact-pattern-matching judgement text with zero `claim_refs` is rejected outright (`UNSUPPORTED_HIGH_IMPACT_CLAIM`) | Yes, live, real |
| `report_integrity.py` | `_CONFIRMED_EXPLOITATION_PATTERNS`/`_PATCH_AVAILABLE_PATTERNS` classify the *source article*; `validate_publication()` separately hard-blocks a short, hand-typed exact-phrase list when rendered content asserts confirmed exploitation, KEV listing, or ransomware/AI schema contamination; `_UNSUPPORTED_COMMERCIAL_PATTERNS` blocks 4 exact-literal numeric strings (the real, already-proven "2,400+" incident fix, `docs/audits/blogger-syndication-run-8459-incident-review-2026-08-20.md`) | Yes, live, real — but see §2 finding 2 |

## 2. Real defects found

### Finding 1 — contradiction detection never sees the actually-published page

`pipeline_composer.compose_report()` calls `find_all_contradictions(graph, dimension_tags=...,
full_text=html)` where `html` is the **composer's own** internally-assembled narrative +
appended sections. `authority_transformer.py`'s `transform()` reads
`composer_outcome.contradictions` (the *result* of that call) but never re-invokes
`find_all_contradictions()` against the page it actually publishes. On the `reportx_composer`
content path these are the same page, so the check is meaningful. On the **LLM-authored** or
**legacy template** paths — where `body_content` becomes the LLM's own prose or the legacy
generator's output, with hunt/attack/role/reliability/gaps/forecast sections appended afterward —
the contradiction check that ran was against a page **that was never published**, and the actually-
published page (LLM prose + appended sections) is never scanned by either contradiction layer at
all. The 3 existing text-pattern rules have therefore never once been evaluated against real
LLM-authored narrative prose in production.

### Finding 2 — two separate, drifted pattern lists for "confirmed exploitation" language

`report_integrity.py` defines `_CONFIRMED_EXPLOITATION_PATTERNS` (5 general regex patterns, used to
classify the *source article*'s `exploitation_status`) and, separately, a hand-typed 4-item exact-
phrase tuple inside `validate_publication()` (`"active exploitation confirmed"`, `"exploitation is
confirmed active"`, `"actively exploited in the wild"`, `"exploitation confirmed?</strong> — yes"`)
used to reject an *unverified* exploitation assertion in rendered output. These are not the same
list: `_CONFIRMED_EXPLOITATION_PATTERNS` also matches `\bobserved exploitation\b` and
`\bexploitation (?:has been|was) observed\b` — plausible LLM paraphrases of exactly the same
fabricated claim — that the render-side `forbidden` tuple does not catch, because it requires an
exact substring match on a different set of phrasings entirely. This is the same "two
implementations of one concept, able to drift" defect class this codebase's own established
discipline (`ROLE_DISPLAY_LABELS`, `CORROBORATION_NOTES`-style single-sourcing) exists to prevent —
found here, not yet fixed.

### Finding 3 — no general mechanism for the "2,400+" defect class, only the 4 specific strings already observed

`_UNSUPPORTED_COMMERCIAL_PATTERNS` is, by the incident review's own account, a denylist added
*after* specific hallucinated numbers were observed in real output. It has no capability to catch
the *next* fabricated number (e.g. `"1,800+ victims"` or `"$4.2 million in losses"`) unless that
exact literal string is added by hand after another incident. This is the precise gap between "the
production integrity behavior that blocked the fabricated 2,400+ claim" (preserved, must not be
weakened) and "every material statement... resolves to SUPPORTED/ASSESSED_WITH_BASIS/UNSUPPORTED/
CONTRADICTED" (the mandate's actual bar — a general mechanism, not a growing denylist).

## 3. What Phase 1M implements this round

Given the above, the highest-confidence, most evidence-grounded, real (not fabricated-signal)
work for this round:

1. Unify the exploitation-assertion checks (Finding 2) — additively, the existing 4-phrase list
   stays as a permanent regression guard, the general regex patterns are added alongside it.
2. Fix the contradiction-check reach (Finding 1) — re-run the text-pattern layer against the final,
   actually-published HTML in `authority_transformer.py`, before `validate_publication()`.
3. Add the mandate's own explicitly-named text-contradiction pairing ("no exploitation confirmed" +
   "actively exploited" appearing together) to `contradiction_engine.py`'s existing rule tuple —
   not currently covered by any of the 3 existing rules.
4. Add a family-scoped hard gate for `ransomware_claim`: a *definite, unhedged* assertion of
   confirmed breach/compromise/data theft for the specific claimed victim — mirrors the exact
   evidence-boundary discipline `_lean_role_decisions()`'s IR_MANAGER decision and
   `_family_analysis()`'s "Claim Assessment" boundary text already establish for this family, now
   enforced as a hard publication gate, not only descriptive prose.
5. Build a general, source-text-grounded quantitative-claim check (Finding 3) — a specific number in
   a high-impact context (victim/record/organization counts, currency amounts) must be traceable to
   the source article's own text; a number appearing only in rendered output, never in the source,
   is fabricated by construction (this pipeline invents no facts the source didn't supply).
6. Expose `key_judgements.py`'s existing, real verification outcome using the mandate's own
   4-state vocabulary explicitly (`SUPPORTED`/`ASSESSED_WITH_BASIS`/`UNSUPPORTED`/`CONTRADICTED`) —
   this is a labeling/observability change over already-correct logic, not a new gate.

## 4. What this round does not attempt, named explicitly

- Wiring `evaluate_claim_support_gate()` into the live pipeline — real, but currently low marginal
  value (every claim the live pipeline constructs already carries evidence by construction; this
  gate would pass trivially today). Worth revisiting only if a future change starts constructing
  claims without evidence.
- Full actor/campaign-attribution named-entity verification, and a general "customer
  exposure"/"production compromise" assertion detector — both need materially more sophisticated
  text analysis to avoid false-positiving on this pipeline's own extensive, already-correct hedged
  guidance language ("confirm whether your organization is affected," etc.) than a regex pass can
  responsibly deliver this round. Phase 1K's own experience this session (a naive whole-page
  substring check false-positiving on cautionary boilerplate) is the direct cautionary precedent for
  not rushing this.
- A fully general LLM-prose-to-claim-graph entailment checker (verifying arbitrary sentences, not
  just pattern-matched high-impact phrases) — this is a materially larger, different kind of system
  than what can be built and adversarially proven correct in one round with real evidence, not
  fabricated confidence.
