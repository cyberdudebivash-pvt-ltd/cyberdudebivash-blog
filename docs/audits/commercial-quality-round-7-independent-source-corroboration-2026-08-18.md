# Commercial Quality — Round 7: Real Independent-Source Corroboration

**Scope:** the "not started" gap named in every prior round's doc — "an active corroboration engine (fetching a genuine second source, not just grading whatever's already in the graph)."

## The gap, confirmed by reading the code, not assumed

`claim_model.EvidenceGraph.recompute_corroboration()` is a correct, already-tested *derivation* over whatever sources a claim actually cites — it has never been the problem. The problem is one level up: `discovery_bridge.build_evidence_graph(article, context)` constructs exactly one `SourceRecord` from the one triggering `DiscoveredArticle`, full stop. There was no code path anywhere that could ever hand a claim a second, independent source — every live report was structurally guaranteed to be `UNCORROBORATED` or `SINGLE_SOURCE`, no matter how good the derivation logic downstream was. `pipeline_composer.py`'s own `corroboration_note` dict already had honest text ready for `MULTI_SOURCE_INDEPENDENT` — it just never had real data to trigger it.

Two more things confirmed before writing any code:
- `automation/content_discovery.py`'s `is_cve_published()` is already called from `nvd_source.py` to skip re-discovering a CVE NVD already covered — but nothing stops an RSS article from a *different* outlet covering the same CVE from being discovered and published as its own, separately single-sourced report. This is real, recurring, already-happening behavior this fix can act on.
- The persisted history (`data/published_posts.json`) never recorded which publisher an entry came from — `internal_linker.build_correlation_block()`'s own CVE/label matching had no way to distinguish "a different outlet already covered this" from "the same feed was re-crawled." Without that, no corroboration engine can be built honestly; fixing it was the necessary first step, not a side effect.

## The design

Additive, in three small pieces, each reusing something that already existed rather than inventing a parallel path (Reuse Before Build):

1. **`content_discovery.mark_published()`** now persists `source` and `source_publisher` on every new entry. Purely additive — the ~4,751 entries already in production history simply lack these two keys, and every consumer of this file already treats a missing key as "unknown," never a fabricated value. This means the engine below is honest but forward-looking: it cannot retroactively benefit from history recorded before this change (named under "what remains").

2. **`internal_linker.find_independent_prior_source(cve_id, exclude_publisher, state_file)`** — a new, module-level function next to `build_correlation_block()`, reusing the exact same file-read/CVE-match pattern. Returns the earliest prior entry reporting the same CVE ID whose recorded publisher is real and different from the current article's — `None` (never a guess) when the state file is missing, nothing matches, or every match's publisher is unknown or identical.

3. **`discovery_bridge.build_evidence_graph()`** gained one new, optional, backward-compatible parameter: `state_file: str | None = None`. When `None` (every existing caller, including all 5 pre-existing call sites in `test_discovery_bridge.py`), behavior is byte-for-byte unchanged. `pipeline_composer.compose_report()` is the one production caller, and now passes `config.state_file`. When a real independent match is found, `_apply_independent_corroboration()`:
   - Adds a real, second `SourceRecord` (role `CORROBORATION`, the historical entry's real URL/publisher), reusing the same "honest excerpt-fingerprint fallback, never a fabricated hash" pattern `build_source_record()` already uses when full content isn't available — refactored the shared rule into `_reliability_for()` so both paths use one, non-duplicated policy (Single Source of Truth).
   - Attaches it, deliberately, **only** to `c-cve-id` and `c-summary` — the two claims a bare CVE-ID match actually supports (the vulnerability's identity/existence). `c-exploitation-status`, `c-patch-status`, and any other high-impact claim are left untouched: a second outlet reporting the same CVE does not establish that it agrees on exploitation or patch status, and Section 10's single-source discipline must keep applying to exactly the claims it exists to protect.
   - Rewrites `c-independent-corroboration` — previously a hardcoded string that unconditionally read "has not been assessed" on *every* report regardless of reality — to state the real finding, or leaves it exactly as before when nothing was found.

## A real defect this caught on its own, before it ever shipped

The first live dry-run (a synthetic prior BleepingComputer entry for the same CVE) showed `publication_eligible` flip from `True` to **`False`** — a regression. `blocking_reasons` named it precisely: `Evidence Traceability: ... failing: Evidence hash`. The newly-synthesized second `SourceRecord` had neither `content_sha256` nor an excerpt fingerprint, which `commercial_readiness.py`'s integrity gate correctly treats as a real defect, not a technicality. Fixed by computing an honest excerpt fingerprint from the one real string the persisted history actually has (the historical entry's title), with an explicit `fingerprint_fallback_reason` explaining why — exactly the standard this codebase already holds the primary source to. Re-verified live: `evidence_hash` back to PASS, `overall_score` 91→98, `publication_eligible` **True**.

## Verification

- Live, end-to-end, before/after against a synthetic independent match: `src-corroboration-1` added; `c-cve-id`/`c-summary` genuinely `MULTI_SOURCE_INDEPENDENT`; `c-exploitation-status` correctly stays `SINGLE_SOURCE`; `c-independent-corroboration` rewritten with the real publisher named.
- Confirmed against the real, live `data/published_posts.json` (4,751 entries): zero crashes, zero accidental matches (expected — zero existing entries carry the new publisher fields yet), identical scores to Round 6 for the no-match case.
- 14 new regression tests across `test_content_discovery.py`, `test_internal_linker.py`, and `test_discovery_bridge.py` (including the exact `evidence_hash` regression above, so it can never silently return).
- 338/338 pass at the repository root; 925/926 pass across `Sentinel-APEX/engine` (the same one pre-existing, environment-only Node-rendering-certification failure documented since #91, unrelated to any file this round touched).

## What this does *not* do — named plainly

- **Not retroactive.** Every entry already in `data/published_posts.json` predates the `source`/`source_publisher` fields; the engine will find zero matches against today's history until new posts start recording them going forward. A domain-name-based backfill heuristic (inferring a historical publisher from its `source_url`'s domain) is plausible future work, but is a guess derived from real data rather than a recorded fact, and deserves its own separately-evidenced pass, not a rushed addition here.
- **Does not change the rendered "Source Reliability & Corroboration" headline text** for a typical CVE report. That section correctly shows the *worst* corroboration state across every claim tied to the primary source (`pipeline_composer.worst_corroboration_state()`); since exploitation/patch-status claims deliberately stay single-sourced, the visible headline will usually still say "single-source" even when the CVE's identity is now genuinely doubly-sourced underneath. This is correct, conservative behavior, not a limitation to route around — the improvement is real at the evidence-ledger and `Information Credibility` scoring level (verified directly), even where the headline framing doesn't move. Enriching that section to disclose per-claim-tier nuance is a reasonable, separate future improvement.
- **Only CVE-advisory-family reports.** Ransomware-claim articles have no `cve_id` and are untouched; a defensible equivalent for that family (e.g. matching on actor + victim name) is fuzzier and was not attempted here.

## What remains, named plainly

- A domain-based backfill for historical entries, if the value is judged worth the heuristic risk.
- Enriching the rendered Source Reliability section to show per-claim corroboration nuance instead of only the worst case.
- An equivalent, appropriately-scoped corroboration signal for the ransomware-claim family.
- Historical/campaign correlation beyond the false-positive fix in Round 4.
- Deciding whether/how `publication_eligible` becomes a real hard gate.
