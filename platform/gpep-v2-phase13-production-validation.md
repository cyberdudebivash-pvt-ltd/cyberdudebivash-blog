# GPEP v2 Phase 13 — Production Validation

Covers the one implemented change this program made: the knowledge-graph
correction and Malware-node population (Phase 3, Issue 17). Every other
phase in this program was audit/analysis/backlog, not implementation, so
this is the only item requiring the full validation checklist.

## Implementation

- `api/_lib/threat-graph.js`: `THREAT_ACTOR_DB` (removed CVE-2024-27198/
  27199 from `actor:apt41`; added `actor:apt29`), `CVE_ACTOR_MAP`
  (corrected), `KEYWORD_ACTOR_MAP` (corrected).
- `api/intel/threat-graph.json` (persisted live data): removed 3
  mis-sourced edges + their campaign-level echo (5 total removed across
  both passes), added 5 new edges (1 actor→CVE, 2 actor→campaign,
  2 CVE→malware) and 3 new nodes (`actor:apt29`, `malware:bianlian`,
  `malware:jasmin`) — all via the existing `addNode`/`addEdge`/`saveGraph`
  functions, not hand-edited JSON.

## Testing

- New: `tests-js/threat-graph-attribution-accuracy.test.js` — 8 tests,
  covering both the source-code mapping and the persisted graph data.
- Regression: full suite re-run after the change —
  `scripts/assure.sh --all`, 5 of 5 stages green (Python 176/176,
  renderer 64/64, engine-node 106/106, root JS 105/105, plus quality
  gate/certification against all 3 published reports).
- No existing test referenced the incorrect data, so nothing needed
  updating to accommodate the fix — confirmed by grep before editing, not
  assumed.

## Documentation

- `platform/open-issues.md` Issue 17 — full finding and fix detail.
- `platform/capabilities.md` — Knowledge Graph row updated in place.
- `platform/gpep-v2-phase1-platform-audit.md` and
  `gpep-v2-phase3-knowledge-graph-evolution.md` — both updated/written to
  reflect the post-fix state, not left describing the pre-fix gap as still
  open.

## Operational Verification

- Confirmed the persisted graph JSON remains valid JSON after the edit
  (`json.load` succeeds).
- Confirmed via direct inspection that no residual `actor:apt41`/
  `actor:cl0p` edge or connection touches the TeamCity CVE pair or its
  campaign clusters, in either direction (edges array and per-node
  `connections` array both checked).
- `computeStats()` re-run and matches expectations exactly (actors 8→9,
  malware 0→2, edges 3515→3514).
- Not verified: the live, deployed API response for a real customer query
  against this graph data (e.g. `getGraphForTier()`'s actual HTTP output)
  — this fix has not yet been pushed/deployed as of this document; that is
  Phase 14's closing step, and this section will be accurate once that
  push happens, not before.

## Customer Impact Assessment

- **Positive**: a customer querying the graph for CVE-2024-27198 no longer
  receives an attribution (APT41) contradicted by this platform's own
  certified report on the same CVE — closes a real, if narrow, trust
  inconsistency between two of the platform's own products.
- **Neutral-to-positive**: 2 new Malware entities are now queryable where
  none existed before; this can only add capability, not remove any.
- **None expected to be negative**: no existing customer-facing route,
  field name, or response shape changed — only specific edge/node *content*
  was corrected or added, matching this platform's Backward Compatibility
  principle.

## Rollback Considerations

- The specific edits are fully described in Issue 17 and are individually
  small; reverting would mean re-adding the 3 removed edges and removing
  the `actor:apt29`/Malware additions — mechanically simple via
  `git revert`, though reverting would restore the mis-sourced claims this
  fix was made to correct, so a rollback should only ever be done to
  recover from an unrelated, unforeseen regression, not because the
  correction itself is in question.
- No schema migration occurred — `graph.nodes`/`graph.edges` structure is
  unchanged, only content.

## Remaining Validation Requirements

- Live/production verification after this branch is merged and deployed
  (mirrors what was done for PR #47 — fetch a real API response and
  confirm the corrected data is what's actually served).
- The systemic-audit recommendation (Phase 3, Phase 11) remains
  unvalidated by design — it's a backlog item, not something this pass
  attempted to resolve.

---
*CyberDudeBivash® Sentinel APEX — GPEP v2 Phase 13 Production Validation*
