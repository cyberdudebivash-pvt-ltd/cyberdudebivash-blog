# Product Quality Gates — Per-Tier Mapping

Companion to `REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md`. Defines what
"passes" means at each product tier without weakening Section 46's rule
that a `BLOCKED` row counts against the roll-up exactly like a `FAIL` —
the fix is scoping *which* 23 rows a tier is actually expected to attempt,
not softening what "PASS" means for the rows it does attempt.

## The floor — every tier, no exceptions

`automation/report_integrity.py`'s `validate_publication()` runs first,
unconditionally, regardless of target tier:

- Required provenance present (report ID, source-record hash, source URL,
  generation timestamp, review status, certification status)
- Minimum body length
- No placeholder text
- No unsupported commercial-scale claims
- Exploitation-assertion consistency with KEV status
- No KEV-listing false assertion
- No ransomware/AI schema contamination
- No fabricated human-analyst attribution

A report that fails this gate is not downgraded to a lower tier — it does
not publish at all, exactly as today.

Above that floor, ReportX's `qa_linter.py` (grammar/synthesis defects) and
`contradiction_engine.py` (cross-section contradictions) also run
unconditionally at every tier — a `FLASH_READY` report can be short, it
cannot contradict itself.

## Tier-specific control expectations

| Control (`commercial_readiness.py` row) | FLASH_READY | TACTICAL_READY | PREMIUM_* |
|---|---|---|---|
| 1-2 Source provenance / evidence hash | Required PASS | Required PASS | Required PASS |
| 4 Source-specific facts | Required PASS | Required PASS | Required PASS |
| 5 Cross-source corroboration | Required PASS (single-source claims stay `REPORTED`, never promoted) | Required PASS | Required PASS |
| 6 Threat-type schema correctness | Required PASS | Required PASS | Required PASS |
| 7 Cross-section consistency | Required PASS | Required PASS | Required PASS |
| 8-9 Actor/victim-specific analysis | Expected `BLOCKED` (a routine single-source alert has no independent actor-context research yet) | PASS if researched | Required PASS |
| 10 Current statistics | `BLOCKED` unless the source itself carries a cited figure (e.g. EPSS) | Same | Required PASS |
| 11 Regulatory specificity | `BLOCKED` (no per-report regulatory read at this speed) | PASS if a jurisdiction/sector read was done | Required PASS |
| 12 Technical recommendations | PASS on the existing patch/compensating-control guidance already in `report_renderer.py` | Same | Required PASS |
| 13 Detection evidence discipline | Required PASS (reuses `report_renderer.py`'s existing governed-withholding discipline) | Required PASS | Required PASS |
| 14-15 Temporal integrity / grammar QA | Required PASS | Required PASS | Required PASS |
| 16 Forecast methodology | `BLOCKED` (no forecast attempted) or PASS with 1 evidence-scoped forecast | PASS, 2-3 forecasts | PASS, full 24h/72h/7d/30d/90d ladder |
| 17 Evidence ledger | Required PASS | Required PASS | Required PASS |
| 18 Alternative hypotheses | `BLOCKED` | `BLOCKED` or PASS if a real hypothesis set applies | Required PASS |
| 19 Intelligence gaps | Required PASS (at minimum: "no independent corroboration obtained yet" is itself a real, honest gap) | Required PASS | Required PASS |
| 20 Report-specific bibliography | Required PASS | Required PASS | Required PASS |
| 21 Human analyst certification governance | N/A below premium (governs `PREMIUM_CERTIFIED` only) | N/A | Required |
| 22 Premium depth | N/A (not the target shape) | N/A | Required PASS |
| 23 Roll-up | **Only rows the tier is expected to attempt count toward "23/23 for this tier."** A `FLASH_READY` report is never compared against premium's full 23; it is compared against its own tier's applicable subset, computed the same `all(status == PASS for applicable rows)` way — no manual override, no partial credit within that subset either. | | |

**This is additive to, not a replacement for, the existing 23-control
matrix** — `commercial_readiness.py` is unmodified; a tier's "applicable
subset" is a caller-side filter over the same real `ControlResult` list
every canary already produces, analogous to how `tier_downgrade.py`
already reads the same `ControlResult` list to compute a fail-closed
achieved tier from real data rather than a hand-set flag.

## Anti-padding stays universal

`product_depth.find_template_repetition()` runs across **every** tier,
including `FLASH_READY` — this is the direct, existing fix for Findings
1/2 (33,470 byte-identical "template" fallbacks). A `FLASH_READY` report
is allowed to be short; it is never allowed to be identical prose from a
different report with the entity name swapped. Section 24's allowed-
shared-content classifications (`STANDARD_DEFENSIVE_GUIDANCE`,
`METHODOLOGY`, `LEGAL_DISCLAIMER`, `PRODUCT_INFORMATION`) still apply —
genuinely generic guidance (e.g., "validate immutable backup health") is
allowed to repeat across ransomware reports; the Business Impact dollar
figure and the Predictive Intelligence forecast text, which today repeat
identically without being classified as shared content at all, would not
be.

## Escalation and automated certification apply per tier, not only to premium

`automated_certification.py`'s `EscalationReason` vocabulary and the
`PREMIUM_AUTOMATED_CERTIFIED` mechanism generalize directly: a
`FLASH_READY`-target report whose own tier-applicable controls all pass,
under a certified release, with zero escalation signals, resolves
automatically; one with an escalation signal (e.g. `DETECTION_STATE_PROMOTION`,
`SOURCE_INTEGRITY_FALLBACK_THRESHOLD`) routes to human review exactly like
a premium report would — the review requirement never depends on tier, only
on evidence quality.
