# ReportX Premium Product Spec

What "premium" means as a product tier, how a report earns it, and where
the commercial value comes from. Every mechanism named here is real code
in `Sentinel-APEX/engine/sentinel_engine/reportx/` — this document maps
that code to the commercial product it enables (Section 27, touching
31-33).

---

## Product tiers (`human_review.CertificationState`)

Five states, strictly ordered by what has actually been verified — never
by what a template claims:

| Tier | Meaning | Commercial use |
|---|---|---|
| `PUBLIC_REFERENCE_DRAFT` | Automated gates have not all passed. | Not published. Internal only. |
| `TACTICAL_READY` | All automated gates pass; not marked premium tier. | Free/syndicated tactical content — SEO authority, newsletter lead magnets (Section 8's "Newsletter acquisition" and "SEO authority" categories). |
| `PREMIUM_READY_PENDING_HUMAN` | All automated gates pass AND the bundle is flagged premium tier, but no valid `ReviewRecord` is bound to the current artifact hash. | Internal — staged for analyst review, not yet sellable. |
| `PREMIUM_CERTIFIED` | `PREMIUM_READY_PENDING_HUMAN` conditions met, plus a real `ReviewRecord(decision=APPROVE)` whose `artifact_sha256` matches the *current* rendered text exactly. | Sellable Fortune-500 commercial deliverable — detection packs, premium intelligence reports, consulting-attached research (Section 8's "Revenue enablement" and "Enterprise conversion" categories). |

`resolve_certification_state()` (`human_review.py`) computes this
deterministically from three inputs — automated-gate pass/fail, the
premium-tier flag, and the review record — with **no manual override
parameter in its signature**. A caller cannot special-case a report into
`PREMIUM_CERTIFIED`; the only path there is a real approval bound to the
exact bytes being sold.

**Artifact-hash binding is the commercial guarantee, not a technicality.**
If a report is edited after human approval — even a single word — its
SHA-256 changes and `is_review_valid_for_artifact()` returns `False`,
dropping the tier back to `PREMIUM_READY_PENDING_HUMAN` automatically.
This is what makes "human-reviewed" a claim CYBERDUDEBIVASH® can stand
behind commercially: the review is cryptographically pinned to the
sold artifact, not to "a version of it."

## The floor: 23/23 commercial-readiness controls

`PREMIUM_CERTIFIED` is necessary but not sufficient for the product to be
sold — `commercial_readiness.evaluate_commercial_readiness()` is the
independent floor every tier above `PUBLIC_REFERENCE_DRAFT` still has to
clear. See `REPORTX-QUALITY-GATES.md` and `REPORTX-COMMERCIAL-READINESS-MATRIX.md`
for the full 23-row breakdown. The premium tier does not relax any of
those 23 rows — it adds the human-certification row (#21) and the
30-40-page premium-depth row (#22) on top of the same floor every tier
must clear.

## Premium depth (`product_depth.DepthAssessment`) — Sections 24, 28

`passes_premium_depth()` requires, simultaneously:

1. **Zero cross-report template repetition** in any of six named
   incident-specific sections (Actor Analysis, Campaign Analysis,
   Victimology, Forecast, Technical Analysis, Business Impact) — checked
   via Jaccard similarity on shingled text (reused from `quality.py`'s
   existing near-duplicate detector, `NEAR_DUPLICATE_THRESHOLD = 0.80`).
2. **≥8 distinct evidence-backed sections.**
3. **≥15 material claims** (claims actually carrying `evidence_refs` or
   `source_refs`, not just present in the document).

Four categories of boilerplate are explicitly allowed to repeat
(`SHARED_CONTENT_ALLOWED_CLASSIFICATIONS`): `STANDARD_DEFENSIVE_GUIDANCE`,
`METHODOLOGY`, `LEGAL_DISCLAIMER`, `PRODUCT_INFORMATION`. Everything else
must be genuinely incident-specific — **page count alone never satisfies
this control** (Section 28's explicit requirement). A 40-page report built
from padded, cross-report-identical prose fails `premium_depth` even
though it is long.

## Where the commercial value comes from (CLAUDE.md Section 8 mapping)

| Revenue category | ReportX mechanism |
|---|---|
| Detection-pack sales | `detection_validation.py`'s state-promotion check means a sold detection pack never overclaims a rule's validation state — a `WITHHELD_INSUFFICIENT_EVIDENCE` rule cannot carry "push to production" language anywhere in the product. Buyers get an honest maturity label, which is the actual product differentiator against competitors who ship unvalidated Sigma/YARA with confident prose. |
| Premium intelligence reports | The full premium tier above — evidence-first, contradiction-checked, human-certified, depth-verified. |
| Consulting pipeline | `analytic_scaffolding.derive_ransomware_gaps()` mechanically surfaces the same "what we don't know yet" list a paid engagement would close — turning intelligence gaps into a consulting upsell rather than hiding them. |
| Enterprise trust / brand authority | The 23-control gate and the anti-fabrication design of `claim_model.py` (9-state `EpistemicState`, corroboration computed not asserted) are the mechanism behind CLAUDE.md's "treat every published piece as if a Fortune 500 CISO will read it" mandate — this is not a style guideline here, it's enforced by code that fails closed. |
| Regulatory advisory upsell | `regulatory.py`'s `ApplicabilityState` (`CONFIRMED`/`LIKELY`/`POTENTIAL`/`NOT_ASSESSED`/`NOT_APPLICABLE`) with mandatory written `basis` gives an honest, defensible starting point for a compliance-attached engagement (NIS2/DORA/SOC 2) rather than a generic disclaimer. |

## What premium certification does *not* claim

- It does not claim the underlying facts are exhaustive — `intelligence_gaps`
  (row 19) is a required, visible part of the product, not a defect to
  hide.
- It does not claim every forecast is confident — `WithheldForecast` is a
  first-class, always-passing outcome (`forecast.py`); a premium report is
  allowed to say "we are not forecasting this" and still certify.
- It does not claim detections are production-validated unless they
  actually are — `DetectionValidationState` is rendered verbatim, not
  rounded up.

This is the product's actual differentiator: **the certification is a
claim about process integrity, not a claim that nothing is unknown.**
Fortune 500 buyers who have been burned by inflated vendor intelligence
are the target buyer for exactly this distinction.

## Current implementation status

Built and tested (349/349 `Sentinel-APEX/engine` tests passing, 0
regressions): the full claim/evidence model, threat-schema isolation, all
gate modules, the commercial-readiness orchestrator, and the
`reportx-gate` CLI subcommand (System 3, per the operator's hybrid
architecture decision). **Not yet built:** the System 5 JS adapter that
lets `api/_lib/product-composition-engine.js` consume a System-3-validated
`EvidenceGraph` for an actual customer-facing product render (task #44) —
see `REPORTX-ROLLOUT-RUNBOOK.md` for the integration plan and current gap.
No ReportX-gated report has shipped to a paying customer yet; the golden
fixtures (2 of 10 complete) are acceptance tests, not production content.
