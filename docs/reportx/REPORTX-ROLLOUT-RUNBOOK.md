# ReportX Rollout Runbook

How System 3 (the canonical evidence/claim engine) reaches actual
customer-facing product output, without breaking any existing writer
system along the way. Read `CANONICAL-WRITER-TRACE.md` first — this
runbook assumes its five-system map and the operator's hybrid
architecture decision (System 3 = intelligence truth, System 5 =
commercial product composition, System 4 = rendering/export, System 1 =
ingestion/public-volume, System 2 = legacy syndication, not touched).

**Model**: `BUILD → VALIDATE → ADAPT → CANARY →
PREMIUM_READY_PENDING_HUMAN → HUMAN REVIEW → PREMIUM_CERTIFIED →
RELEASE CERTIFICATION → AUTOMATED CERTIFICATION (future reports) →
GO/NO-GO → INTEGRATE → OBSERVE`. The `RELEASE CERTIFICATION → AUTOMATED
CERTIFICATION` stage (Phase 5.5, `REPORTX-RELEASE-CERTIFICATION.md` /
`REPORTX-AUTOMATED-CERTIFICATION.md`) is additive: it lets a
release-certified engine issue `PREMIUM_AUTOMATED_CERTIFIED` to future
reports without a per-report human review, without changing what
`PREMIUM_CERTIFIED` itself means or how any individual canary reaches it.
This corrects an earlier draft of this
runbook, which stated Phase 4 (CANARY) was "blocked on" Phase 5 (human
review) while Phase 5's own text said it was sequenced *after* Phase 4 —
a circular dependency that was never real: CANARY does not depend on
HUMAN REVIEW being operational; HUMAN REVIEW depends on CANARY producing
real artifacts to review. `PREMIUM_READY_PENDING_HUMAN` is not a phase a
person runs — it's the automatic, computed state every canary reaches
the moment its 23 controls all PASS (`resolve_certification_state()`),
and it is the trigger that makes HUMAN REVIEW meaningful. Nothing before
`INTEGRATE` touches any existing production writer path — System 3 is a
new, additive package with no caller in the existing pipeline yet, so
every phase up to and including `HUMAN REVIEW` is fully reversible by
simply not merging further (Architecture Preservation Rule: add, don't
replace).

---

## Phase 0 — Architecture decision. **Done.**

Operator selected the hybrid: System 3 (`Sentinel-APEX/engine/sentinel_engine/reportx/`)
is the single canonical evidence/claim truth model; System 5
(`api/_lib/product-composition-engine.js` and related JS) becomes the
commercial product-composition layer that *consumes* System 3's output;
System 2 (`automation/authority_transformer.py`) is classified
LEGACY/HIGH-RISK and is explicitly not the foundation for anything new
here. No second, parallel claim/evidence truth model is permitted in
JavaScript (Section 2/Principle 3 — Single Source of Truth).

## Phase 1 — BUILD System 3. **Done.**

Fifteen modules under `sentinel_engine/reportx/`: `claim_model.py`,
`threat_schemas.py`, `contradiction_engine.py`, `claim_support_matrix.py`,
`detection_validation.py`, `metrics_registry.py`, `regulatory.py`,
`qa_linter.py`, `forecast.py`, `analytic_scaffolding.py`,
`human_review.py`, `product_depth.py`, `commercial_readiness.py`,
`bundle_io.py`. Wired into `cli.py` as the `reportx-gate` subcommand.

**Verify locally:**

```bash
cd Sentinel-APEX/engine
python3 -m pytest tests/ -q            # 349 passed, 0 regressions, includes pre-existing sentinel_engine suite
python3 -m py_compile sentinel_engine/reportx/*.py
```

## Phase 2 — VERIFY via golden fixtures. **10 of 10 complete.**

`tests/fixtures/reportx-commercial-readiness/` (repo root) holds real,
research-backed evidence for every named acceptance case, built from
WebSearch/WebFetch research — never from model memory. Complete:
CVE-2025-62593 (Ray, the one BEFORE/AFTER defect-catalog pair) and all
9 named ransomware victims (Qilin/Spoonful of Comfort, Panzer/SAGASTA
sro, Qilin/Mulino Padano, MedusaLocker/Twal Family IT Lab,
MedusaLocker/All Parts Dry Cleaning, Aurora/Lloyd Coils Europe,
DragonForce/Vermont XCenter, MedusaLocker/Idex Group,
MedusaLocker/Bija Industrie — each AFTER-only, since the BEFORE/AFTER
defect-catalog demonstration already lives in the Ray pair). 139
acceptance tests, 0 regressions against the full 492-test engine suite.
Two real bugs in System 3 were found this way (a corroboration-count
double-count in `claim_model.py`, a QA-linter false positive on
legitimate "None of..." prose) — direct evidence for why this phase
exists before Phase 3, not after: messy real-world data exercises paths
hand-written unit tests miss. Full per-fixture results, including two
naming-collision catches (Medusa/MedusaLocker, and IDEX Corporation vs.
the unrelated "Idex Group" victim) and a privacy-scoping decision (Twal
Family IT Lab): see `REPORTX-ACCEPTANCE-RESULTS.md`.

## Phase 3 — ADAPT: System 5 JS adapter. **Done.**

System 5 consumes System 3's validated `EvidenceGraph`, never
reimplements it. The interchange point: `bundle_io.py` now has both
directions — `bundle_from_dict()` (JSON → `ReportBundle`, extended this
phase to deserialize `threat_products`, closing the gap noted below) and
`bundle_to_dict()`/`export_report_json()` (`ReportBundle` → JSON,
including the already-computed 23-control gate result, so a JS consumer
never recomputes anything System 3 already validated). `cli.py`'s
`reportx-gate` subcommand gained an `--export PATH` flag that writes this
combined artifact.

**The gap this phase closed:** `bundle_from_dict()` originally didn't
deserialize `threat_products` (the `RansomwareVictimClaim`/`CVERecord`/
`CISAKEVRecord` layer) at all — the golden fixtures worked around this by
constructing bundles directly in Python. `bundle_io.py` now has
`_threat_product_from_dict()` (dispatching on the `threat_type`
discriminator) and reuses each schema's own `to_dict()` unchanged on the
way out. Verified against every real fixture in the repo, not a synthetic
example: `test_bundle_io.py::TestThreatProductsRoundTrip` round-trips all
9 ransomware fixtures and both Ray CVE JSON fixtures through actual JSON
text and re-runs `evaluate_commercial_readiness()` on the reloaded
bundle — the control-result list is byte-identical before and after, for
every fixture.

**`api/_lib/reportx-adapter.js`** is the adapter itself: a `ReportXBundle`
class that reads (never recomputes) claims, sources, threat products, and
the 23-row control matrix from an exported JSON artifact, plus
`toInvestigationShape()` — a best-effort compatibility bridge into the
loosely-typed `investigation` object `product-composition-engine.js`'s
existing `compose*()` methods already consume. `product-composition-engine.js`
itself was **not modified** — the adapter is proven against it exactly as
it already exists: `reportx-adapter.test.js`'s final test calls the real
`ProductCompositionEngine.composeThreatActorProfile()` (unmodified) with
a ReportX-derived investigation object and asserts on the resulting
product, over an exported copy of the Qilin/Spoonful of Comfort fixture
(`tests/fixtures/reportx-commercial-readiness/qilin-spoonful-of-comfort-exported-bundle.json`,
itself produced by the real CLI, not hand-written). 20/20 new JS tests
pass; full JS suite 1620/1620, 0 regressions.

**What Phase 3 does not do:** it does not wire this adapter into any
live route, cron job, or customer-facing product path — that is Phase 7
(INTEGRATE), which requires the Phase 6 GO/NO-GO checkpoint first.

## Phase 4 — CANARY generation. **Done, 4 of 4, all real 23/23.**

Four complete, research-backed premium canaries exist in
`reportx-canary/` (never overwriting anything System 1 or System 2
currently publishes): Qilin/Spoonful of Comfort, MedusaLocker/Bija
Industrie, DragonForce/Vermont XCenter, and CVE-2025-62593 (Ray). Each
independently reaches a genuine 23/23 PASS on real, hash-verified
evidence — not the synthetic `_build_fully_supported_bundle()` fixture
`REPORTX-COMMERCIAL-READINESS-MATRIX.md` documents as proving the gate
is satisfiable in principle. Full detail, per-canary stats, and artifact
hashes: `REPORTX-CANARY-CERTIFICATION.md`.

Includes real System 4 render/print QA (`reportx-canary/render-qa/`):
real PDFs via headless Chromium print-to-PDF, real page counts (20-21
pages per canary — reported truthfully, not inflated to a target),
`checkRendering()` clean on all four, zero orphan headings, zero broken
TOC anchors, zero placeholder text. And real System 5 integration
(`api/_lib/__tests__/reportx-adapter-four-canaries.test.js`, 65 tests):
proves the adapter and the unmodified `ProductCompositionEngine` never
recompute claim truth, promote confidence or detection-validation state,
or lose source/evidence references or commercial-readiness results, for
all four real exports.

This is a read-only proof step: it demonstrates end-to-end System 3 →
System 4 → System 5 → rendered product without any customer-facing
surface changing.

## Phase 5 — Human review workflow. **Operational. Real APPROVE pending
the actual operator.**

`human_review.ReviewRecord` and `resolve_certification_state()` were
already built and tested before this phase; what didn't exist was the
operational process. It now does — documented end-to-end in
`REPORTX-HUMAN-REVIEW-RUNBOOK.md`: a reviewer pack per canary (report ID,
artifact hash, full 23-control matrix, sources, claims, statistics,
regulatory determinations, detection status, forecasts, hypotheses,
gaps, and the real render preview), the exact `reportx-review
approve/reject/request-changes` commands, and the mandatory post-
approval re-verification step. `reject`/`request-changes` were smoke-
tested end-to-end against a real canary export this phase; `approve` was
deliberately never run with a fabricated identity — that is the one step
reserved for a real human, by design (Section 44: "the operator must be
the real reviewer").

**Current state: all four real canaries are `PREMIUM_READY_PENDING_HUMAN`.
Zero real `APPROVE` actions have been recorded.** This phase is complete
from an engineering standpoint; it is blocked only on the real operator
actually running the commands in `REPORTX-HUMAN-REVIEW-RUNBOOK.md`.

## Phase 5.5 — Release Certification + Automated Certification. **Built
and tested; NOT yet certified (same real-APPROVE blocker as Phase 5).**

New, additive layer (`sentinel_engine.reportx.release_certification`,
`.automated_certification`, `.tier_downgrade`, `.quality_sampling`,
`.audit_log`, `.release_health`; CLI: `reportx-release`,
`reportx-certify`) answering the scaling question Phase 5 deliberately
left open: production-volume reporting cannot require a human to
individually re-review every report, but a canary's human approval must
never become a reusable credential for content nobody reviewed.

The resolution, made structural rather than aspirational: a real,
artifact-bound `APPROVE` on all four canaries certifies **the release**
(`REPORTX_RELEASE_CERTIFIED` — real 23-control results, real
`ReviewRecord`s, real regression/render/System-5/anti-padding/npm-audit
results, real component-file hashes for drift detection). A certified
release then lets **individual future reports** earn
`PREMIUM_AUTOMATED_CERTIFIED` on their *own* real evidence — never by
inheriting a canary's approval, which the new automated-certification code
path cannot even reach (it never imports `ReviewRecord`). Full detail:
`REPORTX-RELEASE-CERTIFICATION.md`, `REPORTX-AUTOMATED-CERTIFICATION.md`,
`REPORTX-RISK-BASED-HUMAN-REVIEW.md`.

**Current state, run against the real four canary exports today:**
`reportx-release certify` correctly and honestly reports
`NOT_CERTIFIED` — every canary is still `PREMIUM_READY_PENDING_HUMAN`,
the same real-operator dependency Phase 5 is blocked on. 105 new tests
(`tests/reportx/test_{release_certification,automated_certification,
tier_downgrade,quality_sampling,audit_log,release_health,
reportx_release_cli}.py`) prove the mechanism itself — including that a
canary's review cannot certify a different canary or any newly generated
report, that engine drift invalidates a certified release, that a 22/23
report cannot receive `PREMIUM_AUTOMATED_CERTIFIED`, and that sampling
never alters a certification outcome — using the real canary artifacts,
not synthetic stand-ins.

## Phase 6 — GO/NO-GO checkpoint

Before any ReportX-gated bundle reaches an existing production writer
path or a paying customer, present the operator with:

- Fixture coverage — **10/10 golden fixtures** (`REPORTX-ACCEPTANCE-RESULTS.md`)
  **plus 4/4 real premium canaries** (`REPORTX-CANARY-CERTIFICATION.md`)
- Full `Sentinel-APEX/engine` test suite result (0 regressions — 754/754
  at last count, includes the 105 Phase 5.5 tests) and full JS suite
  result (0 failures — 1688/1748, 60 skipped)
- All four canaries reaching `PREMIUM_CERTIFIED` end-to-end through a
  real (not `is_test_only_fixture=True`) review, and the release itself
  reaching `REPORTX_RELEASE_CERTIFIED` (Phase 5.5's stricter bar — a
  single approved canary was this checklist's original bar before Phase
  5.5 existed; release certification's own Section-4 requirement is all
  four, since that is what "the release has demonstrated correct
  behaviour" actually requires) — **not yet satisfied; this is the
  current blocker on reaching Phase 6.**
- Confirmation that System 1/System 2/System 4 continue operating
  unmodified (Architecture Preservation Rule — this is an addition, not
  a cutover) — satisfied; System 4's own renderer/checkRendering() code
  was read and reused unmodified, never replaced
- The 23-row commercial-readiness matrix for each canary report —
  satisfied, all four at 23/23

**No row in this checklist may be marked complete without the evidence
behind it, per this repository's CLAUDE.md "Proof Before Change" and
"God-Mode Release Gate" requirements.** This runbook does not authorize
Phase 7 by itself — it documents what Phase 7 requires when the operator
chooses to proceed. **Phase 6 is not yet reached**: it requires at least
one real, operator-executed `APPROVE` first.

## Phase 7 — INTEGRATE (requires explicit operator authorization)

Wire the System 5 adapter into the live product-composition path for one
threat type at a time (ransomware first, since it has the most fixture
coverage), behind a flag so System 1/System 2's existing output is
unaffected for any report the adapter hasn't touched — Deprecation
Instead of Deletion applies to System 2 exactly as the operator specified:
it stays available and is not removed as part of this rollout.

## Phase 8 — OBSERVE

Standard post-release monitoring per CLAUDE.md's Observable Everything
principle: track `ControlResult` pass rates across real production
bundles over time (a control that never passes across many real reports
is a signal the control or the upstream data pipeline needs attention,
not that the report is uniquely bad), track `CertificationState`
distribution, and track any `BLOCKED` row that recurs across reports
(recurring `BLOCKED` on the same control, e.g. "no forecasts attempted,"
is a product-completeness gap worth closing deliberately rather than a
per-report accident).

---

## Rollback

Every phase through Phase 6 is inherently rollback-free: System 3 has no
caller in any existing production path, so nothing to roll back. From
Phase 7 onward, rollback is the flag flip described there — disable the
adapter for the affected threat type and the existing System 1/System 2/
System 4 path resumes exactly as it was, since it was never modified.

## Current status summary

| Phase | Status |
|---|---|
| 0 — Architecture decision | Done |
| 1 — Build System 3 | Done |
| 2 — Golden fixtures | Done, 10/10 (139 acceptance tests) |
| 3 — System 5 adapter | Done |
| 4 — Canary generation | **Done, 4/4 real canaries, all 23/23 PASS** (render QA + System 5 integration included) |
| 5 — Human review workflow | **Operational** — reviewer packs + CLI commands ready; 0 real `APPROVE` actions recorded yet |
| 5.5 — Release + automated certification | **Built and tested** — `reportx-release`/`reportx-certify` CLI operational; release honestly `NOT_CERTIFIED` (blocked on the same 0 real `APPROVE` actions as Phase 5) |
| 6 — GO/NO-GO checkpoint | Not reached — blocked on all four real `APPROVE` actions (Phase 5.5's release-certification bar) |
| 7 — Integrate | Not authorized |
| 8 — Observe | N/A |

Full regression snapshot at this status: Python `Sentinel-APEX/engine`
suite 754/754 (0 regressions — 649 pre-existing + 105 new Phase 5.5
tests); JS suite 1688/1748 (60 skipped, 0 failed); all four canary suites
plus the cross-canary anti-padding suite 97/97 together.
