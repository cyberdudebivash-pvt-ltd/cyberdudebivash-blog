# ReportX Rollout Runbook

How System 3 (the canonical evidence/claim engine) reaches actual
customer-facing product output, without breaking any existing writer
system along the way. Read `CANONICAL-WRITER-TRACE.md` first — this
runbook assumes its five-system map and the operator's hybrid
architecture decision (System 3 = intelligence truth, System 5 =
commercial product composition, System 4 = rendering/export, System 1 =
ingestion/public-volume, System 2 = legacy syndication, not touched).

**Model**: `BUILD → VERIFY → ADAPT → CANARY → REVIEW-WORKFLOW → GO/NO-GO
→ INTEGRATE → OBSERVE`. Nothing before `INTEGRATE` touches any existing
production writer path — System 3 is a new, additive package with no
caller in the existing pipeline yet, so every phase up to and including
`CANARY` is fully reversible by simply not merging further (Architecture
Preservation Rule: add, don't replace).

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

**Do not proceed to Phase 6 (INTEGRATE) until Phase 5 (human review
workflow) also has a real answer, or the operator explicitly accepts a
partial-coverage integration.**

## Phase 4 — CANARY generation. **Blocked on Phase 5.**

Per Section 39: once fixture coverage and the adapter both exist,
generate AFTER-quality versions of one Qilin report, one MedusaLocker
report, one other ransomware actor, and CVE-2025-62593 into a
**non-production canary location** — never overwriting anything System 1
or System 2 currently publishes. This is a read-only proof step: it
demonstrates end-to-end System 3 → System 5 → rendered product without
any customer-facing surface changing.

## Phase 5 — Human review workflow. **Design only — no production
process wired yet.**

`human_review.ReviewRecord` and `resolve_certification_state()` are
built and tested, but there is no operational process yet for a human
analyst to actually produce a `ReviewRecord` against a real canary
artifact (who reviews, where the approval is recorded, how the artifact
hash is computed and delivered to the reviewer). This is intentionally
sequenced after Phase 4 — reviewing a canary report is the first
realistic exercise of this workflow; building the process against zero
real artifacts would be speculative.

## Phase 6 — GO/NO-GO checkpoint

Before any ReportX-gated bundle reaches an existing production writer
path or a paying customer, present the operator with:

- Fixture coverage (target: 10/10, or an explicit operator acceptance of
  partial coverage with named gaps)
- Full `Sentinel-APEX/engine` test suite result (0 regressions)
- At least one canary report that reaches `PREMIUM_CERTIFIED` end-to-end
  through a real (not `is_test_only_fixture=True`) review
- Confirmation that System 1/System 2/System 4 continue operating
  unmodified (Architecture Preservation Rule — this is an addition, not
  a cutover)
- The 23-row commercial-readiness matrix for each canary report

**No row in this checklist may be marked complete without the evidence
behind it, per this repository's CLAUDE.md "Proof Before Change" and
"God-Mode Release Gate" requirements.** This runbook does not authorize
Phase 7 by itself — it documents what Phase 7 requires when the operator
chooses to proceed.

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
| 1 — Build System 3 | Done (492/492 Python tests) |
| 2 — Golden fixtures | Done, 10/10 (139 acceptance tests) |
| 3 — System 5 adapter | Done (20/20 new JS tests; full JS suite 1620/1620) |
| 4 — Canary generation | Blocked on Phase 5 |
| 5 — Human review workflow | Design only |
| 6 — GO/NO-GO checkpoint | Not reached |
| 7 — Integrate | Not authorized |
| 8 — Observe | N/A |
