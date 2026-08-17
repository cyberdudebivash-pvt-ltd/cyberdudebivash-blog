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

## Phase 2 — VERIFY via golden fixtures. **2 of 10 complete.**

`tests/fixtures/reportx-commercial-readiness/` (repo root) holds one
BEFORE/AFTER pair per named acceptance case, built from real
WebSearch/WebFetch research — never from model memory. Complete:
CVE-2025-62593 (Ray) and Qilin/Spoonful of Comfort. The Qilin fixture
alone found and fixed two real bugs in System 3 (a corroboration-count
double-count in `claim_model.py`, a QA-linter false positive on
legitimate "None of..." prose) — direct evidence for why this phase
exists before Phase 3, not after: messy real-world data exercises paths
hand-written unit tests miss.

Remaining 8 (Panzer/SAGASTA sro, Qilin/Mulino Padano,
MedusaLocker/Twal Family IT Lab, MedusaLocker/All Parts Dry Cleaning,
Aurora/Lloyd Coils Europe, DragonForce/Vermont XCenter,
MedusaLocker/Idex Group, MedusaLocker/Bija Industrie) each need the same
treatment: real research, `NOT_ASSESSED`/`UNKNOWN` for anything genuinely
unconfirmable, `BLOCKED` (not a guess) for anything unfetchable.

**Do not proceed to Phase 6 (INTEGRATE) until this phase is complete or
the operator explicitly accepts a partial-coverage integration.**

## Phase 3 — ADAPT: System 5 JS adapter. **Not started (task #44).**

System 5 must consume System 3's validated `EvidenceGraph`, never
reimplement it. The interchange point already exists on the System 3
side: `bundle_io.bundle_from_dict()` / the inverse (a `to_dict()` export)
define a plain-JSON shape for a `ReportBundle` — sources, evidence,
claims, metrics, detection rules, regulatory determinations, forecasts,
hypothesis sets, intelligence gaps, review record, depth assessment.

**Known gap to close before this phase can start:** `bundle_from_dict()`
does not yet deserialize `threat_products` (the `RansomwareVictimClaim` /
`CVERecord` / `CISAKEVRecord` layer) — the two completed fixtures work
around this by constructing the bundle directly in Python
(`qilin_spoonful_of_comfort.py`) rather than round-tripping through JSON.
A JS consumer needs a real JSON shape for `threat_products`, so extending
`bundle_from_dict()`/a matching `to_dict()` with that coverage is this
phase's first task, not an afterthought.

Planned shape of the adapter itself: a Python-side export step
(`reportx-gate` extended with an `--export-graph` flag, or a new
`reportx-export` subcommand) produces the validated JSON bundle;
`api/_lib/` gets a new adapter module (not a rewrite of
`product-composition-engine.js` — Principle 2, additive) that reads that
JSON and maps `EvidenceGraph`/`ControlResult` data into whatever shape
the existing product-composition phases already expect, the same way any
other upstream data source is consumed today. System 5 never re-derives
`CorroborationState`, `EpistemicState`, or gate pass/fail — those values
are read, not recomputed, in JS.

## Phase 4 — CANARY generation. **Blocked on Phases 2 and 3.**

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
| 1 — Build System 3 | Done (349/349 tests) |
| 2 — Golden fixtures | 2/10 (Ray CVE, Qilin/Spoonful of Comfort) |
| 3 — System 5 adapter | Not started |
| 4 — Canary generation | Blocked on 2, 3 |
| 5 — Human review workflow | Design only |
| 6 — GO/NO-GO checkpoint | Not reached |
| 7 — Integrate | Not authorized |
| 8 — Observe | N/A |
