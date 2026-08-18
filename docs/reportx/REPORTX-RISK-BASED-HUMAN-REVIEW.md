# ReportX Risk-Based Human Review (Quality Sampling + Release Health)

**Read this alongside:** `REPORTX-AUTOMATED-CERTIFICATION.md` (what gets
sampled) and `REPORTX-RELEASE-CERTIFICATION.md` (the release state
sampling can ultimately force back to review-required).

## What sampling is for, and what it is explicitly not for

Sampling (`sentinel_engine.reportx.quality_sampling`) exists to **monitor**
automated-certification quality over time and catch drift a per-report gate
alone wouldn't — it does not, and structurally cannot, grant any report a
certification state it didn't otherwise earn.

That guarantee is enforced structurally, not by convention:
`quality_sampling.py` imports neither `human_review`, `automated_certification`,
nor `release_certification` — verified directly in
`test_quality_sampling.py::TestSamplingModuleIsStructurallyIsolatedFromCertification`,
which inspects the module's actual `import`/`from` lines. There is no code
path in this package by which recording a `SampleOutcome` — including one
with `defect_found=True` — changes a `CertificationState` computed before or
after it.

## Deterministic, reproducible sampling

`should_sample(report_id, config, risk_factors)` draws from
`sha256(report_id)` rather than an unseeded RNG, so "was this report
sampled" is independently re-derivable by anyone re-running the same
`SamplingConfig` against the same `report_id` — no hidden seed to lose.

`SamplingConfig` fields (all from the P0 task's own list):
`sample_percentage`, `minimum_samples_per_family`,
`minimum_samples_per_release_interval`, `high_risk_weight`,
`new_actor_weight`, `new_vulnerability_weight`. `RiskFactors`
(`is_high_risk`, `is_new_actor`, `is_new_vulnerability`) multiply the base
sampling rate; the result is capped at 1.0, never silently over 100%.

## Sample outcomes are telemetry, not certification input

`SampleOutcome(report_id, sampled_at, reviewer, defect_found, notes)` is
recorded by whoever performs the real human QA pass on a sampled report —
this package provides the record shape and `sample_defect_rate()`, not a
CLI action that pretends to BE the review (the real review, if a sample
surfaces one, is the existing `reportx-review` workflow —
`REPORTX-HUMAN-REVIEW-RUNBOOK.md` — same as any other human review).

## Release health

`sentinel_engine.reportx.release_health.aggregate_health()` rolls up:

- `reports_processed`, `premium_automated_certified`, `human_escalations`,
  `downgrades` — from real `AuditLogRecord` history
  (`sentinel_engine.reportx.audit_log`, append-only).
- `control_failures`, `contradictions_detected`, `unsupported_claims_blocked`,
  `source_integrity_failures` — from the real per-control `ControlResult`
  lists a caller supplies for the reports it processed (never string-parsed
  out of a free-text reason field, which would be a guess dressed up as a
  metric).
- `human_qa_samples`, `human_qa_defect_rate` — from real `SampleOutcome`
  history.

`check_degradation_threshold()` compares the rollup against
`DegradationThresholds` (escalation rate, control-failure rate, human-QA
defect rate — all configurable, sane non-zero defaults). When any threshold
trips, `apply_health_degradation()` flips a `REPORTX_RELEASE_CERTIFIED`
manifest to `REPORTX_RELEASE_REVIEW_REQUIRED` — the exact same transition
`release_certification.apply_drift_check()` performs for component drift,
triggered here by accumulated quality signal instead of file-content
change. A release that isn't currently certified has nothing to degrade
away from, so it passes through unchanged (mirrors
`apply_drift_check()`'s own no-op-on-uncertified behaviour).

## What this layer does not do

- It does not decide which specific reports a human ultimately reads beyond
  what `should_sample()` flags — that remains an operational process
  outside this package's scope.
- It does not replace `automated_certification.py`'s per-report escalation
  signals (Section 9) — those are evaluated at certification time, before a
  report is even eligible for `PREMIUM_AUTOMATED_CERTIFIED`. Sampling is a
  second, independent quality check that runs regardless of whether a
  report was escalated.
- It does not authorize production integration — same closing note as
  every other document in this set.
