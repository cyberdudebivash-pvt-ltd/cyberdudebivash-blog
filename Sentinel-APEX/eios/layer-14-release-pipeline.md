# EIOS LAYER 14 — ENTERPRISE RELEASE PIPELINE

Models publication as a governed workflow with named approval gates. This is
the **governance/approval view** of the same process `pipeline/WORKFLOW.md`
already documents as the **file-system/operational view**. Two views, one
process — do not treat these as competing pipelines, and do not move a
report through directories without also updating its `review_status`
(Layer 8).

## Stage mapping

| EIOS release stage | `WORKFLOW.md` operational stage | `review_status` value (Layer 8) |
|---|---|---|
| Draft | Stage 4 — Draft | `draft` |
| Technical Review | *(part of Stage 4/5 — analyst self-check before gate)* | `technical-review` |
| Detection Review | *(part of Stage 5 — Quality Gates, detection-specific)* | `detection-review` |
| Intelligence Review | *(part of Stage 5 — Quality Gates, analytical-discipline-specific)* | `intelligence-review` |
| Editorial Review | *(part of Stage 5, plus Layer 13)* | `editorial-review` |
| Rendering Validation | *(new — see EICF v1 below)* | *(no dedicated status — folds into Certification)* |
| Executive Approval | *(new — no current WORKFLOW.md equivalent)* | `executive-approval` |
| Certification | *(new — see EICF v1 below)* | *(no dedicated status — the gate immediately before Publication)* |
| Publication | Stage 8 — Publish & Distribute | `published` |
| Continuous Monitoring | *(new — see Layer 11)* | `published` (unchanged; monitoring doesn't change status) |
| Update or Retirement | *(new — archive/ on supersession)* | new report: `draft`; old report: archived, `review_status` frozen at whatever it was |

Technical / Detection / Intelligence / Editorial Review are one pass through
`quality/quality-gate.md`'s eight sections in practice — this layer names
them separately because a report can fail on detection-content validity
(Layer 4) while passing analytical discipline, and naming the specific
review that failed makes the return-to-draft loop faster than a single
undifferentiated "quality gate failed."

## Executive Approval — the one genuinely new gate

Neither `WORKFLOW.md` nor `quality-gate.md` currently has an explicit
sign-off step between "passed quality gate" and "published." This matters
specifically for reports that name a victim organization, make a
attribution claim likely to draw a response, or cross a disclosure
threshold (Layer 5's Board Summary criteria). Not every report needs this
gate — a routine CVE advisory does not — but the pipeline should make the
decision to skip it explicit (`review_status` jumping straight from
`editorial-review` to `published`) rather than silently absent.

## Rendering Validation and Certification — EICF v1

Two more genuinely new stages, added when the Enterprise Intelligence
Certification Framework (EICF v1) formalized what "passed quality gate"
actually needs to mean once a canonical renderer (Layer 4 predates
`Sentinel-APEX/renderer/`; see `platform/open-issues.md` Issue 5) and a
first real publication (`SA-2026-0001`) both existed to certify against.

**Rendering Validation** did not exist as a named stage before because
nothing rendered a report for a reader before EIRE v1 — Layer 4's quality
gate audits *content*, never whether that content actually turns into
correct HTML (tables intact, fenced code intact, no raw heading markers
leaking through). It is not its own human review step; it is a mechanical
check (`Sentinel-APEX/renderer/certify-rendering.js`) that runs as part of
Certification below, named separately here for the same reason Technical/
Detection/Intelligence Review are named separately: so a rendering failure
reads as "rendering failed," not an undifferentiated gate failure.

**Certification** is the single gate that actually produces a scorecard:
`python3 cli.py certify <report.md> [--html --sitemap --index]`
(`Sentinel-APEX/engine/sentinel_engine/certification.py`) composes the
existing quality gate (Technical/Detection/Intelligence Review, bucketed
into Intelligence/Evidence/Detection Quality domains), the rendering check
above, and — when the report is already live — a Publication Quality check
against the shipped HTML/sitemap/index files. It re-implements none of
these; it buckets their existing findings into a qualitative Pass / Needs
Review / Fail / Not Applicable scorecard per domain and emits a Release
Governance Markdown record (Executive Summary through Certification
Decision). A report with any domain at Fail is **NOT CERTIFIED** — the
`review_status` progression above must not reach `published` until
re-certified. "Not Applicable" (e.g. Publication Quality before a report
has ever been published) is not a failure; it means that domain was not yet
checkable, not that it passed.

## Retirement

A report is retired (not deleted) when: it is superseded (Layer 8
`supersedes` chain), its detection content's underlying technique is
confirmed abandoned by the tracked actor, or its CVE is fully remediated
industry-wide with no continuing exploitation. Retirement moves the file to
`archive/` per `docs/CONVENTIONS.md` with the date appended — the existing
mechanism, unchanged.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 14*
