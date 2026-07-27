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
| Executive Approval | *(new — no current WORKFLOW.md equivalent)* | `executive-approval` |
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

## Retirement

A report is retired (not deleted) when: it is superseded (Layer 8
`supersedes` chain), its detection content's underlying technique is
confirmed abandoned by the tracked actor, or its CVE is fully remediated
industry-wide with no continuing exploitation. Retirement moves the file to
`archive/` per `docs/CONVENTIONS.md` with the date appended — the existing
mechanism, unchanged.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 14*
