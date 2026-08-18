# ReportX Automated Certification

**Read this alongside:** `REPORTX-RELEASE-CERTIFICATION.md` (the
precondition this document's entire mechanism depends on) and
`REPORTX-COMMERCIAL-READINESS-MATRIX.md` (the 23-control gate every
decision below reads from, never recomputes).

## The one invariant that matters most

> `PREMIUM_AUTOMATED_CERTIFIED` means this exact report cleared 23/23 under
> a currently `REPORTX_RELEASE_CERTIFIED` release with zero escalation
> signals. **It does not mean a human read this report.**

Never render it, describe it, or log it as "human reviewed," "analyst
approved," or `PREMIUM_CERTIFIED`. Those three phrases are reserved,
permanently, for a real `ReviewRecord` resolved through
`human_review.resolve_certification_state()`. See "The two rendered
blocks" below for how that separation is enforced in output, not just in
prose.

## Structural guarantee, not a convention

`sentinel_engine.reportx.automated_certification` never imports
`ReviewRecord` and never constructs one — checked directly in
`test_automated_certification.py::TestAutomatedCertificationNeverCreatesAReviewRecord`,
which inspects the module's actual source for a `ReviewRecord(` construction
call. Automated certification and human review are two disjoint code paths
that happen to write into the same `CertificationState` vocabulary
(`human_review.py`'s enum, extended with one new additive member,
`PREMIUM_AUTOMATED_CERTIFIED` — every pre-existing member and every
pre-existing function in that file is untouched).

## The algorithm

`certify_report_automated()` implements the P0 task's pseudo-contract
literally:

```
if release is None or not release.is_certified:
    refuse -> PREMIUM_READY_PENDING_HUMAN

elif release has drifted since certification (release_certification.detect_drift):
    refuse -> PREMIUM_READY_PENDING_HUMAN  (Section 8: escalate to human review)

elif this report's own 23-control result != 23/23:
    fail-closed downgrade via tier_downgrade.determine_achieved_tier()
    -> PUBLIC_REFERENCE_DRAFT / TACTICAL_READY / FLASH_READY, never PREMIUM_AUTOMATED_CERTIFIED

elif escalation_reasons is non-empty:
    -> PREMIUM_READY_PENDING_HUMAN

else:
    -> PREMIUM_AUTOMATED_CERTIFIED
```

A canary's approval never reaches this function at all — there is no
parameter through which one could. The only certified input is the
release's own component hashes and this report's own real `ControlResult`
list.

## Fail-closed downgrade, not disappearance

A report that doesn't clear 23/23 is not discarded — `tier_downgrade.py`
computes which of the existing `CertificationState` tiers it actually
earned, from its real control results:

| Situation | Achieved tier |
|---|---|
| Any correctness control (`cross_section_consistency`, `source_specific_facts`, `evidence_hash`, `victim_specific_analysis`, ...) FAILED | `PUBLIC_REFERENCE_DRAFT` — content itself is unreliable, not just incomplete. No higher tier is fail-closed-safe. |
| Correctness clean, but a premium-completeness control (`forecast_methodology`, `alternative_hypotheses`, `premium_depth`, `regulatory_specificity`, ...) is FAILED/BLOCKED | `TACTICAL_READY` |
| Correctness clean, reasonably complete, but not a full 23/23 | `FLASH_READY` |
| 23/23 | requested tier, unchanged |

Nothing in this ladder ever manufactures a passing control or borrows
evidence from a different one to preserve a higher tier — see
`test_tier_downgrade.py`'s `TestNeverManufacturesAHigherTierThanRequested`.

## Escalation signals

`EscalationReason` names all 14 categories from the P0 task. Three are
**derived automatically today**, reusing existing gates rather than
re-implementing them:

| Signal | Reused from |
|---|---|
| `DETECTION_STATE_PROMOTION` | `detection_validation.check_all_rules()` |
| `SOURCE_INTEGRITY_FALLBACK_THRESHOLD` | `evidence_integrity.evaluate_source_integrity_gate()` |
| `CROSS_REPORT_SIMILARITY_ANOMALY` | `product_depth.find_template_repetition()` |

The remaining 11 (`NOVEL_THREAT_TYPE`, `CRITICAL_ATTRIBUTION`,
`CONFIDENCE_ANOMALY`, `EXTREME_SEVERITY`, ...) are inherently analyst/
product judgment calls this data model has no honest signal to derive them
from today. `EscalationReason` still names the full vocabulary so a human
reviewer, an upstream classifier, or a future gate can supply them as
`certify_report_automated()` input without inventing a new one later.
Wiring fabricated detection logic for a signal the system genuinely cannot
see would violate the same non-fabrication discipline that governs claims
and evidence elsewhere in this platform — so this module does not pretend
to detect what it cannot.

## The two rendered blocks

Section 12's literal templates, implemented as
`render_automated_certification_block()` and
`render_human_reviewed_certification_block()`:

```
Certification:
CYBERDUDEBIVASH SENTINEL APEX REPORTX
AUTOMATED PREMIUM CERTIFIED

Commercial Readiness:
23/23 PASS

Release:
<release-id>

Human Review:
NOT INDIVIDUALLY HUMAN REVIEWED
```

```
Certification:
CYBERDUDEBIVASH SENTINEL APEX REPORTX
PREMIUM CERTIFIED

Commercial Readiness:
23/23 PASS

Human Review:
APPROVED

Reviewer:
<actual reviewer>

Artifact:
<hash prefix>
```

`test_automated_certification.py::TestAutomatedReportNeverSaysHumanReviewed`
asserts the automated block never contains "HUMAN REVIEWED" as a positive
claim, "ANALYST APPROVED", or the string "PREMIUM_CERTIFIED", and that
the two templates share none of their defining language.

## CLI

```bash
cd Sentinel-APEX/engine

python3 cli.py reportx-certify <export.json> --release-manifest <manifest.json> [--audit-log log.jsonl]
python3 cli.py reportx-certify batch <directory> --release-manifest <manifest.json> [--audit-log log.jsonl]
```

Every decision, with `--audit-log`, is appended (never overwritten — see
`sentinel_engine.reportx.audit_log`, whose only write function opens in
`"a"` mode) as an `AuditLogRecord`: report id, artifact hash, release id,
timestamp, the real `N/23` control count, the resolved certification
state, and the escalation/downgrade reason if any.

## Today's actual state

`reportx-certify` against the real exports today correctly refuses on
every one of them, for the same reason `REPORTX-RELEASE-CERTIFICATION.md`
documents: no release is currently `REPORTX_RELEASE_CERTIFIED` (no
canary has a real `ReviewRecord` yet). This is by design — automated
certification cannot exist before release certification does.
