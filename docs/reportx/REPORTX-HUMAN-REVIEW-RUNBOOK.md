# ReportX Human Review Runbook

**Scope note:** this document covers approving one artifact. A real
`APPROVE` recorded here on all four canaries is also the precondition for
`REPORTX_RELEASE_CERTIFIED` (`REPORTX-RELEASE-CERTIFICATION.md`), which in
turn is what lets *future, non-canary* reports earn
`PREMIUM_AUTOMATED_CERTIFIED` without individual human review
(`REPORTX-AUTOMATED-CERTIFICATION.md`) — but that scaling mechanism never
changes what `PREMIUM_CERTIFIED` means here: an exact artifact, reviewed by
a real human, exactly as this document describes.

The one manual step in the entire ReportX pipeline. Everything up to
`PREMIUM_READY_PENDING_HUMAN` is engineering — automated gates,
evidence hashing, contradiction detection, depth assessment. Everything
from `PREMIUM_READY_PENDING_HUMAN` to `PREMIUM_CERTIFIED` requires a real
human analyst, and only that.

**No production process previously existed for this step** (per
`REPORTX-ROLLOUT-RUNBOOK.md`'s original Phase 5: "design only"). This
document is that process, exercised against four real canary artifacts —
the first realistic exercise of this workflow, per that same phase's own
stated sequencing rationale.

## What the reviewer is approving

Not code. Not a Python object. A real, rendered intelligence product: the
exact Markdown text in `bundle.rendered_text`, hashed to a SHA-256
(`human_review.compute_artifact_hash`). Approving that hash is what
`ReviewRecord.artifact_sha256` binds to — not the report ID, not a
version number. **Any change to the artifact text, including a single
whitespace character, produces a different hash and silently invalidates
any prior approval** (`human_review.is_review_valid_for_artifact`,
enforced by `resolve_certification_state()`, not by reviewer discipline).

## Reviewer pack

Before approving anything, read the reviewer pack — not the source code.
Generated via `reportx-review inspect`, one per canary, at
`reportx-canary/exports/<report-id>-REVIEWER-PACK.md`. Contains: the
report ID, artifact hash, the full 23-control matrix, every source with
its reliability tier, every material claim with its evidence links and
corroboration state, the metrics registry, regulatory determinations,
detection status, forecasts, alternative hypotheses, known intelligence
gaps, and the render-preview path (the actual PDF, per
`reportx-canary/render-qa/`). This is deliberately everything Section 10
of the commercial-readiness spec requires a reviewer to have without
reading raw code.

## Commands

Run from `Sentinel-APEX/engine/`. All four commands are already wired
into `cli.py`'s `reportx-review` subcommand — nothing here is new
tooling, this section documents existing commands operationally.

### Inspect (repeatable, non-destructive, safe for anyone)

```bash
python3 cli.py reportx-review inspect ../../reportx-canary/exports/<report-id>-export.json \
  --render-preview reportx-canary/render-qa/<report-id>-PREVIEW.pdf \
  --out ../../reportx-canary/exports/<report-id>-REVIEWER-PACK.md
```

### Approve — THE ONLY WAY TO REACH `PREMIUM_CERTIFIED`

**Must be run by the actual human reviewer, using their own real name.**
Never run this on a reviewer's behalf, never with a placeholder identity,
never automated. `--reviewer` is a required argument with no default —
the CLI will not run without a real value supplied.

```bash
python3 cli.py reportx-review approve ../../reportx-canary/exports/<report-id>-export.json \
  --reviewer "Full Name" \
  --role "Senior CTI Analyst" \
  --comments "Optional review notes" \
  --out ../../reportx-canary/exports/<report-id>-REVIEW-RECORD.json
```

### Reject / Request changes

Same shape, different action name:

```bash
python3 cli.py reportx-review reject ../../reportx-canary/exports/<report-id>-export.json \
  --reviewer "Full Name" --comments "Why" \
  --out ../../reportx-canary/exports/<report-id>-REVIEW-RECORD.json

python3 cli.py reportx-review request-changes ../../reportx-canary/exports/<report-id>-export.json \
  --reviewer "Full Name" --comments "What needs to change" \
  --out ../../reportx-canary/exports/<report-id>-REVIEW-RECORD.json
```

Neither `reject` nor `request-changes` ever resolves to
`PREMIUM_CERTIFIED`, regardless of whose name is on it or which artifact
hash it's bound to — verified directly against a real canary artifact
this session (see the commit history for the concrete before/after
certification-state proof), not just the pre-existing unit test.

## Exact commands for the four real canaries

```bash
cd Sentinel-APEX/engine

# Canary A — Qilin / Spoonful of Comfort
python3 cli.py reportx-review approve ../../reportx-canary/exports/qilin-spoonful-of-comfort-premium-canary-export.json \
  --reviewer "<REAL NAME>" --role "<REAL ROLE>" \
  --out ../../reportx-canary/exports/qilin-spoonful-of-comfort-premium-canary-REVIEW-RECORD.json

# Canary B — MedusaLocker / Bija Industrie
python3 cli.py reportx-review approve ../../reportx-canary/exports/medusalocker-bija-industrie-premium-canary-export.json \
  --reviewer "<REAL NAME>" --role "<REAL ROLE>" \
  --out ../../reportx-canary/exports/medusalocker-bija-industrie-premium-canary-REVIEW-RECORD.json

# Canary C — DragonForce / Vermont XCenter
python3 cli.py reportx-review approve ../../reportx-canary/exports/dragonforce-vermont-xcenter-premium-canary-export.json \
  --reviewer "<REAL NAME>" --role "<REAL ROLE>" \
  --out ../../reportx-canary/exports/dragonforce-vermont-xcenter-premium-canary-REVIEW-RECORD.json

# Canary D — CVE-2025-62593 (Ray)
python3 cli.py reportx-review approve ../../reportx-canary/exports/cve-2025-62593-ray-canary-export.json \
  --reviewer "<REAL NAME>" --role "<REAL ROLE>" \
  --out ../../reportx-canary/exports/cve-2025-62593-ray-canary-REVIEW-RECORD.json
```

Replace `<REAL NAME>`/`<REAL ROLE>` with the actual reviewer's identity.
No default is assumed or should be assumed.

## After a real approval — mandatory re-verification

Do not treat a written `REVIEW-RECORD.json` as final. Re-derive
certification state from the artifact and the review record together,
every time:

```bash
python3 -c "
import json
from sentinel_engine.reportx.human_review import ReviewRecord, ReviewDecision, resolve_certification_state

with open('<REVIEW-RECORD.json>') as f: r = json.load(f)
with open('<export.json>') as f: export = json.load(f)

review = ReviewRecord(
    report_id=r['report_id'], artifact_sha256=r['artifact_sha256'],
    reviewer_identity=r['reviewer_identity'], review_timestamp=r['review_timestamp'],
    decision=ReviewDecision(r['decision']), review_version=r['review_version'],
    notes=r['notes'], is_test_only_fixture=r['is_test_only_fixture'],
    reviewer_role=r['reviewer_role'], gate_snapshot_sha256=r['gate_snapshot_sha256'],
)
state = resolve_certification_state(True, True, review, export['bundle']['rendered_text'])
print(state.value)
assert state.value == 'PREMIUM_CERTIFIED', 'approval did not resolve to certified -- investigate before treating this as final'
"
```

If the artifact was touched in any way after the review was recorded
(even a re-export with identical intended content — whitespace
normalization, re-serialization, anything), this will correctly report
`PREMIUM_READY_PENDING_HUMAN`, not `PREMIUM_CERTIFIED`. That is not a
bug to work around — it is Section 44's governance rule holding. Get a
fresh approval against the current artifact hash instead.

## What this runbook does not authorize

Reaching `PREMIUM_CERTIFIED` on all four canaries does not, by itself,
authorize:
- Production writer integration (System 1/System 2 cutover)
- Any change to live API routes or scheduled jobs
- Bulk historical regeneration of past reports

Those require the separate GO/NO-GO checkpoint in
`REPORTX-ROLLOUT-RUNBOOK.md` Phase 6, with explicit operator
authorization for Phase 7 (INTEGRATE).
