# ReportX Release Certification

**Read this alongside:** `REPORTX-CANARY-CERTIFICATION.md` (the four real
canary artifacts this document's certification depends on),
`REPORTX-HUMAN-REVIEW-RUNBOOK.md` (how a canary reaches `PREMIUM_CERTIFIED`
in the first place), and `REPORTX-AUTOMATED-CERTIFICATION.md` (what a
certified release then unlocks for individual future reports).

## The problem this solves

Requiring a real human analyst to individually review and approve every
report does not scale to "high-volume continuously updated threat
intelligence." But turning human approval into a reusable credential —
letting one canary's `APPROVE` silently vouch for reports nobody reviewed —
would fabricate the very certification this platform's entire credibility
rests on.

**Release certification is the resolution, not a compromise between the
two:** a human analyst reviews a small, fixed, representative set of real
reports (the four canaries). That review certifies **the release** — the
literal, hashed engine code, renderer, and adapter that produced and
validated those four reports. It never certifies any report those
components produce afterward. A different mechanism —
`sentinel_engine.reportx.automated_certification` — decides, per report,
whether *this release's demonstrated correctness* extends to *this specific
new report*, using that report's own real evidence, never the canaries'.

## What `REPORTX_RELEASE_CERTIFIED` means

Computed by `sentinel_engine.reportx.release_certification.certify_release()`
as a strict boolean AND — every one of these must independently be true, or
the release is `NOT_CERTIFIED` with the exact reason recorded:

1. All four required canaries (`REQUIRED_CANARY_IDS`) are present.
2. Every one of them is a genuine 23/23 commercial-readiness PASS.
3. Every one of them resolves to `PREMIUM_CERTIFIED` — i.e. has a real,
   artifact-hash-bound `ReviewRecord` with `decision == APPROVE`, verified
   through the unmodified `human_review.resolve_certification_state()`.
   This function is never re-implemented here; release certification calls
   it, it does not second-guess it.
4. Every supplied regression-test suite result has zero failures.
5. Render QA passed.
6. System 5 integration tests passed.
7. Cross-canary anti-padding passed.
8. `npm audit` passed.

There is no partial credit and no manual override field — same discipline
`REPORTX-COMMERCIAL-READINESS-MATRIX.md` already documents for the 23-control
gate (`all(...)`, not `not any(FAIL)`).

## The manifest

`certify_release()` returns a `ReleaseCertificationManifest`
(`reportx-certification/releases/<release-id>.json` once written via
`reportx-release certify --out`) recording:

- `release_id`, `reportx_engine_version` (from
  `sentinel_engine.reportx.__version__`), `git_commit_sha`
- `component_hashes` — real SHA-256 of every tracked file's actual current
  bytes (`TRACKED_COMPONENT_PATHS`: the full System 3 claim/evidence/
  validator layer, System 4's renderer, System 5's adapter + composition
  engine). `claim_schema_version`, `quality_gate_version`,
  `commercial_validator_version`, `threat_schema_versions`,
  `renderer_version`, `system5_adapter_version` are convenience aliases
  into this same hash map — not a second, separately-maintained version
  scheme nobody remembers to bump.
- `dependency_lock_hash` — SHA-256 of `package-lock.json`, the one real
  lock file this repository has. The Python engine package is stdlib-only
  and carries no lock file of its own; that's a documented fact, not a gap
  papered over with a fabricated hash.
- `certified_canary_ids`, `certified_canary_artifact_hashes`,
  `certified_canary_review_record_hashes` — real hashes, recomputed from
  each canary's own `rendered_text` and `ReviewRecord`, never trusted from
  a stored value.
- `test_results`, `reviewer_identity` (the operator who ran release
  certification — a recorded, audited fact, not a gate condition), and
  `release_decision` (`NOT_CERTIFIED` / `REPORTX_RELEASE_CERTIFIED` /
  `REPORTX_RELEASE_REVIEW_REQUIRED`) with `failed_requirements`.

`ReleaseCertificationManifest.manifest_hash()` hashes the manifest's own
canonical serialization, so the certification record itself is
tamper-evident.

## Drift detection

A certified release stops being usable for automated certification the
moment any tracked component's real file content changes —
`detect_drift()` re-hashes every `TRACKED_COMPONENT_PATHS` entry against
the manifest's recorded hashes; `apply_drift_check()` flips
`REPORTX_RELEASE_CERTIFIED → REPORTX_RELEASE_REVIEW_REQUIRED` the instant
one differs, and records exactly which component changed. This is not a
version number someone forgot to bump — it is a real hash of real bytes,
checked fresh on every `reportx-release status`/`verify` call.

Release-health degradation (`release_health.apply_health_degradation`) can
trigger the same transition independently — see
`REPORTX-RISK-BASED-HUMAN-REVIEW.md`.

## CLI

All new, additive subcommands on the existing `cli.py` — nothing here is a
new, uncontrolled script:

```bash
cd Sentinel-APEX/engine

# Certify a release from the four real canary exports (requires each to
# already have a real ReviewRecord -- see REPORTX-HUMAN-REVIEW-RUNBOOK.md)
python3 cli.py reportx-release certify \
  --release-id reportx-p0-YYYY-MM-DD \
  --canary ../../reportx-canary/exports/qilin-spoonful-of-comfort-premium-canary-export.json \
  --canary ../../reportx-canary/exports/medusalocker-bija-industrie-premium-canary-export.json \
  --canary ../../reportx-canary/exports/dragonforce-vermont-xcenter-premium-canary-export.json \
  --canary ../../reportx-canary/exports/cve-2025-62593-ray-canary-export.json \
  --test-result "engine:754:0" --test-result "js:1688:0" \
  --render-qa pass --system5-tests pass --anti-padding pass --npm-audit pass \
  --reviewer "Full Name" \
  --out ../../reportx-certification/releases/reportx-p0-YYYY-MM-DD.json

# Inspect / live drift check (read-only) / live drift check (persists) / force-invalidate
python3 cli.py reportx-release inspect  <manifest.json>
python3 cli.py reportx-release status   <manifest.json>
python3 cli.py reportx-release verify   <manifest.json>
python3 cli.py reportx-release invalidate <manifest.json> --reason "..."
```

`reportx-release certify` auto-discovers each canary's `ReviewRecord` from
a sibling `<report-id>-REVIEW-RECORD.json` next to its export file (the
exact filename `REPORTX-HUMAN-REVIEW-RUNBOOK.md`'s `approve` commands
already write to). It never constructs a `ReviewRecord` itself.

## Today's actual state

As of this document, **no real `ReviewRecord` exists anywhere in this
repository** for any of the four canaries — confirmed by searching every
branch for `*-REVIEW-RECORD.json` files and checking each canary export's
`bundle.review` field (all `null`). Running `reportx-release certify`
against the real exports today, honestly, produces:

```
RELEASE DECISION: NOT_CERTIFIED

Failed requirements:
  - canaries not PREMIUM_CERTIFIED: [... all four, each PREMIUM_READY_PENDING_HUMAN ...]
```

This is the correct output, not a defect — see
`REPORTX-HUMAN-REVIEW-RUNBOOK.md` for the exact commands the real operator
runs to change it.

## What release certification does NOT authorize

Identical to `REPORTX-HUMAN-REVIEW-RUNBOOK.md`'s own closing section, and
worth repeating here since this document is the more "automatable"-sounding
of the two: reaching `REPORTX_RELEASE_CERTIFIED` does not, by itself,
authorize production writer integration (System 1/System 2 cutover), any
change to live API routes or scheduled jobs, or bulk historical
regeneration of past reports. Those require the separate GO/NO-GO
checkpoint in `REPORTX-ROLLOUT-RUNBOOK.md` Phase 6/7.
