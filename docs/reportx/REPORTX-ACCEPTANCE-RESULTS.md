# ReportX Acceptance Results

Section 36's before/after delta table, for real, this session — every
number below is reproducible tool output, not a summary written from
memory. Reproduce the whole set with:

```bash
cd Sentinel-APEX/engine
python3 -m pytest tests/reportx/test_acceptance_*.py -v   # 139 tests across all 10 fixtures
```

Golden fixtures live in `tests/fixtures/reportx-commercial-readiness/`
(repo root); each fixture module's own docstring names its real sources
(WebSearch/WebFetch, retrieved 2026-08-17/18) — this document does not
repeat citations, only results.

---

## CVE-2025-62593 (Ray) — the one BEFORE/AFTER defect-catalog pair

This is the only fixture pair with a deliberately broken BEFORE version,
reconstructing every named defect class from Sections 4/8/35 side by side
with a clean AFTER version, so the delta itself is the evidence the
validator works.

| | BEFORE | AFTER |
|---|---|---|
| Commercial-readiness matrix | **7 / 23 PASS** | **14 / 23 PASS** |
| Verdict | NOT COMMERCIAL-READY | NOT COMMERCIAL-READY (see note) |
| Evidence hash | FAIL | FAIL (no `content_sha256` captured for either — a real, shared limitation, not a defect unique to BEFORE) |
| Cross-source corroboration | FAIL | PASS |
| Cross-section consistency | FAIL | PASS |
| Regulatory specificity | FAIL | PASS |
| Technical recommendations | FAIL | PASS |
| Detection evidence discipline | FAIL | BLOCKED (no rules rendered in AFTER at all, vs. BEFORE's rules with false "production-validated" language) |
| Temporal integrity | FAIL (a date-only source wearing `EXACT_TIMESTAMP` precision) | PASS |
| Grammar/synthesis QA | FAIL | PASS |
| Forecast methodology | FAIL | PASS |
| Source-specific facts | PASS | **FAIL** (see note below — AFTER's stricter completeness surfaces one gap BEFORE's looser construction didn't have) |
| 30-40 page premium depth | FAIL | FAIL (AFTER is intentionally short — proves defect-freedom, not premium length) |

**Note on AFTER not reaching 23/23:** AFTER is a *clean, defect-free*
fixture, not a *complete* one — it has no forecasts, no hypothesis set, no
detection rules, and no depth assessment, so five rows are honestly
`BLOCKED`. That is the correct behavior (see
`REPORTX-COMMERCIAL-READINESS-MATRIX.md`'s "why BLOCKED counts against
the roll-up") — a real 23/23 bundle exists (`test_commercial_readiness.py`)
and demonstrates the ceiling is reachable, but demonstrating "zero
fabricated defects" and demonstrating "every optional section is present"
are different claims, and this pair only makes the first one.

**Contradictions found:** BEFORE: several (the fixture reconstructs
Section 8's own motivating examples — CVSS "CONFIRMED" vs. exploitation
"NOT_ASSESSED" stated as certainty, an overclaimed detection state).
AFTER: 0.
**Two real test-file defects were found and fixed while building this
pair** (a malformed duplicate-assignment line; a fabricated-timestamp
test that embedded the fake value directly into `source_date`, masking
the very defect it was supposed to catch) — see git history for
`test_acceptance_ray_cve.py`.

---

## The 9 ransomware victim fixtures — AFTER-only

None of these reconstructs a BEFORE version. Rationale (stated in every
fixture's own docstring): the BEFORE/AFTER defect-catalog demonstration
already lives in the Ray CVE pair above. Each ransomware fixture's job is
different — prove the three-layer ransomware evidence model (victim
observation / actor-historical-context / generic-readiness), the
corroboration-state policy, and the individual gates all hold up against
**real, messy leak-site data**, not synthetic text. Two real bugs in the
engine itself were found this way (a corroboration double-count in
`claim_model.py`, a QA-linter false positive on "None of..." prose) — by
the first fixture, Qilin/Spoonful of Comfort — that 130+ hand-written unit
tests never exercised.

All 9 share three results, run identically for every fixture:

- **Contradictions found: 0** (all 9)
- **QA critical defects: 0** (all 9)
- **Temporal integrity: PASS** (all 9 — no source's claimed
  `EXACT_TIMESTAMP` precision outruns what its raw date string supports)
- **Detection evidence discipline: BLOCKED** (all 9 — none of these
  fixtures include a detection rule; there is nothing to overclaim)
- **Source-specific facts: FAIL** (all 9, and shared with the pre-existing
  Ray AFTER fixture) — every fixture includes an honestly-`UNKNOWN`,
  no-evidence claim asking "did a compromise actually occur here?"
  (`c-compromise-occurred-*`). `commercial_readiness.py`'s row-4 check
  currently flags any `OBSERVED` claim without evidence regardless of
  status, without the exemption `claim_support_matrix.py`'s own gate
  already grants to honestly-unresolved states. This is a known,
  consistent characteristic across every fixture in this set (not a
  per-fixture defect) — see "Open question" below.

| Fixture | Sources | Claims | Matrix (PASS/FAIL/BLOCKED) | Corroboration mix | Unsupported claims (beyond the shared `source_specific_facts` case) |
|---|---|---|---|---|---|
| Qilin / Spoonful of Comfort | 2 | 6 | 12/3/8 | SINGLE_SOURCE | none |
| Panzer / SAGASTA sro | 4 | 7 | 12/3/8 | SINGLE_SOURCE (two sources, differing specificity, kept as separate claims — not merged, not flagged as contradictory) | none |
| Qilin / Mulino Padano | 2 | 7 | 12/3/8 | SINGLE_SOURCE | none |
| MedusaLocker / Twal Family IT Lab | 3 | 6 | 11/4/8 | **MULTI_SOURCE_DEPENDENT** (two trackers syndicating the same post) | none |
| MedusaLocker / All Parts Dry Cleaning | 2 | 5 | 12/3/8 | SINGLE_SOURCE | none |
| Aurora / Lloyd Coils Europe | 4 | 6 | 12/3/8 | **MULTI_SOURCE_INDEPENDENT** (two non-syndicating sources agree on the corporate HQ) | none |
| DragonForce / Vermont XCenter | 3 | 7 | 11/4/8 | SINGLE_SOURCE, plus a VICTIM_STATEMENT-tier corroborating source for the business description | none |
| MedusaLocker / Idex Group | 2 | 6 | 10/5/8 | SINGLE_SOURCE | **1** — see below |
| MedusaLocker / Bija Industrie | 3 | 6 | 11/4/8 | SINGLE_SOURCE, plus a VICTIM_STATEMENT-tier corroborating source | none |

**Idex Group's one additional unsupported claim** is
`c-not-idex-corporation`, the fixture's own disambiguation claim
("this victim is NOT the unrelated, much larger IDEX Corporation") —
`status=ASSESSED` with no `evidence_refs`/`source_refs`, because its
epistemic basis is the *absence* of any connecting source, not a positive
citation. `claim_support_matrix.py`'s gate correctly flags this as an
assertive-state claim without evidence; it is not incorrect, it is a
genuine edge case the gate was never designed around (a claim whose whole
content is "no evidence connects X and Y"). Recorded honestly here rather
than reclassified to make the count prettier.

## Notable individual findings (not defects — the point of real data)

- **Panzer / SAGASTA sro**: two independent write-ups of the same
  leak-site post describe the claimed data differently ("46GB" vs.
  "internal documents and at least one password field"). The
  contradiction engine correctly does not flag this — differing
  specificity is not a directly opposed `EpistemicState`.
- **MedusaLocker / Twal Family IT Lab**: the tracker's own record shows
  this victim was "previously misidentified as Forces/forces.gc.ca" (a
  Canadian government entity) before being corrected to a personal home
  lab — captured as a `CONFIRMED` claim about the tracker's own
  correction, not the incident.
- **Aurora / Lloyd Coils Europe**: "Aurora" is a three-way overloaded
  name in public reporting (the 2026 leak-site group, a Go-based
  malware/infostealer sold since mid-2022, and an unrelated 2018
  "OneKeyLocker/Zorro" family). Represented as `UNKNOWN`, not resolved by
  assumption; no 2018-era TTPs are attributed to the 2026 group.
- **MedusaLocker / Idex Group**: a naive business-description search
  surfaces "IDEX Corporation" (S&P 500, ~9,000 employees) — an unrelated
  company. The fixture never borrows that profile for the actual,
  much-smaller leak-site victim.
- **MedusaLocker / Bija Industrie**: the victim's own site states it
  serves military aviation programs — real, self-stated context, but
  never escalated into a claim that military-specific data was
  exfiltrated (the leak-site post itself states only an email count).
- **Two cross-fixture anti-padding proofs** (Qilin pair, MedusaLocker
  triple): an honestly-labeled "Actor Historical Context" heading is
  never flagged for reused prose about the same real actor; the identical
  prose mislabeled under the incident-specific "Actor Analysis" heading
  is correctly flagged every time (`test_acceptance_qilin_mulino_padano.py`,
  `test_acceptance_medusalocker_all_parts.py`,
  `test_acceptance_medusalocker_bija.py`).

## Open question carried forward

`commercial_readiness.py` row 4 (`source_specific_facts`) and
`claim_support_matrix.py`'s gate implement two different completeness
policies for the same underlying question ("does this claim have its own
evidence?") — the matrix gate exempts honestly-unresolved states
(`UNKNOWN`/`NOT_ASSESSED`/etc.), row 4 does not. Every fixture in this set
carries exactly one deliberately-`UNKNOWN`, no-evidence claim
(`c-compromise-occurred-*`) that trips row 4 for that reason. This was
observed consistently enough across 10 independent, real fixtures that it
is a candidate for a follow-up decision (align row 4 with the matrix
gate's exemption, or accept the stricter behavior as intentional) rather
than a fixture-specific defect — flagged here rather than silently
patched, since changing gate behavior is a decision for the operator, not
something to slip in while building acceptance fixtures.
