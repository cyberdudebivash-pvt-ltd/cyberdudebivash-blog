# ReportX Canary Certification

The real-world, non-synthetic proof this repository's `REPORTX-COMMERCIAL-READINESS-MATRIX.md`
explicitly says the 10 golden fixtures do not provide: four complete,
research-backed, evidence-hashed premium reports, each independently
clearing all 23 commercial-readiness controls.

**Read this alongside, not instead of:**
- `REPORTX-COMMERCIAL-READINESS-MATRIX.md` — the SYNTHETIC 23/23
  demonstration (`_build_fully_supported_bundle()`), which proves the
  gate itself is satisfiable; this document is the REAL 23/23
  certification the synthetic demonstration explicitly disclaimed.
- `REPORTX-HUMAN-REVIEW-RUNBOOK.md` — the operational review process that
  takes these four artifacts from `PREMIUM_READY_PENDING_HUMAN` to
  `PREMIUM_CERTIFIED`.
- `reportx-canary/render-qa/RENDER-QA-RESULTS.md` — System 4 render/print
  QA detail for all four.

## Source code

- `reportx-canary/qilin_spoonful_of_comfort_canary.py`
- `reportx-canary/medusalocker_bija_industrie_canary.py`
- `reportx-canary/dragonforce_vermont_xcenter_canary.py`
- `reportx-canary/cve_2025_62593_ray_canary.py`

Every canary's own module docstring is the authoritative source list and
research trail — this document summarizes; it does not replace reading
the module for the full evidentiary chain.

## Regression coverage

- `Sentinel-APEX/engine/tests/reportx_canary/test_qilin_canary.py` (26 tests)
- `Sentinel-APEX/engine/tests/reportx_canary/test_medusalocker_canary.py` (26 tests)
- `Sentinel-APEX/engine/tests/reportx_canary/test_dragonforce_canary.py` (25 tests)
- `Sentinel-APEX/engine/tests/reportx_canary/test_ray_canary.py` (21 tests)
- `Sentinel-APEX/engine/tests/reportx_canary/test_four_canary_anti_padding.py` (5 tests, cross-canary)
- `api/_lib/__tests__/reportx-adapter-four-canaries.test.js` (65 tests, System 5)

---

## Canary A — Qilin / Spoonful of Comfort

| Field | Value |
|---|---|
| Report ID | `qilin-spoonful-of-comfort-premium-canary` |
| Artifact SHA-256 | `213eec33d30d4062e183699deea477e330c004463786a15aa3a9e49e0e1d1d0a` |
| Sources | 5 (all full `content_sha256`, 0 excerpt-fingerprint fallback) |
| Claims / evidence records | 18 / 18 |
| Rendered words | 3,004 |
| Material claims (evidence-backed) | 17 |
| Evidence-backed sections | 17 |
| Detection rules | 1 (Sigma, `SYNTAX_VALIDATED`) |
| Forecasts / hypothesis sets / intel gaps | 1 / 2 / 7 |
| Regulatory determinations | 4 |
| **Commercial readiness** | **23 / 23 PASS — COMMERCIAL-READY** |
| Certification state | `PREMIUM_READY_PENDING_HUMAN` (no fabricated review) |
| Render QA | `checkRendering()` ok, 0 chrome issues, 17 sections, **21 real PDF pages** |
| System 5 | Composes a real `threat-actor-profile` product through the unmodified `ProductCompositionEngine`; actor name `Qilin`, aliases `['Agenda']` |

Sources: ransomware.live's leak-site post; Wikipedia's "Qilin (cybercrime
group)" article; MITRE ATT&CK S1242 (Qilin software profile), G1050
(Water Galura, the RaaS operators), and G1036 (Moonstone Sleet — actor-
ecosystem context only, never linked to this incident).

## Canary B — MedusaLocker / Bija Industrie

| Field | Value |
|---|---|
| Report ID | `medusalocker-bija-industrie-premium-canary` |
| Artifact SHA-256 | `4b986cdee8b3a17ecd567e4caf21a721fe0c75fc024207be06937d31da5436a8` |
| Sources | 5 (all full `content_sha256`, 0 excerpt-fingerprint fallback) |
| Claims / evidence records | 17 / 16 |
| Rendered words | 2,649 |
| Material claims (evidence-backed) | 16 |
| Evidence-backed sections | 16 |
| Detection rules | 1 (Sigma, `SYNTAX_VALIDATED`) |
| Forecasts / hypothesis sets / intel gaps | 1 / 2 / 7 |
| Regulatory determinations | 4 |
| **Commercial readiness** | **23 / 23 PASS — COMMERCIAL-READY** |
| Certification state | `PREMIUM_READY_PENDING_HUMAN` (no fabricated review) |
| Render QA | `checkRendering()` ok, 0 chrome issues, 16 sections, **20 real PDF pages** |
| System 5 | Composes a real `threat-actor-profile` product; actor name `MedusaLocker` |

Sources: ransomware.live's leak-site post and MedusaLocker group
aggregate page; the victim's own site (bija-industrie.com); the ic3.gov
mirror of CISA/FBI/Treasury/FinCEN Joint Cybersecurity Advisory AA22-181A
(cisa.gov itself 403-blocked both the advisory page and its own PDF);
Cybersecurity Dive's independent journalism on the same advisory, giving
genuine `MULTI_SOURCE_INDEPENDENT` corroboration of the 55-60% RaaS split.
Explicitly documents and avoids the unrelated MITRE ATT&CK "Medusa"
(S1244/G1051) naming collision.

## Canary C — DragonForce / Vermont XCenter

Selected over Aurora/Lloyd Coils Europe and Panzer/SAGASTA sro on
evidence quality — see the module's own docstring for the full,
evidence-driven selection rationale (Aurora carries two flagged identity-
ambiguity problems; Panzer's own golden fixture describes it as "a newly
observed operation" with no confirmed revenue split or multi-year track
record).

| Field | Value |
|---|---|
| Report ID | `dragonforce-vermont-xcenter-premium-canary` |
| Artifact SHA-256 | `4bac2b5c705835e4efb4f3f9c91863b1ac067ee088248a5b9940c04de577250b` |
| Sources | 5 (all full `content_sha256`, 0 excerpt-fingerprint fallback) |
| Claims / evidence records | 16 / 18 |
| Rendered words | 3,192 |
| Material claims (evidence-backed) | 15 |
| Evidence-backed sections | 17 |
| Detection rules | 1 (Sigma, `SYNTAX_VALIDATED`) |
| Forecasts / hypothesis sets / intel gaps | 1 / 2 / 7 |
| Regulatory determinations | 4 |
| **Commercial readiness** | **23 / 23 PASS — COMMERCIAL-READY** |
| Certification state | `PREMIUM_READY_PENDING_HUMAN` (no fabricated review) |
| Render QA | `checkRendering()` ok, 0 chrome issues, 17 sections, **21 real PDF pages** |
| System 5 | Composes a real `threat-actor-profile` product; actor name `DragonForce` |

Sources: ransomware.live's leak-site post and DragonForce group aggregate
page; the victim's own site (vermont.com.br); Group-IB's named-analyst
research (2024-09-25); Blackpoint Cyber's current (February 2026, 30-page)
threat profile. Two facts — the 80% affiliate split and the two-variant
malware lineage — are independently corroborated by both named CTI
vendors (`MULTI_SOURCE_INDEPENDENT`). A genuine, unresolved discrepancy
this session's own research surfaced (the tracker's earliest tracked
victim predates named-vendor discovery dating by ~10 months) is recorded
as an open intelligence gap, not silently resolved. The actor's own most
sensitive identity question — any link to the hacktivist group
"DragonForce Malaysia" — is carried as `UNKNOWN`, mirroring the vendor
source's own explicit "even chance ... has yet to be confirmed" framing.

## Canary D — CVE-2025-62593 (Ray)

| Field | Value |
|---|---|
| Report ID | `cve-2025-62593-ray-canary` |
| Artifact SHA-256 | `dde2c5ce3efe673ebb8a80e069ede5c713778bba422f7e34aa296b6b095e398a` |
| Sources | 7 (6 full `content_sha256`, 1 reasoned excerpt-fingerprint fallback — GHSA, access-blocked to direct fetch) |
| Claims / evidence records | 19 / 16 |
| Rendered words | 2,555 |
| Material claims (evidence-backed) | 19 |
| Evidence-backed sections | 16 |
| Detection rules | 1 (Sigma, `SYNTAX_VALIDATED`) |
| Forecasts / hypothesis sets / intel gaps | 1 / 1 / 3 |
| Regulatory determinations | 3 |
| **Commercial readiness** | **23 / 23 PASS — COMMERCIAL-READY** |
| Certification state | `PREMIUM_READY_PENDING_HUMAN` (no fabricated review) |
| Render QA | `checkRendering()` ok, 0 chrome issues, 16 sections, **20 real PDF pages** |
| System 5 | CVE-type product — correctly produces zero fabricated threat actors (`investigation.threatActors` stays `[]`; the engine's own `'Unknown'` fallback appears in `product.metadata.title`, not an invented name) |

Sources: NVD, the CISA KEV catalog entry, GHSA advisory (excerpt-
fingerprint fallback — access-blocked), the PyTorch Foundation's Ray
security advisory, MITRE ATT&CK T1190, and RondoDox actor-context
sources. No CISA KEV ransomware-campaign linkage is asserted (represented
`NOT_ASSESSED`, not guessed).

---

## Cross-canary regression gate

All four run together: **97/97 tests pass**
(`Sentinel-APEX/engine/tests/reportx_canary/`), full engine suite
**649/649**, full JS suite **1688/1748** (60 skipped, 0 failed).

## Cross-canary anti-padding

`test_four_canary_anti_padding.py` maps each canary's own section
headings onto `product_depth.py`'s canonical `INCIDENT_SPECIFIC_SECTIONS`
vocabulary (Forecast, Actor Analysis, Victimology) and runs pairwise
near-duplicate detection: **0 findings** across all four Forecast
sections, all four actor-context deep-dives, and all three ransomware
canaries' Victim Claim Record sections. A whole-document pairwise
similarity check confirms no two full reports are near-duplicates of each
other either. Full detail: see that test file directly.

## What none of the four claim

- No incident-specific IOC is asserted for any victim — every IOC-shaped
  claim is explicitly actor-historical/generic.
- No detection rule claims a validation tier beyond `SYNTAX_VALIDATED` —
  none was tested against lab or live telemetry this session.
- No forecast or hypothesis set fabricates confidence — every one carries
  a written rationale traceable to specific claim IDs.
- No page count is inflated — see `reportx-canary/render-qa/RENDER-QA-RESULTS.md`
  for why 20-21 real PDF pages, not a fabricated 30-40, is the honest
  answer, and why the premium-depth gate (word count, material claims,
  section count, zero padding) is the actual commercial bar, not a page
  target.

## Final state

All four: **23 / 23 PASS, PREMIUM_READY_PENDING_HUMAN.** No real human
`APPROVE` has been recorded for any of them. See
`REPORTX-HUMAN-REVIEW-RUNBOOK.md` for the exact operator commands.
