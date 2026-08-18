# The Intelligence Factory — Target Architecture

Answers `REPORTX-LEGACY-PIPELINE-AUDIT.md`'s root cause (no claim/evidence
model connects the high-volume pipeline's variables to per-report analysis)
with a design that reuses, rather than replaces, three things this
repository already has working: `content_discovery.py`'s live feed
ingestion, `report_integrity.py`'s fail-closed evidence gate, and
`sentinel_engine.reportx` (ReportX/System 3 + the P0 release-certification
layer) as the claim/evidence/confidence engine. **This document is a design
+ one reference implementation (the flagship report). It does not modify
the live pipeline** — see "What this does not do" at the end.

---

## Ten-stage pipeline, mapped to what already exists

| Stage | Reused component | New work required |
|---|---|---|
| **Data collection** | `automation/content_discovery.py` (`DiscoveredArticle`, NVD/CISA KEV/ransomware.live/CISA advisory feeds) — unchanged | None |
| **Validation (fail-closed floor)** | `automation/report_integrity.py`'s `validate_publication()` — unchanged, stays the mandatory floor for every tier | None |
| **Correlation** | ReportX `EvidenceGraph`, `contradiction_engine.py`, `claim_support_matrix.py` | A bridge adapter (below) to populate the graph from a `DiscoveredArticle` instead of only from hand/JSON-authored bundles |
| **Intelligence analysis** | ReportX `Claim`/`ClaimType`/`ObservedVsContext`, `threat_schemas.py` (`CVERecord`, `CISAKEVRecord`, `RansomwareVictimClaim` already exist; other product families need new `ThreatProduct` subclasses — Section "Product family taxonomy" below) | Same bridge adapter |
| **Confidence assessment** | ReportX `EpistemicState`, `Confidence`, `CorroborationState`, Section 10's high-impact-claim-type corroboration policy — unchanged | None |
| **Evidence traceability** | ReportX `SourceRecord`/`EvidenceRecord` + `evidence_integrity.py`'s hash policy. `report_integrity.py`'s existing `_record_hash()` becomes the `content_sha256` input rather than being reimplemented | Map `DiscoveredArticle` fields onto `SourceRecord` fields (bridge adapter) |
| **Detection engineering** | `report_renderer.py`'s `_detection_package()` (real, vulnerability-class-conditional, evidence-gated) + ReportX `detection_validation.py`'s governed-withholding ladder | Wrap the existing `DetectionPackage` into a ReportX `DetectionRule` so it flows through the same validation-state discipline the premium canaries already use |
| **Executive reporting** | ReportX `forecast.py` (`Forecast.time_horizon` is already free text — no schema change needed for the 24h/72h/90d ladder), `analytic_scaffolding.py` (`Hypothesis`/`HypothesisSet` — the right shape for threat-hunting hypotheses), `regulatory.py` (sector/jurisdiction fields) | New: a role-based executive-section renderer, a hunt-hypothesis renderer, a sector-impact-matrix renderer, an Admiralty-style source-reliability display (see below) |
| **QA** | ReportX `qa_linter.py`, `contradiction_engine.py`, `product_depth.py` (anti-padding — this is the direct fix for Findings 1/2's repeated-boilerplate problem: `find_template_repetition()` already exists and already catches byte-identical prose across reports) | None |
| **Publication** | `automation/blogger_publisher.py` / System 1's HTML pipeline — unchanged transport | None — richer content flows through the existing publish call |

**The headline point**: seven of ten stages need zero new engineering,
because ReportX already built them this repository's own history. The real
gap is one bridge adapter (`DiscoveredArticle` → `EvidenceGraph`) and four
new, focused renderers for sections the MISSION wants that no existing
renderer produces yet.

---

## The bridge adapter — the one genuinely missing piece

`sentinel_engine.reportx.bundle_io` already has the JSON↔`ReportBundle`
direction (built for System 5). What does not exist is the live-feed
direction: `DiscoveredArticle` (System 1/2's ingestion shape) →
`SourceRecord`/`Claim`/`EvidenceGraph` (ReportX's evidence shape). This is
architecturally the same kind of adapter `api/_lib/reportx-adapter.js`
already is for System 5 — a translation layer that never recomputes
anything, only reshapes real data:

```
DiscoveredArticle.url/source/published_at/content_hash
    -> SourceRecord.url/source_type/source_date/content_sha256
       (content_sha256 = report_integrity._record_hash(), REUSED not reimplemented)

DiscoveredArticle.cve_id/cvss_score/cwe_ids/epss_score/kev_listed/...
    -> CVERecord / CISAKEVRecord fields (already-existing ThreatProduct subclasses)

DiscoveredArticle.title/summary/full_content
    -> one or more Claim objects, ClaimType selected by report_integrity._family()
       (already-existing family classifier, REUSED not reimplemented),
       status=EpistemicState.REPORTED (single source, until corroborated)
```

This adapter is where Finding 3 (no reliability grading) gets closed for
free: `SourceRecord.reliability` (`Reliability.HIGH/MODERATE/LOW/UNKNOWN`)
already exists in ReportX's schema — it has simply never been populated or
rendered by the legacy pipeline. The adapter assigns it from
`DiscoveredArticle.source` (NVD/CISA/MITRE-sourced → `HIGH`; a named CTI
vendor or victim statement → `MODERATE`; an unauthenticated leak-site
listing → `LOW`), and a new small display helper renders it in Admiralty-
adjacent language (see "Source reliability display" below) — this is
presentation on top of an existing field, not a new evidence dimension.

## Product family taxonomy

The MISSION asks for CVE advisories, ransomware victim reports, KEV
updates, malware intelligence, threat actor profiles, campaigns, APT
reporting, IOC bulletins, and strategic intelligence, on one consistent
commercial standard. Mapped onto ReportX's existing `ThreatProduct`
hierarchy (`threat_schemas.py`):

| Product family | `ThreatProduct` subclass | Status |
|---|---|---|
| CVE advisory | `CVERecord` | Exists — used by all 8 CVE samples and Canary D |
| CISA KEV update | `CISAKEVRecord` | Exists — used by the KEV sample and Canary D |
| Ransomware victim claim | `RansomwareVictimClaim` | Exists — used by Canaries A/B/C |
| Threat actor profile | `RansomwareVictimClaim.actor_context` (`ActorHistoricalContext`) already models this *within* a ransomware report | Exists as a sub-object; a **standalone** actor-profile product (not tied to one victim) is new and out of scope for this pass |
| Malware intelligence, campaigns, APT reporting, IOC bulletins, strategic intelligence | None yet | **New `ThreatProduct` subclasses, deferred** — no sample in the 11 requires them, and Section 6/Principle 4 ("build new logic only when no match exists, and document the decision") means they should be added when a real, evidence-backed report actually needs one, not speculatively now |

This keeps Single Source of Truth intact: every product family that
already has evidence to render (8 of the 11 samples' families) reuses the
existing schema; nothing is duplicated.

## Product tier — reusing the certification ladder, not inventing a new one

The P0 release-certification work already extended `CertificationState`
with a real, evidence-driven downgrade ladder
(`tier_downgrade.determine_achieved_tier()`): `PUBLIC_REFERENCE_DRAFT` →
`FLASH_READY` → `TACTICAL_READY` → `PREMIUM_READY_PENDING_HUMAN`/
`PREMIUM_CERTIFIED`/`PREMIUM_AUTOMATED_CERTIFIED`. This is the correct
home for "not every report needs to be a 20-page dossier":

- **FLASH_READY** — the default landing tier for a routine, single-source
  CVE/KEV/ransomware-victim-claim report: correctness controls pass, full
  evidence traceability, but intentionally short (matches this pipeline's
  actual publication cadence — every 15-30 minutes, high volume).
- **TACTICAL_READY** — a report with enough real evidence for forecasts,
  a hypothesis set, and a regulatory read, but not the full ≥15-material-
  claim/≥8-section premium depth floor.
- **PREMIUM_READY_PENDING_HUMAN / PREMIUM_CERTIFIED / PREMIUM_AUTOMATED_CERTIFIED**
  — reserved for the deep, multi-source dossiers this repository's four
  real canaries already demonstrate, now reachable at volume through the
  automated-certification path once a release is certified
  (`REPORTX-AUTOMATED-CERTIFICATION.md`).

Every tier still passes through the same `report_integrity.validate_publication()`
floor and ReportX's `qa_linter`/`contradiction_engine`/`product_depth`
anti-padding check — **the tier changes depth, never changes the honesty
bar**.

## New renderers required (the flagship exercises all four)

1. **Role-based executive decision renderer** — replaces the single generic
   "Executive Decision Matrix" with distinct, evidence-scoped sections for
   CEO/Board, CISO/CIO, SOC Manager, IR Manager, Threat Hunter,
   Vulnerability Manager, Cloud/OT (when relevant), Legal/Compliance/
   Privacy, Business Continuity/Supply Chain, and MSSP — each populated
   only where the evidence graph actually has a claim relevant to that
   role (never padded to fill every role for every report).
2. **Threat-hunting hypothesis renderer** — reuses `analytic_scaffolding.Hypothesis`
   (statement, supporting/contradicting evidence, confidence,
   `collection_requirement`) plus a small new `HuntPackage` (pivot
   opportunities, negative indicators, false-positive considerations,
   validation steps, success criteria) adjacent to `report_renderer.py`'s
   existing `DetectionPackage` pattern.
3. **Predictive-intelligence timeframe-ladder renderer** — populates
   `Forecast.time_horizon` across the MISSION's 24h/72h/7d/30d/90d ladder,
   each forecast carrying its own `supporting_observation_claim_ids` and
   `confidence_rationale` (no schema change — `forecast.py` already
   supports this; the legacy template's forecasts do not use real evidence
   IDs at all).
4. **Sector-impact matrix renderer** — one row per MISSION-named sector,
   each populated from `regulatory.py`'s existing jurisdiction/sector
   fields plus the claim graph, explicitly marked `NOT_ASSESSED` for
   sectors the evidence doesn't address (never defaulted to the same
   generic paragraph).

### Source reliability display

`Reliability` (`HIGH`/`MODERATE`/`LOW`/`UNKNOWN`) already exists on every
`SourceRecord`. A small, presentation-only mapping renders it
Admiralty-adjacent (`HIGH → "A/B — Reliable"`, `MODERATE → "C —
Fairly Reliable"`, `LOW → "D/E — Not Usually/Cannot Be Judged Reliable"`,
`UNKNOWN → "F — Reliability Cannot Be Judged"`). This is a **documented
simplification**, not the full independent 2-axis Admiralty matrix
(separate Source Reliability A-F and Information Credibility 1-6 grades) —
extending `SourceRecord` with a second, independent credibility axis is a
real, additive follow-up if the operator wants the full 2-D grid; it is
flagged here rather than silently approximated as complete.

---

## Quality gates per product family

See `REPORTX-PRODUCT-QUALITY-GATES.md` for the full mapping. Summary: every
tier reuses `commercial_readiness.py`'s 23 controls; `BLOCKED` counts
against a tier's own floor exactly as it does for premium (Section 46's
rule is not weakened for high-volume products), but each tier's floor only
requires the controls that tier's own depth can support — a `FLASH_READY`
report is not penalized for lacking a hypothesis set it was never meant to
carry, the same way today's fixtures are correctly `BLOCKED` (not
penalized as `FAIL`) for sections genuinely not attempted.

---

## What this does not do

- Does not modify `automation/authority_transformer.py`,
  `automation/main.py`, or any scheduled workflow. The legacy pipeline
  keeps running exactly as it does today.
- Does not add a sixth writer system. The bridge adapter's whole purpose
  is to make ReportX the **single** evidence engine behind every future
  product family, per Principle 3 (Single Source of Truth) — it replaces
  `_legacy_template_enhance()`'s boilerplate, it does not sit beside it as
  a seventh path.
- Does not touch the LLM-authored path (`call_llm()`/`llm_client.py`) —
  that path's low success rate (Finding 1) is a separate, orthogonal
  reliability problem from the content-quality problem this document
  addresses, and conflating a "make the API calls succeed more often" fix
  with a "make the fallback non-generic" fix would risk shipping neither
  correctly.
- Ships one reference implementation (the flagship report, transforming
  the CVE-2025-62593/Ray sample using the existing Canary D evidence
  bundle) as proof the design works end-to-end on real data, per the
  user's own explicit sequencing: benchmark first, mass refactor only
  after it is approved.
