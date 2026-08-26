# SENTINEL APEX — Detection Capability Inventory v1
## Reuse-Before-Build Audit (Threat-to-Defense Fabric v1, Phase 2-3)

**Date:** 2026-08-26
**Branch:** `claude/p1-threat-to-defense-fabric-v1`
**Purpose:** exhaustive, evidence-based inventory of every existing detection-engineering capability in this repository, so the Threat-to-Defense Fabric build extends real production systems instead of duplicating them. Every claim below was verified by direct file reads, grep, and (where noted) direct inspection of real committed data — not inferred from file names or existing documentation, several pieces of which are shown below to be materially wrong about what is actually live.

---

## 1. Executive finding: five independent, non-unified "detection rule" implementations exist

| # | Implementation | Storage | ID scheme | Formats | Live-wired? |
|---|---|---|---|---|---|
| 1 | `api/_lib/detection-rules.js` | file (`data/detection-rules-canonical.json`) | sha256(content).slice(0,16) | sigma/kql/splunk/osquery/suricata | **Yes** — `fetch-live-intel.js` writes; `api/v1/detections/rules[.js]`/`rules/[id].js` read, wired into both Vercel and `workers/lib/router.js` |
| 2 | `lib/detection/*.ts` + `lib/api/detection-rules.ts` | in-memory `Map` (non-persistent) | `det_${Date.now()}_${random}` | sigma/yara/suricata/siem (splunk/elk/sentinel/arcsight) | **No** — only its own test file imports it; no route, build step, or bundler reaches it |
| 3 | `Sentinel-APEX/engine-node/detection-engine.js` + `Sentinel-APEX/engine/sentinel_engine/{detection_builder,detection_specs,sigma_builder}.py` | none (pure function; caller persists) | UUIDv5 (RFC4122, Node/Python byte-identical) | sigma/kql/splunk/osquery (technique-based, 6 of 35 curated techniques buildable) + suricata (IOC-based) | **Yes** — `fetch-live-intel.js` |
| 4 | `build-detections.js` → `detections/rules/*.yml` | flat YAML files | sha1-based UUID (fourth scheme) | sigma only, 8 hand-authored rules | **Yes**, as a static one-off artifact, stale since 2026-07-05 |
| 5 | `api/_lib/detection-export-engine.js` | none (renders from a `product` object) | none | 9 formats (widest list), crude field substitution, **zero validation** | **Yes** — `api/v1/products/export.js` (Vercel only, unauthenticated, not in Workers router) |

**No two of these five agree on ID scheme, storage, or data shape.** This inventory's job is to say which one is canonical for which purpose, and why, per CLAUDE.md Principle 3 (Single Source of Truth).

---

## 2. Per-system detail and classification

### 2.1 `api/_lib/detection-rules.js` — **CANONICAL detection-rule store**

353 lines. File-persisted (`data/detection-rules-canonical.json`, atomic tmp-rename write), with a frozen build-time snapshot served read-only on Cloudflare Workers (no filesystem there — the module's own header discloses this). Real record shape:

```js
{
  id, technique_id, title, level, description, data_source,
  platforms: { sigma, kql, splunk, osquery },
  suricata: [],
  governance: { status, confidence, created_at, updated_at, version },
  source: { iocs: [], articles: [], campaigns: [], evidence: '' },
  history: [{ version, timestamp, change, author, comment? }],
}
```

**Verified against real data** (`data/detection-rules-canonical.json`, 2 records today): `source.articles` genuinely contains raw CVE-ID strings (`["CVE-2026-19598"]`) on real pipeline output — meaning a `getRulesByCVE(cveId)` lookup is a simple, safe, additive filter over existing data, no migration needed. One record (`TEST-001`/`10.0.0.1`) is a placeholder whose origin predates the current tree (no test file requires this module — its provenance is not traceable to any current automated run, but it is real, committed data, left as-is here per Zero Unnecessary Modification).

**Classification: CANONICAL.** This is the only persisted, dual-runtime-reachable (Vercel + Cloudflare Workers), pipeline-fed detection-rule store. The Threat-to-Defense Fabric extends this store's schema additively (new optional fields only — see §4 of the certification) rather than replacing it.

**Known, disclosed, pre-existing gap carried forward unfixed:** `api/v1/detections/rules.js` and `rules/[id].js` have **no authentication at all**, confirmed by direct read (no auth import, no header check) and confirmed live-wired on both runtimes. This is the same class of gap `platform/open-issues.md` Issue 20 has left open, undecided by explicit operator sign-off, across five-plus prior rounds specifically because silently adding auth to a previously-public production route is a live behavior change requiring a documented migration path (Principle 5), not a unilateral fix. **Not fixed in this tranche**, for the same reason — see `platform/open-issues.md` new Issue 29. This tranche's own new detection API surface (§section below) is authenticated from day one, since it has no prior public-access contract to break.

### 2.2 `lib/detection/*.ts` + `lib/api/detection-rules.ts` — **EXPERIMENTAL / UNWIRED, not canonical**

3,533 lines of real, non-trivial TypeScript (per-IOC-type Sigma/YARA/Suricata/SIEM generators covering 18 IOC types, a validator/optimizer/correlator/renderer layer, plus a sibling `lib/governance/`+`lib/ioc/`+`lib/reporting/` stack). This is genuinely well-designed code, not a stub.

**Confirmed unwired to any live route:** no production `.js` file, cron, or API route anywhere in the repository imports `lib/detection/*` or `lib/api/detection-rules.ts`. `package.json` has no build/bundle script that compiles `.ts` → runtime JS (`tsc --noEmit` in CI is type-check-only; `ts-jest` only runs the test suite). The only importers are `tests/detection-engine.test.ts` and a type-only re-export barrel (`types/index.ts`) with no further live consumer found. Cloudflare's own `workers/lib/router.js` — verified directly — registers exactly two detection routes, both pointing at `api/v1/detections/rules[.js]` (i.e. system #1, above), never at `lib/api/detection-rules.ts`.

**A confirmed, material documentation-vs-reality gap**, disclosed here rather than perpetuated: `docs/architecture/module-ownership.md`, `docs/architecture/public-api-audit.md`, and `docs/architecture/dependency-graph.md` all describe this TypeScript stack as **"Stable (RC1 ready)"** / **"FROZEN (v1 contract)... Ready for external integration,"** with documented HTTP endpoints (`POST /api/v1/detections/generate`, `GET /api/v1/detections/search`, etc.) that **do not exist as route files anywhere in the repository**, and documented function signatures (e.g. `generateSigmaFromIOC(ioc: IOC): SigmaRule`) that do not match the real, more detailed code (`generateSigmaFromIOC(iocType, iocValue, malwareName, options?)`). This is the same "docs describe an aspiration, production reality differs" pattern this platform has found repeatedly elsewhere (campaign delivery, search UI, Vercel Cron status) — recorded honestly rather than treated as ground truth. Correcting those three architecture docs is a separate, standalone documentation-accuracy task, out of scope for this tranche (touching them is not required to ship the Threat-to-Defense Fabric and would widen this PR's blast radius for no functional benefit) — flagged in `platform/open-issues.md` (new Issue 29) for whoever picks it up.

**Classification: EXPERIMENTAL, not reachable, not extended.** Building customer-facing capability on top of code with zero live entry point would not ship anything a customer could use. Not deleted (Deprecation Instead of Deletion — it is real code with real test coverage, just unwired), not extended, not imported by the new system.

### 2.3 `Sentinel-APEX/engine-node/detection-engine.js` + Python parity port — **CANONICAL generator**

527-line Node port + 399-line `detection_builder.py` + 221-line `detection_specs.py` + 55-line `sigma_builder.py` (a thin compatibility shim over the two above, `sigma_builder.py`'s own header: "All detection logic now lives in one place, `detection_specs.REGISTRY`"). Field-by-field comparison confirms the two runtimes' `REGISTRY` (6 techniques: `T1059.001, T1204.002, T1490, T1547.001, T1003.001, T1218.005`) is genuinely, verifiably identical — the deliberate, already-classified (`platform/open-issues.md` Issue 1) parity-port pattern this platform uses elsewhere. Both sides carry real structural validators (`validateKql`/`validateSplunk`/`validateOsquery`/`validateSuricata` — heuristic/string-structural checks: balanced quotes/parens, required prefixes, not a full grammar parser) that `guard()`/`_guard()` enforce before any output is returned, so this generator cannot silently emit malformed output for the 4 non-Sigma formats it produces.

**Real, disclosed limitation carried forward, not expanded in this tranche:** only 6 of the ~35 (Node) / ~85 (Python `attack_mapper.py`) curated ATT&CK technique IDs have a buildable detection spec (`buildableTechniques()`). This is the honest `DETECTION_GENERATABLE` vs. `INSUFFICIENT_TELEMETRY`/`UNSUPPORTED` boundary the Threat-to-Defense Fabric's opportunity engine (§11 of the mandate) is built around — not silently worked around by inventing specs for the other ~29, which would be exactly the "generate rules for every ATT&CK ID" the mandate explicitly forbids.

**A second, real documentation-vs-reality gap found and disclosed:** `platform/capabilities.md`'s Detection Generation row claims this engine is "wired into the 5-minute live bot cadence." No 5-minute schedule exists anywhere in `.github/workflows/*.yml` — the actual, currently-committed cadence for the workflow that calls `fetch-live-intel.js` (`sentinel-apex.yml`) is `0,30 * * * *` (30 minutes), matching that same workflow's own inline comment ("Intel still refreshes every 30 min"). Corrected in `platform/capabilities.md` this round (§ below) — a one-line factual correction, not a capability change.

**Classification: CANONICAL for rule generation.** Called, not modified — `REGISTRY`/`buildableTechniques()`/format builders/validators are used exactly as they exist. This tranche does not touch `detection-engine.js`, `detection_builder.py`, `detection_specs.py`, or `sigma_builder.py`.

### 2.4 `detections/` static pages — **existing customer-facing surface, extended not replaced**

Two real, live, linked-from-navigation pages, confirmed distinct:
- `/detections` (`detections/index.html`) — 8 hand-authored Sigma rules from `build-detections.js`, stale since 2026-07-05, independent of every other system here.
- `/detections/live-feed.html` — generated by `generate-intelligence-hub.js` from `api/intel/detections-library.json` (200 curated per-article records with `mitreAttack[]`/`sigma[]`/`kql[]`/`splunk[]`/`osquery[]`/`suricata[]`), refreshed same-day. The page's own on-page copy already discloses the two-tier structure to visitors.

**Classification: existing production surface, left as-is.** Neither page is modified by this tranche — the new Detection Coverage / Detection Detail UI (mandate §57-59) is integrated into the **dossier** flow (Search → Dossier → Detection Coverage), a different, already-planned customer journey, not a competing detections landing page. No duplicate route introduced.

### 2.5 `api/_lib/detection-export-engine.js` — **INTERNAL, not reused for the new system**

404 lines, 9-format export (the widest format list in the repo) but confirmed **zero validation of any generated output**, operating on a `product.modules.indicators` shape from the unrelated `phase-N-orchestrator`/product-catalog family, called by an **unauthenticated** `api/v1/products/export.js` (Vercel-only, not in the Workers router). **Classification: INTERNAL/LEGACY relative to this tranche** — a real, live, but architecturally separate capability (product-catalog exports, not evidence-backed detection intelligence). Not reused, not modified, not duplicated; its own pre-existing auth gap is the same already-tracked class as §2.1's, not newly introduced or newly fixed here.

### 2.6 `api/_lib/vulnerability-detection-intelligence-engine.js`, `intelligence-change-detection.js`, `mitre-intelligence-engine.js`, `sa-eix-premium-mitre.js` — **INTERNAL, unrelated despite naming, not reused**

All four are real, live-called code inside the `phase-8`/`phase-9`/`phase-11`-orchestrator → product-catalog pipeline (a system that composes internal "products" from SOC Workbench investigations — System B in this platform's own established System-A/System-B split, per the Intelligence Dossiers v1 certification). Verified directly:
- `intelligence-change-detection.js` is **not** the watchlist change-detection system — `api/_lib/change-detector.js`'s own header already documents evaluating and explicitly rejecting it as a base to extend (whole-snapshot diffing, array-order-sensitive comparisons, no idempotent event identity).
- `vulnerability-detection-intelligence-engine.js`'s "detection packages" are stub field-substitution (`Detects ${ioc.type} ${ioc.value}`) with no real rule syntax — despite its name, it produces no genuine Sigma/YARA/Suricata content.
- `mitre-intelligence-engine.js`'s technique lookup table is hardcoded to 2 techniques with a crude string-`.includes()` tactic classifier — far less rigorous than either `attack_mapper.py` or the dossier's own evidence-graded ATT&CK linkage (§2.7 below).
- `sa-eix-premium-mitre.js` is a presentation/HTML-rendering layer only, currently referenced only by its own test file.
- A related fact found in passing: `threat-graph.js`'s hand-curated `ThreatActor.ttps[]` arrays contain at least 6 technique IDs (`T1571, T1048, T1530, T1619, T1213, T1021.006`) that appear in **none** of the other technique registries checked — a third, uncorrelated ATT&CK ID list. Not reconciled in this tranche (out of scope; flagged in open-issues).

**Classification: INTERNAL, not reused, not modified.** None of the four is on the evidence-backed path this tranche needs; reusing them would import their real defects (stub content, no negation-awareness, hardcoded 2-technique lookup) into a customer-facing product.

### 2.7 ATT&CK evidence linkage — **reused directly from the already-shipped dossier, no new mapper built**

`api/_lib/intelligence-dossier.js`'s `buildAttackContext(relatedActorNodes, matchingReports)` (already shipped, Intelligence Dossiers v1) is the **only** ATT&CK linkage in this codebase that is already evidence-graded and already distinguishes source quality: every technique carries an explicit `source: 'linked_report' | 'linked_actor'` plus `via` attribution, sourced from a linked report's hand-authored, negation-aware `attack_ids[]` (offline `attack_mapper.py`) or a curated ThreatActor's static `ttps[]` — never presented as the CVE/campaign's own self-evident techniques. This is materially more trustworthy than either JS engine's keyword mapper (`Sentinel-APEX/engine-node/detection-engine.js`'s `mapTechniques()`, confirmed to have **no negation-awareness at all**, unlike the Python `attack_mapper.py` it claims to port) or `mitre-intelligence-engine.js`'s crude lookup.

**Decision:** the Threat-to-Defense Fabric's coverage engine (mandate §36-38) consumes `attack_context.techniques[]` from the existing, exported `buildCveDossier()`/`buildCampaignDossier()` — it does not re-derive ATT&CK evidence from raw text, and does not build a new mapper. This directly satisfies the mandate's Phase 8-10 (threat linkage, evidence-aware mapping) via reuse rather than new logic, and guarantees a dossier's ATT&CK view and its own detection-coverage view can never disagree (Principle 3, Single Source of Truth) — the same anti-drift design this platform already applied to watchlists (`classifyExploitation()`/`campaignConfidenceBucket()` reuse).

### 2.8 Structural/behavioral validation landscape

- **Real structural validators exist today**, but are heuristic/string-based, not full grammar parsers: `detection_builder.py`/`detection-engine.js`'s `validate{Kql,Splunk,Osquery,Suricata}` (§2.3). No Sigma-specific structural validator exists anywhere in the live JS/Python pipeline (`sigma_builder.py` calls `quality.validate_sigma`, itself a structural/string check, not a real Sigma-schema parser).
- **`Sentinel_engine/reportx/detection_validation.py`** (212 lines) is **not** a rule-syntax validator despite its name — it is a narrative-honesty gate, regex-matching *report prose* for promotion language ("production-validated," "ready for deployment") against a rule's recorded `DetectionValidationState` enum (9 states: `DRAFT/SYNTAX_VALIDATED/LAB_VALIDATED/TELEMETRY_VALIDATED/PRODUCTION_CANDIDATE/PRODUCTION_VALIDATED/WITHHELD_INSUFFICIENT_EVIDENCE/NOT_APPLICABLE/TELEMETRY_SPECIFICATION`), certified production-ready by `docs/audits/REPORTX-PHASE1I-ATTACK-DETECTION-HUNTING-CERTIFICATION.md` (2026-08-20). This operates one layer downstream of rule generation (report-composition/publication gating), not on rule bodies — **no overlap** with this tranche's release gate, but its 9-state vocabulary is the most mature validation-maturity taxonomy already in this codebase and is reused as this tranche's starting point for its own lifecycle states (mandate §6), reconciled rather than replaced with a competing vocabulary.
- **`Sentinel-APEX/eios/layer-06-detection-engineering-standards.md`** documents a separate, simpler 4-level maturity model (Reference/Reviewed/Tested/Production Validated) intended for report-prose tracking only, explicitly deferred pending "Layer 3's `DetectionRule` object" — i.e. it already anticipated needing exactly what this tranche builds. Its documented format list (CrowdStrike FQL, SentinelOne, Cortex XDR/XSIAM, Snort, ES|QL) is broader than anything actually implemented anywhere in the repo — those formats remain honestly `UNSUPPORTED` in this tranche's format matrix (mandate §14-15), not fabricated to match the standards doc's aspiration.
- **No dependency exists for real Sigma-YAML-schema or Sigma-condition-grammar parsing.** `js-yaml` (already a dependency, used by `report-renderer.js`) gives real YAML structural parsing (catches malformed YAML, missing required top-level keys) — used as this tranche's L2 structural validator for Sigma, a genuine improvement over string-only checks, without adding a new dependency.

---

## 3. Canonical ownership decisions (Phase 3 classification, summary table)

| System | Classification | Action this tranche |
|---|---|---|
| `api/_lib/detection-rules.js` + `data/detection-rules-canonical.json` | **CANONICAL** (store) | Extended additively (new optional fields; new CVE/campaign lookup functions) |
| `Sentinel-APEX/engine-node/detection-engine.js` + Python parity port | **CANONICAL** (generator) | Called unchanged; not modified |
| `intelligence-dossier.js`'s `buildAttackContext`/dossier `attack_context` | **CANONICAL** (ATT&CK evidence linkage) | Consumed via existing exports; no new mapper |
| `lib/detection/*.ts` + `lib/api/detection-rules.ts` + sibling `lib/governance`/`lib/ioc`/`lib/reporting` | **EXPERIMENTAL / UNWIRED** | Not reused, not modified, not deleted (Deprecation Instead of Deletion) |
| `detections/` static pages + `generate-intelligence-hub.js`/`api/intel/detections-library.json` | **Existing production surface** | Left as-is; new UI lives in the dossier flow instead |
| `api/_lib/detection-export-engine.js` | **INTERNAL/LEGACY** (relative to this tranche) | Not reused |
| `vulnerability-detection-intelligence-engine.js`, `intelligence-change-detection.js`, `mitre-intelligence-engine.js`, `sa-eix-premium-mitre.js` | **INTERNAL** | Not reused |
| `detection_validation.py` (ReportX narrative gate) | **CANONICAL** (report-prose honesty layer, different concern) | Not modified; its lifecycle vocabulary informs (not replaces) this tranche's own |
| Stray root `.patch` files (`0001`-`0006`) | **STALE/already-incorporated** | Left as-is (git history artifacts, not pending work — verified via `git apply --check`, all fail as already-applied) |

**Zero duplicate canonical stores are introduced.** The Threat-to-Defense Fabric is one new orchestration layer over two existing canonical systems (§2.1 store + §2.3 generator + §2.7 ATT&CK linkage), not a sixth parallel implementation.

---
*CyberDudeBivash® Sentinel APEX — Detection Capability Inventory v1*
