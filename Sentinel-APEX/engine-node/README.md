# Sentinel APEX Node Intelligence Modules

Zero-dependency Node modules wired into the **live publishing generator**
(`fetch-live-intel.js`) so every report carries evidence-driven detections,
persistent memory, threat correlation, and structured analyst reasoning.

| Module | Role |
|---|---|
| `detection-engine.js` | Multi-platform detections (Sigma/KQL/Splunk/OSQuery + Suricata) |
| `analyst-memory.js` | Persistent memory + threat-correlation knowledge graph |
| `reasoning-engine.js` | Structured analyst reasoning (facts / observations / assessments / gaps / outlook) |

See `ANALYST-MEMORY.md` for the memory + correlation layer.

## Analyst Reasoning Engine

`reasoning-engine.js` makes the platform's core discipline explicit and
auditable: it **separates verified fact from labeled assessment** and states
intelligence gaps honestly. `buildReasoning(item, memory)` returns five stages —
Verified Facts, Correlated Observations (from the knowledge graph), Analyst
Assessments (each LOW/MEDIUM/HIGH with a stated basis), Intelligence Gaps
(explicit unknowns), and Forward Outlook (labeled, evidence-anchored). It is
deterministic and composed from artifacts already produced — no model calls,
no fabrication — and renders as the *Structured Intelligence Assessment*
section. Attribution is always an assessment (never a fact); severity is an
assessment while CVSS is a fact; gaps shrink only as real evidence appears.

## Detection Engine — Node port

A zero-dependency Node port of the Python engine's detection layer, so the
live generator can emit the same evidence-driven, multi-platform detections the
Python engine produces and its tests validate.

## Why a port (and not a shell-out)

The production pipeline is single-runtime Node. Rather than add a Python
dependency to the workflow, the detection logic is ported to Node and kept in
lockstep with the Python source of truth. Fidelity is enforced by a
cross-language test: generated Sigma rule IDs must match the Python engine
**byte-for-byte** (`uuid5(uuid5(NAMESPACE_DNS, "sentinel.cyberdudebivash.in"),
title)`), so the two implementations cannot silently diverge.

## What it does

`detection-engine.js` exposes:

- `mapTechniques(text)` — evidence-anchored MITRE ATT&CK mapping (curated
  lexicon + explicit-ID extraction), a port of `attack_mapper.py`.
- `buildDetections(text, iocs, opts)` — the top-level call: maps techniques,
  compiles one canonical detection per technique to **Sigma / KQL / Splunk /
  OSQuery**, and compiles network IOCs to **Suricata**. Returns
  `{ detections, suricata, techniques }`.
- Per-format validators (`validateKql`, `validateSplunk`, `validateOsquery`,
  `validateSuricata`); builders throw rather than emit a broken rule.

A format is emitted only where the platform data model can express it (LSASS
handle access → no OSQuery). Suricata rules refang and use live IOC values
because a network rule must match real traffic.

## Integration

`fetch-live-intel.js` loads the engine defensively:

```js
let detEngine = null;
try { detEngine = require('./Sentinel-APEX/engine-node/detection-engine'); }
catch (e) { console.warn('detection-engine unavailable:', e.message); }
```

and renders a **Multi-Platform Detection Engineering** section via
`genMultiPlatformDetections(item, escHtml)`. That function is fully guarded:
any failure (or an item with no mapped techniques and no network IOCs) returns
`''`, so the new section can never break the existing report or the 3000-post
generation. The generator only runs its pipeline when invoked directly
(`require.main === module`), so it can be required by tests without triggering
live fetches.

## Tests

```bash
cd Sentinel-APEX/engine-node
node --test        # full suite across all tests/ files in this directory
```

Covered: ATT&CK mapping with evidence, cross-language UUID parity, all four
detection renderers + validators, Suricata generation/refang/SID sequencing,
the guarded HTML wrapper (including null/malformed items), a full-post
render that stays well-formed with the section embedded, analyst memory +
threat correlation, and the Sentinel APEX native provider (see
`../docs/SENTINEL-APEX-PROVIDER.md`).

Run in CI by `.github/workflows/detection-engine-node-ci.yml`.
