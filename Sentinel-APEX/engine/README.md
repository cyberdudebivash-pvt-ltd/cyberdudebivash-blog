# Sentinel APEX Intelligence Engine

Phase 2 of the Intelligence Factory roadmap: the executable core that turns
the Phase 1 scaffold (prompts, templates, checklists) into a **tested,
deterministic intelligence-production system**. Zero external dependencies
beyond `pyyaml` — runs offline and inside CI.

```
raw source ──▶ normalizer ──▶ evidence layer (NormalizedDoc)
                                │
              ┌─────────────────┼──────────────────┐
              ▼                 ▼                  ▼
        ioc_extractor     attack_mapper        entities
              │                 │                  │
              └────────┬────────┴───────┬──────────┘
                       ▼                ▼
                  enrichment      knowledge_graph
               (NVD/EPSS/KEV)   (cross-report memory)
                       │                │
                       └───────┬────────┘
                               ▼
                   detection_specs (one canonical spec / technique)
                               ▼
                   detection_builder ──▶ Sigma · KQL · Splunk · OSQuery
                               │          + Suricata (from network IOCs)
                               ▼
                        draft (markdown)
                               ▼
                       quality gates ──▶ publish-eligible / BLOCKED
```

## Design principles

1. **Evidence first, never fabricate.** Every ATT&CK mapping stores the
   source phrase that triggered it. Enrichment fields stay `None` when a
   live source (NVD, FIRST EPSS, CISA KEV) is unreachable — scores are never
   estimated. Sections without evidence are omitted, never padded.
2. **Single responsibility, independently testable.** Each stage is one
   module with its own test file. Network access is injectable
   (`Enricher(fetch_json=...)`), so the full pipeline is testable offline.
3. **The gate is code, not a checklist.** `quality.py` executes the
   publication gate: a report either passes every blocking rule or it is not
   eligible. The Sigma builder validates its own output against the same
   gate, so the engine cannot emit a rule the gate would reject.

## Modules

| Module | Responsibility |
|---|---|
| `models.py` | Typed artifacts: IOC, TechniqueMapping, NormalizedDoc, GateResult… |
| `normalizer.py` | Strip scraper noise / site chrome; produce the evidence layer |
| `ioc_extractor.py` | Deterministic IOC extraction, categorization, defang/refang |
| `attack_mapper.py` | Evidence-backed ATT&CK mapping + technique-ID validation |
| `entities.py` | Curated-lexicon actor/malware/tool/vendor extraction |
| `enrichment.py` | NVD (CVSS), FIRST (EPSS), CISA (KEV) — injectable fetchers |
| `knowledge_graph.py` | JSON-backed cross-report entity/relationship memory |
| `detection_specs.py` | One normalized detection spec per technique (source of truth) |
| `detection_builder.py` | Compiles specs → Sigma/KQL/Splunk/OSQuery + Suricata; self-validates |
| `sigma_builder.py` | Evidence-threaded Sigma (thin layer over the registry) |
| `scoring.py` | Deterministic 10-dimension publication scoring + tiering |
| `report_parser.py` | Parses published SENTINEL APEX reports for auditing |
| `quality.py` | Executable per-report + corpus-level publication gates |
| `pipeline.py` | Orchestrator: source → scored, gated draft |
| `cli.py` | `normalize` / `gate` / `run` / `enrich` / `detect` / `score` commands |

## Intelligence Scoring (v2)

The analytical gate the pipeline funnels through. Every report is scored
0–100 across ten dimensions — computed **only** from artifacts the engine
already produced, so scoring never fabricates or re-derives:

| Dimension | Weight | Driven by |
|---|:-:|---|
| Evidence Quality | 0.22 | source, CVEs, IOCs, successful enrichment, entities, techniques |
| Original Analysis | 0.18 | techniques mapped, prior-context correlation, derived detections |
| Detection Value | 0.15 | detection formats generated + Suricata rules |
| SOC Value | 0.10 | detection value + network IOCs + hunt hypotheses |
| DFIR Value | 0.06 | forensic-tactic techniques + host artifacts |
| Executive Value | 0.10 | KEV listing, CVSS, named threat actors |
| Commercial Value | 0.08 | mappable services (detection pack, IOC feed, consulting) |
| Analyst Confidence | 0.06 | technique confidence + enrichment + source corroboration |
| SEO Value | 0.05 | title, CVE, vendor/product, entity richness |

The weighted **overall publication score** plus a hard **threshold** (default
60) decide eligibility — and a blocking quality-gate finding forces
ineligibility regardless of score (correctness before commercial value). The
score also assigns a commercial **tier** (FREE / PRO / ENTERPRISE), so the
same evidence effort is routed to the audience its value justifies. Every
dimension carries a one-line, auditable rationale. `cli.py score` prints the
full breakdown and exits non-zero when a report is held below threshold.

## Detection Engine (Phase 3)

Every technique has exactly **one** canonical detection spec in
`detection_specs.REGISTRY`, expressed in a platform-neutral field vocabulary.
`detection_builder` compiles that single spec into every SIEM/EDR format the
spec's data model can support:

| Technique | Sigma | KQL | Splunk | OSQuery | Data source |
|---|:-:|:-:|:-:|:-:|---|
| T1059.001 Encoded PowerShell | ✓ | ✓ | ✓ | ✓ | process_creation |
| T1204.002 Office → interpreter | ✓ | ✓ | ✓ | ✓ | process_creation |
| T1490 Shadow copy deletion | ✓ | ✓ | ✓ | ✓ | process_creation |
| T1547.001 Run-key persistence | ✓ | ✓ | ✓ | ✓ | registry_set |
| T1218.005 mshta remote script | ✓ | ✓ | ✓ | ✓ | process_creation |
| T1003.001 LSASS access | ✓ | ✓ | ✓ | — | process_access |

A format is emitted **only** where the data model can express it (LSASS
handle access has no OSQuery table, so no OSQuery is produced — never a
fabricated one). Network IOCs compile separately to **Suricata** rules
(DNS/IP/HTTP), which use live IOC values because a network rule must match
real traffic. Every generated artifact is run through a format-specific
validator before it is returned — the builder cannot emit a syntactically
broken rule. This is the structural fix for the Phase 2 finding that one
generic Sigma rule was pasted into 6+ unrelated reports.

## Usage

```bash
cd Sentinel-APEX/engine

# run the test suite (53 tests, offline)
python3 -m pytest tests/ -q

# audit published reports against the quality gates (exit 1 on block)
python3 cli.py gate path/to/report-*.txt

# full pipeline on a raw source article
python3 cli.py run source.txt --id CDB-2026-0001 \
    --url https://vendor.example/advisory --graph intelligence/kg.json

# live CVE enrichment
python3 cli.py enrich CVE-2024-4577
```

## Quality gates (executable)

Per-report **blocking** gates:

- required sections present; valid severity; title resolvable
- MITRE section contains technique IDs; malformed IDs rejected
  (IDs outside the curated validation set → review warning)
- live (undefanged) URLs/IPs/domains/emails in the IOC section
- Sigma rule: YAML-valid, required fields, condition references defined
  selections, valid level, valid ATT&CK tags
- assessments present without any confidence labels
- aggregator/scraper text (`submitted by /u/…`, `[link] [comments]`)
  leaked into Technical Analysis

Corpus-level gates (templated-content detection):

- **block**: identical Sigma rule published across multiple reports
- **warn**: MITRE / IOC / Threat Hunting sections ≥80% shingle-identical
  between reports; thin analysis; executive summary that is a verbatim copy
  of the technical analysis

These gates were validated against 10 real published reports and correctly
identified every known defect class (scraper leakage, template-stamped
detections, duplicated operational sections).

## Roadmap position

- **Phase 1 — Foundation** (done): prompts, templates, workflow, checklist
- **Phase 2 — Intelligence Engine** (this package): normalization,
  extraction, enrichment, correlation, knowledge graph, executable gates
- **Phase 3 — Detection Engine**: broaden per-technique detection logic
  (KQL/SPL/Suricata/OSQuery), rule back-testing
- **Phase 4 — Publishing Platform**: multi-format rendering, SEO assembly,
  syndication integration, API/JSON feed output
- **Phase 5 — Enterprise Platform**: subscriptions, portals, analytics,
  feedback loops
