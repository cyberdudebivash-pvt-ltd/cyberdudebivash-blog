# EIOS LAYER 3 — INTELLIGENCE OBJECT MODEL

Standardizes every reusable object so intelligence can be composed across
reports instead of re-described from scratch each time. This layer is
honest about what already exists in code versus what is specified here for
a future implementation — nothing below is claimed as "done" unless a file
and line reference backs it.

## Implemented today (`Sentinel-APEX/engine/sentinel_engine/models.py`)

| Object | Fields | Notes |
|---|---|---|
| `IOC` | `value`, `type` (`IOCType` enum: ipv4/domain/url/email/md5/sha1/sha256/cve/registry_key), `context` | Frozen dataclass; `key()` gives a dedup identity. Always stored refanged internally — defanging happens only at render time via `ioc_extractor.defang`. |
| `TechniqueMapping` | `technique_id`, `name`, `tactic`, `evidence`, `confidence` (`Confidence` enum LOW/MEDIUM/HIGH) | An ATT&CK mapping is never bare — it always carries the source phrase that justified it. |
| `Entity` | `name`, `type` (`threat_actor`\|`malware`\|`tool`\|`vendor`\|`product`\|`sector`\|`country`), `context` | The current representation of both **Threat Actor** and **Malware Family** — see gap note below. Populated by the curated lexicon in `entities.py` (APT28/APT29/LockBit/etc. — extend the lexicon, don't build a parallel extractor). |
| `SourceDocument` | `raw_text`, `source_url`, `source_name`, `title`, `published` | Pre-normalization input. |
| `NormalizedDoc` | `title`, `text`, `source_url`, `source_name`, `published`, `iocs[]`, `cves[]`, `techniques[]`, `entities[]` | The evidence layer — only what was extracted, nothing added. |
| `CVEEnrichment` | `cve_id`, `status`, `description`, `cvss_score`, `cvss_vector`, `epss_score`, `epss_percentile`, `kev_listed`, `sources[]` | This **is** the Vulnerability/CVE object. Fields stay `None`/`"unavailable"` rather than fabricated — never guess a CVSS vector. |
| `GateFinding` / `GateResult` | `gate`, `severity`, `message` / `findings[]`, `.passed`, `.blocks`, `.warnings` | The Quality Gate's own object model (Layer 4). |

## Implemented today (`engine/sentinel_engine/knowledge_graph.py`)

`KnowledgeGraph` (entities dict + relation triples) is the working
implementation of **Intelligence Relationships** — see Layer 9 for the full
write-up. It is listed here because it is also, functionally, the
persistence layer for every object in this model: every `Entity`, CVE, and
technique that appears in a `NormalizedDoc` gets upserted into the graph on
ingest.

## Gap: Threat Actor and Malware Family need richer fields than `Entity`

**Correction (GTIEP v1 audit, 2026-07-29):** this gap is real for the
*Python engine's* `Entity` model specifically, but was previously stated
here without qualification, which read as "no richer Threat Actor
representation exists anywhere in the platform" — that part is false. The
**live JS graph** (`api/_lib/threat-graph.js`, `THREAT_ACTOR_DB`) already
has exactly the richer fields described below — `aliases[]`, `category`,
`motivation`, `sophistication`, `origin`, `target_sectors[]`,
`target_regions[]`, `ttps[]`, `known_cves[]`, `refs[]` — for 8 curated,
real actors (LockBit, APT41, Cl0p, Volt Typhoon, Salt Typhoon, PhantomCore,
ShinyHunters, a Russia-nexus cluster). It does not close the gap
described below: it's a curated set of 8, not a general extraction
pipeline, and it lives in the live JS side, not the Python `models.py`
this section is about — the two remain unconverged, consistent with
`platform/open-issues.md` Issue 1's canonical-ownership pattern. The point
is narrower than it reads below: `Entity` (Python) is minimal; a richer
Threat Actor representation is not universally absent from the platform.

`Entity` today is intentionally minimal (name + type discriminator +
free-text context) — sufficient for extraction and graph relationships, not
for structured fields like an actor's known aliases, motivation, or
sophistication tier, or a malware family's lineage and platform. Two
options when a report needs those fields:

1. **Today:** carry them as prose in the report's Threat Actor Profile /
   Malware Analysis sections (already required by `master-prompt.md`
   sections 10 and 16), with the `Entity.context` field holding a short
   extraction anchor, not the full profile.
2. **Future increment:** promote `ThreatActor` and `MalwareFamily` to
   dedicated dataclasses (aliases, motivation, sophistication, first_seen /
   family, malware_type, platform, lineage respectively) once a consumer
   needs to query those fields programmatically rather than read them in
   prose. Not built now — a dataclass with no producer or consumer is dead
   code, which this repository's own QA pipeline flags.

## Specified, not yet implemented in code

These objects are named in the report structure and templates today only as
prose sections, not as structured types **in the Python engine**. The
schema below is what a future `models.py` extension should implement when
an API or dashboard needs to query them directly (see Layer 12). Treat
this as the contract to build against, not as a description of existing
code — **with one confirmed exception, corrected below (GTIEP v1 audit,
2026-07-29): Campaign was listed here as prose-only. It is not.**
`api/_lib/campaign-engine.js` is a real, live, 573-line weighted-clustering
implementation (`cluster_score = ioc_overlap*0.35 + cve_match*0.25 +
time_proximity*0.20 + text_similarity*0.20`) persisting a real
`campaigns.json` with `campaign_id`/`name`/`item_count`/`confidence`/
`severity`/`reasoning[]`/`threat_actors[]` — a superset of the fields
proposed below. This was a documentation gap, not a product gap: the row
is left in this table (rather than deleted) so the field-level contract
below stays visible, but it must not be read as "not yet implemented" —
the remaining gap is convergence with the Python side, not existence.

| Object | Key fields | Today's prose home |
|---|---|---|
| **Campaign** — **already implemented live, see correction above** | `name`, `actors[]`, `first_seen`, `last_seen`, `victims[]`, `techniques[]`, `related_cves[]`, `malware_families[]` | `api/_lib/campaign-engine.js` (live JS); master-prompt.md § Campaign Overview (prose, Python-engine side only) |
| **Incident** | `incident_id`, `campaign_or_actor`, `victim`, `date`, `impact`, `status` | master-prompt.md § Timeline of Events |
| **Victim** | `sector`, `geography`, `confirmation_status` (confirmed\|alleged), `source` | master-prompt.md § Victimology |
| **Organization** | `name`, `sector`, `role` (victim\|vendor\|researcher\|customer), `first_seen` | Currently folded into `Victim` (as victim) or the report's Affected Products/Vendors prose (as vendor) — added by EIPS v4 § Canonical Knowledge Model as its own type because "vendor disclosing a flaw" and "victim of exploitation" are different roles the same organization can hold across reports, which `Victim` alone can't represent |
| **Sector** | `name` (e.g. finance, healthcare, critical-infrastructure), `report_ids[]` | Currently free-text `sectors: []` in report front matter (`report-prompt.md`) — added by EIPS v4 as a first-class entity so sector-level correlation ("which sectors does this actor target across campaigns") is a graph query (Layer 9) instead of a front-matter grep |
| **Infrastructure** | `identifier` (domain/IP/ASN), `role` (C2\|payload-host\|exfil\|dead-drop), `first_seen`, `last_seen`, `hosting_provider` | master-prompt.md § Infrastructure Analysis |
| **C2** | *(specialization of Infrastructure)* + `protocol`, `beaconing_interval`, `encryption` | master-prompt.md § Malware Analysis (C2 & network behavior) |
| **Exploit** | `cve_id`, `maturity` (PoC\|weaponized\|in-the-wild), `author_if_known`, `first_observed_exploitation` | cve-prompt.md § Exploitation status |
| **Mitigation** | `applies_to` (CVE or technique_id), `control_type` (patch\|compensating\|architectural), `sla` | cve-prompt.md § Compensating controls |
| **DetectionRule** | `format` (see Layer 6), `maturity` (see Layer 6), `technique_ids[]`, `false_positive_notes`, `required_telemetry` | Currently raw text in `sigma/`, `yara/`, etc. — no metadata wrapper object yet |
| **ExecutiveBriefing** | `report_id`, `audience`, `bottom_line`, `risk_snapshot`, `recommendations[]` | `templates/executive/executive-brief.md` (a template, not an object) |

## Relationships

See Layer 9 — relationships between these objects are already a working
graph (`KnowledgeGraph.relate()`), not a separate concern from the object
model. Do not build a second relationship mechanism for the newly-specified
objects above; when they are implemented, they should upsert into the same
graph using the same `type:name` key convention.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 3*
