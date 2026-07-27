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
prose sections, not as structured types. The schema below is what a future
`models.py` extension should implement when an API or dashboard needs to
query them directly (see Layer 12). Treat this as the contract to build
against, not as a description of existing code.

| Object | Key fields | Today's prose home |
|---|---|---|
| **Campaign** | `name`, `actors[]`, `first_seen`, `last_seen`, `victims[]`, `techniques[]`, `related_cves[]`, `malware_families[]` | master-prompt.md § Campaign Overview |
| **Incident** | `incident_id`, `campaign_or_actor`, `victim`, `date`, `impact`, `status` | master-prompt.md § Timeline of Events |
| **Victim** | `sector`, `geography`, `confirmation_status` (confirmed\|alleged), `source` | master-prompt.md § Victimology |
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
