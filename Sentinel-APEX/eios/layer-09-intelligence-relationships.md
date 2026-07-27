# EIOS LAYER 9 — INTELLIGENCE RELATIONSHIPS

Represents how entities connect across reports. This is implemented and
tested today — `engine/sentinel_engine/knowledge_graph.py`'s
`KnowledgeGraph` class — not a new mechanism to build.

## What exists

`KnowledgeGraph` is a persistent, JSON-backed graph of entities and typed
relations:

- **Entities**: keyed `"type:name"` (lowercased), each tracking which
  reports mentioned it (`upsert_entity`).
- **Relations**: `{src, rel, dst, report}` triples (`relate`). Relation
  types already in use: `mentions`, `references`, `maps_to`, `observed`,
  `associated_with`, `linked_to`.
- **Ingestion** (`ingest(doc, report_id)`): every `NormalizedDoc` — actors,
  malware, tools, CVEs, ATT&CK techniques, IOCs — is automatically upserted
  and related to its source report, plus co-occurrence edges between
  threat actors and the malware/tools/CVEs mentioned alongside them in the
  same report.
- **Queries**: `neighbors(key)` (everything connected to an entity),
  `prior_context(doc)` (human-readable notes on what the graph already
  knows about a new document's entities — this is what feeds the
  `known_context` correlation step in `prompts/report-prompt.md`'s
  production rule 7 and what appears under "Prior Intelligence Context" in
  `pipeline.py::render_draft`), `stats()` (entity/relation counts by type).
- **Persistence**: `save`/`load` to a single JSON file, versioned alongside
  the repository — deliberately no external database, so it runs in CI.

## The relationship graph this layer describes

```
Threat Actor  --associated_with-->  Malware / Tool
Threat Actor  --linked_to-->        CVE
Report        --mentions-->         Entity (any type)
Report        --references-->       CVE
Report        --maps_to-->          ATT&CK Technique
Report        --observed-->         IOC
```

This is the same relationship set the v2 specification asked for (Actor →
Campaign → Malware → Infrastructure → CVEs → Techniques → Victims →
Detection Content → Mitigations) expressed with the relation types that
already exist in code, plus the objects Layer 3 specifies but has not yet
implemented (Campaign, Infrastructure, Victim, Mitigation). **When those
objects are implemented, they upsert into this same graph using the same
`type:name` key convention — do not build a second graph.**

## How a new report uses this layer

1. Before drafting, call `graph.prior_context(doc)` on the normalized
   document — this is Stage 3 (Correlation) of Layer 2's lifecycle.
2. Surface what comes back in the report's Verified Facts / Analyst
   Assessment sections, labeled per Layer 2 (a prior appearance is a
   **Verified Evidence** fact — "this domain appeared in report SA-2026-0031";
   whether it indicates the *same* campaign is an **Analyst Assessment**).
3. After the report is finalized, call `graph.ingest(doc, report_id)` so the
   next report benefits from this one.

## What this layer does not do

It does not attribute or correlate automatically beyond co-occurrence in
the same report — `associated_with` and `linked_to` edges record that two
entities appeared together, not that the graph has concluded they are
related. That interpretation is always an analyst judgment, labeled per
Layer 2.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 9*
