# Analyst Memory + Threat Correlation — persistent intelligence knowledge graph

Turns a stream of isolated reports into an evolving intelligence asset. As each
report is generated, the entities it references are recorded **and related** to
one another, so new reports answer not only **"have we seen this before?"** but
**"which campaigns reused these TTPs?"**, **"what techniques does this actor
use?"**, and **"which vendors are repeatedly targeted?"**

## Two layers over one store

1. **Analyst Memory** — per-entity `firstSeen` / `lastSeen` / `count` / recent
   reports. Powers the *Prior Intelligence Context* section.
2. **Threat Correlation Engine** — a co-occurrence relationship graph
   (`edges[a][b] = count`) among correlatable entities (actors, malware,
   techniques, CVEs, vendors, products). Powers the *Threat Correlation
   Analysis* section. `correlate(item)` returns, computed **before** ingest:
   - **actor TTP profiles** — techniques a report's actors/malware are known for
   - **TTP reuse** — for each technique in the report, which actors/malware have
     used it historically (cross-campaign shared-TTP correlation)
   - **repeated targeting** — vendors/products seen in ≥2 prior reports
   - **related prior reports** — ranked by shared-entity overlap

Both layers persist in the single `intel-memory.json` store (one source of
truth) and are bounded — 50k-entity cap with LRU pruning, plus a per-node
neighbor cap (60) on the graph, so neither can grow without limit.

## What's tracked

Per entity: `type`, `name`, `firstSeen`, `lastSeen`, occurrence `count`, and the
last five report slugs. Entity types:

- `cve` — CVE identifiers
- `vendor` / `product` — affected technology
- `ioc_domain` / `ioc_ipv4` / `ioc_url` — network infrastructure (refanged)
- `technique` — MITRE ATT&CK IDs (via the shared detection engine's mapper)
- `actor` — threat groups (compact high-precision lexicon)
- `malware` — malware/tooling families

## How it's wired into the live generator

`fetch-live-intel.js` loads it defensively and drives the full lifecycle:

1. **Load** `intel-memory.json` at the start of a run (missing/corrupt → empty, never fatal).
2. **Render** a *Prior Intelligence Context* section in each post — computed
   **before** the current report is ingested, so counts reflect history only.
3. **Ingest** each successfully published report's entities.
4. **Persist** the memory back to `intel-memory.json` at the end of the run
   (committed alongside the site, like `intel-state.json`).

Every step is guarded: the require, the render (`genPriorIntelligence`), and
load/save all fail closed to a no-op, so memory can never break the ~1500-post
generation. The store is **bounded** — capped at 50k entities with
least-recently-seen pruning — so it cannot grow without limit.

## Example

A report on a recurring adversary renders:

> **Threat Correlation Analysis** — knowledge-graph correlation:
> - Malware LockBit has been correlated with prior TTP use: T1059.001, T1490
> - Technique T1490 was previously observed with: APT41, LockBit, Akira
> - Vendor Fortinet has been targeted in 2 prior CYBERDUDEBIVASH reports (recurring target)
> - Related prior intelligence: apt41-lockbit-fortinet (5 shared entities), akira-fortinet (2 shared entities)

## Tests

```bash
cd Sentinel-APEX/engine-node
node --test        # 46 tests: 18 detection + 8 memory + 11 correlation + 9 wiring
```

Coverage: entity extraction, prior-context timing (first sighting empty,
recurrence surfaces), count accumulation, edge construction, actor-TTP profiles,
cross-campaign TTP reuse, recurring-target detection, related-report ranking,
read-only correlation, bounded entity + neighbor pruning, corrupt/missing-file
resilience, and full round-trip persistence of both entities and edges.
