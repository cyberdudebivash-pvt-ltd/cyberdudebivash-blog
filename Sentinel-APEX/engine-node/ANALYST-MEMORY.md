# Analyst Memory — persistent cross-report intelligence

Turns a stream of isolated reports into an evolving intelligence asset. As each
report is generated, the entities it references are recorded; new reports then
answer **"have we seen this before?"** instead of treating every event as
isolated.

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

A second report on a recurring adversary renders:

> **Prior Intelligence Context** — correlated against SENTINEL APEX persistent memory:
> - Threat actor APT41 — previously observed 4 times in CYBERDUDEBIVASH intelligence since 2026-05-02
> - Malware family LockBit — previously observed 11 times …
> - Vendor Fortinet — previously observed 12 times …

## Tests

```bash
cd Sentinel-APEX/engine-node
node --test        # 34 tests: 18 detection + 8 memory + 8 wiring
```

Memory tests cover entity extraction, prior-context timing (first sighting is
empty; recurrence surfaces), count accumulation, bounded pruning, corrupt/missing
-file resilience, and full round-trip persistence.
