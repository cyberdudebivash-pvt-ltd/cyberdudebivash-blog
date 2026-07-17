# Sentinel APEX Native Provider — intel.cyberdudebivash.com

## What this is

`fetch-live-intel.js` ingests intelligence from `intel.cyberdudebivash.com`,
the product-delivery portal for the same Sentinel APEX ecosystem this repo's
own engine feeds (see `Sentinel-APEX/README.md`) — not a third-party vendor.
It is registered as the 28th source, alongside NVD, CISA KEV, GitHub
Advisories, and the rest of the existing 27.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `/api/v1/intel/latest.json` | Latest threat intelligence |
| `/api/v1/intel/apex.json` | Sentinel-scored intelligence |
| `/api/v1/intel/ai_summary.json` | AI-generated threat summaries |
| `/api/feed.json` | Unified feed (may superset the above) |
| `/api/reports/latest.json` | Full threat reports |

All 5 are fetched in parallel (`Promise.allSettled`) inside one
`fetchSentinelApex()` call, registered as a single Tier 1 source
(`sentinel_apex`). One endpoint failing (timeout, non-200, malformed JSON)
never blocks the other 4 or the rest of the pipeline — the same failure
contract every other source already has.

## Schema tolerance — read before touching normalizeSentinelApexRecord()

The live response shape was **not** independently verified when this
provider was built: this repo's dev sandbox blocks outbound access to
`intel.cyberdudebivash.com` at the network-policy level (production GitHub
Actions runners are unaffected — they have normal internet access, which is
the real validation point).

Every field is read defensively through `sapexPick()` / `sapexPickArray()`
candidate-key lookups covering common REST/CTI and STIX 2.1 field-name
variants (e.g. `title|name|headline`, `cvss|cvss_score|severity`,
`references|refs|external_references`). Unknown/extra fields are ignored.
A record with no title and no description is skipped, not fabricated
(`sapexUnknownShapeCount` tracks how many were skipped, logged in the
per-run summary line).

**If production logs show 0 items from `sentinel_apex` for multiple
consecutive runs while `/api/health` is reachable, the schema likely
doesn't match any of the candidate keys.** Everything lives in one place:
`normalizeSentinelApexRecord()` (and its helpers `extractSentinelApexRecords()`,
`sapexNativeMitre()`, `sapexCanonicalId()`) in `fetch-live-intel.js`. Update
the candidate-key lists there against a real captured payload — nothing
else in the pipeline assumes a specific shape.

## Canonical IDs & deduplication

A real CVE id always wins as the dedup key (explicit `cve`/`cve_id`/`cves`
fields, unioned with regex-extracted CVEs from title+description via the
existing `extractCVEs()`), so a Sentinel APEX record about a CVE already
published from NVD/CISA/GitHub Advisories correctly merges into the
existing article instead of duplicate-publishing. Records with no CVE fall
back to a stable hash of the platform's own record id, then the title —
the same fallback convention already used by the OTX/RansomWatch/
AIIncidentDB sources.

`sentinel_apex` sits at rank 7 in `correlateAndMerge()`'s source-rank table
(above generic RSS/community sources, below the primary government/vendor
authorities NVD/CISA KEV/GitHub Advisories) — it decides only which side's
title/desc/vendor/product wins a merge tie-break. IOCs, CVEs, references,
`exploited`/`cisaKev`/`ransomware` flags, and native MITRE mappings are
unioned/preserved regardless of which side wins.

## MITRE ATT&CK — native mapping preferred over inference

`normalizeSentinelApexRecord()` maps any native MITRE data (`mitre_tactics`,
`mitre_attack`, `ttps`, …) into `item.mitreNative`. `generatePostHTML()`
uses `item.mitreNative || getMitre(item)` — a real analyst mapping always
wins over the regex-based `getMitre()` inference used for sources that don't
provide one. This also populates the previously-unset `item._mitre` output
field already read by the per-CVE API file writer, for every source, not
just this one. `correlateAndMerge()` preserves `mitreNative` across a merge
even when Sentinel APEX loses the source-rank tie-break.

## Health monitoring

No new monitoring surface — reuses the existing per-source convention
exactly: `recordSourceSuccess`/`recordSourceFailure` write into
`state.sourceHealth.sentinel_apex` (inside `intel-state.json`), the same
mechanism every one of the other 27 sources already uses, read in the
workflow's run-summary step. Degraded status follows the same
3-consecutive-failure threshold (`CFG.healthFailThreshold`).

## Configuration

`SENTINEL_APEX_API_KEY` (optional, GitHub Actions secret) — sent as
`Authorization: Bearer <key>` when set. The endpoints are currently public;
this exists only so a future auth requirement or higher rate-limit tier
doesn't need a code change, mirroring `NVD_API_KEY`/`GITHUB_TOKEN`/
`OTX_API_KEY`.

## Tests

`Sentinel-APEX/engine-node/tests/sentinel-apex-provider.test.js` — run via
`cd Sentinel-APEX/engine-node && node --test` (already wired into
`.github/workflows/detection-engine-node-ci.yml`, which triggers on any
change to `fetch-live-intel.js`). Covers envelope-shape tolerance, canonical
ID derivation, defensive field mapping across schema variants, malformed/
missing-field handling, native-MITRE-preferred-over-inferred (through a full
`generatePostHTML()` render), and dedup/merge integration with an existing
source. These validate the mapper's *contract*, not asserted-real production
field values — see the schema-tolerance section above.

## Future endpoint expansion

To add a 6th endpoint: add its URL to `CFG` next to the other 5, add
`['key', CFG.newUrl]` to the `endpoints` array in `fetchSentinelApex()`,
done — `extractSentinelApexRecords()`/`normalizeSentinelApexRecord()` need
no changes unless the new endpoint introduces genuinely new field names.
