# SENTINEL APEX™ — Customer Defense Context: Reuse-Before-Build Inventory v1

Scope: everything a "customer telemetry / environment-aware defense coverage"
feature could plausibly reuse. Read directly from code (not from other docs'
claims) on 2026-08-26 against `main` @ `5bf05750` (PR #141 merged).

## 1. Search terms and where they actually led

| Search term | Real hits | Verdict |
|---|---|---|
| `workspace_id` / `tenant_id` | Only in unrelated CVE JSON records and test fixtures (false positives — field names that happen to contain the substring) | **No workspace/tenant concept exists anywhere in this codebase.** |
| `owner_id` | `watchlist-store.js`, `change-engine.js` (D1 schema + queries) | Real, reusable ownership pattern — see §2. |
| "customer profile" / "environment" / "technology" | No existing store | Gap — this tranche's core new object. |
| "telemetry" / "data source" / "log source" | `api/_lib/detection-intelligence.js`'s `TELEMETRY_REQUIREMENTS` (4-key vocabulary: `process_creation`, `process_access`, `registry_set`, `network`) | **Real, existing, canonical telemetry vocabulary — reused verbatim, not reinvented (§3).** |
| "SIEM" / "EDR" / "XDR" | `Sentinel-APEX/engine-node/detection-engine.js`'s `FIELD_MAP` — `_kql_table` values are Microsoft Sentinel/Defender XDR's real Advanced Hunting table names (`DeviceProcessEvents`, `DeviceEvents`, `DeviceRegistryEvents`); `_splunk_dm`/`_osquery_table` are Splunk CIM data models / osquery tables | **The KQL/Splunk/OSQuery generators already target real vendor schemas — this IS the field-mapping engine the mandate asks for (§54). Reused, not duplicated.** |
| "entitlement" | `watchlist-store.js#getWatchlistEntitlements(tier)` — flat, non-tier-differentiated, documented gap in `platform/open-issues.md` | Pattern to follow exactly for Defense Profile entitlements. |
| "connector" / "integration" | Nothing live — `docs/audits/SENTINEL-APEX-DETECTION-CAPABILITY-INVENTORY-V1.md` already documented the 43-file `lib/detection/` TS stack's docs-vs-reality gap for a different subsystem | No SIEM/EDR connector exists anywhere. Confirms mandate §4's "no automatic deployment" boundary matches current reality, not just policy. |
| "coverage" / "detection compatibility" | `api/_lib/detection-intelligence.js#computeCoverage()` (global, entity-scoped, no customer dimension) | Extended, not duplicated — see §4. |
| D1 schemas | `migrations/0001_notification_delivery.sql`, `migrations/0002_watchlists_change_detection.sql` | New migration `0003` follows the identical conventions (see certification doc §6/§24). |

## 2. Customer ownership — reused exactly, not reinvented

`api/_lib/middleware.js#authenticate()` is the platform's single authentication
chokepoint. It returns `{ tier, userId, email, keyHash, requestsUsed,
requestsLimit }` from a server-side API-key hash lookup — `userId` is never
client-supplied. `watchlist-store.js` already builds a full D1-backed,
per-owner CRUD resource on top of this (`owner_id` column, `getOwnedWatchlist()`
returning an identical 404 for "missing" and "someone else's", full audit
log). **Defense Profile reuses this identical ownership pattern verbatim** —
no new identity concept, no workspace/tenant model invented (mandate §53:
"If not [multi-workspace foundation exists]: do not invent full MSSP
architecture now" — confirmed no such foundation exists, so v1 is
one-profile-per-`owner_id`, matching mandate §52).

## 3. Telemetry vocabulary — reused, not reinvented

`detection-intelligence.js`'s `TELEMETRY_REQUIREMENTS` already defines the
platform's canonical normalized telemetry concepts (`process_creation`,
`process_access`, `registry_set`, `network`), each with a `source_label` and
`known_fields`/`optional_fields`. This is exactly the "normalized telemetry
model" the mandate's §14 asks for. **The new `api/_lib/defense-taxonomy.js`
imports this object directly rather than declaring a second, parallel
vocabulary** — a customer's telemetry declaration is keyed by the same 4
strings a detection's `telemetry_requirements` already uses, so matching them
is a direct lookup, not a fuzzy cross-reference.

Note: only 3 of the 4 data sources (`process_creation`, `process_access`,
`registry_set`) are exercised by `detectionEngine.REGISTRY`'s 6 real buildable
techniques today; `network` is documented but has no buildable technique yet
(disclosed, not hidden — see certification doc's Known Limitations).

## 4. Field mapping — reused, not reinvented

`detection-engine.js`'s `FIELD_MAP` + `resolveField(dataSource, logical,
platform)` already compiles each technique's logical fields (`process_path`,
`command_line`, …) into per-format-language field names, AND ties each format
to a real backend: `toKql()` emits queries against `FIELD_MAP[ds]._kql_table`
(`DeviceProcessEvents` / `DeviceEvents` / `DeviceRegistryEvents` — Microsoft
Sentinel/Defender XDR's real Advanced Hunting schema table names), `toSplunk()`
against `_splunk_dm` (Splunk CIM data models, vendor-neutral by design), and
`toOsquery()` against `_osquery_table` (osquery's cross-platform tables).
**This means format compatibility (§25) and telemetry-source compatibility
(§54) are the SAME fact, already computed by the existing generator** — a
detection's `kql` format is Microsoft-Sentinel/Defender-XDR-native by
construction, not by a separately-maintained mapping table this tranche would
have to keep in sync. `FIELD_MAP` was not previously exported; this tranche
adds it to `detection-engine.js`'s `module.exports` (one additive line, zero
behavior change) so the new compatibility engine can read the real
`_kql_table`/`_splunk_dm`/`_osquery_table` values instead of re-declaring them
as a second, driftable copy.

## 5. API router pattern — two existing conventions, both reused

Two different, deliberate router conventions already coexist:

- `api/v1/intel.js` — **GET-only** (`if (req.method !== 'GET') return 405`
  enforced at the top), `action=` dispatch, entity-keyed lookups
  (`dossier`, `detection-coverage`, `campaign`, …). New GET-only,
  entity-keyed lookup (`defense-coverage`) is added here, matching every
  sibling action's shape exactly.
- `api/v1/watchlists.js` — its own file, GET+POST, customer-owned CRUD
  resource, ownership always re-derived from `authenticate()`'s `userId`,
  never from the request body (`sec.assertFieldWhitelist` bounds every POST
  body to a fixed field list). Defense Profile is the same shape of problem
  (a customer-owned, mutable resource) — **a new `api/v1/defense-profile.js`
  is added following this exact convention**, not crammed into `intel.js`'s
  GET-only gate and not a from-scratch design.

## 5a. UI convention — reused, not reinvented

No existing "customer settings" page covers security-stack configuration —
`api-dashboard.html` is API-key management only. `dossier.html`'s existing
`refreshDetectionCoverage()` / `esc()` / `sessionKey` (in-memory-only) /
`showStatus()` pattern (added in PR #141) is reused verbatim for the new
"Your Defense Coverage" panel and for the new `defense-profile.html` settings
page's own fetch/render/XSS-safety conventions — same CSS design tokens, same
API-key-in-memory-never-persisted discipline.

## 6. Canonical ownership decisions (summary)

| Capability | Existing implementation | Canonical owner going forward | Reusable | Gap this tranche fills |
|---|---|---|---|---|
| Customer identity / ownership | `middleware.js#authenticate()` → `userId` | Unchanged | Yes, verbatim | — |
| Customer-owned D1 CRUD resource pattern | `watchlist-store.js` + `migrations/0002_*.sql` | Pattern reused for `defense-profile-store.js` + `migrations/0003_*.sql` | Yes, pattern only (new table) | Defense Profile has no existing store |
| Normalized telemetry vocabulary | `detection-intelligence.js#TELEMETRY_REQUIREMENTS` | Unchanged, imported | Yes, verbatim | Provider→source label mapping (new) |
| Field/format mapping | `detection-engine.js#FIELD_MAP`/`resolveField` | Unchanged, exported (additive) | Yes, verbatim | Technology→preferred-format mapping (new) |
| Global detection coverage | `detection-intelligence.js#computeCoverage()` | Unchanged, wrapped | Yes, verbatim | Per-customer compatibility rollup (new) |
| GET entity-lookup router | `api/v1/intel.js` | Unchanged, extended (+1 action) | Yes | — |
| Customer-owned CRUD router | `api/v1/watchlists.js` (pattern) | Pattern reused for new `api/v1/defense-profile.js` | Yes, pattern only | — |
| Entitlements | `watchlist-store.js#getWatchlistEntitlements()` (flat, non-tier) | Pattern reused | Yes, pattern only | — |

**No second customer/workspace system is introduced. No second telemetry
vocabulary is introduced. No second field-mapping table is introduced.**
