# EIPS — ENTERPRISE AUTOMATION INVENTORY

What's actually automated today, grounded in real workflow files — not a
wishlist. Principle, stated because one real tension below tests it:
**automation supports analyst review, it does not replace it.**

## Automated today

| Function | Mechanism | Cadence |
|---|---|---|
| Multi-source content ingestion, dedup, correlation | `fetch-live-intel.js` | Every 5 minutes (`sentinel-apex.yml`) |
| IOC normalization | `fetch-live-intel.js` (live pipeline) + `ioc_extractor.py` (offline, on-demand) | Live: continuous. Offline: manual invocation |
| Detection generation (Sigma/KQL/Splunk/OSQuery/Suricata) | `engine-node`'s Detection Engine, wired into `fetch-live-intel.js` | Every 5 minutes, same cadence as ingestion |
| Metadata enrichment (CVSS/EPSS/KEV) | Live: `fetch-live-intel.js`. Offline: `enrichment.py` | Live: continuous. Offline: manual/on-demand |
| Publication (posts, RSS, sitemap) | `blogger-syndication.yml`, `generate-rss.yml`, `sentinel-apex.yml` | Every 5–15 minutes, throttled by `vercel-ignore-build.sh` for deploy-quota reasons |
| AI security intelligence collection | `ai-security-intel.yml` → `ai-security-intel-engine.js` | Scheduled |
| Freshness checking | `freshness-check.yml` | Scheduled |
| CVE page generation | `cve-pages.yml` | Scheduled |
| Dependency/secret security audit | `security-audit.yml` | On `api/**` push + weekly |
| Production smoke test + pricing integrity | `smoke-test.yml` | On non-doc push to `main` |
| Engine test suites (path-scoped, fast feedback) | `intelligence-engine-ci.yml`, `detection-engine-node-ci.yml`, `report-renderer-ci.yml` | On push to their respective paths |
| Full assurance pass: all 4 suites + `cli.py gate` + `cli.py certify` (EICF v1) across every published report | `scripts/assure.sh` (ECAP v1), wired into CI by `continuous-assurance.yml` | On push/PR touching `Sentinel-APEX/**`, `tests-js/**`, `fetch-live-intel.js`; on demand locally or via `workflow_dispatch` |

## Not automated (by design or by gap)

| Function | Status |
|---|---|
| `Sentinel-APEX/prompts/` report drafting | Manual/session-driven — no automated pipeline calls `master-prompt.md` for general reports |
| `knowledge_graph.py::ingest()` (offline graph) | Requires manual invocation; the *live* graph (`api/_lib/threat-graph.js`) updates automatically but is a separate system — see `open-issues.md` |
| Report version bump / change_log entry (EIOS Layer 8) | Manual convention, no tooling generates it |
| Changelog generation for `prompts/*.md` / `eios/*.md` themselves | Manual — the "Changelog" sections in root `/prompts/` files were hand-maintained, not generated |

## The real tension worth naming

The automated content pipeline (`fetch-live-intel.js`, 5-minute cadence,
hundreds of commits/day per `vercel-ignore-build.sh`'s own comments)
publishes without passing through `Sentinel-APEX/engine/sentinel_engine
/quality.py` — that gate is wired to the manual `Sentinel-APEX/prompts/`
pipeline, not the automated one. This may be entirely intentional (the
automated pipeline's own internal logic — defensive parsing, source-rank
tie-breaking, KEV/CVSS-only exploitation claims — is a different, narrower
quality mechanism suited to its higher volume). It is flagged here because
"automation supports review, never replaces it" is stated as a platform
principle, and the automated pipeline's actual relationship to the
EIOS Layer 4 gate should be a decision someone made on purpose, not an
artifact of the two systems having been built separately and never
cross-checked — which is exactly the pattern found twice already this
session in other subsystems.

---
*CyberDudeBivash® Sentinel APEX — Automation Inventory*
