# Build System

_Auto-generated from `orchestrator/generators.js` — the single source of truth for every generator's metadata. Regenerate with `node scripts/generate-docs.js`._

## Generator SDK

Every generator is described via `orchestrator/generator-sdk.js`'s `defineGenerator()` contract: `{ id, description, inputs, outputs, dependsOn, freshnessCheck, schedule, run | command }`. Generators with a `run()` execute in-process (only `generate-intelligence-hub.js` today, the SDK's reference implementation — it already exported `main()`). Every pre-existing, already-CI-scheduled generator is wrapped via `command` instead, shelled out exactly as its own GitHub Actions workflow already invokes it, so registering it here never requires modifying its working code.

## Registered Generators (dependency order)

| ID | Schedule | Depends On | Description |
|---|---|---|---|
| `live-intel` | 0,30 * * * * (sentinel-apex.yml) | — | Live threat intel ingestion — posts, CVE/product JSON, search index, sitemap |
| `ai-security-intel` | 0 */2 * * * (ai-security-intel.yml) | — | AI security & LLM threat intelligence ingestion |
| `blogger-syndication` | 15 */2 * * * (blogger-syndication.yml) | — | Re-syndicates published reports to Blogger (cyberbivash.blogspot.com) |
| `cve-pages` | 0 */6 * * * (cve-pages.yml) | `live-intel` | Renders static /cve/{id}.html pages from ingested CVE JSON |
| `intelligence-hub` | 20 */6 * * * (intelligence-hub.yml) | `live-intel` | Vendor/ecosystem centers, timeline, collections, live detection feed |
| `rss-feed` | 0 */6 * * * (generate-rss.yml) | `live-intel` | Rebuilds rss.xml from published posts |

## Orchestrator CLI

```
node orchestrator/build-orchestrator.js --discover              # list generators
node orchestrator/build-orchestrator.js --run <id>               # run one generator
node orchestrator/build-orchestrator.js --run-all [--incremental] # run all, in dependency order
```

Every invocation writes `logs/build-manifest-<timestamp>.json` and `logs/build-manifest-latest.json`. `--incremental` skips a generator whose declared `inputs` haven't changed since its last recorded success (generators with no local inputs — e.g. external feed pulls — always run).

This orchestrator is available on-demand via the `workflow_dispatch`-only `build-orchestrator.yml` workflow. It does **not** replace or schedule over any of the six generators' own independent GitHub Actions workflows.
