# EIPS — CAPABILITY MAP

What the platform actually does today, not an aspirational list. "Owner" is
left honest where the repository has no ownership record — inventing a name
would be exactly the kind of fabrication this document family exists to
prevent.

| Capability | Inputs | Outputs | Depends on | Quality gate | Maturity | Owner |
|---|---|---|---|---|---|---|
| Threat Intelligence (general reports) | Source material + URLs | 60-section report | `Sentinel-APEX/prompts/{master,report}-prompt.md` | EIOS Layer 4 | Mature spec; production is manual/session-driven | Unassigned |
| Vulnerability Intelligence | CVE ID / advisory | CVE report + `intelligence/cves/*.md` | `cve-prompt.md`, `enrichment.py` (live NVD/EPSS/KEV) | EIOS Layer 4 + CVE-specific checklist | Mature; enrichment is live-fetched, drafting is manual | Unassigned |
| Malware Intelligence | Sample / analysis writeup | Malware report + YARA rules | `malware-prompt.md`, `entities.py` lexicon | EIOS Layer 4 incl. `_gate_yara` | Mature spec, manual production | Unassigned |
| Campaign Tracking | Correlated reports/entities | Campaign correlation notes | `knowledge_graph.py` co-occurrence edges | None dedicated | **Low** — `Campaign` is specified (EIOS Layer 3) but not a coded object | Unassigned |
| Threat Hunting | Report + hypotheses | Hunting playbook | `templates/hunting/threat-hunting-playbook.md` | `quality-gate.md` §7 | Template mature, content manual | Unassigned |
| Detection Engineering | TTPs / IOCs | Sigma / YARA / KQL / Suricata / OSQuery | `engine-node` (`detection-engine.js`), `sigma_builder.py` | `validate_sigma`, `validate_yara` | **Most automated capability** — wired into the 5-minute `fetch-live-intel.js` cadence, not manual | Unassigned |
| Executive Reporting | Full report | Executive brief / board summary | `templates/{executive,board}/` | `quality-gate.md` §8 | Templates mature, manual derivation | Unassigned |
| Knowledge Graph | Normalized docs (automated pipeline) **and, since GIKEP v1,** published reports directly (`cli.py graph`, `report_ingest.py`) | Entity/relation graph, persisted at `Sentinel-APEX/knowledge-graph.json` | `knowledge_graph.py` (offline) **and, separately,** `api/_lib/threat-graph.js` (live) | None cross-checking the two | **Duplicated — see `open-issues.md`.** The offline side's publish-time gap (no path from a published report into the graph) is closed; ingestion is still a manual `cli.py graph` invocation, not wired to the publish step itself | Unassigned |
| Search | Blog posts | `search-index.json` | `generate-search-index.py` | None | Live, scoped to `posts/` only (verified — does not index Sentinel-APEX content) | Unassigned |
| Correlation | Entities across reports | Prior-context notes / campaign links | `knowledge_graph.py.prior_context()` **and, separately,** `api/_lib/campaign-engine.js` | None | **Duplicated — see `open-issues.md`** | Unassigned |
| APIs | HTTP requests | JSON responses, billing, auth | `api/v1/{intel,auth,billing,admin}.js`, `vercel.json` | `security-audit.yml`, `smoke-test.yml` (incl. pricing-integrity check) | Live production, revenue-bearing | Unassigned |
| Automation | Cron schedule | Auto-published posts, refreshed feeds | `fetch-live-intel.js` (5 min), `ai-security-intel-engine.js`, `blogger-syndication.yml` | `intelligence-engine-ci.yml`, `detection-engine-node-ci.yml` | Mature — see `platform/automation.md` for full inventory | Unassigned |

## How to keep this current

This table decays the moment a new capability ships without an update — the
same "documentation freshness" concern `quality-metrics.md` tracks
platform-wide. Update this file in the same commit that changes a
capability's maturity or dependencies, not as a follow-up.

---
*CyberDudeBivash® Sentinel APEX — Capability Map*
