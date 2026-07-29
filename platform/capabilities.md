# EIPS — CAPABILITY MAP

What the platform actually does today, not an aspirational list. "Owner" is
left honest where the repository has no ownership record — inventing a
name would be exactly the kind of fabrication this document family exists
to prevent.

**Rewritten in full (GPLCIP v1)** — the previous version predated four
full sprints of real work (report publication, backup/restore, auth
observability, pricing fixes, FAQ) and had gone stale despite this file's
own rule that it be updated in the same commit as any capability change.
That rule was not followed across those sprints; this rewrite is the
correction, not a claim that the rule will now be followed perfectly going
forward — treat "last touched" per row as the actual freshness signal.

**Lifecycle Status** uses GPLCIP v1's taxonomy: Active / Improving /
Stable / Monitor / Candidate for Refactoring / Candidate for Retirement.

## Intelligence Production

| Capability | Lifecycle Status | Customer Value | Operational Value | Key Dependencies | Notes |
|---|---|---|---|---|---|
| Intelligence Reports (hand-authored, published) | **Improving** | High — the core differentiated content asset | Builds SEO/authority; the thing that distinguishes this platform from an automated aggregator | `Sentinel-APEX/renderer/` (marked + js-yaml), `Sentinel-APEX/engine/` quality gate + EICF certification, `publish-report.js` (manual CLI) | 3 published (SA-2026-0001/2/3), all now actually live at `/intelligence/` — 2 of 3 sat certified-but-unpublished for weeks before GCDOM v1 caught it. **Publication is still a manual step, separate from certification** — the exact gap that caused that. Not automated; a real recurring risk until someone closes it or a human commits to running it every time. |
| Knowledge Graph — offline (Python, `knowledge_graph.py`) | **Candidate for Refactoring** (blocked on Issue 1's executive decision) | Indirect — feeds report-ingestion quality, not customer-facing directly | Low today — 10 entities, small, not wired to any automated trigger | `report_ingest.py`, `attack_mapper.py`, `entities.py`, `ioc_extractor.py` | Architecturally duplicated with the live JS graph below (Issue 1). ATT&CK tactic-label false-positive fix and ASP.NET IOC misclassification fix landed here this session (GCDOM v1/GPEP v1). Genuinely should converge with the live graph eventually — not attempted, correctly, without an executive decision on canonical ownership first. |
| Knowledge Graph — live (JS, `api/_lib/threat-graph.js`) | **Improving** | Powers paid-tier graph queries; the closest thing to a real competitive differentiator vs. Recorded Future/GreyNoise per the sourced competitive review | Live, ~30-min ingest cycle, revenue-adjacent (paid-tier-gated via `getGraphForTier()`) | `enrichment-pipeline.js`, `campaign-engine.js` | Real correlation work landed across 3 sprints: Campaign↔Campaign (GEPMO v1), CVE↔CVE (GCDOM v1), Actor↔Actor (GPEP v1) — all additive `co_occurs_with` edges, tested against real data cardinality each time. Still open: Malware node type fully unpopulated; actor-attribution coverage still ~2%/~1% of the graph (unchanged — none of the correlation work touched attribution itself). |
| ATT&CK Mapping (`attack_mapper.py`) | **Improving** | Trust-critical — a wrong technique mapping is actively misleading to a SOC analyst | Feeds both graphs above and every published report's own mapping table | `_LEXICON` keyword patterns, negation handling | Multiple real defects found and fixed across 4+ sprints (negation-unaware matching, table-row sentence-boundary bug, tactic-label self-reference false positives — closed for 4 technique IDs, not just the 1 observed). Known remaining false-positive mechanisms (forward-looking hedge language without a cue word; association-fact vs. impact-fact conflation) are correctly left unfixed — each needs more evidence than the current n=1/n=2 before a safe structural fix is possible. |
| IOC / Entity Extraction (`ioc_extractor.py`, `entities.py`) | **Improving** | Same trust-critical reasoning as ATT&CK mapping — a false IOC is actionable-but-wrong advice to a customer | Feeds both graphs, published reports | `DEFAULT_ALLOWLIST`, `TECH_NAME_ALLOWLIST` (new) | Citation-URL-as-IOC fix (EIOS-X v1), ASP.NET-as-domain fix (GPEP v1, verified against the real published report). `entities.py` still has no negation awareness at all (Issue 9) — a known, documented gap, not attempted. |
| Detection Generation (Sigma/YARA/KQL/Suricata/OSQuery) | **Stable** | Direct — detection-pack/MSSP revenue line | Most automated capability on the platform — wired into the 5-minute live bot cadence | `engine-node/detection-engine.js`, `sigma_builder.py` (deliberate parity port, not duplication — see Issue 1's Detection Generation row) | Not touched this session; no new evidence gathered. Carried forward from the prior capability map without re-verification — flagged honestly rather than silently re-asserted as freshly checked. |

## Customer-Facing Platform

| Capability | Lifecycle Status | Customer Value | Operational Value | Key Dependencies | Notes |
|---|---|---|---|---|---|
| API Platform (`api/v1/{intel,auth,billing,admin}.js`) | **Active** | Direct — the product itself for API-tier customers | Revenue-bearing, live production | `vercel.json`, Upstash Redis | 0 CI failures across all recently-sampled workflow runs; `npm audit` clean (0 vulnerabilities, 38 deps). |
| Authentication (`api/_lib/middleware.js`) | **Improving** | Indirect — reliability of every authenticated request | Security-relevant chokepoint, shared by every authenticated endpoint | Redis (`user:key:*`) | Gained failure-path observability this session (GEORP v1) — previously zero visibility into missing-key, invalid-key, or rate-limit-exceeded events at this platform's single shared auth chokepoint. |
| Registration & Onboarding (`handleRegister`, welcome email) | **Active** | Direct — first real interaction a customer has with the platform | Low support burden once live (email closes the "lost my key" gap) | Resend (`RESEND_API_KEY`) | Welcome email merged to `main` and live in production (the one item this session explicitly received isolated deployment approval for). |
| Billing / Payments | **Active**, with a verified caveat | Direct | Revenue-critical | Manual UPI/bank-transfer (primary, human-reviewed), Stripe/Razorpay (secondary) | Manual UPI/bank-transfer confirmed as the working primary path. Stripe/Razorpay's live-activation status is "⚠️ verify" per `OPERATIONS.md`, **not independently re-confirmed this session** — stated as unverified, not assumed working. Separately: live-verified `GET /api/v1/billing?action=plans` still returns the pre-fix Starter price — the tested reorder fix has not deployed (Issue 12). |
| Customer Dashboard (`api-dashboard.html`) | **Stable** | Direct — where a customer manages their key/tier/usage | Low | `api/v1/auth?action=usage` | Price display fix exists on the feature branch, not live, same Issue 12 gap as Billing above. |
| Documentation / FAQ (`faq.html`) | **Active** | Direct — reduces support load | Reduces reliance on the single-channel `mailto:` support path | None beyond static hosting | New this session (GCDOM v1) — flagged as absent across 3 consecutive prior reviews before being built. |
| Newsletter (Resend audience capture) | **Monitor** | Indirect — acquisition funnel | Low today | Resend (`RESEND_AUDIENCE_ID`) | Per `OPERATIONS.md`, last verified 2026-07-05 as "not configured" (`esp_status: not_configured`, provider still `formsubmit`). **Not independently re-verified this session** — no safe way to check without live credentials or triggering a real signup. Status stated as unknown-current, not assumed unchanged. |

## Operations & Governance

| Capability | Lifecycle Status | Customer Value | Operational Value | Key Dependencies | Notes |
|---|---|---|---|---|---|
| Backup & Restore | **New — not yet active** | Indirect but severe if absent (data-loss recoverability) | High once active — the difference between a recoverable incident and permanent data loss | 3 GitHub Actions secrets (none provisioned yet), Node's built-in `crypto` | Built and tested this session (GEORP v1) closing a gap that existed with zero mitigation before: registered API keys, tier assignments, and the payment audit log lived only in Redis with no export path at all. Held pending secret provisioning, same activation pattern as the welcome email. No restore has been rehearsed against a live Redis instance yet — stated explicitly as remaining validation in `RUNBOOKS.md`. |
| Observability / Monitoring | **Improving** | None directly | Detects abuse patterns and operational issues before a customer reports them | Redis counters (`analytics:*`) | Registration counters (pre-existing), a genuinely comprehensive payment audit log via `auditLog()` covering 11 distinct event types (pre-existing — more complete than an earlier sprint assumed before actually reading the code), auth-failure counters (new, GEORP v1). Still no dashboard or alerting layer on top of any of these raw counters — that's a Strategic Investment, not attempted here. |
| Runbooks / Operational Documentation (`RUNBOOKS.md`) | **New — Active as documentation** | None directly | Reduces incident mean-time-to-resolution | None | New this session. Procedures are accurate to the current codebase but explicitly marked unrehearsed against a real incident — confidence in the documentation's correctness is high, confidence in the procedures working under real pressure is not yet earned. |
| CI/CD & Continuous Assurance | **Mature** | None directly | High — the actual quality gate before any change is trusted | 14 GitHub Actions workflows, `scripts/assure.sh` | 0 failures across all recently-sampled runs across every workflow checked (spot-verified further on pricing-integrity and detection-engine-node specifically). |
| Deployment Pipeline (Vercel, no build step) | **Monitor** | Indirect | Directly gates whether any of the above ever reaches a real customer | `main` branch, Vercel auto-deploy | **The platform's actual current bottleneck, not code quality**: verified live that fixes from 3 consecutive sprints exist only on `claude/cti-platform-standards-f64l5x` and have not been merged to `main` (Issue 12). Everything above marked "Active"/"Improving" based on branch state should be read as "ready to be active," not "active in production," except the welcome email, which is the one item explicitly merged. |
| Sales Enablement / Marketing Collateral (`marketing/`) | **New**, internal-only | Indirect (supports a human doing outreach) | Enables consistent, fact-checked external communication | None | New this session (GCDOM v1) — datasheet, competitive battle card (sourced, no invented claims), and a durable (committed, not chat-only) marketing-asset package for SA-2026-0003. No defined ongoing-maintenance owner, same as everything else in this table. |
| Search (`search-index.json`) | **Stable** | Direct, minor | Low | `generate-search-index.py` | Not touched this session, no new evidence. Scoped to `posts/` only per prior verification — carried forward without re-checking. |
| Deprecated `/prompts/` content | **Candidate for Retirement** — already actioned | None (superseded) | None | N/A | Already marked deprecated per the Deprecation Instead of Deletion policy in an earlier session; kept for reference, not extended. Listed here only so this table doesn't imply it was missed. |

## How to keep this current

This table decays the moment a new capability ships without an update —
the same "documentation freshness" concern `quality-metrics.md` tracks
platform-wide, and the same rule this file itself failed to follow across
four sprints before this rewrite. Update it in the same commit that
changes a capability's status or dependencies. If that discipline slips
again, the honest thing to do is what this rewrite did: say so plainly and
re-verify, not silently patch one row and leave the rest stale.

---
*CyberDudeBivash® Sentinel APEX — Capability Map*
