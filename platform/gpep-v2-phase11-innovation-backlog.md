# GPEP v2 Phase 11 — Platform Innovation Backlog

Living register, consolidated from Phases 1–10 and 12. Every item traces
to a specific phase/finding; none invented for this list. Grouped per this
phase's required taxonomy.

## High Impact / Low Effort

| Item | Customer Value | Business Value | Engineering Effort | Dependencies | Risks | Evidence |
|---|---|---|---|---|---|---|
| Automate `drafts/`→`published/` on `review_status: published` | High — every other improvement compounds on top of this | High — 2 of 3 reports already lost weeks to this gap once | Small — wire existing `publish-report.js` to an existing status transition | None | Must preserve a human review gate, not just remove friction | Phase 1 §1, Phase 2 |
| Re-verify newsletter/ESP configuration status | Direct — acquisition funnel | Moderate-high if still broken; unknown-status for 3+ weeks | Minimal — a status check | Live credentials or a real signup | None from checking | Phase 1 §11, Phase 9 |
| Relevance filter on AI-security aggregator inclusion | Direct — removes non-security content (a job listing) from a security collection | Moderate — protects "definitive AI security authority" positioning | Small — extends existing `labels`/categorization logic | None | Could over-filter if scoped too broadly | Phase 1 §4, Phase 8 |
| Customer-facing API reference, generated from existing route definitions | Direct — closes the largest documentation gap for a paid product | Moderate | Small — source from `api-dashboard.html`'s existing endpoint list | None | A second, hand-maintained source of truth if not generated | Phase 1 §13, Phase 9 |

## High Impact / High Effort

| Item | Customer Value | Business Value | Engineering Effort | Dependencies | Risks | Evidence |
|---|---|---|---|---|---|---|
| Systemic audit of the graph's automated, keyword-derived actor attributions | Indirect but foundational — trust in every graph query depends on it | High — this is the same trust category as the Issue 17 fix, at unmeasured scale | Large — likely needs a new source-URL-vs-claim consistency checker built and run across thousands of edges | The `sources` array already present on every edge | Could surface a large volume of findings requiring triage, not just detection | Phase 3, Phase 8, Issue 17 |
| Resolve the commercial-scoring BLOCKED-threshold question | None directly; indirectly high (gates premium pricing of the only 3 flagship products) | High | Low-to-moderate depending on the answer chosen | Real score/certification data already exists | A model change made without a policy decision risks moving the bar to fit the data | Phase 1 §1/§10, Phase 6 |
| Consolidate the 3 not-yet-reconciled report-structure systems (Issue 15) | Indirect — clearer authoring guidance | Moderate | Large — a genuine architecture decision, not a wiring fix | None blocking, but requires an explicit canonical-ownership decision first | Staged twice already (GTIEP v1, GCIEP v1) without resolution — risk of staying permanently deferred | Phase 1 §9, Phase 7, Issue 15 |

## Experimental

| Item | Rationale for "experimental," not "planned" |
|---|---|
| Automated report-consistency checker (Phase 5) extending Editorial Quality | The need is proven (2 real instances caught by hand this session), but the detection mechanism's precision/recall isn't yet designed — needs a prototype against known-good and known-bad fixtures before it's a committed capability |
| `MALWARE_DB`/`CVE_MALWARE_MAP` pattern, generalizing this session's one-off Malware population | Only one report (SA-2026-0003) currently has qualifying data; building the generalized pattern before a second qualifying report exists is speculative |

## Research

| Item | Open question |
|---|---|
| Which other major real actors (APT28, Lazarus, Sandworm, Scattered Spider — several already referenced as bare keywords in `intelligence-hub.js`) are "known to the codebase's classification logic but absent from the curated graph," beyond the APT29 gap closed this session |
| Whether infrastructure/supply-chain/cloud/AI relationship types (absent from the graph's current vocabulary per Phase 3) would ever be justified by a real report, or whether IOC nodes are a sufficient proxy indefinitely |

## Strategic Investment

| Item | Why it's strategic, not tactical |
|---|---|
| A dashboard/alerting layer over the existing raw Redis observability counters | Phase 1 §11 and Phase 10 (Customer Engagement) both independently found the same gap: real data is being collected but never summarized into a reportable metric — this is infrastructure work that unblocks measurement for every future program, not a one-off fix |
| Building out the remaining ~18 of 21 GTIEP v1 subject-type templates | Large, multi-sprint content-and-tooling investment; the Threat Actor Profile and (recommended) Campaign Report templates prove the pattern works — scaling it to the full 21 is a deliberate, multi-phase commitment, not a quick win |
| Detection-format expansion (CrowdStrike/Defender XDR/Cortex XDR) in the Sentinel-APEX pipeline specifically | Already staged since GTIEP v1; genuinely large scope (the separate Blogger pipeline already has 5 SIEM formats the Sentinel-APEX pipeline doesn't) |

---
*CyberDudeBivash® Sentinel APEX — GPEP v2 Phase 11 Platform Innovation Backlog*
