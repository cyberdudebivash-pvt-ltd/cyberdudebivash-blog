# GTIEP v1 — GLOBAL THREAT INTELLIGENCE EXCELLENCE PROGRAM
## Phase 1: Current-State Audit vs. the 9 Strategic Priorities

---

## What this is

A production task ("Sentinel APEX™ Global Threat Intelligence Excellence
Program") asked this platform's intelligence reports to compete with
Google Threat Intelligence, Microsoft Threat Intelligence, CrowdStrike
Intelligence, Unit 42, Recorded Future, Mandiant, Cisco Talos, Secureworks
CTU, Intel 471, and Flashpoint — via a redesigned report standard, an
11-category quality framework, a living knowledge base, a 21-template
library, and explicit credibility/confidence discipline.

Before writing any code, a full current-state audit was run against every
one of these asks, with file:line evidence, not assumption — matching this
platform's own established discipline (see `platform/social-preview-metadata-audit.md`
for the same approach applied to a prior initiative). This document is
that audit, condensed, plus the staged plan it produced.

## The headline finding

**This platform has substantially more of what GTIEP v1 asks for than a
first read of the vision document would suggest — but it is scattered
across non-agreeing parallel systems, and in at least two real cases the
platform's own governance documentation is simply wrong about what exists.**
`Sentinel-APEX/eios/layer-03-intelligence-object-model.md` claims Threat
Actor profiles "need richer fields" and Campaign profiles are "specified,
not yet implemented in code." Both are false: `api/_lib/threat-graph.js`
already has 8 fully-attributed real threat actors (aliases, motivation,
sophistication, TTPs, known CVEs, sourced references), and
`api/_lib/campaign-engine.js` is a full 573-line weighted-clustering
engine with a persisted `campaigns.json`. This is not a minor documentation
lag — it is exactly the kind of stale map that causes future work (by any
future session, human or AI) to rebuild something that already exists,
which is the one failure mode "Reuse Before Build" exists to prevent.
Fixing this is this document's first concrete action, not an afterthought.

---

## Audit by priority

### 1. Report structure — three layers that disagree with each other

| Layer | What it actually contains |
|---|---|
| Code-enforced gate (`quality.py:23-29`, `REQUIRED_SECTIONS`) | Only 5 sections: Executive Summary, Verified Facts, Technical Analysis (aliased to Attack Chain), MITRE ATT&CK, IOC Intelligence |
| Documented taxonomy (`Sentinel-APEX/prompts/master-prompt.md:189-251`) | 60 numbered sections — covers nearly everything GTIEP names by synonym, but **has no code path checking it** (`platform/quality-metrics.md:21`: *"Not computed — no cross-reference exists yet"*) |
| Real published reports (SA-2026-0001/2/3) | ~24 bespoke sections, genuinely including a real, distinct Kill Chain Analysis (7-phase, separate from the 5-step evidence-cited Attack Chain) |

**Genuinely absent at all three layers**: Key Findings, Geographic Impact,
CWE Analysis, CAPEC Mapping, Exploit Analysis as dedicated sections.
Industry/Threat Actor/Malware/Infrastructure/Campaign Analysis exist only
as taxonomy line items, never once populated in a real published report
(front-matter `sectors: []` is empty in all three).

### 2. Detection format coverage — two generators, almost no overlap

- **Sentinel-APEX report pipeline** (`detection_specs.py`, `detection-engine.js`): Sigma, KQL, Splunk, OSQuery (generated) + Suricata (network-IOC-derived). **YARA is validated only** (`quality.py`'s `validate_yara` checks structure of a rule a human/LLM already wrote) — `platform/capabilities.md`'s "Sigma/YARA/KQL/Suricata/OSQuery" framing overstates this; there is no YARA-generating code anywhere, confirmed by `Sentinel-APEX/yara/` containing only `.gitkeep`.
- **Blogger pipeline** (`automation/authority_transformer.py:52-58`, `SIEM_PLATFORM_LABELS`): Splunk SPL, Elastic EQL, Microsoft Sentinel KQL, IBM QRadar AQL, Google Chronicle YARA-L.
- **Only Splunk and Sentinel-KQL are common to both.** CrowdStrike, Defender XDR, Cortex XDR, SentinelOne, and Snort are named in `master-prompt.md`'s "aspirational" coverage table with zero generating code.
- Real-world caveat: even the formats that exist go unused in practice — `platform/quality-metrics.md:23` puts detection coverage at 33% (1/3 published reports), the other two explicitly refusing to fabricate a Sigma rule against undocumented log-schema fields.

### 3–5. Hunting / Defensive / Operational Intelligence — real content under different organizing labels

- **Hunting**: hunt hypotheses and playbooks are real (`Sentinel-APEX/templates/hunting/threat-hunting-playbook.md`, used in real reports). ATT&CK-evidence pivots are real (every technique cites its source phrase). **Graph pivots (`co_occurs_with` edges) are confirmed, by exhaustive grep, to have zero report-facing consumers** — real, tested, additive internal structure with no hunt-guidance rendering anywhere yet.
- **Defensive Intelligence**: GTIEP's exact 6-category label set (prevention/detection/containment/hardening/recovery/validation) does not exist anywhere as a group. 3 of 6 concepts have real, named, template-enforced homes under different names (Containment Strategy, Eradication Strategy, Recovery Guidance). Prevention ≈ "Compensating controls" (narrower). Hardening ≈ "Security Architecture Recommendations"/"Zero Trust Considerations." Validation has no equivalent at all.
- **Operational Intelligence by role**: two independent 6-role systems exist, neither matching GTIEP's list (SOC/IR/CISO/Threat Hunting/Vuln Team/Management). `authority_transformer.py`'s Executive Decision Center: CEO/Board/CISO/SOC/DevSecOps/Cloud. EIOS Layer 5's audience templates: Executive/SOC/Hunter/IR/Board/Detection-Engineer. Combined coverage: SOC ✓, CISO ✓, IR ✓ (templates only), Threat Hunting ✓ (templates only), Management ≈ (Board/CEO), **Vuln Team ✗ never its own audience view in either system** (only a generic report section).

### 6–7. Confidence and Quality scoring — real, but two non-matching scales each

- **Confidence**: a real, used, partially-gated 4-tag convention (`[Verified Fact]`/`[Analyst Assessment]`/`[Intelligence Gap]`/`[Unresolved Reference]`) exists in all 3 published reports. A **richer, documented-but-never-practiced** 9-category Provenance × 8-word Epistemic-status model also exists (`eios/layer-02`) — closer to GTIEP's exact 8-category ask, but zero real reports use it. The code-level `Confidence` enum has only 3 levels (LOW/MEDIUM/HIGH) while every prose scale uses 5 (VERY LOW→VERY HIGH) — **the code and the prose don't share a scale**. Per-finding confidence is real (every Attack Chain step, every ATT&CK mapping row); per-finding "evidence count" as a discrete metric does not exist anywhere.
- **Quality scoring** — exact current weights, `scoring.py:29-39`:

  | Dimension | Weight |
  |---|---|
  | evidence_quality | 22% |
  | original_analysis | 18% |
  | detection_value | 15% |
  | soc_value | 10% |
  | executive_value | 10% |
  | commercial_value | 8% |
  | dfir_value | 6% |
  | analyst_confidence | 6% |
  | seo_value | 5% |

  GTIEP proposes 11 categories at different weights; only 4 have a direct
  namesake here (Evidence Quality, Original Analysis, Detection Value,
  Executive Value — all at different weights). **Technical Accuracy,
  Defensive Guidance, Analyst Usability, Report Structure, and
  Visualizations have no scored dimension today** (some are gated pass/fail
  by `quality.py`, a separate mechanism from scoring). Conversely,
  `scoring.py` carries 5 dimensions GTIEP doesn't ask for (SOC/DFIR/
  Commercial/Analyst-Confidence/SEO value) — notably, GTIEP's own proposal
  has no commercial-tiering dimension at all, whereas commercial tiering is
  `scoring.py`'s primary current purpose.

  **This also directly intersects `platform/open-issues.md` Issue 3 item
  3**, already on record as unresolved: `scoring.py` computes from an
  automated `PipelineResult.detections[]/iocs[]` shape that hand-authored
  reports don't have, so a correct, gate-passing, IOC-honest report like
  SA-2026-0001 scores 43/100 BLOCKED. Building GTIEP's more structural
  framework is the natural occasion to fix this, not defer it further.

### 8. Living Knowledge Base — mature in places docs say it isn't, genuinely thin in others

| Component | State |
|---|---|
| Threat Actor Profiles | **Mature** (8 real actors, rich fields) — EIOS docs wrongly say otherwise |
| Campaign Profiles | **Mature** (573-line clustering engine, persisted) — EIOS docs wrongly say otherwise |
| Vulnerability Profiles | Mature (real NVD/EPSS/KEV enrichment) |
| TTP Library | Mature (~80 curated ATT&CK IDs with evidence lexicon) |
| Intelligence Graph | Mature, live (9,315 nodes / 3,378 edges) |
| Industry Intelligence | Mature (9 detailed profiles, wired into the Blogger pipeline) |
| IOC Library | Exists as a live, monetized feed (STIX export, Pro+) |
| Malware Profiles | Thin — name/alias lexicon only; the graph's Malware node type is fully schema-supported but has 0 populated nodes |
| Detection Library | **Does not exist as a stored asset** — `Sentinel-APEX/{sigma,kql,suricata,osquery,yara}/` are empty `.gitkeep` stubs; generation code exists, a browsable rule library does not |
| Country Intelligence | **Does not exist at all** — zero entries, zero logic |
| Sector Intelligence (in the Sentinel-APEX engine specifically) | Only a free-text, always-empty front-matter field; the real sector system (`industry_intelligence.py`) lives only in the separate Blogger pipeline |

### 9. Template library — one axis exists (audience), a different axis is asked for (subject)

Real contents of `Sentinel-APEX/templates/`, in full: `executive/executive-brief.md`,
`board/board-summary.md`, `soc/soc-detection-brief.md`,
`hunting/threat-hunting-playbook.md`, `ir/incident-response-playbook.md`,
`detection-engineer/detection-engineer-brief.md` — six real,
actively-documented **audience** templates (who reads it). GTIEP's 21
proposed templates are organized by **subject type** (what kind of event
it is) — a different axis this platform has almost nothing on: only
"Executive Briefing" has a direct namesake; "Threat Hunting Report" has a
near one. The other ~18 (Zero-Day, Threat Actor Profile, Malware Profile,
Ransomware Intelligence, APT Campaign, Supply Chain Attack, Cloud Threat,
AI Security Threat, Insider Threat, Data Breach, Weekly/Monthly/Quarterly,
Sector/Country/Industry Intelligence, Detection Pack Report, Customer
Advisory) have no dedicated template anywhere, live or deprecated.

### 10. Credibility categories — a real, working 4-tag convention; a richer, unused 9-category one

Already covered under item 6 — restated here because GTIEP's exact ask
(Observed Facts/Verified Evidence/Analyst Assessment/Intelligence
Judgments/Confidence Levels/Assumptions/Unknowns/Collection Gaps) maps
more closely to the *documented-but-unpracticed* Layer 2 Provenance model
than to the 4-tag convention actually used in all 3 real reports.

### 11. Commercial Readiness — one excellent precedent, not yet a system

`Sentinel-APEX/reports/drafts/SA-2026-0001-commercial-packaging.md` is a
genuinely strong, real, per-report answer to "why would a customer pay for
this" (target customer, pain points, competitive differentiation, pricing
placement, upsell/cross-sell) — produced once, for one of three published
reports. No equivalent exists for SA-2026-0002/0003. The systematic
mechanism that should generalize this (`scoring.py`'s `commercial_value`
dimension) can't run on hand-authored reports at all (same root cause as
item 7's Issue 3 item 3).

### Also flagged: no real competitive-analysis document exists

`marketing/competitive-battlecard.md` is genuinely sourced (real cited
URLs) but covers only Recorded Future and GreyNoise, on pricing/positioning,
not report structure — and treats "hand-authored vs. automated" as a single
one-line differentiator. No document anywhere compares this platform's
actual report structure, confidence model, or detection coverage against
any of GTIEP's ten named vendors (Google TI, Microsoft TI, CrowdStrike,
Unit 42, Recorded Future, Mandiant, Cisco Talos, Secureworks CTU, Intel
471, Flashpoint). `CLAUDE.md`'s own "CYBERSECURITY MEDIA EMPIRE MODE"
competitor list is aspirational framing with zero citations — not usable
as evidence.

---

## Staged implementation plan

Consistent with `CLAUDE.md`'s Architecture Preservation Rule and this
platform's own established pattern (audit → stage → build the additive,
low-risk, evidence-backed subset → leave the rest explicitly tracked, not
silently dropped) — matching exactly how `platform/social-preview-metadata-audit.md`
staged the prior initiative.

**This sprint (GTIEP v1):**

| Item | Addresses | Risk |
|---|---|---|
| Fix stale EIOS Layer 3 docs (Threat Actor/Campaign) | Reuse-before-build integrity for all future work | NONE — docs only |
| Fix imprecise YARA-generation claim in capabilities.md | Same | NONE — docs only |
| Sourced competitive analysis vs. the 10 named vendors | Priority 1 — "compete with X" requires first knowing what X actually does | LOW — new doc, real citations only |
| Quality Framework v2 — additive scoring.py extension + hand-authored-report scoring path | Priority 4, and resolves the long-open Issue 3 item 3 | LOW-MEDIUM — additive dimensions, existing 9 unchanged, weights rebalanced and tested |
| CWE/CAPEC/Exploit Analysis as real, checkable sections | Priority 2's genuinely-absent elements | LOW — additive taxonomy + alias entries |
| Threat Actor Profile template sourced from real `threat-graph.js` data | Priority 5+6 together, and the report-structure gap in one move | LOW — new template file + renderer, no existing template changed |

**Explicitly staged for a future sprint, not attempted now:**

- The other ~18 subject-type templates — each needs real structural design and validation against real content, not a shallow stub; building all 21 in one sprint would trade depth for coverage, which this platform's own quality culture has consistently rejected.
- Detection Library as a persisted, browsable rule asset (vs. generation-on-demand) — a real product-surface decision (what gets stored, versioned, and served) beyond this sprint's doc/template scope.
- Reconciling the 3 non-agreeing "operational intelligence by role" systems into 1, and relabeling Containment/Eradication/Recovery/Compensating-Controls/Security-Architecture into GTIEP's exact 6-category Defensive Intelligence framing — a genuine consolidation decision (which existing system is canonical), same category as `open-issues.md` Issue 1's Scoring/Graph precedent, not a same-sprint rename.
- Reconciling the two confidence scales (3-level code enum vs. 5-level prose) and the two credibility taxonomies (4-tag practiced vs. 9-category documented) into one — touches the `Confidence` enum used across `scoring.py`/`quality.py`/`certification.py`, a larger blast radius than this sprint's additive scope.
- Populating rich Malware profiles and any Country Intelligence — new entity-extraction/curation work, not a wiring fix.
- Detection format expansion to CrowdStrike/Defender XDR/Cortex XDR/Chronicle-in-the-Sentinel-pipeline (vs. the separate Blogger pipeline, which already has Chronicle) — net-new generator work per format.
- Producing a commercial-packaging document for SA-2026-0002/0003 to match SA-2026-0001's precedent — real analyst work, not an engineering task.

---
*CyberDudeBivash® Sentinel APEX — Global Threat Intelligence Excellence Program, Phase 1 Audit*
