# SENTINEL INTELLIGENCE STANDARD (SIS)

## What this document is

Seven files already pointed here before this document existed
(`templates/threat-actor/threat-actor-profile.md`,
`templates/soc/soc-detection-brief.md`, `docs/CONVENTIONS.md`) — each citing
it as the place a scattered, cross-cutting convention would be made
canonical. This document is that place. It is **not** a fifteenth EIOS
layer: the 14 layers in this directory each own one architectural concern in
depth (confidence model, quality gates, versioning, and so on) and remain
the authoritative source for their own subject matter. SIS does not
re-specify what they already specify. Its job is the two things no single
layer owns:

1. **Consolidation** — the canonical *value* of every enum and field
   contract that a template author or analyst currently has to reconstruct
   by reading 6–14 separate files (proven necessary by
   `threat-actor-profile.md`'s own `audience` field, hand-written as
   `"soc,ciso,threat-hunter"` before GCIEP v1 corrected it — the single-value
   convention existed in practice across six other templates but nowhere
   in one place an author could check first).
2. **The open-decision register** — questions this platform has surfaced
   and deliberately left unresolved rather than silently deciding one way.
   `docs/CONVENTIONS.md` already forward-references this section for
   exactly one such decision (the `drafts/`→`final/`→`archive/` lifecycle);
   this document is where that reference resolves.

Every value below is sourced from the real template/report/code files cited
next to it, not restated from memory or invented for this document —
consistent with this platform's own governing constraint that documentation
must describe what is actually true of the system (see Issue 15's finding
that the opposite failure mode — governance docs describing capabilities
that don't exist, or denying ones that do — is a materially worse problem
than staleness).

## 1. Canonical Front-Matter Field Contract

Base contract: `prompts/report-prompt.md` § Output Contract. Version-control
extension: `eios/layer-08-report-version-control.md`. This table is the
union of both, plus fields templates have added on top, in one place.

| Field | Required on | Allowed values / format | Source |
|---|---|---|---|
| `title` | every report | free text | report-prompt.md |
| `report_id` | every report | `SA-<YYYY>-<NNNN>` | docs/CONVENTIONS.md |
| `date` | every report | `YYYY-MM-DD` | report-prompt.md |
| `tlp` | every report | `TLP:CLEAR` \| `TLP:GREEN` \| `TLP:AMBER` \| `TLP:RED` (default `TLP:CLEAR` for published media; higher restriction never published to the blog) | docs/CONVENTIONS.md |
| `report_type` | every report | `campaign` \| `incident` \| `actor-profile` \| `sector-threat` — never a fifth value; a report spanning multiple picks its dominant structural shape | prompts/master-prompt.md §163 |
| `audience` | every audience-variant template | single value — see § 2.1 below | eios/layer-05, corrected GCIEP v1 |
| `severity` | all 3 real published reports so far | **no formal enum documented anywhere in `master-prompt.md` or `quality-gate.md`** — all 3 real reports use `CRITICAL`; recommend formally adopting `CRITICAL \| HIGH \| MEDIUM \| LOW` rather than continuing to leave this field's contract implicit. Recorded here, not silently assumed. | none (gap) |
| `overall_confidence` | every report and every template's front matter (GCIEP v1: made universal — see `soc-detection-brief.md`'s note) | `VERY LOW` \| `LOW` \| `MEDIUM` \| `HIGH` \| `VERY HIGH` | eios/layer-07 |
| `detection_confidence` | detection-bearing templates only (narrower than `overall_confidence`, not redundant with it) | same 5-point scale | templates/soc/soc-detection-brief.md |
| `threat_actors` / `malware_families` / `cves` / `sectors` / `attack_ids` | every report | arrays, empty (`[]`) when genuinely none apply — an empty array is a valid, honest value, not a gap to fill with an invented entry (see § 6 item 6 below for why this matters to commercial scoring) | report-prompt.md |
| `sources` | every report | array of URLs; every one must appear in the rendered References section | report-prompt.md; enforced by `_gate_reference_completeness` (GIAAP v1) |
| `version` / `last_updated` / `supersedes` / `superseded_by` / `review_status` / `next_review` / `analyst` / `reviewer` / `change_log` | every report | see eios/layer-08 for full semantics | eios/layer-08 |

## 2. Canonical Enums

### 2.1 `audience` (single value — real values in use today, not aspirational)

| Value | Template | Distinguishing question it answers |
|---|---|---|
| `executive` | `templates/executive/executive-brief.md` | What does leadership decide, right now? |
| `board` | `templates/board/board-summary.md` | What does the board need to govern, not act on? |
| `soc` | `templates/soc/soc-detection-brief.md` (also reused by `threat-actor-profile.md`) | What does an analyst do when this fires? |
| `detection-engineer` | `templates/detection-engineer/detection-engineer-brief.md` | What should I build, and how sure am I in it? |
| `hunting` | `templates/hunting/threat-hunting-playbook.md` | Where do I go looking without a trigger? |
| `dfir` | `templates/ir/incident-response-playbook.md` | How do we contain, eradicate, and recover? |

`ciso` and `threat-hunter` are deliberately not separate values — CISO
concerns are served by `executive`'s depth, and `threat-hunter` is `hunting`
under a different name from the pre-EIOS-v2 spec. A template needing a
7th value is a Layer 5 change (new distinguishing question), not a SIS
change — see `eios/layer-05-multi-audience-output.md`'s own "Not
duplicated" section for why Technical Analyst was rejected as an 8th.

### 2.2 `overall_confidence` / per-claim confidence dimensions

Five-point scale (`VERY LOW`/`LOW`/`MEDIUM`/`HIGH`/`VERY HIGH`) across the
7 dimensions in `eios/layer-07-confidence-model.md`: Source, Evidence,
Technical, Attribution, Detection, Operational, Business Impact. Every
rating requires a stated rationale — the word alone is non-compliant.

### 2.3 `review_status` (release-pipeline lifecycle)

`draft` → `technical-review` → `detection-review` → `intelligence-review` →
`editorial-review` → `executive-approval` → `published` → `archived`. See
`eios/layer-14-release-pipeline.md` for the gate sequence between stages.
**Practice gap, not silently fixed**: no code validates a report's
`review_status` against this enum today, and all 3 real published reports
sit at `published` with `reviewer: null` — the intermediate stages and the
reviewer field are specified but not yet exercised (see § 6 item 2).

### 2.4 `report_type` (structural, not subject-matter)

`campaign` \| `incident` \| `actor-profile` \| `sector-threat`. Distinct
from subject-matter category (CVE, malware, APT, AI security, etc.), which
selects a *task prompt* to load, not this field's value — see
`prompts/master-prompt.md` § Report Type Taxonomy.

## 3. Directory Lifecycle

`drafts/` → (quality gate) → `final/` → (publish) → `published/`;
superseded versions move to `archive/`. Full authority:
`docs/CONVENTIONS.md`. **This is the open decision CONVENTIONS.md points
here for**: the 4-stage lifecycle has never been followed in practice
(`final/` has held only `.gitkeep` since scaffolding; no `archive/`
directory has ever existed; every real report moved `drafts/` →
`published/` directly). Restated here, not re-litigated — see § 6 item 1
for the standing decision this document register carries forward.

## 4. EIOS Layer Index

One line per layer, so a reader can find the right authority without
opening all 14:

| Layer | Owns |
|---|---|
| 1 | Executive mission and mandate |
| 2 | Intelligence governance — evidence classification, hedge vocabulary |
| 3 | Intelligence object model — entities (CVE, Actor, Malware, Campaign, Organization, Sector, ...) |
| 4 | Production quality gates — the hard-blocking gate `quality.py` runs |
| 5 | Multi-audience output — the 8 audience views, 6 templates |
| 6 | Detection engineering standards — Sigma/YARA/KQL/Suricata/OSQuery conventions |
| 7 | Intelligence confidence model — the two confidence mechanisms (§ 2.2 above) |
| 8 | Report version control — `version`, `change_log`, supersession |
| 9 | Intelligence relationships — the knowledge-graph edge types |
| 10 | Commercial readiness — the scoring/tiering model (`scoring.py`) |
| 11 | Continuous intelligence — the "living document" staleness model |
| 12 | Enterprise API readiness — external delivery contract |
| 13 | Editorial style guide — tone, evidentiary tags, hype-language gate |
| 14 | Enterprise release pipeline — the 10-stage governance view, now including Rendering Validation and Certification (GIAAP v1 / this platform's `certify` command) |

## 5. Template Conformance State (real count, not aspirational)

8 audience views specified (§ 2.1), 6 distinct templates built (2 folded
into adjacent templates by design, not a gap). Of GTIEP v1's 21 proposed
subject-type templates, **1 is built**
(`templates/threat-actor/threat-actor-profile.md`, sourced from the real
`THREAT_ACTOR_DB`) — the other ~18 remain explicitly staged, not silently
dropped (`platform/open-issues.md` Issue 15).

## 6. Remaining Executive Decisions

Carried forward from across GIAAP v1, GTIEP v1, and GCIEP v1 — each a real,
surfaced question this platform has deliberately left open rather than
quietly resolving one way. Listed here as the single register
`docs/CONVENTIONS.md` already points to.

1. **Report-lifecycle stages** (§ 3 above): adopt `final/`/`archive/` in
   practice, or simplify the documented lifecycle to the 2-stage reality.
   Neither chosen. (`docs/CONVENTIONS.md`)
2. **Reviewer accountability**: `review_status` and `reviewer` are fully
   specified but not yet practiced — every real report ships
   `reviewer: null` at `published`. Whether a second-reviewer step becomes
   mandatory before publication, or the field is honestly scoped down, is
   unresolved. (`eios/layer-08-report-version-control.md`)
3. **Commercial scoring threshold/weighting fit for hand-authored
   reports**: all 3 real reports ever produced score BLOCKED against the
   60-point threshold (43, 37, 48 — see each report's own commercial
   brief in `reports/drafts/`), despite reaching CERTIFIED or CERTIFIED
   WITH CONDITIONS on the separate qualitative gate. The threshold/weights
   were tuned before any hand-authored report existed to test them against.
   Whether 60 is the right bar for this report shape, or hand-authored and
   pipeline-generated content need different thresholds, is unresolved.
   (`platform/open-issues.md` Issue 3 item 3; each report's commercial
   brief)
4. **Scoring credit for malware-family entities without a named actor**:
   found producing SA-2026-0003's commercial brief — `scoring.py`'s
   `executive_value` and `commercial_value` dimensions each award fixed
   credit for `threat_actor`-typed entities but have no equivalent credit
   path for a confirmed `malware_families` entry absent a named operator,
   even when that entry represents direct, high-confidence ransomware
   confirmation. Whether to add one is an open scoring-model question, not
   a defect — the report itself is correct to record `threat_actors: []`
   rather than invent an operator name no source supports.
   (`reports/drafts/SA-2026-0003-commercial-packaging.md`)
5. **Three scattered, not-yet-reconciled report-structure systems**: a
   5-section code-gated minimum (`quality.py`), a 60-section documented
   taxonomy (`master-prompt.md`), and ~24 sections actually used by real
   reports. Which becomes canonical, or how the three are formally
   reconciled, is unresolved. (`platform/open-issues.md` Issue 15)
6. **Remaining subject-type templates**: ~18 of 21 proposed templates
   (§ 5 above), rich Malware profiles, Country Intelligence, and a
   persisted/browsable Detection Library (`sigma/`, `yara/`, etc. are
   still empty `.gitkeep` stubs) are explicitly staged, not scheduled.
   (`platform/open-issues.md` Issue 15)
7. **`severity` has no formal enum** anywhere in the governing prompts
   (§ 1 table above) despite being load-bearing front matter on every real
   report. Recommend formally adopting one rather than continuing on
   inferred convention.
8. **Executive/closing reports have no durable existence.** Checked
   directly against `platform/`'s real directory listing while writing
   this document: none of the named closing deliverables from at least
   eight prior work blocks (GTIEP v1's Sprint Completion Report, GEORP
   v1's Enterprise Operations Report, GPLCIP v1's Platform Lifecycle
   Report, GEPMP v1's Enterprise Maturity Report, GECTP v1's Production
   Closeout document and Competitive Capability Review, GIOS v1's
   executive platform evolution review, EIPP-X v1's strategy document)
   exist as files anywhere in this repository — only `README.md`,
   `automation.md`, `capabilities.md`, `extensibility.md`,
   `gtiep-v1-audit.md`, `gtiep-v1-competitive-analysis.md`,
   `open-issues.md`, `quality-metrics.md`, and
   `social-preview-metadata-audit.md` are actually present in `platform/`.
   This is the same "delivered as chat output only, never persisted"
   failure mode `marketing/SA-2026-0003-marketing-assets.md`'s own header
   already named and fixed for one specific asset type (its own package),
   but the fix was never generalized to executive/closing reports — this
   platform's own compaction-summary mechanism is itself proof of the
   risk: that content is not recoverable from this session by normal
   means. Whether every future closing report gets written to
   `platform/` as a matter of standing policy, or these specific reports
   are accepted as permanently lost, is unresolved. This document's own
   companion, the GCIEP v1 Intelligence Excellence Report, is written to
   `platform/` specifically to not repeat this pattern.

## 7. Enforcement

This document is descriptive of a moving system and will drift the moment
a new template introduces a 7th `audience` value or a report ships a
`severity` this document doesn't list, unless something checks it. No
automated check exists as of this writing; adding one — a static test
asserting every template's `audience:` front-matter value appears in § 2.1's
table, in the same spirit as `test_certification.py`'s
`test_domain_mapping_covers_every_gate_tag_quality_py_can_emit` — is
recorded as the natural next step (see the Intelligence Excellence Report's
recommendations) rather than asserted here as already done.

---
*CyberDudeBivash® Sentinel APEX — Sentinel Intelligence Standard (SIS)*
