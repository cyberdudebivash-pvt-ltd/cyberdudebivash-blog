# REPORTX Phase 1K — 24-Section Contract Audit

**Written:** 2026-08-20, before any Phase 1K implementation. Read `automation/report_contract.py`,
`automation/report_renderer.py`, `automation/authority_transformer.py`, and
`Sentinel-APEX/engine/sentinel_engine/reportx/pipeline_composer.py` in full; grepped for every
render call site to confirm — not assume — whether each structured object genuinely reaches
`transform()`'s published output on all three content paths (`reportx_composer`, LLM-authored,
legacy `template` fallback).

## 0. Starting-state verification

- `origin/main` and this branch were reconciled: PR #119 (Phase 1J) is merged into `main`
  (`html_url` confirmed via the GitHub API, `merged: true`, head sha matches the exact commit
  pushed last round). No other open PRs. Branch was restarted from `origin/main` per the
  already-merged-PR protocol.
- Baseline reproduced fresh on the new `main`: root 497 passed, engine 1045 passed + 1
  pre-existing unrelated failure (`test_certify_real_end_to_end_with_the_actual_node_rendering_check`,
  reconfirmed present, Node-rendering environment issue), JS 123 passed — exactly matching the
  Phase 1J certification's own numbers.
- `role_decision_count` confirmed present in `report_contract.py`/`analytical_depth_gate.py`/
  `authority_transformer.py` (grep counts 6/3/1 respectively), certification doc present — Phase
  1J's claims verified against code, not trusted from the prior report alone.

## 1. Section-by-section table

Legend — RENDERED?: which of the 3 real content paths (`reportx_composer` / `LLM-authored` /
legacy `template`) actually show this section's content in `transform()`'s published
`result["content"]`, not just in `pipeline_composer.compose_report()`'s own isolated HTML.
QUALITY_GATED?: does `evaluate_section_states()` check real per-article content before claiming
`COMPLETE`, or does it fall through to an unconditional default.

| # | Section | Resolver | Structured object | Rendered on (composer / LLM / template) | Quality-gated? | Defect class |
|---|---|---|---|---|---|---|
| 1 | Executive Risk Command Center | `_IMPLEMENTED_ELSEWHERE`, unconditional COMPLETE | `_build_risk_command_center()` (CVSS/EPSS/KEV) | **All 3** — rendered once, outside the per-path body, before any path branches | No (but content is real & unconditionally present when any CVSS/EPSS/KEV data exists) | None found |
| 2 | Executive Summary | `_IMPLEMENTED_TODAY`, unconditional COMPLETE | `article.summary` truncated + fixed decision line | All 3 (LLM writes its own; template/composer use `report_renderer`'s) | No — no minimum-content check | `LEGITIMATELY_COMPLETE` in practice (summary is a required upstream field) but no floor exists if it were ever empty/trivial |
| 3 | Key Judgements | Dynamic (`key_judgement_count`) | `KeyJudgement[]` | LLM-authored path only (composer/template have no LLM narrative to extract judgements from — correct, since `generate_key_judgements()` requires LLM-authored evidence text) | Yes (RX-P1F) | None found — already correctly gated |
| 4 | Intelligence Requirements / Scope | none — final `else` | none | Never | N/A (always WITHHELD) | `NOT_MEASURED` — no capability exists; WITHHELD is honest |
| 5 | Verified Facts | `_IMPLEMENTED_TODAY`, real per-article check | `article.cwe_ids`/`cvss_vector` | All 3 | Yes | None found |
| 6 | Evidence & Source Assessment | `_IMPLEMENTED_ELSEWHERE`, unconditional COMPLETE | `reliability_html` (two-axis Admiralty + corroboration, real per-article) | **Composer only** — no render call on LLM-authored or template paths | No | **FALSE_COMPLETE + missing-render.** Section always claims COMPLETE, but on 2 of 3 real content paths the actual reliability content never reaches the published page at all |
| 7 | Technical Analysis | `_IMPLEMENTED_TODAY`, unconditional COMPLETE | `_family_analysis()` | All 3 (baked into `report_renderer`/composer HTML directly, or the LLM writes its own) | Partial — real per-article branching only for `cve_advisory`/`cisa_kev`/`cisa_advisory` (`context.exploitation_status`); the other 6 families get a real, family-specific, but **article-invariant** static block | `BACKWARD_COMPATIBILITY_ONLY` for the non-CVE families — legitimate family-differentiated content, not generic filler, but does not vary within a family the way the mandate's "report-specific reasoning" bar implies |
| 8 | Exploitation / Incident Assessment | `_IMPLEMENTED_ELSEWHERE`, unconditional COMPLETE | `context.exploitation_status`/label + KEV cross-check | All 3 (part of the classification block rendered once, like Section 1) | No, but content is genuinely per-article (real evidence field) | None found |
| 9 | Exposure / Asset Relevance | `_IMPLEMENTED_TODAY`, real check for CVE-like families only | `article.affected_vendor`/`product` (CVE-like); static per-family block otherwise | All 3 | Partial — same as Section 7: real per-article for CVE-like, family-static for the trio | Same `BACKWARD_COMPATIBILITY_ONLY` characterization as Section 7 |
| 10 | Attack Path / Intrusion Chain | none — final `else` | none | Never | N/A (always WITHHELD, or NOT_APPLICABLE for ransomware_claim) | `NOT_MEASURED` — correct per mandate §7 ("do not invent an intrusion chain"); WITHHELD/NOT_APPLICABLE is the honest, intended state, not a gap |
| 11 | ATT&CK Mapping | Dynamic (`attack_mapping_count`) | `AttackMapping[]` | All 3 (RX-P1I) | Yes | None found |
| 12 | Actor / Campaign Context | Dynamic (`article.ransomware_group`) | — | Only where the underlying fact renders as prose (family-analysis text); not a distinct structured section render | Yes (real field, placeholder-name-aware) | None found structurally; the *state* is real even though there's no dedicated "Section 12" HTML block — same "fact exists, not split into its own section" characterization noted for Section 20 below |
| 13 | Historical Correlation | `_PARTIAL_SIGNAL_ONLY`, always PARTIAL_EVIDENCE | `internal_linker._classify_relation()` | Not rendered as a distinct customer-visible section at all today | No (deliberately — needs live state file) | Documented, pre-existing, honest limitation (see `report_contract.py`'s own comment) — not a new finding |
| 14 | Threat Hunting | Dynamic (`hunt_hypothesis_count`) | `HuntHypothesis[]` | All 3 (RX-P1I) | Yes | None found |
| 15 | Detection Engineering | Dynamic (`detection_status`) | `DetectionPackage` | All 3 | Yes | None found (legacy `template` path's own separately-hardcoded Sigma/hunt content is a distinct, lower-severity issue — see §3 below, not this table) |
| 16 | Indicators / Observables | none — final `else` | none | Never | N/A (always WITHHELD) | `NOT_MEASURED` — no IOC extraction capability exists; WITHHELD is honest |
| 17 | Business Impact | none — final `else` | none | Never | N/A (always WITHHELD; **MANDATORY** for `ransomware_claim`) | `NOT_MEASURED`. Because this is MANDATORY for `ransomware_claim`, that family can structurally never reach `PREMIUM_LONG_FORM` today — see §4 |
| 18 | Sector / Geographic Impact | Dynamic (`article.ransomware_sector`/`country`) | — | Same "real fact, not its own rendered block" situation as Section 12 | Yes | None found structurally |
| 19 | Role Decision Matrix | Dynamic (`role_decision_count`) | `RoleDecision[]` | All 3 (RX-P1J, last round) | Yes | None found — fixed last round |
| 20 | Time-bound Actions | none — final `else` | none | Never as its own object; P0/P1/P2-labeled bullets already exist *inside* Sections 7/9's "Decisions" sub-blocks | N/A (always WITHHELD) | `NOT_MEASURED` as a distinct section, though materially-related content exists nearby — see §5 |
| 21 | Intelligence Gaps | `_PARTIAL_SIGNAL_ONLY`, always PARTIAL_EVIDENCE | `IntelligenceGap[]` (real, family-conditioned, RX-P1F/1H) | **Never — on any of the 3 paths** | No | **FALSE_COMPLETE-adjacent (PARTIAL_EVIDENCE claimed) + missing-render on all paths.** The section state has been claiming a real signal exists since Phase 1F; the actual gap text has never once reached a published page |
| 22 | Forecast / Outlook | none — final `else` | `forecast.py`'s `Forecast`/`WithheldForecast` (real, tested, certified — `Sentinel-APEX/engine/sentinel_engine/reportx/forecast.py`) exists but is **never imported by `pipeline_composer.py`, `authority_transformer.py`, or `report_contract.py`** | Never | N/A (always WITHHELD) | **Certified-but-dormant module** — the exact recurring defect class this pipeline has now found four times (hunt_hypotheses, attack_mapping, role_decisions, now forecast) |
| 23 | References / Evidence Ledger | `_IMPLEMENTED_TODAY`, unconditional COMPLETE | `article.url`, CVE/KEV links | All 3 | No, but content is always genuinely present (`article.url` is a required field) | None found |
| 24 | Provenance / Certification | `_IMPLEMENTED_TODAY`, unconditional COMPLETE | report_id/hashes/timestamps | All 3 | No, but content is always genuinely present (required fields) | None found |

## 2. Classification of every unconditional-COMPLETE resolver found

Per the mandate's required classification (§4 of the prompt):

| Section | Classification | Reasoning |
|---|---|---|
| 1 (Risk Command Center) | `LEGITIMATELY_COMPLETE` | real data, rendered once, universally, no duplication risk |
| 2 (Executive Summary) | `LEGITIMATELY_COMPLETE` | `article.summary` is a required upstream field; a genuinely-empty summary is not a real production case today |
| 6 (Evidence & Source Assessment) | `FALSE_COMPLETE` | claims COMPLETE regardless of whether the content actually rendered — proven false on 2 of 3 paths |
| 7, 9 (trio families only) | `BACKWARD_COMPATIBILITY_ONLY` | real, non-generic, family-specific content — but not evidence-conditioned per article the way the mandate's semantic-completeness bar implies. Not touched this round (see §6) |
| 8 (Exploitation/Incident) | `LEGITIMATELY_COMPLETE` | genuinely per-article real field |
| 21 (Intelligence Gaps) | `FALSE_COMPLETE`-adjacent (claims `PARTIAL_EVIDENCE`, a real state, but with zero rendered evidence backing the claim) | the mechanism is real, but "mechanism is real" was never proven to reach the reader — fixed this round |
| 23, 24 (References, Provenance) | `LEGITIMATELY_COMPLETE` | required fields, always present |

No section was found silently defaulting to `WITHHELD` where it used to be something else — every never-implemented section (4, 10, 16, 17, 20, 22) has been `WITHHELD`/`NOT_APPLICABLE` since this contract was first built, so there is no backward-compatibility sentinel needed for those (unlike Section 19 last round, where the *prior* behavior was COMPLETE).

## 3. A related, lower-severity finding: the legacy `template` fallback path

`authority_transformer._legacy_template_enhance()` — a pre-ReportX, keyword-heuristic content
generator (`is_ransomware`/`is_ot`/`is_apt` text matching) kept as the last-resort path when
*both* the LLM call fails or is unavailable *and* `compose_report()` itself either raised or
returned `PUBLIC_REFERENCE_DRAFT` — contains its own hardcoded MITRE ATT&CK-labeled prose, Sigma
rules, and hunt queries, entirely independent of `attack_mapping.py`'s semantic gate or
`report_contract.py`'s Section 11/15 state machine. When this path fires, the published page can
show ATT&CK/detection-looking content that Section 11/15 structurally still (correctly) resolve
based on real evidence (`attack_mapping_count`, `detection_status`) — meaning the two can disagree:
a page showing hardcoded, unvalidated "T1078"-style text while Section 11 honestly reports
`WITHHELD_INSUFFICIENT_EVIDENCE` structurally.

**Real-world reach:** narrow. Verified this fires only when `compose_report()` itself fails or
distrusts its own evidence — not the common "no LLM configured" case (confirmed empirically:
`reportx-canary/phase1j_role_decision_representative_fixtures.py`'s run last round showed
`content_source: "reportx_composer"` for every case with no LLM provider present; the composer
path, not this legacy one, is what actually serves that common case). `analytical_depth_gate.py`
also already caps `content_source == "template"` at `TACTICAL`, never `PREMIUM_LONG_FORM`.

**Disposition:** documented, not fixed this round. Rewriting a ~1,000-line pre-ReportX generator to
either suppress its own ATT&CK/detection prose or reconcile it with the real semantic gate is a
substantially different, standalone piece of work from "24-section semantic population" — named
here as real follow-up, not silently dropped.

## 4. `ransomware_claim` and `PREMIUM_LONG_FORM`

Because Section 17 (Business Impact) is `MANDATORY` for `ransomware_claim` and has no
implementation anywhere in this pipeline, **`ransomware_claim` cannot structurally reach
`PREMIUM_LONG_FORM` today, regardless of any other section's quality.** This is not a
newly-introduced regression — it has been true since RX-P1H's applicability matrix was written —
but it had not been stated explicitly as a hard ceiling before. Mandate §8's own instruction
("do not invent financial losses, regulatory penalties, customer impact... without evidence") means
this is very likely the *correct*, permanent state for this family: an unverified, third-party
leak-site claim has no organization-specific financial/operational impact evidence this pipeline
could ever honestly produce. This is named explicitly rather than silently accepted.

## 5. Sections 12/18/20: real facts that exist but aren't split into their own rendered block

Sections 12 (Actor/Campaign Context) and 18 (Sector/Geographic Impact) resolve real, per-article
states today (`_resolve_actor_context()`/`_resolve_sector_impact()`), but neither has a distinct,
separately-titled HTML block the way Sections 1/6/7/9/15/19 do — the underlying facts
(`ransomware_group`/`ransomware_sector`/`ransomware_country`) surface only as part of other prose
(family-analysis text, provenance data). Section 20 (Time-bound Actions) has real, evidence-scoped
P0/P1/P2 bullets already living *inside* Sections 7/9's "Decisions" sub-blocks, but they are not
counted or exposed as their own tracked section. None of these are being newly built or split out
this round (see §6) — flagged for a future round to decide whether promoting them to their own
titled blocks is genuine customer value or unnecessary section-count inflation, per the mandate's
own "do not chase word count" instruction.

## 6. What this round implements, and what it defers

**Implements** (§7 below has the full before/after): the two confirmed missing-render defects
(Section 6, Section 21) and one real, previously-dormant capability wired for the first time
(Section 22 Forecast, scoped to `cve_advisory`/`cisa_kev`/`cisa_advisory` only — mirrors the exact
"prove the wiring pattern on the family with the strongest real evidence first" precedent already
established for hunt hypotheses in RX-P1I).

**Defers, named explicitly, not silently skipped:**
- Sections 4, 10, 16, 17, 20 — no real evidence-extraction capability exists in this pipeline for
  any of these; building one is new capability work, not a wiring fix, and risks exactly the
  fabrication the mandate prohibits if rushed.
- Sections 7/9's article-invariant (but family-real) content for the non-CVE trio — a real
  content-generation project (per-article branching logic for 5+ families), not a wiring fix.
- Forecast for families other than the CVE-shaped three.
- The legacy `template` fallback's content-integrity issue (§3) — narrow reach, already tier-capped.
- Sections 12/18/20 promotion to distinct rendered blocks (§5).
