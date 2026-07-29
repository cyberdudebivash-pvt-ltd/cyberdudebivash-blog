# GPEP v2 Phases 2, 4–9 — Innovation & Excellence Review

Consolidated per Reuse Before Build: Phase 1's 13-subsystem audit
(`gpep-v2-phase1-platform-audit.md`) and Phase 3's knowledge-graph writeup
already established the evidence base each of these phases draws on. This
document applies that evidence to each phase's specific question rather
than re-deriving it. The top recommendation in each phase carries the full
mandatory field set (Evidence / Customer / Intelligence / Business /
Operational / Engineering Impact / Dependencies / Risks / Confidence /
Success Criteria); secondary items are stated more concisely and carried
into Phase 11's backlog register at full detail.

## Phase 2 — Intelligence Innovation

**Top recommendation: close the manual-publication gap (Phase 1 subsystem
1) before adding any new intelligence capability.**

- **Evidence**: `capabilities.md` row 1 — publication from `drafts/` to
  live is a manual CLI step separate from certification; this exact gap
  already let 2 of 3 reports sit unpublished for weeks once.
- **Customer Impact**: every other innovation in this review compounds on
  top of whatever actually reaches a reader — a report that's certified but
  unpublished has zero customer impact regardless of its quality.
- **Intelligence Impact**: none directly — this is a delivery-mechanism fix,
  not an analytical one.
- **Business Impact**: high — SEO/authority and commercial conversion both
  depend on cadence; a 3-week publication lag on 2 of 3 reports is a real,
  already-incurred cost.
- **Operational Impact**: low effort — likely a single automated step
  triggered by `review_status: published` rather than a human remembering
  to run `publish-report.js`.
- **Engineering Impact**: small — wire an existing script to an existing
  status transition; no new subsystem.
- **Dependencies**: none blocking; can be done independently of any other
  Phase 2-9 item.
- **Risks**: automating publication removes a manual check that currently
  also serves as a final human read-through — the fix should preserve a
  review gate, not just remove the friction.
- **Confidence**: HIGH — the gap and its cost are both directly documented,
  not inferred.
- **Objective Success Criteria**: 0 reports sit certified-but-unpublished
  for more than 24 hours after their `review_status` reaches `published`.

**Other Phase 2 dimensions, more concisely**: *More predictive* — no
evidence found of any predictive (as opposed to descriptive) intelligence
capability anywhere in the platform; genuinely new ground, not a gap in an
existing feature, so not recommended without a specific customer use case
to anchor it. *More correlated* — real progress already made (Phase 3);
the systemic-audit gap found there is the actual next step, not a new
correlation feature. *More explainable* — already a relative strength
(every score/certification decision in this platform ships a rationale
string, per `scoring.py`'s per-dimension rationale and `certification.py`'s
findings) — not a gap.

## Phase 4 — Intelligence Product Innovation

**Top recommendation: a Campaign Report subject-type template.**

- **Evidence**: `campaign-engine.js` is a full 573-line, live, tested
  clustering engine (Phase 1 subsystem 6) with zero customer-facing product
  built on top of it — the Threat Actor Profile template
  (`templates/threat-actor/`) already proved this exact pattern (render a
  new template from existing curated/computed data, not new research) works.
- **Customer Impact**: gives a customer a reason to query campaign data
  directly rather than only encountering it indirectly inside a CVE report.
- **Intelligence Impact**: none new — surfaces existing computed clusters,
  doesn't require new analysis.
- **Business Impact**: moderate — a second subject-type template doubles
  the platform's template-driven product surface from 1 to 2 with no new
  underlying data requirement.
- **Operational Impact**: low — same rendering pipeline as the existing
  Threat Actor Profile template.
- **Engineering Impact**: moderate — a new template file + a
  `buildCampaignReportMarkdown()`-equivalent renderer function, mirroring
  `threat-actor-profile.js`'s existing pattern exactly.
- **Dependencies**: none new; reuses EIRE v1's renderer and the Sentinel
  Intelligence Standard's front-matter contract.
- **Risks**: low — additive, no existing template or route changes.
- **Confidence**: HIGH — the exact same pattern already shipped once.
- **Objective Success Criteria**: 1 real campaign profile published and
  certified, sourced from `campaigns.json` data that already exists.

**Other Phase 4 products, concisely**: Executive Intelligence, SOC
Intelligence — already served by 2 of the 6 built audience templates;
Threat Hunting Packs, Detection Packs — blocked on Detection Engine
subsystem's own gap (0 of 3 reports ship a Sigma rule), not a template gap;
Research Reports, Strategic Assessments — the 3 published reports already
qualify as this category; Industry/Country/Sector Reports — no data
foundation exists yet (no Sector/Country entity population found in the
graph beyond the Organization/Sector schema additions from an earlier EIOS
Layer 3 change) — not recommended without a data source to build from
first; Customer Briefings, Roadmaps — internal-facing, not a graph/report
product, out of this review's scope.

## Phase 5 — AI Intelligence Enhancement

**Constraint restated up front, since it governs every item below: all AI
output must remain subject to human review before publication — nothing
recommended here proposes autonomous publication.**

**Top recommendation: an automated report-consistency checker, extending
`certification.py`'s existing Editorial Quality domain.**

- **Evidence**: this exact session found 2 real cross-document consistency
  defects by hand (SA-2026-0002's commercial brief citing a stale 3-tier
  pricing structure; marketing assets overstating detection content the
  report doesn't provide) — both were catchable by comparing a report's own
  claims against its own front matter/body, a mechanical check, not a
  judgment call.
- **Customer Impact**: indirect — fewer overstated or stale claims reaching
  customer-facing marketing surfaces.
- **Intelligence Impact**: none to the intelligence itself — this checks
  consistency of *derived* content (briefs, marketing copy) against the
  certified report, not the report's own analytical claims.
- **Business Impact**: moderate — protects the same Enterprise Trust
  Enforcement Layer this platform's own governance names as foundational.
- **Operational Impact**: reduces a category of manual-review burden this
  session's own work demonstrates is real (found twice in one afternoon).
- **Engineering Impact**: moderate — a new Editorial Quality sub-check
  reading a report's own "no Sigma rule provided" / "no such discrepancy
  exists" style disclaimers and flagging any sibling document
  (marketing/commercial-brief) that contradicts them; extends existing
  infrastructure, doesn't replace it.
- **Dependencies**: `certification.py`'s existing 6-domain framework.
- **Risks**: a naive keyword-based checker could false-positive on
  legitimate paraphrase; needs a narrow, high-precision rule set (exact
  claim contradiction, not general similarity) to avoid becoming noise.
- **Confidence**: MEDIUM — the need is proven (2 real instances), the
  specific detection mechanism is not yet designed.
- **Objective Success Criteria**: re-running this checker against the 2
  already-fixed defects (as historical fixtures) produces a flag for both,
  with zero flags against the current, corrected state.

**Other Phase 5 items, concisely**: IOC normalization, duplicate detection
— already exist in some form (`DEFAULT_ALLOWLIST`, corpus-level duplication
gates in `quality.py`); relationship suggestions — `computeActorAttribution`
already does exactly this, analyst-facing via `attribution_quality` labels,
not blindly auto-applied; draft report/detection generation — exists for
detection (`detection-engine.js`), not for full report drafting from the
hand-authored pipeline, and not recommended to build without a clearer
customer need than "AI could write more," per this program's own
"don't build features because they're interesting" mandate.

## Phase 6 — Commercial Excellence

**Top recommendation: resolve the BLOCKED-threshold question, not
re-caveat it a fourth time.**

- **Evidence**: 3 of 3 real reports score BLOCKED (43/37/48 of 100) against
  the unchanged 60-point threshold; 2 of 3 are independently CERTIFIED (one
  unconditionally) on the separate qualitative gate. Every commercial brief
  produced this session (SA-2026-0001/2/3) has independently arrived at the
  same caveat.
- **Customer Impact**: none directly, but indirectly high — this is the
  gate standing between 3 certified reports and being sold as anything
  above the lowest tier.
- **Intelligence Impact**: none — purely a commercial-scoring/tiering
  question, not an intelligence-quality one (certification already
  confirms quality independently).
- **Business Impact**: high — this is literally the question of whether the
  platform's only 3 flagship products can be priced as premium content.
- **Operational Impact**: none beyond a one-time policy decision.
- **Engineering Impact**: low if the decision is "keep 60, treat these as a
  lower product tier by design"; moderate if the decision is "add a credit
  path for malware-family-without-actor entities" (Phase 1 subsystem 1's
  scoring-model finding) since that requires a `scoring.py` change.
- **Dependencies**: none blocking a decision; the data needed to decide
  already exists (real scores, real certification outcomes, real per-
  dimension rationale from `scoring.py`).
- **Risks**: re-pricing without changing the model could feel arbitrary to
  a future analyst; changing the model without a policy decision risks
  moving the bar to fit the data rather than the reverse.
- **Confidence**: HIGH that the question needs answering; MEDIUM on which
  answer is correct — this is a judgment call, not a technical one.
- **Objective Success Criteria**: an explicit, dated decision recorded in
  `docs/PRICING.md` or the Sentinel Intelligence Standard, either way.

**Other Phase 6 items, concisely**: transparent public pricing is already a
real, deliberate differentiator (2026-07-29 decision); Stripe/Razorpay's
"⚠️ verify" status (Phase 1 subsystem 10) is a smaller, independent
operational item, not a strategic one.

## Phase 7 — Editorial Excellence

**Top recommendation: none new — the Sentinel Intelligence Standard
(GCIEP v1) and the audience-enum conformance test already are this phase's
main deliverable, produced one work-block before this one.**

Reviewed directly rather than assumed current: `test_sis_conformance.py`
(4 tests) still passes against the live template set; the 3 published
reports' front matter still conforms to the canonical enums SIS documents.
The one still-open editorial-consistency question (Issue 15's 3-way
report-structure reconciliation: 5-section gate vs. 60-section taxonomy vs.
~24-section real usage) remains explicitly staged, not newly re-opened
here — restating an existing, already-honest "not yet decided" is more
accurate than manufacturing a new recommendation where the real blocker is
a decision, not more analysis.

## Phase 8 — Automation Excellence

**Top recommendation: a relevance filter on the AI-security/general
aggregator's inclusion logic (Phase 1 subsystem 4's finding).**

- **Evidence**: sampled directly — a job listing ("Qualcomm Product
  Security Engineer – AI Software Development, Job ID: 3092777") was
  auto-published to `collections/ai-security-intelligence.html` as if it
  were threat intelligence.
- **Customer Impact**: direct — a reader browsing this collection for
  security analysis encounters non-security content mixed in.
- **Intelligence Impact**: none to certified reports; this is the
  automated aggregator, a separate pipeline.
- **Business Impact**: moderate — undermines the "definitive AI security
  authority" positioning CLAUDE.md's own governance names as a goal, every
  time a non-security item slips through.
- **Operational Impact**: low — a filter runs automatically, no new manual
  step.
- **Engineering Impact**: small — the pipeline already computes `labels`
  for categorization (used elsewhere for `primary_category()`); a
  job-listing/non-security exclusion rule using signals already computed
  (e.g., "Job ID:", salary/location patterns common to postings) is a
  targeted addition, not new infrastructure.
- **Dependencies**: none blocking.
- **Risks**: an overly aggressive filter could drop legitimate security-job
  market commentary (a real sub-genre of security news); scope the rule
  narrowly (structural job-posting patterns) rather than broadly (any
  mention of hiring).
- **Confidence**: MEDIUM — the specific instance is confirmed; whether it's
  representative of a broader volume of non-security inclusions wasn't
  measured (would require sampling more of the feed than this pass did).
- **Objective Success Criteria**: the specific sampled job-listing post,
  and any structurally similar ones, no longer appear in
  `collections/ai-security-intelligence.html` after the filter ships.

**Other Phase 8 items, concisely**: CI/CD is already Mature (Phase 1
subsystem 12 — 0 failures across recently-sampled runs, `assure.sh` as a
single entry point); the graph-attribution systemic-audit opportunity
(Phase 3) is itself an automation-excellence candidate (an automated
source-URL-vs-claim consistency checker) and is tracked once, in Phase 11,
rather than duplicated here.

## Phase 9 — Customer Intelligence Experience

**Top recommendation: re-verify the newsletter/ESP configuration status.**

- **Evidence**: `capabilities.md` — last verified "not configured"
  2026-07-05, stated as unknown-current rather than assumed fixed, over 3
  weeks of otherwise-continuous development since.
- **Customer Impact**: direct — this is the acquisition-funnel capture
  point CLAUDE.md's own mission statement names as a primary objective.
- **Intelligence Impact**: none.
- **Business Impact**: moderate-to-high if genuinely still unconfigured —
  every visitor who would have subscribed during 3+ weeks is a lost
  acquisition, silently.
- **Operational Impact**: none beyond the check itself.
- **Engineering Impact**: minimal — a status check, not a build.
- **Dependencies**: requires either live credentials or a real signup to
  verify, per the existing note explaining why it hasn't been re-checked.
- **Risks**: none from checking; the risk is entirely in *not* checking
  while assuming it's fine.
- **Confidence**: HIGH that this is worth checking; unknown on the actual
  current state (that's exactly what makes it worth checking).
- **Objective Success Criteria**: a dated, current status recorded
  replacing the 2026-07-05 unknown.

**Other Phase 9 items, concisely**: FAQ, dashboard, `/intelligence/` hub,
onboarding/welcome-email all independently confirmed live this session
(Phase 1 subsystem 11); a customer-facing API reference (Phase 1 subsystem
13's Documentation finding) is the more material remaining gap given the
API is a paid product, generated from existing route definitions rather
than hand-maintained separately.

---
*CyberDudeBivash® Sentinel APEX — GPEP v2 Phases 2, 4–9 Innovation Review*
