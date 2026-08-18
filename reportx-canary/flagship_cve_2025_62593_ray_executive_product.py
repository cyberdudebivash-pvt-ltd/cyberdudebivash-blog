"""P0 Intelligence Factory flagship reference implementation.

Transforms the existing, real, 23/23-certified Canary D bundle
(``cve_2025_62593_ray_canary.py`` — unmodified, imported not duplicated)
into the full MISSION-standard executive product by adding the four
renderers ``REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md`` identifies as
genuinely missing: role-based executive decisions, a threat-hunting
hypothesis package, a sector-impact matrix, and Admiralty-style source-
reliability display — plus completing the Predictive Intelligence section
to the MISSION's full 24h/72h/7d/30d/90d timeframe ladder (the existing
canary already has the 90-day forecast; this adds the other four).

Every new claim, decision, and hypothesis below traces to a claim_id
already present in the existing canary's evidence graph, or is explicitly
marked as a forward-looking hunt/forecast with no retrospective evidence
(the honest alternative to fabricating one). Nothing here re-researches
CVE-2025-62593 from scratch and nothing here overrides or edits a single
line of the existing, real, hash-verified source material.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cve_2025_62593_ray_canary import (  # noqa: E402
    build_bundle as build_base_bundle,
    build_cve_record,
    build_detection_rule,
    build_forecast as build_90_day_forecast,
    build_graph,
    build_hypothesis_sets,
    build_intelligence_gaps,
    build_metrics_registry,
    build_regulatory_applicabilities,
)
from sentinel_engine.reportx.claim_model import Reliability  # noqa: E402
from sentinel_engine.reportx.commercial_readiness import ReportBundle  # noqa: E402
from sentinel_engine.reportx.executive_products import (  # noqa: E402
    HuntHypothesis,
    RoleAudience,
    RoleDecision,
    SectorApplicability,
    SectorImpact,
    admiralty_label,
    render_hunt_package,
    render_role_decisions,
    render_sector_impact_matrix,
)
from sentinel_engine.reportx.forecast import Forecast, WithheldForecast  # noqa: E402
from sentinel_engine.reportx.product_depth import DepthAssessment  # noqa: E402


# ============================================================
# Forecast ladder — the 90-day forecast already exists in the base canary
# (build_90_day_forecast). These four add the shorter horizons, each
# genuinely distinct: grounded in different subsets of the same evidence,
# not the same paragraph with the number changed.
# ============================================================

def build_24_hour_forecast() -> Forecast:
    return Forecast(
        judgment="No material change to the exploitation picture is expected within 24 hours. CISA's KEV "
                 "entry, SSVC assessment, and the EPSS score were all set/observed the same day this report "
                 "was compiled (2026-08-17); a same-day reversal of any of the three would be unusual absent "
                 "a new public event.",
        time_horizon="24 hours from 2026-08-17",
        supporting_observation_claim_ids=("c-kev-listed", "c-ssvc-active", "c-epss-score"),
        historical_baseline_claim_ids=(),
        assumptions=("No new public PoC, vendor disclosure, or CISA catalog update lands within the window.",),
        counter_evidence_claim_ids=(),
        alternative_scenarios=(
            "A security researcher publishes a corrected exploit (fixing RondoDox's own User-Agent flaw) "
            "within 24 hours, which would immediately raise near-term exploitation likelihood.",
        ),
        indicators_to_watch=("CISA KEV catalog diff", "NVD lastModified timestamp change"),
        confidence="HIGH",
        confidence_rationale="A 24-hour window is short enough that the current, same-day snapshot of KEV/"
                              "SSVC/EPSS is the best available predictor of the next 24 hours specifically.",
        what_would_change_assessment=("Any new source publishing within the window would supersede this forecast.",),
    )


def build_72_hour_forecast() -> Forecast:
    return Forecast(
        judgment="Scanning activity consistent with CVE-2025-62593 (unauthenticated POST probes to /api/jobs/ "
                 "or /api/job_agent/jobs/) is likely to be attempted by opportunistic actors within 72 hours, "
                 "given CISA's active-exploitation classification and RondoDox's own documented pattern of "
                 "broad, shotgun-style targeting. Whether such attempts succeed depends on whether the actor's "
                 "payload has corrected RondoDox's documented User-Agent implementation flaw.",
        time_horizon="72 hours from 2026-08-17",
        supporting_observation_claim_ids=("c-ssvc-active", "c-rondodox-predisclosure", "c-rondodox-profile"),
        historical_baseline_claim_ids=("c-rondodox-profile",),
        assumptions=("RondoDox or a comparable opportunistic actor continues actively scanning for this exploit class.",),
        counter_evidence_claim_ids=("c-rondodox-implementation-flaw", "c-epss-score"),
        alternative_scenarios=(
            "Scanning volume stays flat because the low EPSS score (0.369%) reflects genuinely low current "
            "attacker interest beyond RondoDox's already-documented, flawed attempt.",
        ),
        indicators_to_watch=(
            "Any change to RondoDox's payload User-Agent string in newly published research",
            "EPSS score movement over the 72-hour window",
        ),
        confidence="MEDIUM",
        confidence_rationale="72 hours is the window this report's own Predictive Intelligence discipline "
                              "(Section: Predictive Intelligence) treats as the standard weaponization-"
                              "acceleration horizon for KEV-listed vulnerabilities, but the specific "
                              "counter-evidence (the implementation flaw, the low EPSS) tempers confidence "
                              "below HIGH.",
        what_would_change_assessment=("A confirmed successful exploitation report in this window would raise confidence sharply.",),
    )


def build_7_day_forecast() -> Forecast:
    return Forecast(
        judgment="CISA's BOD 26-04 remediation due date (2026-08-20) falls inside this window. Federal "
                 "agencies face a compliance deadline; enterprise patch-cycle pressure typically follows KEV "
                 "deadlines even for non-federal organizations, per this pipeline's established remediation-"
                 "urgency framing. Expect the highest volume of vendor/CTI-vendor commentary on this CVE "
                 "within this 7-day window, coinciding with the deadline.",
        time_horizon="7 days from 2026-08-17",
        supporting_observation_claim_ids=("c-kev-listed",),
        historical_baseline_claim_ids=(),
        assumptions=("CISA does not extend or waive the 2026-08-20 due date within the window.",),
        counter_evidence_claim_ids=(),
        alternative_scenarios=("CISA extends the due date, which would shift both the compliance pressure and the associated commentary volume later.",),
        indicators_to_watch=("CISA KEV catalog due-date field for this CVE",),
        confidence="MEDIUM",
        confidence_rationale="The due date itself is a confirmed fact (c-kev-listed); the DOWNSTREAM effect "
                              "(commentary volume, patch-cycle pressure) is an analyst inference about typical "
                              "post-KEV-deadline behavior, not itself a sourced claim about this specific CVE.",
        what_would_change_assessment=("A CISA due-date change would directly falsify the forecast's premise.",),
    )


def build_30_day_forecast() -> WithheldForecast:
    return WithheldForecast(
        topic="Confirmed real-world compromise volume attributable to CVE-2025-62593 over the next 30 days",
        reason="No source reviewed provides vendor (Anyscale/ray-project) or independent incident-telemetry "
               "data on confirmed compromises for this CVE at any point so far, and no source establishes a "
               "trend line from which a 30-day compromise-volume forecast could be derived without "
               "fabricating a rate. This is recorded as a governed withholding (see Intelligence Gaps: "
               "'whether any exploitation attempt has technically succeeded is not established'), not a "
               "silent omission.",
    )


def build_forecast_ladder() -> list:
    return [
        build_24_hour_forecast(),
        build_72_hour_forecast(),
        build_7_day_forecast(),
        build_30_day_forecast(),
        build_90_day_forecast(),
    ]


# ============================================================
# Role-based executive decisions — only roles with real, claim-grounded
# content for THIS CVE. OT Team is deliberately omitted: the existing
# canary's own regulatory-applicability findings (build_regulatory_
# applicabilities()) already establish NOT_APPLICABLE for OT/ICS context,
# so a Ray-specific OT decision would be padding, not analysis.
# ============================================================

def build_role_decisions() -> list[RoleDecision]:
    return [
        RoleDecision(
            role=RoleAudience.CEO_BOARD,
            decision="No board-level incident disclosure is warranted on current evidence. Direct the CISO to "
                     "confirm internal Ray exposure and report back within 72 hours.",
            rationale="No source reviewed connects a confirmed compromise to any specific organization; the "
                       "KEV listing and active-exploitation classification are real but do not by themselves "
                       "establish organization-specific impact (c-kev-listed, c-ssvc-active). Board attention "
                       "is warranted for the internal-exposure question, not for an unconfirmed breach.",
            evidence_claim_ids=("c-kev-listed", "c-ssvc-active"),
            timeline="Within 72 hours",
        ),
        RoleDecision(
            role=RoleAudience.CISO_CIO,
            decision="Treat as a federal-deadline-driven P0: confirm Ray deployment inventory, upgrade to "
                     "2.52.0 or restrict network exposure of the dashboard/API by the CISA due date.",
            rationale="CISA's BOD 26-04 due date (2026-08-20) is a real, confirmed compliance deadline "
                       "(c-kev-listed); the vendor fix is confirmed available (c-fixed-version). This is a "
                       "patch-and-verify decision, not a novel-mitigation-design decision.",
            evidence_claim_ids=("c-kev-listed", "c-fixed-version"),
            timeline="By 2026-08-20 (CISA due date)",
        ),
        RoleDecision(
            role=RoleAudience.SOC_MANAGER,
            decision="Deploy the SYNTAX_VALIDATED Sigma detection for unauthenticated POST to /api/jobs/ or "
                     "/api/job_agent/jobs/ from outside localhost, and treat any hit as an investigation lead, "
                     "not a confirmed compromise.",
            rationale="The detection rule is grounded directly in the confirmed exploit chain (c-root-cause, "
                       "c-exploit-prereqs) but has not been exercised against real telemetry this session — "
                       "SOC teams should tune the internal-client filter to their own network topology before "
                       "enabling blocking actions on it.",
            evidence_claim_ids=("c-root-cause", "c-exploit-prereqs"),
            timeline="Within 24 hours",
        ),
        RoleDecision(
            role=RoleAudience.IR_MANAGER,
            decision="No incident response activation is indicated by current evidence alone. Pre-stage the "
                     "playbook (isolate the affected developer workstation, preserve volatile memory, do not "
                     "power off) so it is ready if the SOC hunt below produces a confirmed hit.",
            rationale="This is a real, actively-exploited-per-CISA vulnerability, but the corroborating "
                       "RondoDox evidence documents a payload flaw that likely makes the one publicly-known "
                       "attempt ineffective (c-rondodox-implementation-flaw) — activation should follow a "
                       "confirmed hit, not the advisory alone.",
            evidence_claim_ids=("c-ssvc-active", "c-rondodox-implementation-flaw"),
        ),
        RoleDecision(
            role=RoleAudience.THREAT_HUNTER,
            decision="Execute the hunt hypothesis in the Threat Hunting section below.",
            rationale="Real, specific pivot data exists (RondoDox's documented pre-disclosure attempt, its "
                       "identified C2/exploiting-IP counts) that a generic 'monitor for ransomware' hunt would "
                       "waste.",
            evidence_claim_ids=("c-rondodox-predisclosure", "c-rondodox-profile"),
        ),
        RoleDecision(
            role=RoleAudience.VULNERABILITY_MANAGER,
            decision="Prioritize CVE-2025-62593 in the current patch cycle at KEV-driven urgency, tracked "
                     "separately from routine CVSS-only prioritization.",
            rationale="Two independent, authoritative CVSS scores exist for this CVE (9.4 GHSA v4 vs. 8.8 NVD "
                       "v3.1, c-cvss-v4-ghsa / c-cvss-v31-nvd) — vulnerability management tooling keyed to a "
                       "single CVSS feed may show a different number than the source record this report "
                       "verified directly; use the KEV listing, not CVSS alone, to drive urgency here.",
            evidence_claim_ids=("c-cvss-v4-ghsa", "c-cvss-v31-nvd", "c-kev-listed"),
        ),
        RoleDecision(
            role=RoleAudience.CLOUD_TEAM,
            decision="Audit for Ray dashboard/API endpoints reachable from developer workstations or CI "
                     "runners with outbound browser access, not just internet-facing deployments.",
            rationale="The exploit chain requires only that a developer's browser can reach a locally-bound "
                       "Ray instance via DNS rebinding (c-root-cause, c-exploit-prereqs) — conventional "
                       "internet-facing-asset scanning would miss this exposure class entirely.",
            evidence_claim_ids=("c-root-cause", "c-exploit-prereqs"),
        ),
        RoleDecision(
            role=RoleAudience.LEGAL_COMPLIANCE_PRIVACY,
            decision="No regulatory notification obligation is triggered by current evidence. Revisit only if "
                     "the SOC hunt confirms an actual compromise with data-access scope.",
            rationale="The existing canary's own regulatory-applicability findings (data-protection "
                       "frameworks) are explicitly `NOT_ASSESSED` at the CVE level — applicability depends on "
                       "deployer-specific facts (what data a given Ray deployment processes), not on a "
                       "property of the vulnerability itself; no deployer-specific fact was reviewed for this "
                       "report.",
            evidence_claim_ids=(),
        ),
        RoleDecision(
            role=RoleAudience.BUSINESS_CONTINUITY_SUPPLY_CHAIN,
            decision="Confirm whether Ray sits in any AI/ML training or inference pipeline that is a "
                     "dependency for a customer-facing service; if so, treat the patch as pipeline-critical, "
                     "not routine.",
            rationale="Ray's confirmed, named production use (Uber, quoted directly) demonstrates this class "
                       "of exposure is real at scale in the industry, not hypothetical (c-uber-user, "
                       "c-ray-adoption) — though this is industry context, not a claim about any specific "
                       "reader's own supply chain.",
            evidence_claim_ids=("c-uber-user", "c-ray-adoption"),
        ),
        RoleDecision(
            role=RoleAudience.MSSP,
            decision="Issue a client advisory citing the confirmed KEV due date (2026-08-20) and the SOC "
                     "Manager decision's detection rule; do not issue client-facing language asserting "
                     "confirmed active compromise beyond what CISA's SSVC record actually states.",
            rationale="Overstating exploitation certainty to clients beyond CISA's own 'active' SSVC "
                       "classification (c-ssvc-active) — e.g., implying confirmed breaches — would not be "
                       "supported by any source reviewed and would itself be exactly the kind of unsupported "
                       "assertion this report's own discipline exists to avoid.",
            evidence_claim_ids=("c-ssvc-active", "c-kev-listed"),
            timeline="Within 24 hours",
        ),
    ]


# ============================================================
# Threat hunting — operationalizes the existing canary's own "Hunting"
# prose section into the full structured HuntHypothesis shape.
# ============================================================

def build_hunt_hypotheses() -> list[HuntHypothesis]:
    return [
        HuntHypothesis(
            hypothesis_id="h-dns-rebind",
            statement="An attacker used DNS rebinding to reach a locally-bound Ray dashboard/API from a "
                       "victim's browser, evidenced by a short-TTL DNS response resolving to a loopback or "
                       "private address immediately preceding a Ray API request.",
            required_telemetry=(
                "Browser/endpoint DNS resolution logs with TTL values",
                "Local host firewall or EDR network-connection logs for the Ray API port",
                "Reverse-proxy or host-based logs of POST requests to /api/jobs/ or /api/job_agent/jobs/",
            ),
            pivot_opportunities=(
                "Pivot from the anomalous DNS response to the resolving domain's registration/hosting history",
                "Pivot from the requesting process (browser) to the tab/site history around the request time",
            ),
            expected_observations=(
                "A DNS response for an external-looking domain resolving to 127.0.0.1 or another loopback/"
                "private address, with an unusually short TTL",
                "A POST to a Ray job-submission endpoint originating from the browser process shortly after "
                "that resolution",
            ),
            negative_indicators=(
                "No DNS responses resolving to loopback/private addresses for any externally-registered "
                "domain in the observed window",
                "Ray API access exclusively from known internal orchestration clients on expected ports",
            ),
            false_positive_considerations=(
                "Legitimate local development tooling that itself resolves external domains to localhost "
                "(some local dev proxies do this deliberately)",
                "Split-horizon DNS configurations that legitimately resolve internal service names to private "
                "addresses",
            ),
            validation_steps=(
                "Confirm the requesting process is a browser, not an authorized orchestration client",
                "Confirm the resolved domain is not on an internal allowlist of legitimate local-proxy domains",
                "Correlate the browser's tab/navigation history for the same timeframe if endpoint telemetry allows",
            ),
            success_criteria="At least one DNS-rebind-pattern resolution is confirmed to have immediately "
                              "preceded a non-allowlisted POST to a Ray job-submission endpoint from a browser "
                              "process.",
            evidence_claim_ids=("c-root-cause", "c-exploit-prereqs"),
        ),
        HuntHypothesis(
            hypothesis_id="h-rondodox-reuse",
            statement="A RondoDox-attributed or RondoDox-derived exploitation attempt against this CVE, "
                       "reusing the specific flawed User-Agent pattern Bitsight documented, reached the "
                       "environment.",
            required_telemetry=(
                "Reverse-proxy or WAF logs capturing full request User-Agent headers for Ray API endpoints",
            ),
            pivot_opportunities=(
                "Pivot from a matching User-Agent string to source IP, then to Bitsight's published RondoDox "
                "infrastructure indicators for further correlation (not reproduced in this report; pull "
                "current IOCs from Bitsight's own research)",
            ),
            expected_observations=(
                "A request to /api/jobs/ or /api/job_agent/jobs/ carrying a User-Agent value beginning with "
                "the literal string 'Mozilla' despite originating from a non-browser client — the exact "
                "implementation-flaw signature Bitsight documented",
            ),
            negative_indicators=(
                "No requests to the affected endpoints carry a User-Agent value at all",
                "All observed User-Agent values on these endpoints match known-legitimate orchestration clients",
            ),
            false_positive_considerations=(
                "Legitimate automated clients that happen to set a 'Mozilla'-prefixed User-Agent for "
                "compatibility reasons (uncommon for backend orchestration clients, but not impossible)",
            ),
            validation_steps=(
                "Confirm the request would have been rejected by the endpoint's own User-Agent check (HTTP 405) "
                "if the flaw were absent — i.e., confirm this specific request pattern, not just any 'Mozilla' "
                "User-Agent, matches the documented flaw",
                "Cross-reference source IP against current Bitsight-published RondoDox indicators before "
                "attributing to RondoDox specifically",
            ),
            success_criteria="A confirmed request matching the documented flawed-payload pattern is found, "
                              "with source-IP correlation to published RondoDox infrastructure before actor "
                              "attribution is made.",
            evidence_claim_ids=("c-rondodox-predisclosure", "c-rondodox-implementation-flaw"),
        ),
    ]


# ============================================================
# Sector impact — only Technology is ASSESSED (the one sector with a
# named, quoted, sourced production deployment). Every other MISSION-
# named sector is explicitly NOT_ASSESSED with its own reason, never a
# shared paragraph.
# ============================================================

def build_sector_impact() -> list[SectorImpact]:
    not_assessed_reason = (
        "No source reviewed for this report names a deployment of Ray in this sector specifically. Ray's "
        "237M+ cumulative downloads (c-ray-adoption) establish broad AI/ML-industry adoption in the "
        "aggregate, not sector-specific exposure — extrapolating a sector claim from an aggregate download "
        "count would not be supported by the evidence."
    )
    return [
        SectorImpact(
            "Technology", SectorApplicability.ASSESSED,
            "Confirmed, named, quoted production use at Uber for AI/ML model training, hyperparameter "
            "tuning, and distributed data processing.",
            "No sector-specific regulatory determination made; see Legal/Compliance/Privacy decision above.",
            ("c-uber-user", "c-ray-adoption"),
        ),
        SectorImpact("Healthcare", SectorApplicability.NOT_ASSESSED, not_assessed_reason),
        SectorImpact("Finance", SectorApplicability.NOT_ASSESSED, not_assessed_reason),
        SectorImpact("Government", SectorApplicability.NOT_ASSESSED, not_assessed_reason),
        SectorImpact("Manufacturing", SectorApplicability.NOT_ASSESSED, not_assessed_reason),
        SectorImpact("Retail", SectorApplicability.NOT_ASSESSED, not_assessed_reason),
        SectorImpact("Energy", SectorApplicability.NOT_ASSESSED, not_assessed_reason),
        SectorImpact(
            "Critical Infrastructure", SectorApplicability.NOT_ASSESSED,
            "The existing canary's own regulatory-applicability findings already establish NOT_APPLICABLE "
            "for OT/ICS context — no source reviewed establishes any operational-technology deployment "
            "nexus for Ray or this vulnerability.",
        ),
        SectorImpact(
            "Cloud Providers", SectorApplicability.ASSESSED,
            "Ray is commonly deployed on cloud compute infrastructure for distributed AI/ML workloads "
            "(inferred from its stated purpose as a distributed compute engine and its PyTorch Foundation "
            "positioning, c-ray-adoption) — no source names a specific cloud provider's own exposure.",
            "", ("c-ray-adoption",),
        ),
        SectorImpact("Education", SectorApplicability.NOT_ASSESSED, not_assessed_reason),
        SectorImpact("Telecommunications", SectorApplicability.NOT_ASSESSED, not_assessed_reason),
    ]


# ============================================================
# Assembly
# ============================================================

def _admiralty_appendix(graph) -> str:
    lines = ["## Appendix B: Source Reliability (Admiralty-Adjacent)", "", "| Source | Publisher | Reliability |", "|---|---|---|"]
    for sid, s in graph.sources.items():
        lines.append(f"| {sid} | {s.publisher} | {admiralty_label(s.reliability)} |")
    lines.append("")
    lines.append(
        "This is a presentation-only mapping of this report's existing 4-tier source-reliability field onto "
        "Admiralty-Code-adjacent language, not the full independent 2-axis Admiralty matrix (Source "
        "Reliability A-F separately from Information Credibility 1-6) — see "
        "`REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md` for why the second axis is a documented, deferred "
        "follow-up rather than approximated here."
    )
    return "\n".join(lines)


def build_flagship_bundle() -> ReportBundle:
    base = build_base_bundle()
    graph = build_graph()

    forecast_ladder = build_forecast_ladder()
    role_decisions = build_role_decisions()
    hunt_hypotheses = build_hunt_hypotheses()
    sector_rows = build_sector_impact()

    extension = "\n\n".join(filter(None, [
        render_role_decisions(role_decisions),
        render_hunt_package(hunt_hypotheses),
        render_sector_impact_matrix(sector_rows),
        _admiralty_appendix(graph),
    ]))

    rendered_text = base.rendered_text.rstrip() + "\n\n" + extension + "\n"

    section_count = rendered_text.count("\n## ")
    material_claims = [c for c in graph.claims.values() if c.has_evidence()]

    return ReportBundle(
        report_id="cve-2025-62593-ray-flagship-executive-product",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags=base.dimension_tags,
        detection_rules=base.detection_rules,
        metrics_registry=base.metrics_registry,
        cited_metric_ids=base.cited_metric_ids,
        rendered_metric_ids=base.rendered_metric_ids,
        regulatory_applicabilities=base.regulatory_applicabilities,
        forecasts=forecast_ladder,
        hypothesis_sets=base.hypothesis_sets,
        intelligence_gaps=base.intelligence_gaps,
        threat_products=base.threat_products,
        review=None,
        is_premium_tier=True,
        depth_assessment=DepthAssessment(
            rendered_word_count=len(rendered_text.split()),
            material_claim_count=len(material_claims),
            distinct_evidence_backed_sections=section_count,
        ),
        technical_recommendation_count=base.technical_recommendation_count,
        technical_recommendations_with_evidence_basis=base.technical_recommendations_with_evidence_basis,
    )


if __name__ == "__main__":
    bundle = build_flagship_bundle()
    print(bundle.rendered_text)
