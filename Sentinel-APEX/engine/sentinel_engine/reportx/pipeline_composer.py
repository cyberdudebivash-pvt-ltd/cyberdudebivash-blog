"""The live-pipeline composer: turns one ``DiscoveredArticle`` into a real,
evidence-graph-backed, commercial-readiness-gated report -- the piece
``REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md`` designed and
``discovery_bridge.py`` half-built. This module is the other half: it
reuses ``automation.report_renderer.render_evidence_report()`` (the real,
evidence-first HTML core, "RX-STABILIZATION-1" in that module's own
history) UNCHANGED for the base narrative, and adds exactly two new
sections on top using that same module's own styling primitives
(``_section``/``_panel``/``_bullets``) -- never a second, competing visual
system.

The point of this module is not to write new analytical prose from
scratch (``report_renderer.py`` already does that honestly, per
vulnerability class). The point is to make the result *gate-checkable*:
build the real ``EvidenceGraph`` alongside the HTML, run it through
``commercial_readiness.py``'s unmodified 23-control matrix scoped to the
tier the evidence actually supports (``tier_downgrade.py``, reused from
the P0 release-certification work), and report an achieved tier a caller
can trust -- rather than a fixed template nobody re-validates per report.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

# See discovery_bridge.py's identical bootstrap for why this is needed:
# automation/ lives at the repo root, not under Sentinel-APEX/engine/.
_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from automation.report_integrity import ReportContext, build_report_context  # noqa: E402
from automation.report_renderer import (  # noqa: E402
    DetectionPackage,
    _bullets,
    _detection_package,
    _esc,
    _panel,
    _section,
)

from .analytic_scaffolding import IntelligenceGap
from .claim_model import CorroborationState
from .commercial_readiness import ControlResult, ReportBundle, evaluate_commercial_readiness
from .detection_validation import DetectionRule, DetectionValidationState
from .discovery_bridge import build_evidence_graph, build_threat_product
from .intelligence_validation import IntelligenceScorecard, evaluate_intelligence_validation
from .executive_products import (
    RoleAudience,
    RoleDecision,
    render_role_decisions,
    role_display_label,
    two_axis_reliability,
    worst_corroboration_state,
)
from .human_review import CertificationState
from .product_depth import DepthAssessment
from .tier_downgrade import DowngradeResult, determine_achieved_tier

from sentinel_engine.attack_mapper import extract_technique_ids  # noqa: E402

_STATUS_TO_VALIDATION_STATE = {
    "syntax_validated_experimental": DetectionValidationState.SYNTAX_VALIDATED,
}


def _detection_rules(report_id: str, package: DetectionPackage) -> list[DetectionRule]:
    """One ``DetectionRule`` per format the (single, shared) evidence basis
    actually supports -- ``DetectionPackage.status`` governs both formats
    identically, since Sigma and KQL are two renderings of the same
    evidence-conditioned decision, not two independent judgments. A
    withheld package still yields exactly one rule (as before), so
    ``commercial_readiness.py``'s detection_evidence_discipline control
    (which requires at least one rule to evaluate) keeps working unchanged."""
    validation_state = _STATUS_TO_VALIDATION_STATE.get(package.status, DetectionValidationState.WITHHELD_INSUFFICIENT_EVIDENCE)
    # COMMERCIAL-QUALITY-2026-08-18: package.attack_mappings entries are
    # full descriptive sentences ("Defense Evasion -> Valid Accounts
    # (T1078), only if authentication/session abuse is observed."), not
    # bare technique IDs -- DetectionRule.technique_id must hold the ID
    # alone (it's serialized as a structured field by bundle_io.py and read
    # as one by intelligence_validation.py's own scorer, which already had
    # to work around this exact shape via the same extract_technique_ids()
    # reused here rather than storing the raw sentence and pushing the
    # parsing burden onto every consumer).
    _ids = extract_technique_ids(package.attack_mappings[0]) if package.attack_mappings else []
    technique_id = _ids[0] if _ids else ""
    formats = [("sigma", package.sigma_yaml), ("kql", package.kql)]
    rules = [
        DetectionRule(
            rule_id=f"{report_id}-detection-{fmt}", technique_id=technique_id,
            format=fmt, validation_state=validation_state, body=body, evidence_gap_rationale=package.rationale,
        )
        for fmt, body in formats if body
    ]
    if rules:
        return rules
    return [DetectionRule(
        rule_id=f"{report_id}-detection", technique_id=technique_id,
        format="none", validation_state=validation_state, body="", evidence_gap_rationale=package.rationale,
    )]


_VULNERABILITY_MANAGER_FAMILIES = ("cve_advisory", "cisa_advisory", "cisa_kev")


def _lean_role_decisions(article, context: ReportContext, threat_product) -> list[RoleDecision]:
    """A deliberately SHORT role list for FLASH-tier volume content --
    the full 10-role treatment (``REPORTX-INTELLIGENCE-FACTORY-BENCHMARK.md``)
    is reserved for premium dossiers with the evidence depth to ground all
    10. Padding every routine alert with 10 roles it has no real basis for
    would itself be the padding defect this factory exists to remove.

    Vulnerability Manager guidance requires a real patch/exploitation
    dimension to be relevant -- gated to the families
    ``context.exploitation_status``/``context.patch_label`` are actually
    meaningful for (Section 10's evidence-scoping discipline applied to
    role routing, not just to claims). Before this gate, every family --
    including phishing/PhaaS and third-party ransomware-campaign reporting
    with no patch or exploitation dimension at all -- got a bare "Track
    against {family} intake..." Vulnerability Manager decision regardless
    (verified live against a real published JWR PhaaS report,
    family=general_intelligence, which had no CVE/patch evidence anywhere in
    its bundle). ``ransomware_claim`` was also removed from this list
    (COMMERCIAL-QUALITY-2026-08-18 finding, independently verified against
    the live-fetched CVE-2026-75105 report and this module's own then-empty
    ``evidence_claim_ids`` for that family, which had already signalled the
    decision wasn't really evidence-backed): an unverified leak-site victim
    claim has no CVE, no patch, and no exploitation-status dimension either
    -- it is not a vulnerability-management concern at all. The IR Manager
    decision below already covers this family with real, evidence-scoped
    guidance; it does not also need a Vulnerability Manager decision with
    nothing to track against."""
    decisions: list[RoleDecision] = []
    if context.family in _VULNERABILITY_MANAGER_FAMILIES:
        # exploitation_label/patch_label (report_integrity._exploitation()/
        # _patch()) are standalone display phrases -- several of them (e.g.
        # "Not confirmed by available evidence; not in verified KEV
        # snapshot") were never written to grammatically complete a
        # mid-sentence clause like "severity commensurate with {X}.", which
        # produced broken English (independently verified live against the
        # published CVE-2026-75105 report, and separately flagged in the
        # same terms by an external review -- COMMERCIAL-QUALITY-2026-08-18).
        # Presenting each status as its own colon-introduced clause is
        # grammatically correct for every current and future value, rather
        # than special-casing individual label strings.
        decisions.append(RoleDecision(
            role=RoleAudience.VULNERABILITY_MANAGER,
            decision=f"Track against {context.family_label.lower()} intake. "
                     f"Exploitation status: {context.exploitation_label}. Patch status: {context.patch_label}.",
            rationale="Prioritization reflects this record's own exploitation/patch evidence, not a fixed severity template.",
            evidence_claim_ids=("c-exploitation-status", "c-patch-status"),
        ))
    if context.family in ("cve_advisory", "cisa_advisory", "cisa_kev"):
        decisions.append(RoleDecision(
            role=RoleAudience.SOC_MANAGER,
            decision="Review the detection guidance below before enabling any blocking action on it.",
            rationale="Detection maturity for this record is stated explicitly, not assumed production-ready.",
            evidence_claim_ids=("c-summary",),
        ))
    if context.family == "ransomware_claim":
        decisions.append(RoleDecision(
            role=RoleAudience.IR_MANAGER,
            decision="Treat as a validation task (confirm internally), not an activation trigger, absent "
                      "independent corroboration.",
            rationale="The victim claim is a single, third-party leak-site source (c-victim-claim, REPORTED "
                       "not CONFIRMED) -- Section 10's high-impact-claim-type discipline applies.",
            evidence_claim_ids=("c-victim-claim",),
        ))
    return decisions


@dataclass(frozen=True)
class ComposedReport:
    report_id: str
    context: ReportContext
    html: str
    bundle: ReportBundle
    control_results: list[ControlResult]
    downgrade: DowngradeResult
    # COMMERCIAL-QUALITY-2026-08-18: the 20-dimension, weighted commercial-
    # readiness scorecard (Intelligence Validation Framework, PR #90) --
    # already built, already tested against 5 real canary exports, and
    # already calibrated (ValidationThresholds' per-dimension overrides).
    # Computed unconditionally from the same bundle/control_results this
    # function already builds, at zero extra evidence cost. Exposed here as
    # real, observable data first (report_id, overall_score, coverage,
    # publication_eligible, blocking_reasons) -- NOT yet wired into the hard
    # publication gate. Elevating it to a gate is a separate, deliberate
    # calibration decision (does today's live pipeline actually clear the
    # existing 75-point threshold consistently, the same question PR #90
    # answered empirically for the 5 canaries before setting it) that must
    # be made from live evidence, not assumed here.
    scorecard: IntelligenceScorecard

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.control_results if r.status == "PASS")

    @property
    def total_count(self) -> int:
        return len(self.control_results)


def compose_report(
    article, config, requested_tier: CertificationState = CertificationState.FLASH_READY,
    include_provenance: bool = True,
) -> ComposedReport:
    """``include_provenance=False`` produces a body-content fragment (no
    Provenance and Certification section) for callers -- namely
    ``authority_transformer._composer_enhance()`` -- that append their own
    single canonical provenance section afterward and would otherwise get it
    twice. Standalone/direct callers get the default ``True``, matching
    ``render_evidence_report()``'s own default, so ``ComposedReport.html``
    stays a complete, self-contained artifact unless a caller opts out."""
    context = build_report_context(article)
    graph = build_evidence_graph(article, context, state_file=getattr(config, "state_file", None))
    threat_product = build_threat_product(article, context)
    package = _detection_package(article, context)

    from automation.report_renderer import render_evidence_report
    base = render_evidence_report(article, config, include_provenance=include_provenance)

    role_decisions = _lean_role_decisions(article, context, threat_product)
    # An empty-but-titled section (heading with nothing under it) reads as
    # broken, not honest -- omit the section entirely when this record's
    # family has no grounded role guidance at all, matching
    # executive_products.render_role_decisions()'s own "if not decisions:
    # return ''" convention for the same situation.
    role_html = "" if not role_decisions else _section(
        "Role-Based Decisions",
        _bullets([f"<strong>{role_display_label(d.role)}:</strong> {_esc(d.decision)} "
                  f"<span style=\"color:#64748b\">&mdash; {_esc(d.rationale)}</span>" for d in role_decisions],
                 "#00d4ff"),
        "#00d4ff",
    )

    source = next(iter(graph.sources.values()))
    # COMMERCIAL-QUALITY-2026-08-18: real, independent 2-axis Admiralty
    # grading -- Source Reliability (the publisher) separate from
    # Information Credibility (this record's own corroboration standing,
    # already computed by EvidenceGraph.recompute_corroboration(), read
    # here rather than re-derived) -- instead of one blended "A/B —
    # Reliable" line, and an honest corroboration statement that reflects
    # the actually-computed state rather than always asserting "not been
    # assessed" regardless of it.
    corroboration_state = worst_corroboration_state(
        c.corroboration_state for c in graph.claims.values() if source.source_id in c.source_refs
    )
    reliability_lines = "<br>".join(
        _esc(line) for line in two_axis_reliability(source.reliability, corroboration_state).split("\n")
    )
    corroboration_note = {
        CorroborationState.MULTI_SOURCE_INDEPENDENT:
            "This record is corroborated by independent sources (see the evidence ledger).",
        CorroborationState.MULTI_SOURCE_DEPENDENT:
            "Multiple outlets report this, but they trace to a shared, non-independent origin (see the "
            "evidence ledger) -- treated as a single-source claim, not independent confirmation.",
        CorroborationState.SINGLE_SOURCE:
            "Reported by a single identified source; an independent second source has not been found "
            "(see the evidence ledger).",
        CorroborationState.UNCORROBORATED:
            "Whether an independent second source corroborates this record has not been assessed (see the "
            "evidence ledger). This report does not wait on that assessment to publish, and does not "
            "overstate certainty in the meantime.",
    }[corroboration_state]
    reliability_html = _section(
        "Source Reliability & Corroboration",
        _panel(
            f'<p style="margin:0 0 8px"><strong>{_esc(source.publisher)}</strong></p>'
            f'<p style="margin:0 0 8px;font-family:monospace;font-size:12px;line-height:1.7">{reliability_lines}</p>'
            f'<p style="margin:0;color:#94a3b8">{corroboration_note}</p>',
        ),
        "#64748b",
    )

    html = base.html + role_html + reliability_html

    intelligence_gaps = [
        IntelligenceGap(
            description="Whether an independent second source corroborates this record has not been assessed.",
            category="KNOWN_UNKNOWN",
            what_would_confirm_or_refute="A second, independent source reporting the same underlying fact.",
        ),
    ]

    material_claims = [c for c in graph.claims.values() if c.has_evidence()]
    bundle = ReportBundle(
        report_id=context.report_id, graph=graph, rendered_text=html,
        detection_rules=_detection_rules(context.report_id, package),
        threat_products=[threat_product] if threat_product else [],
        intelligence_gaps=intelligence_gaps,
        review=None, is_premium_tier=(requested_tier in (
            CertificationState.PREMIUM_READY_PENDING_HUMAN, CertificationState.PREMIUM_CERTIFIED,
            CertificationState.PREMIUM_AUTOMATED_CERTIFIED,
        )),
        depth_assessment=DepthAssessment(
            rendered_word_count=len(html.split()), material_claim_count=len(material_claims),
            distinct_evidence_backed_sections=html.count("data-section="),
        ),
    )
    control_results = evaluate_commercial_readiness(bundle)
    downgrade = determine_achieved_tier(control_results, requested_tier=requested_tier)
    scorecard = evaluate_intelligence_validation(bundle, control_results)

    return ComposedReport(
        report_id=context.report_id, context=context, html=html, bundle=bundle,
        control_results=control_results, downgrade=downgrade, scorecard=scorecard,
    )
