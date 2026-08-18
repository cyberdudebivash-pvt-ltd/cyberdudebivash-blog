"""Intelligence Validation Framework — Commercial CTI Platform Phase 3,
Deliverable 1.

Produces one objective, numeric scorecard per report across the 20
measurable dimensions the Phase 3 mandate names (Evidence Traceability,
Source Reliability, Information Credibility, Confidence Discipline,
Analytical Reasoning, Business Context, Technical Accuracy, Operational
Guidance, Executive Decision Support, Detection Engineering, Threat
Hunting Guidance, MITRE ATT&CK Justification, Forecast Quality, Writing
Quality, Consistency, Editorial Quality, Duplicate Detection, Unsupported
Claims, Analytical Completeness, Production Readiness), plus a
mandatory-threshold publication-eligibility verdict.

This is deliberately NOT a second evidence engine. Per Single Source of
Truth and Reuse Before Build, every dimension is computed from artifacts
``commercial_readiness.py``, ``qa_linter.py``, ``analytic_scaffolding.py``,
``tier_downgrade.py``, and ``attack_mapper.py`` already produce — several
dimensions reuse ``qms.py``'s own ``QMS_CONTROL_MAP`` control-id groupings
directly rather than re-typing them. Where the Phase 3 dimension list asks
for something no existing gate measures at all (Information Credibility as
an axis independent of Source Reliability; MITRE ATT&CK technique
justification; Threat Hunting / Executive Decision Support / Business
Context grounded in role- and sector-specific guidance; cross-report
Duplicate Detection), this module adds real, narrowly-scoped computation —
never a fabricated or hand-set score. A dimension with no real signal to
compute from is reported ``BLOCKED`` (score ``None``), exactly like a
``BLOCKED`` row in ``commercial_readiness.py``'s 23-control matrix — never
silently defaulted to a passing number.

What this module deliberately does not do (see
``docs/reportx/REPORTX-INTELLIGENCE-VALIDATION-FRAMEWORK.md`` for the full
account): it does not modify ``ReportBundle`` — every additional input a
few dimensions need (role decisions, sector impact, hunt hypotheses,
cross-report similarity) arrives through the optional, purely-additive
``SupplementalEvidence`` wrapper defined here, so ``commercial_readiness.py``
(a release-certification ``TRACKED_COMPONENT_PATH``) is untouched. It is
also not wired into ``pipeline_composer.py`` or the live syndication
pipeline in this pass — it ships computed, tested, documented, and
reachable via the ``reportx-validate`` CLI command and
``evaluate_from_export()``, the same "design + one reference path, wire
into production as a separate follow-up" sequencing this package's own
history (``REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md``) already used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from ..attack_mapper import extract_technique_ids, is_valid_technique_id, map_techniques
from .analytic_scaffolding import build_bibliography
from .claim_model import CorroborationState, EpistemicState, Reliability
from .claim_support_matrix import STATUSES_REQUIRING_EVIDENCE
from .commercial_readiness import ControlResult, ReportBundle
from .detection_validation import DetectionValidationState
from .executive_products import HuntHypothesis, RoleAudience, RoleDecision, SectorApplicability, SectorImpact
from .forecast import Forecast
from .product_depth import TemplateRepetitionFinding
from .qa_linter import QAFinding, lint_text
from .qms import QMS_CONTROL_MAP, QMSCategory
from .tier_downgrade import PREMIUM_COMPLETENESS_CONTROLS


class ValidationDimension(str, Enum):
    """Verbatim from the Phase 3 mandate's "Every report must be scored
    across measurable dimensions including:" list — not renamed, reordered,
    or paraphrased, so the mapping stays checkable against the source
    requirement (mirrors ``qms.QMSCategory``'s own fidelity discipline)."""

    EVIDENCE_TRACEABILITY = "Evidence Traceability"
    SOURCE_RELIABILITY = "Source Reliability"
    INFORMATION_CREDIBILITY = "Information Credibility"
    CONFIDENCE_DISCIPLINE = "Confidence Discipline"
    ANALYTICAL_REASONING = "Analytical Reasoning"
    BUSINESS_CONTEXT = "Business Context"
    TECHNICAL_ACCURACY = "Technical Accuracy"
    OPERATIONAL_GUIDANCE = "Operational Guidance"
    EXECUTIVE_DECISION_SUPPORT = "Executive Decision Support"
    DETECTION_ENGINEERING = "Detection Engineering"
    THREAT_HUNTING_GUIDANCE = "Threat Hunting Guidance"
    MITRE_ATTACK_JUSTIFICATION = "MITRE ATT&CK Justification"
    FORECAST_QUALITY = "Forecast Quality"
    WRITING_QUALITY = "Writing Quality"
    CONSISTENCY = "Consistency"
    EDITORIAL_QUALITY = "Editorial Quality"
    DUPLICATE_DETECTION = "Duplicate Detection"
    UNSUPPORTED_CLAIMS = "Unsupported Claims"
    ANALYTICAL_COMPLETENESS = "Analytical Completeness"
    PRODUCTION_READINESS = "Production Readiness"


# Composite-score weighting. Explicit and summing to 1.0 (test-enforced),
# matching sentinel_engine.scoring.WEIGHTS's own convention. Biased toward
# Section 0's Level-1 correctness signals (Evidence Traceability, Unsupported
# Claims, Consistency, Technical Accuracy, Confidence Discipline) over
# dimensions that are legitimately BLOCKED for routine, high-volume FLASH-tier
# content (Threat Hunting Guidance, Business Context, Executive Decision
# Support) -- see ``_clamp_weighted_average`` for how BLOCKED dimensions are
# excluded and the remaining weights renormalized, not just zero-filled.
WEIGHTS: dict[ValidationDimension, float] = {
    ValidationDimension.EVIDENCE_TRACEABILITY: 0.09,
    ValidationDimension.SOURCE_RELIABILITY: 0.05,
    ValidationDimension.INFORMATION_CREDIBILITY: 0.06,
    ValidationDimension.CONFIDENCE_DISCIPLINE: 0.07,
    ValidationDimension.ANALYTICAL_REASONING: 0.04,
    ValidationDimension.BUSINESS_CONTEXT: 0.03,
    ValidationDimension.TECHNICAL_ACCURACY: 0.07,
    ValidationDimension.OPERATIONAL_GUIDANCE: 0.04,
    ValidationDimension.EXECUTIVE_DECISION_SUPPORT: 0.03,
    ValidationDimension.DETECTION_ENGINEERING: 0.06,
    ValidationDimension.THREAT_HUNTING_GUIDANCE: 0.03,
    ValidationDimension.MITRE_ATTACK_JUSTIFICATION: 0.05,
    ValidationDimension.FORECAST_QUALITY: 0.04,
    ValidationDimension.WRITING_QUALITY: 0.03,
    ValidationDimension.CONSISTENCY: 0.08,
    ValidationDimension.EDITORIAL_QUALITY: 0.05,
    ValidationDimension.DUPLICATE_DETECTION: 0.04,
    ValidationDimension.UNSUPPORTED_CLAIMS: 0.08,
    ValidationDimension.ANALYTICAL_COMPLETENESS: 0.03,
    ValidationDimension.PRODUCTION_READINESS: 0.03,
}

DEFAULT_PER_DIMENSION_MINIMUM = 70
DEFAULT_OVERALL_MINIMUM = 75
DEFAULT_MINIMUM_COVERAGE = 0.5  # at least 10/20 dimensions must be scoreable, not BLOCKED

# Two dimension-specific defaults, lower than the blanket 70, set from real
# calibration evidence rather than guessed: running this framework against
# every real, human-reviewed flagship premium canary this repository has
# (reportx-canary/exports/*-export.json -- the exact reports
# release_certification.REQUIRED_CANARY_IDS names) showed BOTH dimensions
# landing consistently below 70 on content this repository already treats
# as commercial-ready, for reasons that are real and structural, not
# defects to threshold away:
#   - Information Credibility: Section 10's own single-source-stays-REPORTED
#     discipline means a genuinely honest, single-incident CTI report's
#     claims are typically REPORTED+SINGLE_SOURCE, which this axis
#     correctly grades around "3 -- possibly true" (~50-55) -- that IS the
#     honest ceiling for well-sourced but single-incident reporting, not a
#     credibility defect. 70 would fail every one of them on day one.
#   - Forecast Quality: the base adequacy control (real support + a written
#     confidence rationale) is the actual correctness floor and is already
#     enforced via forecast_methodology; the 6-field richness bonus this
#     dimension adds on top (historical baseline, counter-evidence,
#     alternative scenarios, ...) is a genuine but ASPIRATIONAL depth
#     signal current flagship forecasts do not yet populate (0% richness
#     across all 5 real canaries checked) -- 55 lets an adequately-supported
#     forecast clear the gate while still rewarding richer ones with a
#     higher score.
# See docs/reportx/REPORTX-INTELLIGENCE-VALIDATION-FRAMEWORK.md's
# "Validation results" section for the full run.
_DEFAULT_MINIMUM_OVERRIDES: dict[ValidationDimension, int] = {
    ValidationDimension.INFORMATION_CREDIBILITY: 50,
    ValidationDimension.FORECAST_QUALITY: 55,
}


def _default_per_dimension_minimums() -> dict[ValidationDimension, int]:
    minimums = dict.fromkeys(ValidationDimension, DEFAULT_PER_DIMENSION_MINIMUM)
    minimums.update(_DEFAULT_MINIMUM_OVERRIDES)
    return minimums


@dataclass(frozen=True)
class ValidationThresholds:
    """Mandatory publication gate. Sane, documented defaults — every field
    overridable per product tier/customer, mirroring
    ``release_health.DegradationThresholds``'s own configurable-dataclass
    shape. ``per_dimension_minimum`` only binds a dimension once it is
    actually scored (not ``BLOCKED``); ``minimum_coverage`` is what stops a
    report with almost nothing scoreable from certifying itself on the
    strength of the few dimensions it happened to clear."""

    overall_minimum: int = DEFAULT_OVERALL_MINIMUM
    minimum_coverage: float = DEFAULT_MINIMUM_COVERAGE
    per_dimension_minimum: dict[ValidationDimension, int] = field(default_factory=_default_per_dimension_minimums)

    def minimum_for(self, dimension: ValidationDimension) -> int:
        return self.per_dimension_minimum.get(dimension, DEFAULT_PER_DIMENSION_MINIMUM)


@dataclass(frozen=True)
class SupplementalEvidence:
    """Optional, purely-additive evidence for dimensions
    ``commercial_readiness.ReportBundle`` does not itself carry (role
    decisions, sector impact, hunt hypotheses, cross-report similarity).
    Every field defaults to empty/``None`` — a dimension that depends on one
    reports ``BLOCKED``, never a fabricated score, when the caller has
    nothing to supply. Deliberately a separate wrapper rather than new
    ``ReportBundle`` fields: keeps ``commercial_readiness.py`` (a
    release-certification ``TRACKED_COMPONENT_PATH``) untouched. See the
    module docstring."""

    role_decisions: tuple[RoleDecision, ...] = ()
    sector_impacts: tuple[SectorImpact, ...] = ()
    hunt_hypotheses: tuple[HuntHypothesis, ...] = ()
    # None = cross-report similarity was never checked (honestly unknown,
    # not assumed clean). () = checked against a corpus and found nothing.
    # Non-empty = checked and found real repetition. Mirrors
    # automated_certification.derive_cross_report_similarity_escalation()'s
    # own input shape (product_depth.TemplateRepetitionFinding).
    cross_report_similarity_findings: tuple[TemplateRepetitionFinding, ...] | None = None


@dataclass(frozen=True)
class DimensionScore:
    dimension: ValidationDimension
    score: int | None  # 0-100; None only when BLOCKED — never a fabricated number
    status: str  # "PASS" | "FAIL" | "BLOCKED"
    rationale: str
    contributing_control_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "dimension": self.dimension.value, "score": self.score, "status": self.status,
            "rationale": self.rationale, "contributing_control_ids": list(self.contributing_control_ids),
        }


@dataclass(frozen=True)
class IntelligenceScorecard:
    report_id: str
    dimension_scores: tuple[DimensionScore, ...]
    overall_score: int
    coverage: float  # fraction of the 20 dimensions actually scored (not BLOCKED)
    publication_eligible: bool
    blocking_reasons: tuple[str, ...]
    evaluated_at: str

    def dimension(self, dimension: ValidationDimension) -> DimensionScore:
        return next(d for d in self.dimension_scores if d.dimension == dimension)

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "dimension_scores": [d.to_dict() for d in self.dimension_scores],
            "overall_score": self.overall_score,
            "coverage": round(self.coverage, 3),
            "publication_eligible": self.publication_eligible,
            "blocking_reasons": list(self.blocking_reasons),
            "evaluated_at": self.evaluated_at,
        }


def _clamp(v: float) -> int:
    return int(max(0, min(100, round(v))))


# ============================================================
# Internal contract every per-dimension scorer returns before threshold
# comparison is applied uniformly in evaluate_intelligence_validation().
# hard_fail=True means a REAL correctness defect was found (e.g. an
# underlying commercial_readiness control FAILED) -- this always forces
# FAIL regardless of the numeric score, so a partial-credit average can
# never launder a known defect into an apparent PASS. Continuous-signal
# scorers (no underlying binary control) always set hard_fail=False; their
# only gate is the configured per-dimension score threshold.
# ============================================================

@dataclass(frozen=True)
class _RawScore:
    score: int | None
    hard_fail: bool
    rationale: str
    control_ids: tuple[str, ...] = ()


def _binary(control_ids: tuple[str, ...], by_id: dict[str, ControlResult]) -> _RawScore:
    """Shared scorer for every dimension whose real signal is entirely a
    group of already-computed ``commercial_readiness.py`` controls --
    several dimensions reuse ``qms.QMS_CONTROL_MAP``'s own tuples for this
    directly, rather than re-typing which control_ids belong together."""
    attempted = [by_id[cid] for cid in control_ids if cid in by_id and by_id[cid].status in ("PASS", "FAIL")]
    if not attempted:
        return _RawScore(None, False, f"No evidence yet for: {', '.join(control_ids)} "
                                       "(not present, or not attempted, in this bundle).", control_ids)
    n_pass = sum(1 for r in attempted if r.status == "PASS")
    failing = [r.name for r in attempted if r.status == "FAIL"]
    rationale = f"{n_pass}/{len(attempted)} contributing control(s) PASS"
    if failing:
        rationale += f" — failing: {', '.join(failing)}"
    return _RawScore(_clamp(100 * n_pass / len(attempted)), bool(failing), rationale + ".", control_ids)


# ============================================================
# Continuous-signal dimensions — real computation beyond a bare control
# regroup, each reusing an existing module's public API.
# ============================================================

_RELIABILITY_POINTS: dict[Reliability, int] = {
    Reliability.HIGH: 100, Reliability.MODERATE: 65, Reliability.LOW: 30, Reliability.UNKNOWN: 10,
}


def _score_source_reliability(bundle: ReportBundle) -> _RawScore:
    """Averages ``claim_model.Reliability`` (the existing Source Reliability
    /Admiralty-A-F-equivalent field, see ``executive_products.admiralty_label``)
    over sources actually CITED by a claim (``analytic_scaffolding.build_bibliography``)
    -- an unused source in the graph has no bearing on what this report
    actually relies on."""
    bibliography = build_bibliography(bundle.graph)
    cited = [bundle.graph.sources[e.source_id] for e in bibliography if e.source_id in bundle.graph.sources]
    if not cited:
        return _RawScore(None, False, "No sources are cited by any claim in this bundle yet.", ())
    points = [_RELIABILITY_POINTS[s.reliability] for s in cited]
    dist: dict[str, int] = {}
    for s in cited:
        dist[s.reliability.value] = dist.get(s.reliability.value, 0) + 1
    return _RawScore(_clamp(sum(points) / len(points)), False,
                      f"{len(cited)} cited source(s); reliability mix {dist}.", ())


# Information Credibility is the Admiralty system's SECOND, independent axis
# (1-6, "how believable is this specific information") -- deliberately kept
# separate from Source Reliability (A-F, "how reliable is the channel in
# general") rather than collapsing the two, per
# REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md's own named gap ("extending
# SourceRecord with a second, independent credibility axis is a real,
# additive follow-up"). Computed here as a DERIVED view over claim_model's
# existing EpistemicState + CorroborationState fields -- never a new
# hand-set field, so it can never drift from what the claim ledger actually
# records, and a claim with an authoritative single source (e.g. NVD
# assigning its own CVE ID) can legitimately score high on Source
# Reliability while scoring more modestly here, because corroboration
# genuinely is a distinct axis from source authority under Admiralty
# doctrine -- that divergence is the point of having two numbers, not a bug
# in either one.
_CREDIBILITY_BASE_POINTS: dict[EpistemicState, int] = {
    EpistemicState.CONFIRMED: 60, EpistemicState.CORROBORATED: 50,
    EpistemicState.REPORTED: 30, EpistemicState.ASSESSED: 20, EpistemicState.DISPUTED: 10,
}
_CREDIBILITY_CORROBORATION_BONUS: dict[CorroborationState, int] = {
    CorroborationState.MULTI_SOURCE_INDEPENDENT: 35, CorroborationState.MULTI_SOURCE_DEPENDENT: 15,
    CorroborationState.SINGLE_SOURCE: 10, CorroborationState.UNCORROBORATED: 0,
}


def _admiralty_credibility_grade(score: int) -> str:
    if score >= 90:
        return "1 (independently confirmed)"
    if score >= 70:
        return "2 (probably true)"
    if score >= 50:
        return "3 (possibly true)"
    if score >= 30:
        return "4 (not independently confirmed)"
    if score >= 15:
        return "5 (single-source, low corroboration)"
    return "6 (cannot be judged)"


def _score_information_credibility(bundle: ReportBundle) -> _RawScore:
    material = [c for c in bundle.graph.claims.values() if c.status in STATUSES_REQUIRING_EVIDENCE]
    if not material:
        return _RawScore(None, False, "No assertive-state claims in this bundle yet.", ())
    scores = [
        _clamp(_CREDIBILITY_BASE_POINTS[c.status] + _CREDIBILITY_CORROBORATION_BONUS[c.corroboration_state])
        for c in material
    ]
    avg = _clamp(sum(scores) / len(scores))
    return _RawScore(avg, False,
                      f"{len(material)} assertive-state claim(s); average Admiralty-adjacent grade "
                      f"{_admiralty_credibility_grade(avg)}.", ())


def _score_mitre_attack_justification(bundle: ReportBundle) -> _RawScore:
    """Every technique_id a detection rule cites must be format/registry
    valid (``attack_mapper.is_valid_technique_id``) AND have real textual
    evidence in the rendered report (``attack_mapper.map_techniques``,
    which is itself negation-aware) -- an asserted-but-unevidenced
    technique ID is exactly the un-traceable ATT&CK claim this dimension
    exists to catch. ``DetectionRule.technique_id`` is not always a bare
    ``Txxxx`` string in real, live-composed bundles -- ``report_renderer.py``
    deliberately stores a full conditional-analytical-aid label there (e.g.
    "Execution → Command and Scripting Interpreter (T1059), conditional on
    observed child-process execution."), by design never asserted as fact.
    ``extract_technique_ids`` (reused, not re-implemented) pulls the real ID
    out of either shape, so this check works against both a bare-ID fixture
    and the live composer's richer label."""
    cited = sorted({tid for r in bundle.detection_rules for tid in extract_technique_ids(r.technique_id)})
    if not cited:
        return _RawScore(None, False, "No ATT&CK technique IDs cited by any detection rule in this bundle.", ())
    evidenced = {m.technique_id for m in map_techniques(bundle.rendered_text)} if bundle.rendered_text else set()
    justified = [tid for tid in cited if is_valid_technique_id(tid) and tid in evidenced]
    unjustified = [tid for tid in cited if tid not in justified]
    score = _clamp(100 * len(justified) / len(cited))
    rationale = f"{len(justified)}/{len(cited)} cited technique(s) are valid and evidenced in the rendered text."
    if unjustified:
        rationale += f" Unjustified: {', '.join(unjustified)}."
    return _RawScore(score, False, rationale, ())


_HUNT_REQUIRED_FIELDS = (
    "required_telemetry", "pivot_opportunities", "expected_observations",
    "negative_indicators", "false_positive_considerations", "validation_steps", "success_criteria",
)


def _score_threat_hunting_guidance(supplemental: SupplementalEvidence) -> _RawScore:
    hypotheses = supplemental.hunt_hypotheses
    if not hypotheses:
        return _RawScore(None, False, "No hunt hypotheses supplied for this report "
                                       "(expected for routine/FLASH-tier volume content).", ())
    complete = [
        h for h in hypotheses
        if all(getattr(h, f) for f in _HUNT_REQUIRED_FIELDS)
    ]
    score = _clamp(100 * len(complete) / len(hypotheses))
    return _RawScore(score, False,
                      f"{len(complete)}/{len(hypotheses)} hunt hypothes(es) carry every required field "
                      f"({', '.join(_HUNT_REQUIRED_FIELDS)}).", ())


_EXECUTIVE_ROLES = frozenset({RoleAudience.CEO_BOARD, RoleAudience.CISO_CIO})


def _score_executive_decision_support(supplemental: SupplementalEvidence) -> _RawScore:
    decisions = [d for d in supplemental.role_decisions if d.role in _EXECUTIVE_ROLES]
    if not decisions:
        return _RawScore(None, False, "No CEO/Board- or CISO/CIO-targeted role decisions supplied for this report.", ())
    grounded = [d for d in decisions if d.evidence_claim_ids]
    score = _clamp(100 * len(grounded) / len(decisions))
    return _RawScore(score, False,
                      f"{len(grounded)}/{len(decisions)} executive-facing role decision(s) cite real "
                      "evidence_claim_ids (grounded, not generic).", ())


def _score_business_context(bundle: ReportBundle, by_id: dict[str, ControlResult],
                             supplemental: SupplementalEvidence) -> _RawScore:
    """Blends every real business-facing signal actually supplied: the
    regulatory-applicability gate (a hard correctness signal -- an
    unsupported regulatory determination IS a defect, so it forces
    hard_fail), assessed-sector coverage, and business-continuity/legal
    role guidance. Any signal genuinely absent is excluded, not zero-filled."""
    parts: list[int] = []
    notes: list[str] = []
    hard_fail = False

    reg = by_id.get("regulatory_specificity")
    if reg is not None and reg.status in ("PASS", "FAIL"):
        parts.append(100 if reg.status == "PASS" else 0)
        notes.append(f"regulatory_specificity={reg.status}")
        hard_fail = hard_fail or reg.status == "FAIL"

    if supplemental.sector_impacts:
        assessed = sum(1 for s in supplemental.sector_impacts if s.applicability == SectorApplicability.ASSESSED)
        parts.append(_clamp(100 * assessed / len(supplemental.sector_impacts)))
        notes.append(f"{assessed}/{len(supplemental.sector_impacts)} sectors ASSESSED")

    business_roles = frozenset({RoleAudience.BUSINESS_CONTINUITY_SUPPLY_CHAIN, RoleAudience.LEGAL_COMPLIANCE_PRIVACY,
                                 RoleAudience.CEO_BOARD})
    business_decisions = [d for d in supplemental.role_decisions if d.role in business_roles]
    if business_decisions:
        grounded = sum(1 for d in business_decisions if d.evidence_claim_ids)
        parts.append(_clamp(100 * grounded / len(business_decisions)))
        notes.append(f"{grounded}/{len(business_decisions)} business-facing role decisions grounded")

    if not parts:
        return _RawScore(None, False, "No regulatory determination, sector impact, or business-facing role "
                                       "guidance supplied for this report.", ("regulatory_specificity",))
    return _RawScore(_clamp(sum(parts) / len(parts)), hard_fail, "; ".join(notes) + ".", ("regulatory_specificity",))


def _score_detection_engineering(bundle: ReportBundle, by_id: dict[str, ControlResult]) -> _RawScore:
    base = _binary(("detection_evidence_discipline",), by_id)
    if base.score is None or not bundle.detection_rules:
        return base
    validated = sum(1 for r in bundle.detection_rules if r.validation_state != DetectionValidationState.DRAFT)
    magnitude = _clamp(100 * validated / len(bundle.detection_rules))
    # The base control's PASS/FAIL (governed withholding counts as PASS) is
    # the authoritative gate; magnitude only refines the displayed score,
    # never the status -- reflected here by keeping base.hard_fail as-is.
    blended = _clamp(0.5 * base.score + 0.5 * magnitude)
    return _RawScore(blended, base.hard_fail,
                      base.rationale + f" {validated}/{len(bundle.detection_rules)} rule(s) beyond DRAFT.",
                      base.control_ids)


_FORECAST_RICHNESS_FIELDS = (
    "historical_baseline_claim_ids", "assumptions", "counter_evidence_claim_ids",
    "alternative_scenarios", "indicators_to_watch", "what_would_change_assessment",
)


def _score_forecast_quality(bundle: ReportBundle, by_id: dict[str, ControlResult]) -> _RawScore:
    base = _binary(("forecast_methodology",), by_id)
    if base.score is None:
        return base
    real_forecasts = [f for f in bundle.forecasts if isinstance(f, Forecast)]
    if not real_forecasts:
        # every forecast in this bundle is a governed WithheldForecast --
        # full richness credit, per Section 16: withholding IS the correct,
        # complete answer here, not a thinner version of a real forecast.
        richness = 1.0
    else:
        richness = sum(
            sum(1 for f_ in _FORECAST_RICHNESS_FIELDS if getattr(fc, f_)) / len(_FORECAST_RICHNESS_FIELDS)
            for fc in real_forecasts
        ) / len(real_forecasts)
    if base.hard_fail:
        return _RawScore(base.score, True, base.rationale, base.control_ids)
    score = _clamp(60 + 40 * richness)
    return _RawScore(score, False, base.rationale + f" Estimative richness {richness:.0%} across "
                                                      f"{len(real_forecasts)} structured forecast(s).", base.control_ids)


def _score_writing_quality(qa_findings: list[QAFinding] | None) -> _RawScore:
    """Distinct from Editorial Quality: warn-severity qa_linter findings
    (duplicate headings/paragraphs, dangling colons) are style/flow
    defects, not the block-severity correctness defects Editorial Quality
    (== the ``grammar_synthesis_qa`` control) already gates."""
    if qa_findings is None:
        return _RawScore(None, False, "No rendered text in this bundle.", ())
    warns = [f for f in qa_findings if f.severity == "warn"]
    return _RawScore(_clamp(100 - min(100, len(warns) * 10)), False,
                      f"{len(warns)} style/flow finding(s) (duplicate headings/paragraphs, dangling colons).", ())


def _score_editorial_quality(by_id: dict[str, ControlResult], qa_findings: list[QAFinding] | None) -> _RawScore:
    base = _binary(QMS_CONTROL_MAP[QMSCategory.EDITORIAL_QUALITY], by_id)
    if base.score is None or qa_findings is None:
        return base
    blocks = [f for f in qa_findings if f.severity == "block"]
    magnitude = _clamp(100 - min(100, len(blocks) * 25))
    return _RawScore(magnitude, base.hard_fail, base.rationale + f" {len(blocks)} block-severity finding(s).",
                      base.control_ids)


def _score_duplicate_detection(qa_findings: list[QAFinding] | None, supplemental: SupplementalEvidence) -> _RawScore:
    """Within-report duplication (qa_linter's duplicate_heading/
    duplicate_paragraph) is always checkable once rendered text exists.
    Cross-report template repetition needs a corpus this dimension cannot
    supply itself -- exactly the partial-coverage gap
    ``qms.QMS_CATEGORY_CAVEATS[NO_DUPLICATED_CONTENT]`` already names, so
    this dimension stays honestly BLOCKED (not a fabricated PASS) unless
    the caller actually supplied ``cross_report_similarity_findings``."""
    if qa_findings is None:
        return _RawScore(None, False, "No rendered text in this bundle.", ())
    within = sum(1 for f in qa_findings if f.check in ("duplicate_heading", "duplicate_paragraph"))
    within_score = _clamp(100 - min(100, within * 20))
    cross = supplemental.cross_report_similarity_findings
    if cross is None:
        # Deliberately BLOCKED (score=None), not a partial score: this
        # dimension cannot honestly certify "not duplicated" without a
        # cross-report check, matching every other BLOCKED dimension's
        # score=None convention rather than showing a number that isn't
        # actually gate-authoritative. The within-report count is still
        # surfaced in the rationale text for dashboard visibility.
        return _RawScore(None, False,
                          f"{within} within-report duplication finding(s); cross-report similarity was not "
                          "checked against a corpus (see automated_certification.py's escalation check).", ())
    score = _clamp((within_score + (100 if not cross else 0)) / 2)
    hard_fail = bool(cross)
    rationale = f"{within} within-report duplication finding(s); {len(cross)} cross-report repetition finding(s)."
    return _RawScore(score, hard_fail, rationale, ())


# ============================================================
# Assembly
# ============================================================

def evaluate_intelligence_validation(
    bundle: ReportBundle,
    control_results: list[ControlResult],
    supplemental: SupplementalEvidence | None = None,
    thresholds: ValidationThresholds | None = None,
) -> IntelligenceScorecard:
    """Computes nothing evidence-related itself -- every dimension is a
    pure function of ``control_results`` (already computed once by
    ``commercial_readiness.evaluate_commercial_readiness(bundle)``, per
    Single Source of Truth: this function never recomputes them), the
    bundle's own graph/detection_rules/forecasts, and whatever
    ``SupplementalEvidence`` the caller actually has on hand."""
    supplemental = supplemental or SupplementalEvidence()
    thresholds = thresholds or ValidationThresholds()
    by_id = {r.control_id: r for r in control_results}
    qa_findings = lint_text(bundle.rendered_text) if bundle.rendered_text else None

    raw: dict[ValidationDimension, _RawScore] = {
        ValidationDimension.EVIDENCE_TRACEABILITY: _binary(
            ("source_provenance", "evidence_hash", "evidence_ledger", "report_specific_bibliography"), by_id),
        ValidationDimension.SOURCE_RELIABILITY: _score_source_reliability(bundle),
        ValidationDimension.INFORMATION_CREDIBILITY: _score_information_credibility(bundle),
        ValidationDimension.CONFIDENCE_DISCIPLINE: _binary(QMS_CONTROL_MAP[QMSCategory.CONFIDENCE_DISCIPLINE], by_id),
        ValidationDimension.ANALYTICAL_REASONING: _binary(QMS_CONTROL_MAP[QMSCategory.ANALYTICAL_QUALITY], by_id),
        ValidationDimension.BUSINESS_CONTEXT: _score_business_context(bundle, by_id, supplemental),
        ValidationDimension.TECHNICAL_ACCURACY: _binary(QMS_CONTROL_MAP[QMSCategory.TECHNICAL_ACCURACY], by_id),
        ValidationDimension.OPERATIONAL_GUIDANCE: _binary(QMS_CONTROL_MAP[QMSCategory.OPERATIONAL_UTILITY], by_id),
        ValidationDimension.EXECUTIVE_DECISION_SUPPORT: _score_executive_decision_support(supplemental),
        ValidationDimension.DETECTION_ENGINEERING: _score_detection_engineering(bundle, by_id),
        ValidationDimension.THREAT_HUNTING_GUIDANCE: _score_threat_hunting_guidance(supplemental),
        ValidationDimension.MITRE_ATTACK_JUSTIFICATION: _score_mitre_attack_justification(bundle),
        ValidationDimension.FORECAST_QUALITY: _score_forecast_quality(bundle, by_id),
        ValidationDimension.WRITING_QUALITY: _score_writing_quality(qa_findings),
        ValidationDimension.CONSISTENCY: _binary(QMS_CONTROL_MAP[QMSCategory.CONSISTENCY], by_id),
        ValidationDimension.EDITORIAL_QUALITY: _score_editorial_quality(by_id, qa_findings),
        ValidationDimension.DUPLICATE_DETECTION: _score_duplicate_detection(qa_findings, supplemental),
        ValidationDimension.UNSUPPORTED_CLAIMS: _binary(QMS_CONTROL_MAP[QMSCategory.NO_UNSUPPORTED_CLAIMS], by_id),
        ValidationDimension.ANALYTICAL_COMPLETENESS: _binary(tuple(sorted(PREMIUM_COMPLETENESS_CONTROLS)), by_id),
        ValidationDimension.PRODUCTION_READINESS: _binary(("fortune_500_commercial_deliverable",), by_id),
    }

    dimension_scores: list[DimensionScore] = []
    blocking_reasons: list[str] = []
    for dimension in ValidationDimension:
        r = raw[dimension]
        if r.score is None:
            status = "BLOCKED"
        elif r.hard_fail or r.score < thresholds.minimum_for(dimension):
            status = "FAIL"
        else:
            status = "PASS"
        dimension_scores.append(DimensionScore(dimension, r.score, status, r.rationale, r.control_ids))
        if status == "FAIL":
            blocking_reasons.append(f"{dimension.value}: {r.rationale}")

    scored = [(d, s) for d, s in zip(ValidationDimension, dimension_scores) if s.score is not None]
    coverage = len(scored) / len(ValidationDimension)
    if scored:
        weight_sum = sum(WEIGHTS[d] for d, _ in scored)
        overall = _clamp(sum(WEIGHTS[d] * s.score for d, s in scored) / weight_sum) if weight_sum else 0
    else:
        overall = 0

    if coverage < thresholds.minimum_coverage:
        blocking_reasons.append(
            f"only {len(scored)}/{len(ValidationDimension)} dimensions were scoreable "
            f"({coverage:.0%} coverage, below the {thresholds.minimum_coverage:.0%} minimum)."
        )
    if overall < thresholds.overall_minimum:
        blocking_reasons.append(f"overall score {overall} is below the mandatory minimum {thresholds.overall_minimum}.")

    publication_eligible = not blocking_reasons

    return IntelligenceScorecard(
        report_id=bundle.report_id,
        dimension_scores=tuple(dimension_scores),
        overall_score=overall,
        coverage=coverage,
        publication_eligible=publication_eligible,
        blocking_reasons=tuple(blocking_reasons),
        evaluated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def evaluate_from_export(export: dict, supplemental: SupplementalEvidence | None = None,
                          thresholds: ValidationThresholds | None = None) -> IntelligenceScorecard:
    """Convenience entry point taking the SAME artifact shape
    ``bundle_io.export_report_json()``/``reportx-gate --export`` already
    produce -- no new serialization format. Recomputes
    ``evaluate_commercial_readiness`` fresh from the loaded bundle rather
    than deserializing the exported ``ControlResult`` rows, since the gate
    is a pure, deterministic function of the bundle and recomputing is
    simpler and no less correct than writing a second JSON->ControlResult
    reader nothing else in this package needs."""
    from .bundle_io import bundle_from_dict
    from .commercial_readiness import evaluate_commercial_readiness

    bundle = bundle_from_dict(export["bundle"])
    control_results = evaluate_commercial_readiness(bundle)
    return evaluate_intelligence_validation(bundle, control_results, supplemental=supplemental, thresholds=thresholds)


def render_scorecard_markdown(scorecard: IntelligenceScorecard) -> str:
    lines = [f"INTELLIGENCE VALIDATION SCORECARD — {scorecard.report_id}", ""]
    for d in scorecard.dimension_scores:
        score_display = "—" if d.score is None else str(d.score)
        lines.append(f"{d.dimension.value}: {d.status} ({score_display}/100)")
        lines.append(f"  {d.rationale}")
    lines += [
        "",
        f"Overall score: {scorecard.overall_score}/100",
        f"Coverage: {scorecard.coverage:.0%} of {len(ValidationDimension)} dimensions scored",
    ]
    if scorecard.publication_eligible:
        lines.append("VERDICT: PUBLICATION ELIGIBLE — all mandatory thresholds clear.")
    else:
        lines += ["VERDICT: NOT PUBLICATION ELIGIBLE", "Blocking reasons:"]
        lines += [f"  - {r}" for r in scorecard.blocking_reasons]
    return "\n".join(lines)
