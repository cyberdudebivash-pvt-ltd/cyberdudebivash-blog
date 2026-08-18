"""Quality Management System orchestrator.

The CyberDudeBivash Intelligence Factory ROLE mandate names 18 QUALITY
MANAGEMENT SYSTEM requirements ("Quality gates must evaluate: Evidence,
Analytical Quality, Tradecraft, ... No fabricated evidence") and requires
"measurable quality gates" that block publication when they fail. This
module does not invent 18 new checks. Per Single Source of Truth and Reuse
Before Build, it re-groups the already-computed, already-tested 23-row
``commercial_readiness.py`` matrix under the mandate's own category names,
so a QMS-shaped report can be produced without a second, competing
judgment about whether a report is correct.

Two of the 18 categories (Executive Readability, Role-based Guidance) have
no dedicated row in the 23-control matrix today and are reported
``NOT_GATED`` rather than a fabricated PASS. Three more (No hallucinations,
No duplicated content, No boilerplate repetition) are only *partially*
covered by a matrix row -- their strongest real enforcement
(``report_integrity.validate_publication()``'s fail-closed publish gate,
and ``automated_certification.derive_cross_report_similarity_escalation()``'s
cross-report repetition check) runs outside this matrix and needs inputs
(the rendered HTML; a corpus of other reports) this module does not carry.
Both gaps are recorded in ``QMS_CATEGORY_CAVEATS`` so the rendered summary
states them plainly instead of the code and the docs drifting apart. See
``docs/reportx/REPORTX-QUALITY-MANAGEMENT-SYSTEM.md`` for the full,
evidence-cited mapping this module implements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .commercial_readiness import ControlResult


class QMSCategory(str, Enum):
    """Verbatim category names from the ROLE mandate's QUALITY MANAGEMENT
    SYSTEM section -- not renamed, reordered, or paraphrased, so the
    mapping stays checkable against the source requirement."""

    EVIDENCE = "Evidence"
    ANALYTICAL_QUALITY = "Analytical Quality"
    TRADECRAFT = "Tradecraft"
    TECHNICAL_ACCURACY = "Technical Accuracy"
    EDITORIAL_QUALITY = "Editorial Quality"
    CONSISTENCY = "Consistency"
    TRACEABILITY = "Traceability"
    CONFIDENCE_DISCIPLINE = "Confidence Discipline"
    DETECTION_QUALITY = "Detection Quality"
    OPERATIONAL_UTILITY = "Operational Utility"
    EXECUTIVE_READABILITY = "Executive Readability"
    ROLE_BASED_GUIDANCE = "Role-based Guidance"
    FORECAST_QUALITY = "Forecast Quality"
    NO_UNSUPPORTED_CLAIMS = "No unsupported claims"
    NO_HALLUCINATIONS = "No hallucinations"
    NO_DUPLICATED_CONTENT = "No duplicated content"
    NO_BOILERPLATE_REPETITION = "No boilerplate repetition"
    NO_FABRICATED_EVIDENCE = "No fabricated evidence"


# category -> the commercial_readiness.py control_ids whose real,
# already-enforced logic is this category's actual gate. Categories absent
# from this dict entirely (see QMS_UNGATED_CATEGORIES) have no matrix row
# at all; that is reported honestly, not backfilled here.
QMS_CONTROL_MAP: dict[QMSCategory, tuple[str, ...]] = {
    QMSCategory.EVIDENCE: (
        "source_provenance", "evidence_hash", "evidence_ledger", "source_specific_facts",
    ),
    QMSCategory.ANALYTICAL_QUALITY: (
        "alternative_hypotheses", "victim_specific_analysis", "actor_specific_analysis",
    ),
    QMSCategory.TRADECRAFT: (
        "cross_source_corroboration", "human_analyst_certification_governance",
    ),
    QMSCategory.TECHNICAL_ACCURACY: (
        "threat_type_schema_correctness", "temporal_integrity", "detection_evidence_discipline",
    ),
    QMSCategory.EDITORIAL_QUALITY: (
        "grammar_synthesis_qa",
    ),
    QMSCategory.CONSISTENCY: (
        "cross_section_consistency",
    ),
    QMSCategory.TRACEABILITY: (
        "report_specific_bibliography", "evidence_ledger", "source_provenance",
    ),
    QMSCategory.CONFIDENCE_DISCIPLINE: (
        "cross_source_corroboration", "human_analyst_certification_governance",
    ),
    QMSCategory.DETECTION_QUALITY: (
        "detection_evidence_discipline",
    ),
    QMSCategory.OPERATIONAL_UTILITY: (
        "technical_recommendations",
    ),
    QMSCategory.FORECAST_QUALITY: (
        "forecast_methodology",
    ),
    QMSCategory.NO_UNSUPPORTED_CLAIMS: (
        "source_specific_facts", "victim_specific_analysis", "evidence_ledger",
        "current_statistics", "regulatory_specificity", "technical_recommendations",
    ),
    QMSCategory.NO_HALLUCINATIONS: (
        "source_specific_facts", "evidence_ledger", "cross_section_consistency",
    ),
    QMSCategory.NO_DUPLICATED_CONTENT: (
        "grammar_synthesis_qa",
    ),
    QMSCategory.NO_BOILERPLATE_REPETITION: (
        "grammar_synthesis_qa",
    ),
    QMSCategory.NO_FABRICATED_EVIDENCE: (
        "evidence_hash", "source_provenance",
    ),
}

# Categories the 23-control matrix does not gate at all today. Real,
# tested-but-not-PASS/FAIL-checked support exists (executive_products.py's
# RoleAudience/RoleDecision/render_role_decisions, and report_renderer.py's
# Executive Summary section) but nothing computes a category verdict from
# it yet -- see REPORTX-QUALITY-MANAGEMENT-SYSTEM.md's gap list.
QMS_UNGATED_CATEGORIES: tuple[QMSCategory, ...] = (
    QMSCategory.EXECUTIVE_READABILITY,
    QMSCategory.ROLE_BASED_GUIDANCE,
)

# category -> a note on real enforcement that exists OUTSIDE this matrix
# and outside this module's inputs, so the summary says so instead of
# implying the mapped control_ids are the category's only real gate.
QMS_CATEGORY_CAVEATS: dict[QMSCategory, str] = {
    QMSCategory.NO_HALLUCINATIONS: (
        "The stronger, unconditional gate for this category is "
        "automation.report_integrity.validate_publication() (placeholder-pattern, "
        "unsupported-commercial-claim, exploitation/KEV-contradiction, and schema-contamination "
        "checks), which runs on every report regardless of content_source and hard-blocks "
        "publication by raising PublicationIntegrityError. It runs on the rendered HTML before "
        "this module is ever invoked, so a report that reaches this summary already cleared it; "
        "this module cannot re-check it because it is not passed the HTML, only ControlResults."
    ),
    QMSCategory.NO_DUPLICATED_CONTENT: (
        "grammar_synthesis_qa only catches duplication WITHIN one report (qa_linter.py's "
        "check_duplicate_paragraphs/check_duplicate_headings). Cross-report template repetition "
        "is checked separately by "
        "automated_certification.derive_cross_report_similarity_escalation(), which needs a "
        "corpus of other reports' sections this module does not carry."
    ),
    QMSCategory.NO_BOILERPLATE_REPETITION: (
        "Same partial coverage as No duplicated content (within-report only via "
        "grammar_synthesis_qa; cross-report via automated_certification.py's escalation check, "
        "not available here). The empirical root cause of prior boilerplate "
        "(97.6% of historical reports rendered via the deterministic legacy template -- see "
        "REPORTX-LEGACY-PIPELINE-AUDIT.md) is addressed architecturally, not just detected: "
        "pipeline_composer.py now supplies evidence-graph-backed content ahead of that template "
        "whenever its own tier ladder clears."
    ),
    QMSCategory.EXECUTIVE_READABILITY: (
        "No automated control exists. Real support: report_renderer.py's Executive Summary "
        "section and executive_products.py's Board/CEO/CISO-oriented RoleDecision entries."
    ),
    QMSCategory.ROLE_BASED_GUIDANCE: (
        "No automated control exists. Real support: executive_products.py's RoleAudience "
        "(11 roles) / RoleDecision / render_role_decisions(), used by "
        "pipeline_composer.py's _lean_role_decisions(). Coverage is enforced only by test "
        "assertions (test_pipeline_composer.py), not by a commercial_readiness.py PASS/FAIL row."
    ),
}


@dataclass(frozen=True)
class QMSCategoryResult:
    category: QMSCategory
    status: str  # "PASS" | "FAIL" | "BLOCKED" | "NOT_GATED"
    contributing_control_ids: tuple[str, ...]
    failures: tuple[str, ...] = field(default_factory=tuple)
    caveat: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category.value, "status": self.status,
            "contributing_control_ids": list(self.contributing_control_ids),
            "failures": list(self.failures), "caveat": self.caveat,
        }


@dataclass(frozen=True)
class QMSReport:
    category_results: list[QMSCategoryResult]

    @property
    def gated_categories_pass(self) -> bool:
        """True only if every category the matrix actually gates PASSed --
        NOT_GATED categories are excluded from this roll-up (they are a
        named gap, not a silent pass) rather than counted as satisfied."""
        return all(r.status == "PASS" for r in self.category_results if r.status != "NOT_GATED")

    @property
    def not_gated_categories(self) -> tuple[QMSCategory, ...]:
        return tuple(r.category for r in self.category_results if r.status == "NOT_GATED")

    def to_dict(self) -> dict:
        return {"category_results": [r.to_dict() for r in self.category_results]}


def evaluate_quality_management_system(control_results: list[ControlResult]) -> QMSReport:
    """Read-only re-grouping of an already-computed
    ``evaluate_commercial_readiness()`` result under the ROLE mandate's 18
    named QMS categories. Computes no new evidence judgment: a category's
    status is a pure function of the status of the control_ids
    ``QMS_CONTROL_MAP`` says belong to it, using the same forgiving-but-
    honest BLOCKED semantics ``tier_downgrade.py`` already established
    (a BLOCKED control -- genuinely absent optional input -- does not sink
    a category the way a FAIL does; a category is BLOCKED only when every
    one of its contributing controls is)."""
    by_id = {r.control_id: r for r in control_results}
    category_results: list[QMSCategoryResult] = []

    for category, control_ids in QMS_CONTROL_MAP.items():
        relevant = [by_id[cid] for cid in control_ids if cid in by_id]
        caveat = QMS_CATEGORY_CAVEATS.get(category, "")
        if not relevant:
            category_results.append(QMSCategoryResult(
                category, "BLOCKED", control_ids,
                ("none of this category's contributing controls are present in this bundle",),
                caveat,
            ))
            continue
        if any(r.status == "FAIL" for r in relevant):
            status = "FAIL"
        elif all(r.status == "BLOCKED" for r in relevant):
            status = "BLOCKED"
        else:
            status = "PASS"
        failures = tuple(f for r in relevant for f in r.failures)
        category_results.append(QMSCategoryResult(
            category, status, tuple(r.control_id for r in relevant), failures, caveat,
        ))

    for category in QMS_UNGATED_CATEGORIES:
        category_results.append(QMSCategoryResult(
            category, "NOT_GATED", (), (), QMS_CATEGORY_CAVEATS.get(category, ""),
        ))

    return QMSReport(category_results)


def render_qms_summary(report: QMSReport) -> str:
    lines = ["QUALITY MANAGEMENT SYSTEM", ""]
    for r in report.category_results:
        lines.append(f"{r.category.value}: {r.status}")
        if r.caveat:
            lines.append(f"  note: {r.caveat}")
    n_pass = sum(1 for r in report.category_results if r.status == "PASS")
    n_gated = sum(1 for r in report.category_results if r.status != "NOT_GATED")
    lines += ["", f"{n_pass} / {n_gated} gated categories PASS "
                  f"({len(report.not_gated_categories)} category(ies) not yet gated by an automated control)"]
    if report.gated_categories_pass:
        lines.append("VERDICT: no gated QMS category is failing.")
    else:
        blockers = [f"{r.category.value}: {r.status}" for r in report.category_results
                    if r.status not in ("PASS", "NOT_GATED")]
        lines += ["VERDICT: QMS categories not clear:"] + [f"  - {b}" for b in blockers]
    return "\n".join(lines)
