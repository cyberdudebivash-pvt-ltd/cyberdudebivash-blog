"""Product tier engine (Section 27) + anti-padding / template-repetition
control (Sections 24, 28).

Reuses ``quality.py``'s existing shingle/Jaccard near-duplicate detector
(the same mechanism ``gate_corpus`` already uses for cross-report Sigma/
IOC duplication) rather than re-implementing similarity scoring — applied
here generically to arbitrary named sections so it works across ReportX's
premium-dossier shape without requiring the specific ``ParsedReport``
structure ``gate_corpus`` itself expects.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..quality import _shingles, jaccard  # deliberate reuse, not a re-implementation

# Sections legitimately allowed to be near-identical across reports --
# Section 24's explicit allowlist. Everything else sharing this much text
# across two different incidents/actors is a padding/templating signal.
SHARED_CONTENT_ALLOWED_CLASSIFICATIONS = frozenset({
    "STANDARD_DEFENSIVE_GUIDANCE",
    "METHODOLOGY",
    "LEGAL_DISCLAIMER",
    "PRODUCT_INFORMATION",
})

# Sections where identical text across two DIFFERENT incidents is a real
# defect (Section 24's explicit list) -- shared content here must be
# classified as one of the allowed categories above to legitimately repeat.
INCIDENT_SPECIFIC_SECTIONS = frozenset({
    "Actor Analysis", "Campaign Analysis", "Victimology", "Forecast",
    "Technical Analysis", "Business Impact",
})

NEAR_DUPLICATE_THRESHOLD = 0.80  # matches quality.py's own MITRE/IOC/hunting warn threshold


@dataclass(frozen=True)
class ReportSection:
    report_id: str
    section_name: str
    text: str
    classification: str = ""  # one of SHARED_CONTENT_ALLOWED_CLASSIFICATIONS, or "" for incident-specific


@dataclass(frozen=True)
class TemplateRepetitionFinding:
    report_id_a: str
    report_id_b: str
    section_name: str
    similarity: float

    def to_dict(self) -> dict:
        return {
            "report_id_a": self.report_id_a, "report_id_b": self.report_id_b,
            "section_name": self.section_name, "similarity": round(self.similarity, 3),
        }


def find_template_repetition(sections: list[ReportSection]) -> list[TemplateRepetitionFinding]:
    """Compares every pair of same-named sections across DIFFERENT reports.
    A section explicitly classified into an allowed shared-content category
    is skipped -- boilerplate is supposed to repeat. An unclassified
    section name outside ``INCIDENT_SPECIFIC_SECTIONS`` is also skipped
    (only the named incident-specific sections are held to this check;
    everything else is out of this function's declared scope, not silently
    passed by omission)."""

    findings: list[TemplateRepetitionFinding] = []
    by_section: dict[str, list[ReportSection]] = {}
    for s in sections:
        if s.classification in SHARED_CONTENT_ALLOWED_CLASSIFICATIONS:
            continue
        if s.section_name not in INCIDENT_SPECIFIC_SECTIONS:
            continue
        by_section.setdefault(s.section_name, []).append(s)

    for section_name, group in by_section.items():
        for i, a in enumerate(group):
            for b in group[i + 1:]:
                if a.report_id == b.report_id:
                    continue
                sim = jaccard(_shingles(a.text), _shingles(b.text))
                if sim >= NEAR_DUPLICATE_THRESHOLD:
                    findings.append(TemplateRepetitionFinding(
                        report_id_a=a.report_id, report_id_b=b.report_id,
                        section_name=section_name, similarity=sim,
                    ))
    return findings


@dataclass
class DepthAssessment:
    rendered_word_count: int
    material_claim_count: int  # claims actually backed by evidence (not just present)
    distinct_evidence_backed_sections: int
    template_repetition_findings: list[TemplateRepetitionFinding] = field(default_factory=list)

    @property
    def has_padding_signal(self) -> bool:
        return bool(self.template_repetition_findings)

    def passes_premium_depth(self, min_sections: int = 8, min_claims: int = 15) -> bool:
        """Section 28: page count alone is never sufficient. Requires zero
        cross-report template repetition AND a real floor of distinct
        evidence-backed sections and material claims -- a report can be
        exactly the right word count and still fail this if that length
        came from padding rather than analysis."""
        if self.has_padding_signal:
            return False
        return (
            self.distinct_evidence_backed_sections >= min_sections
            and self.material_claim_count >= min_claims
        )

    def to_dict(self) -> dict:
        return {
            "rendered_word_count": self.rendered_word_count,
            "material_claim_count": self.material_claim_count,
            "distinct_evidence_backed_sections": self.distinct_evidence_backed_sections,
            "template_repetition_findings": [f.to_dict() for f in self.template_repetition_findings],
            "has_padding_signal": self.has_padding_signal,
        }
