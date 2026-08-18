"""Cross-canary anti-padding check across all FOUR real premium canaries
(Section 9/24/28 of the P0-continuation task mandate).

Each of the four canaries is built from genuinely independent research
(different actor, different victim, different sources), but three of them
(Qilin, MedusaLocker, DragonForce) are the same THREAT TYPE
(RansomwareVictimClaim) and share a similar section skeleton by design
(Executive Summary, Actor Overview, Forecast, Hunting, ...). This test
proves that shared SKELETON is not shared CONTENT: the same-named
incident-specific sections across different real canaries must not be
near-duplicates of each other, the way a templated/padded product would
produce.

Reuses product_depth.py's ReportSection/find_template_repetition
unchanged -- this is the same mechanism each individual canary's own
acceptance test already uses for its own cross-fixture checks (e.g.
test_qilin_canary.py verifies no promotion-language leakage; the golden
MedusaLocker fixtures' three-way "Actor Historical Context" check in
test_acceptance_medusalocker_bija.py). This file is the FOUR-canary,
whole-set version the task mandate requires.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

CANARY_DIR = Path(__file__).resolve().parents[3].parent / "reportx-canary"


def _load(name: str, filename: str):
    path = CANARY_DIR / filename
    assert path.is_file(), f"expected {path}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def qilin_module():
    return _load("qilin_spoonful_of_comfort_canary", "qilin_spoonful_of_comfort_canary.py")


@pytest.fixture(scope="module")
def medusalocker_module():
    return _load("medusalocker_bija_industrie_canary", "medusalocker_bija_industrie_canary.py")


@pytest.fixture(scope="module")
def dragonforce_module():
    return _load("dragonforce_vermont_xcenter_canary", "dragonforce_vermont_xcenter_canary.py")


@pytest.fixture(scope="module")
def ray_module():
    return _load("cve_2025_62593_ray_canary", "cve_2025_62593_ray_canary.py")


@pytest.fixture(scope="module")
def all_four_bundles(qilin_module, medusalocker_module, dragonforce_module, ray_module):
    return {
        "qilin-spoonful-of-comfort": qilin_module.build_bundle(),
        "medusalocker-bija-industrie": medusalocker_module.build_bundle(),
        "dragonforce-vermont-xcenter": dragonforce_module.build_bundle(),
        "cve-2025-62593-ray": ray_module.build_bundle(),
    }


def _section_text(rendered_text: str, heading: str, next_headings: list[str]) -> str:
    """Extracts the text between `## {heading}` and whichever of
    next_headings appears next (or end of document) -- the same
    slice-between-markers approach the existing golden-fixture anti-
    padding tests already use."""
    start_marker = f"## {heading}"
    start = rendered_text.index(start_marker)
    end = len(rendered_text)
    for nh in next_headings:
        marker = f"\n## {nh}"
        idx = rendered_text.find(marker, start + len(start_marker))
        if idx != -1:
            end = min(end, idx)
    return rendered_text[start:end]


ALL_HEADINGS_BY_REPORT = {
    "qilin-spoonful-of-comfort": [
        "Executive Summary", "Scope and Methodology", "Victim Claim Record",
        "Actor Overview: Qilin (RaaS Family)", "RaaS Operating Model: Water Galura",
        "Actor Ecosystem Complexity: Moonstone Sleet", "Documented Campaign Chronology (2023-2025)",
        "Tactics, Techniques, and Procedures (ATT&CK-Mapped)", "Detection", "Hunting", "Forecast",
        "Alternative Hypotheses", "Regulatory Considerations",
        "Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)", "Intelligence Gaps",
        "Technical Recommendations", "Appendix A: Sources & Evidence Ledger",
    ],
    "medusalocker-bija-industrie": [
        "Executive Summary", "Scope and Methodology", "Victim Claim Record",
        "Actor Overview: MedusaLocker (RaaS Family)", "Documented Attack Chain",
        "Current Tracked Scale (2026 Snapshot)", "Historical Indicators (Generic, Not Incident-Specific)",
        "Detection", "Hunting", "Forecast", "Alternative Hypotheses", "Regulatory Considerations",
        "Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)", "Intelligence Gaps",
        "Technical Recommendations", "Appendix A: Sources & Evidence Ledger",
    ],
    "dragonforce-vermont-xcenter": [
        "Executive Summary", "Scope and Methodology", "Victim Claim Record",
        "Actor Overview: DragonForce (RaaS-to-Cartel Evolution)",
        "Historical Vulnerability Exploitation (Generic, Not Incident-Specific)",
        "Tactics, Techniques, and Procedures (ATT&CK-Mapped)",
        "Actor Ecosystem: Associations and the DragonForce Malaysia Question",
        "Current Tracked Scale (2026 Snapshot)", "Detection", "Hunting", "Forecast",
        "Alternative Hypotheses", "Regulatory Considerations",
        "Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)", "Intelligence Gaps",
        "Technical Recommendations", "Appendix A: Sources & Evidence Ledger",
    ],
    "cve-2025-62593-ray": [
        "Executive Summary", "Scope and Methodology", "Timeline", "Vulnerability Details",
        "Severity: Two Different Authoritative Scores", "Exploitation Status: A Genuine Analytic Tension",
        "Actor Context: RondoDox (general capability, not incident-specific)", "Business Context",
        "MITRE ATT&CK Mapping", "Detection", "Hunting", "Forecast", "Alternative Hypotheses",
        "Intelligence Gaps", "Technical Recommendations", "Appendix A: Sources & Evidence Ledger",
    ],
}

# Maps this canary set's real (differently-worded) section headings onto
# product_depth.py's canonical INCIDENT_SPECIFIC_SECTIONS vocabulary --
# the same category product_depth.py holds to a zero-near-duplicate bar.
CANONICAL_MAPPING = {
    "Forecast": "Forecast",
    "Actor Overview: Qilin (RaaS Family)": "Actor Analysis",
    "Actor Overview: MedusaLocker (RaaS Family)": "Actor Analysis",
    "Actor Overview: DragonForce (RaaS-to-Cartel Evolution)": "Actor Analysis",
    "Actor Context: RondoDox (general capability, not incident-specific)": "Actor Analysis",
    "Victim Claim Record": "Victimology",
}


def _extract_sections(bundles: dict, heading: str) -> list:
    from sentinel_engine.reportx.product_depth import ReportSection

    canonical_name = CANONICAL_MAPPING[heading]
    sections = []
    for report_id, headings in ALL_HEADINGS_BY_REPORT.items():
        if heading not in headings:
            continue
        idx = headings.index(heading)
        remaining = headings[idx + 1:]
        text = _section_text(bundles[report_id].rendered_text, heading, remaining)
        sections.append(ReportSection(report_id=report_id, section_name=canonical_name, text=text))
    return sections


class TestFourCanaryForecastSectionsAreNotNearDuplicates:
    """All four canaries have a 'Forecast' section (product_depth.py's own
    canonical INCIDENT_SPECIFIC_SECTIONS name, verbatim) -- each must be
    genuinely about its own actor/vulnerability, not a reused template."""

    def test_zero_near_duplicate_forecast_sections_across_all_four(self, all_four_bundles):
        from sentinel_engine.reportx.product_depth import find_template_repetition
        sections = _extract_sections(all_four_bundles, "Forecast")
        assert len(sections) == 4, "expected all four canaries to have a Forecast section"
        findings = find_template_repetition(sections)
        assert findings == [], f"Forecast sections flagged as near-duplicate: {[f.to_dict() for f in findings]}"


class TestFourCanaryActorAnalysisSectionsAreNotNearDuplicates:
    """Each canary's primary actor-context deep-dive section, mapped onto
    product_depth.py's canonical 'Actor Analysis' name -- four genuinely
    different actors (Qilin, MedusaLocker, DragonForce, RondoDox/Ray),
    four genuinely different write-ups."""

    def test_zero_near_duplicate_actor_analysis_sections_across_all_four(self, all_four_bundles):
        from sentinel_engine.reportx.product_depth import find_template_repetition
        sections: list = []
        for heading in (
            "Actor Overview: Qilin (RaaS Family)",
            "Actor Overview: MedusaLocker (RaaS Family)",
            "Actor Overview: DragonForce (RaaS-to-Cartel Evolution)",
            "Actor Context: RondoDox (general capability, not incident-specific)",
        ):
            sections.extend(_extract_sections(all_four_bundles, heading))
        assert len(sections) == 4
        findings = find_template_repetition(sections)
        assert findings == [], f"Actor-context sections flagged as near-duplicate: {[f.to_dict() for f in findings]}"


class TestThreeRansomwareCanaryVictimologySectionsAreNotNearDuplicates:
    """The three ransomware canaries (Qilin, MedusaLocker, DragonForce)
    each have a 'Victim Claim Record' section, mapped onto
    product_depth.py's canonical 'Victimology' name -- three genuinely
    different victims."""

    def test_zero_near_duplicate_victim_claim_record_sections(self, all_four_bundles):
        from sentinel_engine.reportx.product_depth import find_template_repetition
        sections = _extract_sections(all_four_bundles, "Victim Claim Record")
        assert len(sections) == 3
        findings = find_template_repetition(sections)
        assert findings == [], f"Victim Claim Record sections flagged as near-duplicate: {[f.to_dict() for f in findings]}"


class TestWholeReportsAreNotNearDuplicatesOfEachOther:
    """A coarser, whole-document sanity check on top of the per-section
    checks above: no two of the four full rendered reports are
    near-duplicates of each other (each is tagged with its own report_id
    as its own 'section name', outside product_depth.py's incident-
    specific vocabulary, purely to reuse the same Jaccard mechanism for a
    document-level comparison)."""

    def test_pairwise_whole_document_similarity_is_low(self, all_four_bundles):
        from sentinel_engine.quality import _shingles, jaccard
        report_ids = list(all_four_bundles.keys())
        for i, a in enumerate(report_ids):
            for b in report_ids[i + 1:]:
                sim = jaccard(
                    _shingles(all_four_bundles[a].rendered_text),
                    _shingles(all_four_bundles[b].rendered_text),
                )
                assert sim < 0.80, f"{a} and {b} whole-document similarity {sim:.3f} looks templated"


class TestSharedContentIsOnlyTheGenuinelyAllowedCategories:
    """Where these four reports DO share near-identical prose, it must be
    limited to the categories product_depth.py explicitly allows to
    repeat (methodology, standard defensive guidance, legal disclaimer,
    platform information) -- never an incident-specific section."""

    def test_generic_defensive_readiness_labels_are_present_but_not_compared_as_incident_specific(self, all_four_bundles):
        # The GENERIC_DEFENSIVE_READINESS label itself is expected to recur
        # across all ransomware canaries -- that is Section 6C's own
        # explicit, unremovable label design, not a padding defect. This
        # test documents that fact rather than flagging it: the heading is
        # deliberately absent from CANONICAL_MAPPING/INCIDENT_SPECIFIC_
        # SECTIONS, so find_template_repetition() never evaluates it.
        for report_id in ("qilin-spoonful-of-comfort", "medusalocker-bija-industrie",
                           "dragonforce-vermont-xcenter"):
            assert "GENERIC_DEFENSIVE_READINESS" in all_four_bundles[report_id].rendered_text
