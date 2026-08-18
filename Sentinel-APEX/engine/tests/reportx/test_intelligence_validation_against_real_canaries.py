"""Validates the Intelligence Validation Framework against every real,
human-reviewed premium canary this repository has --
``reportx-canary/exports/*-export.json``, the exact artifacts
``release_certification.REQUIRED_CANARY_IDS`` names (plus the flagship
executive-product reference implementation). These are gold-standard,
already-commercial-ready reports per the existing 23-control matrix; this
suite is the "representative live dataset" validation pass the Phase 3
mandate requires, and its assertions are calibrated from a real run against
this exact corpus (see docs/reportx/REPORTX-INTELLIGENCE-VALIDATION-
FRAMEWORK.md's "Validation results" section for the full scorecards and the
narrative behind each threshold below), not guessed.

Deliberately NOT asserting ``publication_eligible is True`` for every
canary: two of the five (dragonforce-vermont-xcenter,
medusalocker-bija-industrie) have a genuine, reproduced MITRE ATT&CK
Justification defect this framework correctly catches -- a real,
previously-invisible false-negative in ``attack_mapper.py``'s
HTML-clause-boundary negation heuristic (an unrelated, later disclaimer
sentence gets pulled into the same "clause" as an earlier technique
citation because minified HTML has no blank-line/sentence-punctuation
boundary between the two `<div>`s). That bug lives in a shared,
``sentinel_engine``-wide module (not touched by this change; see the doc's
"Named gaps" section for why fixing it is out of this PR's scope) --
asserting it away here would hide a real finding, not validate one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from sentinel_engine.reportx.intelligence_validation import ValidationDimension, evaluate_from_export

CANARY_DIR = Path(__file__).resolve().parents[3].parent / "reportx-canary" / "exports"
CANARY_EXPORTS = sorted(CANARY_DIR.glob("*-export.json"))

# The two canaries with the known, real, reproduced attack_mapper.py
# false-negative (see module docstring). Named explicitly so a future fix
# to attack_mapper.py's negation heuristic is a visible, intentional test
# update here, not a silent behavior change nobody notices.
_KNOWN_MITRE_JUSTIFICATION_FAILURES = frozenset({
    "dragonforce-vermont-xcenter-premium-canary-export",
    "medusalocker-bija-industrie-premium-canary-export",
})


@pytest.fixture(scope="module", params=CANARY_EXPORTS, ids=lambda p: p.stem)
def canary_scorecard(request):
    export = json.loads(request.param.read_text(encoding="utf-8"))
    return request.param.stem, evaluate_from_export(export)


def test_at_least_the_four_required_release_canaries_plus_the_flagship_are_present():
    names = {p.stem for p in CANARY_EXPORTS}
    assert {
        "qilin-spoonful-of-comfort-premium-canary-export",
        "medusalocker-bija-industrie-premium-canary-export",
        "dragonforce-vermont-xcenter-premium-canary-export",
        "cve-2025-62593-ray-canary-export",
    } <= names


class TestEveryRealCanary:
    def test_scorecard_computes_without_crashing(self, canary_scorecard):
        _, card = canary_scorecard
        assert len(card.dimension_scores) == 20

    def test_coverage_is_high_for_a_real_premium_dossier(self, canary_scorecard):
        # 17/20: everything except the three purely-supplemental dimensions
        # (Executive Decision Support, Threat Hunting Guidance, Duplicate
        # Detection) that need SupplementalEvidence no export artifact
        # carries -- these are correctly BLOCKED, not a coverage defect.
        _, card = canary_scorecard
        assert card.coverage >= 0.80

    def test_overall_score_is_strong_for_gold_standard_content(self, canary_scorecard):
        _, card = canary_scorecard
        assert card.overall_score >= 85

    def test_evidence_and_correctness_dimensions_clear_pass(self, canary_scorecard):
        # These dimensions must be unambiguously clean for content this
        # repository already treats as commercial-ready and human-reviewed.
        _, card = canary_scorecard
        for dimension in (
            ValidationDimension.EVIDENCE_TRACEABILITY, ValidationDimension.CONSISTENCY,
            ValidationDimension.UNSUPPORTED_CLAIMS, ValidationDimension.TECHNICAL_ACCURACY,
            ValidationDimension.EDITORIAL_QUALITY,
        ):
            d = card.dimension(dimension)
            assert d.status == "PASS", f"{dimension.value}: {d.status} -- {d.rationale}"

    def test_purely_supplemental_dimensions_are_honestly_blocked_not_fabricated(self, canary_scorecard):
        _, card = canary_scorecard
        for dimension in (
            ValidationDimension.EXECUTIVE_DECISION_SUPPORT, ValidationDimension.THREAT_HUNTING_GUIDANCE,
            ValidationDimension.DUPLICATE_DETECTION,
        ):
            d = card.dimension(dimension)
            assert d.status == "BLOCKED"
            assert d.score is None

    def test_publication_eligibility_matches_the_known_mitre_finding(self, canary_scorecard):
        name, card = canary_scorecard
        mitre = card.dimension(ValidationDimension.MITRE_ATTACK_JUSTIFICATION)
        if name in _KNOWN_MITRE_JUSTIFICATION_FAILURES:
            assert mitre.status == "FAIL"
            assert card.publication_eligible is False
            assert any(r.startswith("MITRE ATT&CK Justification:") for r in card.blocking_reasons)
        else:
            assert mitre.status in ("PASS", "BLOCKED")
            assert card.publication_eligible is True
            assert card.blocking_reasons == ()
