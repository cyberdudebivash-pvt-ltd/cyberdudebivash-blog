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

RX-P1I update: this suite used to NOT assert ``publication_eligible is
True`` for two of the five canaries (dragonforce-vermont-xcenter,
medusalocker-bija-industrie), which had a genuine, reproduced MITRE ATT&CK
Justification defect this framework correctly caught. Both are now fixed
and both canaries pass -- but by two narrow, verified DATA/citation fixes,
not by touching ``attack_mapper.py``'s negation heuristic itself (still
unmodified):

- dragonforce cited T1219 (Remote Access Software), a real, genuine MITRE
  technique that simply was not yet in ``attack_mapper.KNOWN_TECHNIQUES``'s
  curated subset. Added (see attack_mapper.py). Verified empirically that
  the citation was already correctly detected as real, non-negated
  evidence before this fix -- ``is_valid_technique_id()`` was the only
  failing half of the check.
- medusalocker's real detection rule cited the bare parent T1053
  (Scheduled Task/Job), but the rendered text's only supporting language
  is "a scheduled task", which ``attack_mapper.py``'s existing lexicon maps
  to the more specific sub-technique T1053.005 -- a granularity mismatch
  between two distinct dict keys, not a missing or negated citation.
  Retargeted the canary's rule to the more precise T1053.005 (see
  reportx-canary/medusalocker_bija_industrie_canary.py), which the rule's
  own CISA/FBI-sourced description supports more accurately anyway.

Neither fix touched ``_is_negated()``/``_clause_span()`` -- if a minified-
HTML clause-boundary negation false-negative is still live somewhere else,
it was not what was blocking either of these two specific citations, which
were verified directly against the real export JSON (see the RX-P1I
certification doc for the verification method and output).
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

# RX-P1I: both formerly-known MITRE-justification failures are now fixed
# (see module docstring) -- empty, not deleted, so a future regression on
# either canary is a visible, intentional test update here, not a silent
# behavior change nobody notices.
_KNOWN_MITRE_JUSTIFICATION_FAILURES = frozenset()


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
