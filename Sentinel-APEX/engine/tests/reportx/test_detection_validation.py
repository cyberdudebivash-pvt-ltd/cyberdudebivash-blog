from sentinel_engine.reportx.detection_validation import (
    DetectionRule,
    DetectionValidationState,
    check_all_rules,
    check_state_promotion,
    check_withheld_rules_have_rationale,
)


class TestNoPromotionBeyondStoredState:
    def test_syntax_validated_rule_described_as_production_validated_is_flagged(self):
        rule = DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                              validation_state=DetectionValidationState.SYNTAX_VALIDATED)
        text = "This experimental detection is a production-validated detection ready for SOC deployment."
        violations = check_state_promotion(rule, text)
        assert any(v.claimed_state == "PRODUCTION_VALIDATED" for v in violations)

    def test_production_validated_rule_described_as_production_validated_is_fine(self):
        rule = DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                              validation_state=DetectionValidationState.PRODUCTION_VALIDATED)
        text = "This is a production-validated detection ready for SOC deployment."
        assert check_state_promotion(rule, text) == []

    def test_describing_a_lower_state_than_stored_is_fine(self):
        # A PRODUCTION_VALIDATED rule can still be accurately described as
        # having passed lab validation earlier in its lifecycle -- that's
        # true, just not the headline claim.
        rule = DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                              validation_state=DetectionValidationState.PRODUCTION_VALIDATED)
        text = "This rule was lab-validated before promotion to production."
        assert check_state_promotion(rule, text) == []

    def test_withheld_rule_never_gets_any_positive_promotion_language(self):
        rule = DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                              validation_state=DetectionValidationState.WITHHELD_INSUFFICIENT_EVIDENCE)
        text = "DETECTION STATUS: WITHHELD_INSUFFICIENT_EVIDENCE. Push actor detection rules covering T1486 immediately."
        violations = check_state_promotion(rule, text)
        assert len(violations) >= 1
        assert any("ready-to-deploy" in v.claimed_state or v.matched_phrase for v in violations)

    def test_withheld_rule_with_no_promotion_language_passes(self):
        rule = DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                              validation_state=DetectionValidationState.WITHHELD_INSUFFICIENT_EVIDENCE)
        text = "DETECTION STATUS: WITHHELD_INSUFFICIENT_EVIDENCE. Insufficient evidence to construct a reliable rule at this time."
        assert check_state_promotion(rule, text) == []

    def test_check_all_rules_aggregates_across_multiple_rules(self):
        rules = [
            DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                          validation_state=DetectionValidationState.DRAFT),
            DetectionRule(rule_id="r2", technique_id="T1490", format="sigma",
                          validation_state=DetectionValidationState.PRODUCTION_VALIDATED),
        ]
        text = "r1 is a production-validated detection. r2 is a production-validated detection."
        violations = check_all_rules(rules, text)
        assert any(v.rule_id == "r1" for v in violations)
        assert not any(v.rule_id == "r2" for v in violations)


class TestWithheldRuleRationaleRequirement:
    """Governed withholding is a PASS path, but only when the withholding
    itself is explained -- an empty-rationale WITHHELD rule is
    indistinguishable from one nobody finished filling in."""

    def test_withheld_rule_without_rationale_is_flagged(self):
        rule = DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                              validation_state=DetectionValidationState.WITHHELD_INSUFFICIENT_EVIDENCE)
        assert check_withheld_rules_have_rationale([rule]) == ["r1"]

    def test_withheld_rule_with_rationale_is_not_flagged(self):
        rule = DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                              validation_state=DetectionValidationState.WITHHELD_INSUFFICIENT_EVIDENCE,
                              evidence_gap_rationale="No incident-specific telemetry located.")
        assert check_withheld_rules_have_rationale([rule]) == []

    def test_non_withheld_rules_are_never_flagged_regardless_of_rationale(self):
        rule = DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                              validation_state=DetectionValidationState.DRAFT)
        assert check_withheld_rules_have_rationale([rule]) == []
