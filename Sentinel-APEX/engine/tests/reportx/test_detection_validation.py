from sentinel_engine.reportx.detection_validation import (
    DetectionRule,
    DetectionValidationState,
    check_all_rules,
    check_state_promotion,
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
