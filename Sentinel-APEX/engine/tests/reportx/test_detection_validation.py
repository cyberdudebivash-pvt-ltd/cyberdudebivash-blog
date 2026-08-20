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

    def test_not_applicable_rule_never_gets_any_positive_promotion_language(self):
        # RX-P1I: NOT_APPLICABLE is a new off-ladder terminal state (a
        # format mismatch, not an evidentiary shortfall) -- it must get the
        # same "never describable as validated" discipline as WITHHELD.
        rule = DetectionRule(rule_id="r1", technique_id="", format="none",
                              validation_state=DetectionValidationState.NOT_APPLICABLE)
        text = "This intelligence/news record has no detection rule, but is production-validated nonetheless."
        violations = check_state_promotion(rule, text)
        assert any(v.claimed_state == "PRODUCTION_VALIDATED" for v in violations)

    def test_telemetry_specification_rule_never_gets_any_positive_promotion_language(self):
        # RX-P1I: TELEMETRY_SPECIFICATION (a real telemetry plan, but no
        # rule body attempted) is also off-ladder -- same discipline.
        rule = DetectionRule(rule_id="r1", technique_id="", format="none",
                              validation_state=DetectionValidationState.TELEMETRY_SPECIFICATION,
                              evidence_gap_rationale="Availability-impact evidence does not justify a rule.")
        text = "Only telemetry guidance is given here, which is lab-validated and ready for deployment."
        violations = check_state_promotion(rule, text)
        assert any(v.claimed_state == "LAB_VALIDATED" for v in violations)

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

    def test_telemetry_specification_rule_without_rationale_is_also_flagged(self):
        # RX-P1I: "here's the telemetry plan, but no rule was attempted" is
        # exactly as much a withholding decision as WITHHELD itself.
        rule = DetectionRule(rule_id="r1", technique_id="", format="none",
                              validation_state=DetectionValidationState.TELEMETRY_SPECIFICATION)
        assert check_withheld_rules_have_rationale([rule]) == ["r1"]

    def test_not_applicable_rule_is_never_flagged_even_without_rationale(self):
        # RX-P1I: a format mismatch is not a withholding decision -- there
        # is no gap to rationalize, so this must never require one.
        rule = DetectionRule(rule_id="r1", technique_id="", format="none",
                              validation_state=DetectionValidationState.NOT_APPLICABLE)
        assert check_withheld_rules_have_rationale([rule]) == []


class TestCheckAllRulesScopeIsWholeDocumentNotPerRule:
    """KNOWN LIMITATION (documented in check_state_promotion()'s own
    docstring, not fixed here -- a real fix needs rendering-level per-rule
    text anchors, a separate, larger change): the promotion-phrase search
    runs against the FULL rendered_text for every rule, not a substring
    scoped to that specific rule. A phrase legitimately describing rule A
    can therefore be misattributed to rule B if they're both checked
    against the same whole-document text."""

    def test_check_all_rules_scope_is_whole_document_not_per_rule(self):
        # Deliberately demonstrates the limitation exists, so a future
        # reader doesn't have to rediscover it: text describing a REAL
        # PRODUCTION_VALIDATED rule (r-real) also gets attributed as a
        # promotion violation against an unrelated NOT_APPLICABLE rule
        # (r-na) in the same bundle, purely because both share one
        # rendered_text search space.
        rules = [
            DetectionRule(rule_id="r-real", technique_id="T1486", format="sigma",
                          validation_state=DetectionValidationState.PRODUCTION_VALIDATED),
            DetectionRule(rule_id="r-na", technique_id="", format="none",
                          validation_state=DetectionValidationState.NOT_APPLICABLE),
        ]
        text = "r-real is a genuine, production-validated detection rule for T1486."
        violations = check_all_rules(rules, text)
        # The real rule correctly has no violation against its own accurate description...
        assert not any(v.rule_id == "r-real" for v in violations)
        # ...but the unrelated NOT_APPLICABLE rule is ALSO flagged, because
        # the same "production-validated" phrase appears anywhere in the
        # shared search text -- this is the known, accepted limitation.
        assert any(v.rule_id == "r-na" for v in violations)

    def test_the_one_real_call_site_never_produces_mixed_validation_states_in_one_bundle(self):
        # This is WHY the limitation above is safe in production today: the
        # only real caller (pipeline_composer.compose_report() ->
        # _detection_rules()) derives every DetectionRule in a bundle from
        # the SAME single DetectionPackage.status via one shared lookup
        # table, so every rule in a real bundle always shares one
        # validation_state. If this ever stops being true, the limitation
        # above becomes live and check_state_promotion() needs the real,
        # rendering-level fix -- this test is the tripwire.
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
        from automation.content_discovery import DiscoveredArticle
        from automation.config import Config
        from sentinel_engine.reportx.pipeline_composer import compose_report

        article = DiscoveredArticle(
            url="https://nvd.nist.gov/vuln/detail/CVE-2026-88888", title="CVE-2026-88888 test vulnerability",
            summary="A SQL injection flaw in the login form allows authentication bypass.",
            published_at="2026-08-20T00:00:00Z", content_hash="scopeguard1",
            labels=["Vulnerabilities"], source="nvd", cve_id="CVE-2026-88888",
        )
        result = compose_report(article, Config())
        states = {r.validation_state for r in result.bundle.detection_rules}
        assert len(states) <= 1, (
            f"expected every rule in one real bundle to share a single validation_state, got {states} -- "
            "check_state_promotion()'s whole-document scoping is no longer safe, see its docstring"
        )
