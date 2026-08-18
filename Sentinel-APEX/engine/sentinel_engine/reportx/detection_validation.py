"""Detection validation governance (ReportX Section 12).

One canonical validation-state enum. The hard rule: downstream prose can
describe a rule's stored state, but can never *promote* it — a rule stored
as ``SYNTAX_VALIDATED`` may not be described anywhere as "production
validated," no matter how confident the surrounding marketing copy sounds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class DetectionValidationState(str, Enum):
    DRAFT = "DRAFT"
    SYNTAX_VALIDATED = "SYNTAX_VALIDATED"
    LAB_VALIDATED = "LAB_VALIDATED"
    TELEMETRY_VALIDATED = "TELEMETRY_VALIDATED"
    PRODUCTION_CANDIDATE = "PRODUCTION_CANDIDATE"
    PRODUCTION_VALIDATED = "PRODUCTION_VALIDATED"
    WITHHELD_INSUFFICIENT_EVIDENCE = "WITHHELD_INSUFFICIENT_EVIDENCE"


# Ordinal rank for "is B a promotion beyond A" comparisons. WITHHELD is not
# on this ladder at all -- it isn't "less validated than DRAFT", it's a
# terminal non-publish state, so it's compared separately (a WITHHELD rule
# promoted to ANY of the others is always a defect).
_RANK = {
    DetectionValidationState.DRAFT: 0,
    DetectionValidationState.SYNTAX_VALIDATED: 1,
    DetectionValidationState.LAB_VALIDATED: 2,
    DetectionValidationState.TELEMETRY_VALIDATED: 3,
    DetectionValidationState.PRODUCTION_CANDIDATE: 4,
    DetectionValidationState.PRODUCTION_VALIDATED: 5,
}


@dataclass
class DetectionRule:
    rule_id: str
    technique_id: str
    format: str  # "sigma" | "kql" | "splunk" | "osquery" | "suricata" | "yara"
    validation_state: DetectionValidationState = DetectionValidationState.DRAFT
    body: str = ""
    # Required whenever validation_state is WITHHELD_INSUFFICIENT_EVIDENCE --
    # the explicit, recorded reason detection was withheld (e.g. "no
    # incident-specific telemetry located; withheld pending confirmed
    # exploitation evidence"). Governed withholding is a valid commercial-
    # readiness PASS path (Section 12/withholding governance), but only
    # when the withholding itself is explained, not just declared.
    evidence_gap_rationale: str = ""


# Phrases that assert a specific validation state in rendered prose,
# keyed to the state they claim. If a phrase matching a HIGHER-ranked (or
# WITHHELD-violating) state than the rule's own stored state appears
# anywhere in text describing that rule, that is a promotion defect.
_PROMOTION_PHRASES: dict[DetectionValidationState, tuple[re.Pattern, ...]] = {
    DetectionValidationState.PRODUCTION_VALIDATED: (
        re.compile(r"production[- ]validated", re.IGNORECASE),
        re.compile(r"validated (?:for|in) production", re.IGNORECASE),
        re.compile(r"ready for (?:immediate )?(?:soc |production )?deployment", re.IGNORECASE),
    ),
    DetectionValidationState.PRODUCTION_CANDIDATE: (
        re.compile(r"production candidate", re.IGNORECASE),
    ),
    DetectionValidationState.TELEMETRY_VALIDATED: (
        re.compile(r"telemetry[- ]validated", re.IGNORECASE),
        re.compile(r"validated against (?:live |production )?telemetry", re.IGNORECASE),
    ),
    DetectionValidationState.LAB_VALIDATED: (
        re.compile(r"lab[- ]validated", re.IGNORECASE),
    ),
}

_PUSH_NOW_LANGUAGE = re.compile(
    r"push\s+(?:this\s+|the\s+|actor\s+)?detection rules?\s+(?:covering\s+\S+\s+)?immediately",
    re.IGNORECASE,
)


@dataclass
class ValidationStateViolation:
    rule_id: str
    stored_state: str
    claimed_state: str
    matched_phrase: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "stored_state": self.stored_state,
            "claimed_state": self.claimed_state,
            "matched_phrase": self.matched_phrase,
        }


def check_state_promotion(rule: DetectionRule, rendered_text: str) -> list[ValidationStateViolation]:
    """Section 12's gate, made concrete: scan text that describes ``rule``
    for language claiming a validation state ranked higher than the rule's
    actually stored state (or claiming any positive state at all for a
    ``WITHHELD`` rule)."""

    violations: list[ValidationStateViolation] = []

    if rule.validation_state == DetectionValidationState.WITHHELD_INSUFFICIENT_EVIDENCE:
        for claimed_state, patterns in _PROMOTION_PHRASES.items():
            for pattern in patterns:
                m = pattern.search(rendered_text)
                if m:
                    violations.append(ValidationStateViolation(
                        rule_id=rule.rule_id,
                        stored_state=rule.validation_state.value,
                        claimed_state=claimed_state.value,
                        matched_phrase=m.group(0),
                    ))
        if _PUSH_NOW_LANGUAGE.search(rendered_text):
            m = _PUSH_NOW_LANGUAGE.search(rendered_text)
            violations.append(ValidationStateViolation(
                rule_id=rule.rule_id,
                stored_state=rule.validation_state.value,
                claimed_state="(implied ready-to-deploy)",
                matched_phrase=m.group(0),
            ))
        return violations

    own_rank = _RANK[rule.validation_state]
    for claimed_state, patterns in _PROMOTION_PHRASES.items():
        claimed_rank = _RANK[claimed_state]
        if claimed_rank <= own_rank:
            continue  # describing the rule's own state or a lower one is fine
        for pattern in patterns:
            m = pattern.search(rendered_text)
            if m:
                violations.append(ValidationStateViolation(
                    rule_id=rule.rule_id,
                    stored_state=rule.validation_state.value,
                    claimed_state=claimed_state.value,
                    matched_phrase=m.group(0),
                ))
    return violations


def check_all_rules(rules: list[DetectionRule], rendered_text: str) -> list[ValidationStateViolation]:
    violations: list[ValidationStateViolation] = []
    for rule in rules:
        violations += check_state_promotion(rule, rendered_text)
    return violations


def check_withheld_rules_have_rationale(rules: list[DetectionRule]) -> list[str]:
    """Governed withholding requires the withholding to be explained, not
    just declared -- an empty-rationale WITHHELD rule is indistinguishable
    from one nobody finished filling in. Returns the rule_ids that fail
    this check."""
    return [
        r.rule_id for r in rules
        if r.validation_state == DetectionValidationState.WITHHELD_INSUFFICIENT_EVIDENCE
        and not r.evidence_gap_rationale
    ]
