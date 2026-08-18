"""Human premium certification governance (ReportX Sections 26, 44).

``PREMIUM_READY_PENDING_HUMAN`` requires only that the automated gates
pass. ``PREMIUM_CERTIFIED`` additionally requires a real review record
bound to the *exact* artifact hash — the moment the artifact's content
changes (a new SHA-256), any prior approval is automatically invalidated,
never carried forward by assumption.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


class ReviewDecision(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REQUEST_CHANGES = "REQUEST_CHANGES"


def compute_artifact_hash(artifact_text: str) -> str:
    return hashlib.sha256(artifact_text.encode("utf-8")).hexdigest()


def compute_gate_snapshot_hash(control_results_json: str) -> str:
    """Hashes the exact serialized 23-control gate output a reviewer saw
    at approval time -- a second, independent binding alongside
    artifact_sha256. The artifact hash alone proves the reviewer approved
    THIS TEXT; the gate-snapshot hash additionally proves they approved
    it against THIS gate result, not a different run that happened to
    produce a different pass/fail mix against the same text (e.g. a
    metrics-freshness check evaluated against a different `as_of` date)."""
    return hashlib.sha256(control_results_json.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ReviewRecord:
    report_id: str
    artifact_sha256: str
    reviewer_identity: str
    review_timestamp: str  # ISO-8601
    decision: ReviewDecision
    review_version: int
    notes: str = ""
    is_test_only_fixture: bool = False  # Section 26: tests may use an explicit TEST-ONLY reviewer fixture
    reviewer_role: str = ""
    gate_snapshot_sha256: str = ""  # optional second binding -- see compute_gate_snapshot_hash()

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id, "artifact_sha256": self.artifact_sha256,
            "reviewer_identity": self.reviewer_identity, "reviewer_role": self.reviewer_role,
            "review_timestamp": self.review_timestamp,
            "decision": self.decision.value, "review_version": self.review_version,
            "notes": self.notes, "is_test_only_fixture": self.is_test_only_fixture,
            "gate_snapshot_sha256": self.gate_snapshot_sha256,
        }


def is_review_valid_for_artifact(review: ReviewRecord, current_artifact_text: str) -> bool:
    """The binding check: a review approves ONE exact byte sequence. Any
    edit -- even whitespace -- produces a different SHA-256 and silently
    invalidates the old approval, exactly as Section 44 requires ('A
    changed report invalidates the previous approval')."""
    if review.decision != ReviewDecision.APPROVE:
        return False
    return review.artifact_sha256 == compute_artifact_hash(current_artifact_text)


class CertificationState(str, Enum):
    PUBLIC_REFERENCE_DRAFT = "PUBLIC_REFERENCE_DRAFT"
    FLASH_READY = "FLASH_READY"
    TACTICAL_READY = "TACTICAL_READY"
    PREMIUM_READY_PENDING_HUMAN = "PREMIUM_READY_PENDING_HUMAN"
    PREMIUM_CERTIFIED = "PREMIUM_CERTIFIED"


def resolve_certification_state(
    automated_gates_passed: bool,
    is_premium_tier: bool,
    review: ReviewRecord | None,
    current_artifact_text: str,
) -> CertificationState:
    """No manual override path exists in this function's signature --
    PREMIUM_CERTIFIED is reachable only through a real, artifact-bound
    ReviewRecord with decision == APPROVE. A production caller must never
    pass an ``is_test_only_fixture=True`` review here (that flag exists so
    test suites can exercise this function without needing a full human
    workflow, and its own presence is why tests must not be mistaken for
    production certification -- see test_human_review.py)."""

    if not automated_gates_passed:
        return CertificationState.PUBLIC_REFERENCE_DRAFT

    if not is_premium_tier:
        return CertificationState.TACTICAL_READY

    if review is not None and is_review_valid_for_artifact(review, current_artifact_text):
        return CertificationState.PREMIUM_CERTIFIED

    return CertificationState.PREMIUM_READY_PENDING_HUMAN
