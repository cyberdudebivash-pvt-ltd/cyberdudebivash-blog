"""Risk-based human QA sampling (P0 Release-Certification layer, Section 10).

Sampling exists to MONITOR system quality and detect drift in report
correctness over time — it never fakes human certification for the
unsampled majority, and it never grants any report a certification state it
did not otherwise earn. Structural guarantee: this module imports neither
``human_review`` nor ``automated_certification`` — there is no code path
here through which recording a sample, or an :class:`SampleOutcome`'s
``defect_found``, could alter a report's ``CertificationState``. Sample
outcomes are release-health telemetry (``release_health.py`` consumes them);
they are not certification inputs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class SamplingConfig:
    sample_percentage: float = 0.05
    minimum_samples_per_family: int = 1
    minimum_samples_per_release_interval: int = 10
    high_risk_weight: float = 3.0
    new_actor_weight: float = 5.0
    new_vulnerability_weight: float = 5.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.sample_percentage <= 1.0:
            raise ValueError(f"sample_percentage must be within [0, 1], got {self.sample_percentage!r}")

    def to_dict(self) -> dict:
        return {
            "sample_percentage": self.sample_percentage,
            "minimum_samples_per_family": self.minimum_samples_per_family,
            "minimum_samples_per_release_interval": self.minimum_samples_per_release_interval,
            "high_risk_weight": self.high_risk_weight,
            "new_actor_weight": self.new_actor_weight,
            "new_vulnerability_weight": self.new_vulnerability_weight,
        }


@dataclass(frozen=True)
class RiskFactors:
    is_high_risk: bool = False
    is_new_actor: bool = False
    is_new_vulnerability: bool = False


def _deterministic_unit_interval(key: str) -> float:
    """A reproducible pseudo-random draw in ``[0, 1)`` derived from the
    report's own id — so "was this report sampled" is independently
    re-derivable by anyone re-running the same config against the same
    ``report_id``, rather than depending on an unrecorded RNG seed."""
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) / 0x1_0000_0000


def sampling_weight(config: SamplingConfig, risk: RiskFactors) -> float:
    weight = config.sample_percentage
    if risk.is_high_risk:
        weight *= config.high_risk_weight
    if risk.is_new_actor:
        weight *= config.new_actor_weight
    if risk.is_new_vulnerability:
        weight *= config.new_vulnerability_weight
    return min(weight, 1.0)


def should_sample(report_id: str, config: SamplingConfig, risk: RiskFactors | None = None) -> bool:
    risk = risk if risk is not None else RiskFactors()
    return _deterministic_unit_interval(report_id) < sampling_weight(config, risk)


@dataclass(frozen=True)
class SampleOutcome:
    report_id: str
    sampled_at: str
    reviewer: str
    defect_found: bool
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id, "sampled_at": self.sampled_at, "reviewer": self.reviewer,
            "defect_found": self.defect_found, "notes": self.notes,
        }


def sample_defect_rate(outcomes: list[SampleOutcome]) -> float:
    if not outcomes:
        return 0.0
    return sum(1 for o in outcomes if o.defect_found) / len(outcomes)
