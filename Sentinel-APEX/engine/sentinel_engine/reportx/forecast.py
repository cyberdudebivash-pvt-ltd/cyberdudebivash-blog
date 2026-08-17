"""Estimative/predictive intelligence model (ReportX Section 16).

A forecast is either fully structured, or withheld — there is no partial
credit for a confidence label with nothing behind it. Withholding an
unsupported forecast is itself the PASS condition (Section 16's explicit
statement), so this module's gate rewards absence over fabrication.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Forecast:
    judgment: str
    time_horizon: str
    supporting_observation_claim_ids: tuple[str, ...]
    historical_baseline_claim_ids: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    counter_evidence_claim_ids: tuple[str, ...] = ()
    alternative_scenarios: tuple[str, ...] = ()
    indicators_to_watch: tuple[str, ...] = ()
    confidence: str = ""
    confidence_rationale: str = ""
    what_would_change_assessment: tuple[str, ...] = ()

    def is_adequately_supported(self) -> bool:
        """A forecast needs at least one real supporting observation and a
        stated confidence rationale -- a confidence label with zero
        observations behind it is exactly the "assigned HIGH CONFIDENCE
        solely because a template says HIGH" defect Section 16 names."""
        return bool(self.supporting_observation_claim_ids) and bool(self.confidence_rationale)

    def to_dict(self) -> dict:
        return {
            "judgment": self.judgment, "time_horizon": self.time_horizon,
            "supporting_observation_claim_ids": list(self.supporting_observation_claim_ids),
            "historical_baseline_claim_ids": list(self.historical_baseline_claim_ids),
            "assumptions": list(self.assumptions),
            "counter_evidence_claim_ids": list(self.counter_evidence_claim_ids),
            "alternative_scenarios": list(self.alternative_scenarios),
            "indicators_to_watch": list(self.indicators_to_watch),
            "confidence": self.confidence, "confidence_rationale": self.confidence_rationale,
            "what_would_change_assessment": list(self.what_would_change_assessment),
        }


@dataclass
class WithheldForecast:
    """The explicit, honest alternative to a Forecast -- Section 16: 'If
    evidence does not support useful forecasting: WITHHOLD FORECAST.
    Withholding an unsupported forecast is a PASS.' Governed withholding
    means EXPLAINED withholding: ``reason`` is required at construction,
    not just declared as a bare "withheld" flag with nothing behind it."""

    topic: str
    reason: str

    def __post_init__(self):
        if not self.reason:
            raise ValueError(
                f"WithheldForecast for {self.topic!r} has no reason -- governed "
                "withholding requires an explicit rationale, not a bare withheld flag."
            )

    def to_dict(self) -> dict:
        return {"topic": self.topic, "withheld": True, "reason": self.reason}


@dataclass
class ForecastGateResult:
    unsupported_forecasts: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.unsupported_forecasts

    def to_dict(self) -> dict:
        return {"passed": self.passed, "unsupported_forecasts": self.unsupported_forecasts}


def evaluate_forecast_gate(items: list[Forecast | WithheldForecast]) -> ForecastGateResult:
    unsupported = [
        f.judgment for f in items
        if isinstance(f, Forecast) and not f.is_adequately_supported()
    ]
    return ForecastGateResult(unsupported_forecasts=unsupported)
