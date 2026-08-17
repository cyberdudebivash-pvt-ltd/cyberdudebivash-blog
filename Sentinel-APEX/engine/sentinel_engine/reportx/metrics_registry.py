"""External-metric registry + freshness gate (ReportX Section 13).

Removes unmanaged hard-coded statistics from report prose. Every rendered
quantitative claim must resolve to a ``metric_id`` in this registry; stale
metrics are caught by a freshness gate rather than silently reused forever.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime


@dataclass(frozen=True)
class ExternalMetric:
    metric_id: str
    name: str
    value: float
    unit: str
    scope: str
    source: str
    source_url: str
    publication_year: int
    retrieved_at: str  # ISO-8601
    valid_until: str | None = None  # ISO date; None means "no stated expiry, review_after governs staleness"
    review_after: str | None = None  # ISO date -- a softer "recheck this" marker distinct from a hard expiry
    sample_scope: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "metric_id": self.metric_id, "name": self.name, "value": self.value,
            "unit": self.unit, "scope": self.scope, "source": self.source,
            "source_url": self.source_url, "publication_year": self.publication_year,
            "retrieved_at": self.retrieved_at, "valid_until": self.valid_until,
            "review_after": self.review_after, "sample_scope": self.sample_scope,
            "notes": self.notes,
        }


class MetricsRegistry:
    def __init__(self):
        self._metrics: dict[str, ExternalMetric] = {}

    def register(self, metric: ExternalMetric) -> ExternalMetric:
        self._metrics[metric.metric_id] = metric
        return metric

    def get(self, metric_id: str) -> ExternalMetric | None:
        return self._metrics.get(metric_id)

    def __contains__(self, metric_id: str) -> bool:
        return metric_id in self._metrics

    def is_expired(self, metric_id: str, as_of: date | None = None) -> bool:
        """True only when ``valid_until`` is set and has passed. A metric
        with no stated expiry is never auto-flagged expired -- that would
        require guessing a shelf life the source never stated (the same
        anti-fabrication principle as temporal precision, Section 4)."""
        metric = self._metrics.get(metric_id)
        if metric is None or not metric.valid_until:
            return False
        as_of = as_of or date.today()
        return date.fromisoformat(metric.valid_until) < as_of

    def needs_review(self, metric_id: str, as_of: date | None = None) -> bool:
        metric = self._metrics.get(metric_id)
        if metric is None or not metric.review_after:
            return False
        as_of = as_of or date.today()
        return date.fromisoformat(metric.review_after) < as_of


@dataclass
class StatisticsGateResult:
    uncited_quantitative_claims: list[str] = field(default_factory=list)
    expired_statistics: list[str] = field(default_factory=list)
    metrics_needing_review: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        # metrics_needing_review is a soft warning bucket, not a hard gate
        # (Section 13: "refresh, be explicitly historical, or be withheld"
        # -- a metric approaching review isn't yet a failure by itself).
        return not (self.uncited_quantitative_claims or self.expired_statistics)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "uncited_quantitative_claims": self.uncited_quantitative_claims,
            "expired_statistics": self.expired_statistics,
            "metrics_needing_review": self.metrics_needing_review,
        }


def evaluate_statistics_gate(
    registry: MetricsRegistry,
    cited_metric_ids: list[str],
    rendered_metric_ids: list[str],
    as_of: date | None = None,
) -> StatisticsGateResult:
    """``cited_metric_ids``: every metric_id a Claim in the report actually
    references. ``rendered_metric_ids``: every metric_id that appears
    somewhere in the rendered quantitative-claim prose. Anything in the
    second list absent from the registry, or present but with no
    corresponding cited claim, is an uncited quantitative claim."""

    result = StatisticsGateResult()
    for metric_id in rendered_metric_ids:
        if metric_id not in registry or metric_id not in cited_metric_ids:
            result.uncited_quantitative_claims.append(metric_id)
    for metric_id in cited_metric_ids:
        if registry.is_expired(metric_id, as_of=as_of):
            result.expired_statistics.append(metric_id)
        elif registry.needs_review(metric_id, as_of=as_of):
            result.metrics_needing_review.append(metric_id)
    return result
