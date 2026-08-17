from datetime import date

from sentinel_engine.reportx.metrics_registry import (
    ExternalMetric,
    MetricsRegistry,
    evaluate_statistics_gate,
)


def _metric(metric_id="m1", **kw):
    defaults = dict(
        name="Average ransomware recovery cost", value=2_730_000.0, unit="USD",
        scope="global, all sectors", source="Sophos State of Ransomware",
        source_url="https://example.com/report", publication_year=2026,
        retrieved_at="2026-08-18T00:00:00Z",
    )
    defaults.update(kw)
    return ExternalMetric(metric_id=metric_id, **defaults)


class TestExpiry:
    def test_no_valid_until_never_auto_expires(self):
        registry = MetricsRegistry()
        registry.register(_metric())
        assert registry.is_expired("m1") is False

    def test_past_valid_until_is_expired(self):
        registry = MetricsRegistry()
        registry.register(_metric(valid_until="2020-01-01"))
        assert registry.is_expired("m1", as_of=date(2026, 8, 18)) is True

    def test_future_valid_until_is_not_expired(self):
        registry = MetricsRegistry()
        registry.register(_metric(valid_until="2030-01-01"))
        assert registry.is_expired("m1", as_of=date(2026, 8, 18)) is False

    def test_review_after_is_separate_from_expiry(self):
        registry = MetricsRegistry()
        registry.register(_metric(review_after="2026-01-01"))
        assert registry.needs_review("m1", as_of=date(2026, 8, 18)) is True
        assert registry.is_expired("m1", as_of=date(2026, 8, 18)) is False


class TestStatisticsGate:
    def test_rendered_metric_not_in_registry_is_uncited(self):
        registry = MetricsRegistry()
        result = evaluate_statistics_gate(registry, cited_metric_ids=[], rendered_metric_ids=["ghost-metric"])
        assert "ghost-metric" in result.uncited_quantitative_claims
        assert not result.passed

    def test_rendered_metric_in_registry_but_not_cited_by_any_claim_is_uncited(self):
        registry = MetricsRegistry()
        registry.register(_metric())
        result = evaluate_statistics_gate(registry, cited_metric_ids=[], rendered_metric_ids=["m1"])
        assert "m1" in result.uncited_quantitative_claims

    def test_rendered_and_cited_metric_passes(self):
        registry = MetricsRegistry()
        registry.register(_metric())
        result = evaluate_statistics_gate(registry, cited_metric_ids=["m1"], rendered_metric_ids=["m1"])
        assert result.uncited_quantitative_claims == []
        assert result.passed

    def test_expired_cited_metric_fails_gate(self):
        registry = MetricsRegistry()
        registry.register(_metric(valid_until="2020-01-01"))
        result = evaluate_statistics_gate(registry, cited_metric_ids=["m1"], rendered_metric_ids=["m1"],
                                            as_of=date(2026, 8, 18))
        assert "m1" in result.expired_statistics
        assert not result.passed

    def test_needs_review_alone_does_not_fail_the_hard_gate(self):
        registry = MetricsRegistry()
        registry.register(_metric(review_after="2026-01-01"))
        result = evaluate_statistics_gate(registry, cited_metric_ids=["m1"], rendered_metric_ids=["m1"],
                                            as_of=date(2026, 8, 18))
        assert "m1" in result.metrics_needing_review
        assert result.passed  # soft warning, not a hard failure
