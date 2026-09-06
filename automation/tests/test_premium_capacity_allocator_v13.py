from automation import premium_capacity_allocator_v13 as allocator
from automation import publication_scheduler as scheduler
from automation.content_discovery import DiscoveredArticle


def _article(
    index: int,
    *,
    words: int,
    source: str = "global_rss",
    url: str | None = None,
    structured: bool = False,
):
    kwargs = {}
    if structured:
        kwargs.update(
            cve_id=f"CVE-2026-{50000 + index}",
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cwe_ids=["CWE-89"],
            affected_vendor="Example Vendor",
            affected_product="Example Product",
            epss_score=0.75,
            epss_percentile=0.98,
            kev_listed=False,
            kev_date_added="2026-09-01",
            kev_due_date="2026-09-22",
        )
    return DiscoveredArticle(
        url=url or f"https://example.test/report/{index}",
        title=f"Evidence report {index}",
        summary="short source summary",
        published_at=f"2026-09-06T20:{index % 60:02d}:00Z",
        content_hash=f"capacity-{index:04d}",
        labels=["Threat Intelligence"],
        source=source,
        full_content="evidence " * words,
        source_publisher="Example Publisher",
        **kwargs,
    )


def _fake_selection(retry, fresh, max_posts):
    selected = list(fresh) + list(retry)
    selected = selected[:max_posts]
    fresh_ids = {id(a) for a in fresh}
    retry_ids = {id(a) for a in retry}
    families = {}
    sources = {}
    for article in selected:
        family = scheduler.classify_publication_family(article)
        families[family] = families.get(family, 0) + 1
        sources[article.source] = sources.get(article.source, 0) + 1
    return scheduler.PublicationSelection(
        selected,
        {
            "candidate_count": len(fresh) + len(retry),
            "fresh_candidates": len(fresh),
            "retry_candidates": len(retry),
            "fresh_selected": sum(1 for a in selected if id(a) in fresh_ids),
            "retry_selected": sum(1 for a in selected if id(a) in retry_ids),
            "strategic_selected": 0,
            "vulnerability_selected": 0,
            "canonical_selected": sum(1 for a in selected if scheduler.is_canonical_report(a)),
            "selected_families": families,
            "selected_sources": sources,
        },
    )


def test_normal_capacity_delegates_to_existing_scheduler_unchanged(monkeypatch):
    article = _article(1, words=20)
    sentinel = scheduler.PublicationSelection([article], {"candidate_count": 1})
    monkeypatch.setattr(allocator, "_ORIGINAL_SELECT", lambda *_args, **_kwargs: sentinel)
    monkeypatch.setattr(allocator, "_capacity_constrained", lambda: (False, []))

    result = allocator.capacity_aware_select_publication_batch([], [article], 5)

    assert result is sentinel


def test_tpd_saturation_filters_thin_candidates_before_generation(monkeypatch):
    thin = _article(1, words=300)
    rich = _article(2, words=allocator.MIN_RICH_EVIDENCE_WORDS + 25)
    monkeypatch.setattr(allocator, "_ORIGINAL_SELECT", _fake_selection)
    monkeypatch.setattr(
        allocator,
        "_capacity_constrained",
        lambda: (
            True,
            [
                {"provider": "groq", "model": "a", "limit_type": "TPD"},
                {"provider": "groq", "model": "b", "limit_type": "TPD"},
            ],
        ),
    )

    result = allocator.capacity_aware_select_publication_batch([], [thin, rich], 5)

    assert result.articles == [rich]
    assert result.metrics["candidate_count"] == 2
    assert result.metrics["provider_independent_candidates"] == 1
    assert result.metrics["provider_capacity_deferred_candidates"] == 1
    assert result.metrics["provider_capacity_constrained"] is True


def test_dense_structured_source_can_qualify_below_rich_word_threshold(monkeypatch):
    article = _article(
        3,
        words=allocator.MIN_DENSE_STRUCTURED_EVIDENCE_WORDS + 25,
        structured=True,
    )

    assert allocator._structured_evidence_count(article) >= allocator.MIN_DENSE_STRUCTURED_FIELDS
    assert allocator._provider_independent_candidate(article) is True


def test_canonical_url_does_not_bypass_source_richness_requirement():
    # A first-party URL is a provenance advantage, not permission to treat
    # previously generated report prose as raw evidence.  A summary-only
    # canonical handoff must therefore remain below the provider-independent
    # admission threshold.
    article = _article(
        4,
        words=40,
        source="rss",
        url="https://blog.cyberdudebivash.in/posts/example.html",
    )

    assert scheduler.is_canonical_report(article) is True
    assert allocator._provider_independent_candidate(article) is False


def test_capacity_saturation_with_no_rich_candidate_defers_entire_batch(monkeypatch):
    fresh = [_article(i, words=100) for i in range(5)]
    monkeypatch.setattr(allocator, "_ORIGINAL_SELECT", _fake_selection)
    monkeypatch.setattr(
        allocator,
        "_capacity_constrained",
        lambda: (
            True,
            [
                {"provider": "groq", "model": "a", "limit_type": "TPD"},
                {"provider": "groq", "model": "b", "limit_type": "TPD"},
            ],
        ),
    )

    result = allocator.capacity_aware_select_publication_batch([], fresh, 5)

    assert result.articles == []
    assert result.metrics["candidate_count"] == 5
    assert result.metrics["fresh_selected"] == 0
    assert result.metrics["provider_independent_candidates"] == 0
    assert result.metrics["provider_capacity_deferred_candidates"] == 5


def test_zero_selection_due_capacity_is_reported_degraded_not_no_intel(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        allocator,
        "_ORIGINAL_WRITE_RUN_REPORT",
        lambda report, logs_dir: captured.update(report=report, logs_dir=logs_dir),
    )
    report = {
        "candidate_count": 191,
        "discovered": 0,
        "published": 0,
        "provider_capacity_constrained": True,
        "active_tpd_cooldown_count": 3,
        "provider_independent_candidates": 0,
        "provider_capacity_deferred_candidates": 191,
        "run_status": "SUCCESS",
    }

    allocator._capacity_write_run_report(report, "logs")

    assert report["run_status"] == "DEGRADED"
    assert report["provider_capacity_deferred"] is True
    assert report["provider_capacity"]["deferred_candidates"] == 191
    assert report["capacity_allocator_v13"]["marker"] == allocator.MARKER
    assert captured["report"] is report
