from types import SimpleNamespace
from unittest.mock import Mock

from automation import astra_revenue_intelligence_v18 as astra
from automation import astra_revenue_yield_alignment_v18_1 as alignment
from automation import premium_publication as premium


def _article(words=600):
    return SimpleNamespace(
        full_content=("trusted public source evidence " * words),
        summary="trusted public source evidence",
        cve_id=None,
        cvss_score=None,
        cvss_vector=None,
        cwe_ids=None,
        affected_vendor=None,
        affected_product=None,
        epss_score=None,
        epss_percentile=None,
        kev_listed=None,
        kev_date_added=None,
        kev_due_date=None,
        kev_required_action=None,
        ransomware_group=None,
        ransomware_sector=None,
        ransomware_country=None,
    )


def _body(words_per_paragraph=110, paragraphs=18, list_items=18):
    para = " ".join(["evidence"] * words_per_paragraph)
    paras = "".join(f"<p>{para} {i}</p>" for i in range(paragraphs))
    items = "".join(f"<li>validated evidence requirement item {i}</li>" for i in range(list_items))
    return paras + f"<ul>{items}</ul>"


def test_alignment_uses_exact_precompiler_dimensions_not_headings():
    content = _body(words_per_paragraph=125, paragraphs=18, list_items=18)
    metrics = alignment._precompiler_metrics(content)
    assert metrics["words"] >= premium.MIN_VISIBLE_WORDS
    assert metrics["paragraphs"] >= premium.MIN_PARAGRAPHS
    assert metrics["list_items"] >= premium.MIN_LIST_ITEMS
    assert alignment._precompiler_complete(content) is True
    assert "<h" not in content


def test_prompt_targets_only_analytical_density_and_forbids_headings():
    existing = _body(words_per_paragraph=70, paragraphs=14, list_items=12)
    prompt = alignment._aligned_continuation_prompt("SOURCE DATA: evidence", existing, 1)
    assert "visible analytical words still required" in prompt
    assert "substantive paragraphs still required" in prompt
    assert "substantive list items still required" in prompt
    assert "Emit NO <h1>, <h2>, <h3>" in prompt
    assert "missing canonical headings" not in prompt.lower()
    assert "deterministic Stage-2 compiler owns ALL report headings" in prompt


def test_aligned_fragment_rejects_any_renderer_owned_heading():
    existing = "<p>Existing evidence-backed analysis.</p>"
    raw = "<h3>Detection Engineering</h3><p>Additional evidence-backed telemetry validation.</p>"
    assert alignment._safe_aligned_fragment(raw, existing) is None


def test_aligned_fragment_accepts_substantive_heading_free_body():
    existing = "<p>Existing evidence-backed analysis.</p>"
    raw = "<p>" + ("source-backed telemetry validation detail " * 30) + "</p>"
    result = alignment._safe_aligned_fragment(raw, existing)
    assert result is not None
    assert "source-backed telemetry" in result
    assert "<h" not in result


def test_complete_precompiler_body_short_circuits_continuation(monkeypatch):
    complete = _body(words_per_paragraph=125, paragraphs=18, list_items=18)
    inner = Mock(return_value=(complete, "gemini"))
    continuation = Mock(side_effect=AssertionError("continuation must not run"))
    monkeypatch.setattr(astra, "_INNER_AUTHORITY_CALL", inner)
    monkeypatch.setattr(astra, "_CONTINUATION_CALL", continuation)

    result = alignment.aligned_astra_quality_aware_authority_llm(
        SimpleNamespace(), "SOURCE DATA", attempts=[], sleep_fn=lambda _s: None
    )

    assert result == (complete, "gemini")
    continuation.assert_not_called()


def test_source_thin_candidate_remains_fail_closed(monkeypatch):
    thin = _body(words_per_paragraph=25, paragraphs=8, list_items=4)
    monkeypatch.setattr(astra, "_INNER_AUTHORITY_CALL", Mock(return_value=(thin, "gemini")))
    continuation = Mock(side_effect=AssertionError("continuation must not run for thin source"))
    monkeypatch.setattr(astra, "_CONTINUATION_CALL", continuation)
    monkeypatch.setattr(astra, "_active_article", lambda: _article(words=10))

    result = alignment.aligned_astra_quality_aware_authority_llm(
        SimpleNamespace(), "SOURCE DATA", attempts=[], sleep_fn=lambda _s: None
    )

    assert result == (thin, "gemini")
    continuation.assert_not_called()


def test_evidence_sufficient_near_miss_can_recover_exact_precompiler_contract(monkeypatch):
    initial = _body(words_per_paragraph=105, paragraphs=17, list_items=17)
    assert alignment._precompiler_complete(initial) is False
    fragment = (
        "<p>" + ("source-bounded operational validation evidence " * 85) + "</p>"
        "<ul><li>Additional source-bounded validation pivot for analyst confirmation.</li></ul>"
    )
    monkeypatch.setattr(astra, "_INNER_AUTHORITY_CALL", Mock(return_value=(initial, "gemini")))
    continuation = Mock(return_value=(fragment, "nvidia_nim"))
    monkeypatch.setattr(astra, "_CONTINUATION_CALL", continuation)
    monkeypatch.setattr(astra, "_active_article", lambda: _article(words=600))

    result = alignment.aligned_astra_quality_aware_authority_llm(
        SimpleNamespace(), "SOURCE DATA: trusted public source evidence", attempts=[], sleep_fn=lambda _s: None
    )

    assert result is not None
    content, provider = result
    assert provider == "gemini"
    assert alignment._precompiler_complete(content) is True
    assert continuation.call_count == 1
    assert continuation.call_args.kwargs["max_tokens"] == astra.CONTINUATION_MAX_TOKENS


def test_alignment_never_changes_public_floors():
    assert premium.MIN_VISIBLE_WORDS == 2200
    assert premium.MIN_DISTINCT_HEADINGS == 18
    assert premium.MIN_PARAGRAPHS == 18
    assert premium.MIN_LIST_ITEMS == 18


def test_alignment_telemetry_contains_no_sensitive_payload(monkeypatch):
    monkeypatch.setattr(alignment, "_ORIGINAL_TELEMETRY", lambda: {"version": "v18"})
    telemetry = alignment._aligned_telemetry_snapshot()["yield_alignment_v18_1"]
    assert telemetry["completion_contract"] == "premium_evidence_compiler.compiler_semantic_preflight_complete"
    assert telemetry["renderer_owns_headings"] is True
    assert telemetry["quality_floor_lowered"] is False
    assert telemetry["telemetry_contains_prompts"] is False
    assert telemetry["telemetry_contains_response_content"] is False
    assert telemetry["telemetry_contains_credentials"] is False
