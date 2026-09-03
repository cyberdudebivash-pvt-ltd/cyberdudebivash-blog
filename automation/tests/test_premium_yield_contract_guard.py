from automation import premium_incident_recovery as recovery
from automation import premium_publication as premium
from automation import premium_yield_contract_guard as guard
from automation.config import Config


_SUBSTANTIVE_PARAGRAPH = (
    "Evidence-backed analysis explains required telemetry validation and enterprise response decisions."
)
_SUBSTANTIVE_LIST_ITEM = (
    "Validate authoritative telemetry before operational escalation or containment decisions."
)


def _report(headings, words=2300):
    sections = "".join(
        f"<h3>{index}. {heading}</h3>"
        f"<p>{_SUBSTANTIVE_PARAGRAPH}</p>"
        f"<ul><li>{_SUBSTANTIVE_LIST_ITEM}</li></ul>"
        for index, heading in enumerate(headings, 1)
    )
    return sections + "<p>" + ("evidence " * words) + "</p>"


def _semantically_dense_without_valid_independent_headings(words=2300):
    composite = " / ".join(guard._MANDATORY_HEADINGS)
    body = f"<h3>{composite}</h3>"
    body += "".join(f"<p>{_SUBSTANTIVE_PARAGRAPH}</p>" for _ in range(20))
    body += "<ul>" + "".join(f"<li>{_SUBSTANTIVE_LIST_ITEM}</li>" for _ in range(20)) + "</ul>"
    return body + "<p>" + ("evidence " * words) + "</p>"


def test_preflight_refuses_non_tail_missing_mandatory_section_even_with_public_heading_floor():
    headings = [
        heading for heading in guard._MANDATORY_HEADINGS
        if heading not in {"Threat Hunting Queries", "Executive Recommendations", "References"}
    ]
    content = _report(headings)

    assert len(premium._headings(content)) >= premium.MIN_DISTINCT_HEADINGS
    assert "threat hunting queries" in guard._missing_mandatory(content)
    assert guard.strict_yield_contract_complete(content) is False
    repaired, added = guard.strict_tail_sections(
        content,
        "SOURCE URL: https://example.test/source\nSOURCE TITLE: Example\n",
    )
    assert repaired == content
    assert added == 0


def test_terminal_recovery_requires_all_other_23_sections_and_preserves_order():
    headings = [
        heading for heading in guard._MANDATORY_HEADINGS
        if heading not in {"Executive Recommendations", "References"}
    ]
    content = _report(headings)
    prompt = (
        "SOURCE URL: https://example.test/source\n"
        "SOURCE TITLE: Example advisory\n"
        "CDB_EVIDENCE_FAMILY: cve_advisory\n"
        "CDB_EXPLOITATION_STATUS: not_confirmed\n"
    )

    assert guard._missing_mandatory(content) == {"executive recommendations", "references"}
    assert guard.strict_yield_contract_complete(content) is True

    repaired, added = guard.strict_tail_sections(content, prompt)

    assert added == 2
    assert guard._missing_mandatory(repaired) == set()
    assert guard._public_semantic_ready(repaired) is True
    executive_offset = repaired.index("<h3>Executive Recommendations</h3>")
    gaps_offset = (
        repaired.index("Intelligence Gaps &amp; Collection Requirements")
        if "Intelligence Gaps &amp; Collection Requirements" in repaired
        else repaired.index("Intelligence Gaps & Collection Requirements")
    )
    references_offset = repaired.index("<h3>References</h3>")
    forecast_offset = repaired.index("Forecast / Outlook")
    assert executive_offset < gaps_offset
    assert references_offset > forecast_offset
    assert "https://example.test/source" in repaired


def test_reference_recovery_fails_closed_without_canonical_source_url():
    headings = [heading for heading in guard._MANDATORY_HEADINGS if heading != "References"]
    content = _report(headings)

    assert guard.strict_yield_contract_complete(content) is True
    repaired, added = guard.strict_tail_sections(content, "SOURCE TITLE: Example advisory\n")

    assert repaired == content
    assert added == 0
    assert guard._missing_mandatory(repaired) == {"references"}


def test_composite_heading_cannot_satisfy_multiple_mandatory_sections():
    # Production run 33746008715 produced responses where many required names
    # collapsed into too few real headings.  Substring matching must never let
    # one composite heading count as the 25 independent section contract.
    content = _semantically_dense_without_valid_independent_headings()

    assert premium._word_count(content) >= premium.MIN_VISIBLE_WORDS
    paragraphs, list_items = premium._semantic_counts(content)
    assert paragraphs >= premium.MIN_PARAGRAPHS
    assert list_items >= premium.MIN_LIST_ITEMS
    assert len(guard._mandatory_hits(content)) == 0
    assert guard.strict_yield_contract_complete(content) is False


def test_all_25_headings_are_not_enough_when_semantic_density_is_below_public_gate():
    sections = "".join(
        f"<h3>{index}. {heading}</h3>"
        for index, heading in enumerate(guard._MANDATORY_HEADINGS, 1)
    )
    sparse = sections + "<p>" + ("evidence " * 2300) + "</p><ul><li>one sparse list item only</li></ul>"

    assert guard._missing_mandatory(sparse) == set()
    assert premium._word_count(sparse) >= premium.MIN_VISIBLE_WORDS
    assert guard.strict_yield_contract_complete(sparse) is False


def test_strict_recovery_continues_to_unused_model_after_semantic_false_positive(monkeypatch):
    config = Config(
        groq_api_key="test-key",
        llm_model_groq="model-primary",
        llm_model_groq_fallbacks=("model-fallback-1", "model-fallback-2"),
    )
    attempts = []
    primary = _semantically_dense_without_valid_independent_headings()

    # Independent headings but still only one paragraph/list item: the second
    # model is also not publication-shaped and must not stop failover.
    sparse_sections = "".join(
        f"<h3>{index}. {heading}</h3>"
        for index, heading in enumerate(guard._MANDATORY_HEADINGS, 1)
    )
    fallback_one = sparse_sections + "<p>" + ("evidence " * 2300) + "</p><ul><li>one sparse list item only</li></ul>"
    fallback_two = _report(guard._MANDATORY_HEADINGS)

    def first_call(config, prompt, max_tokens=3000, attempts=None, sleep_fn=None):
        attempts.append({"provider": "groq", "model": "model-primary", "ok": True, "error": None})
        return primary, "groq"

    tried = []

    def try_provider(**kwargs):
        model = kwargs["model"]
        tried.append(model)
        kwargs["attempts"].append({"provider": "groq", "model": model, "ok": True, "error": None})
        return fallback_one if model == "model-fallback-1" else fallback_two

    monkeypatch.setattr(recovery, "_ORIGINAL_PREMIUM_LLM_CALL", first_call)
    monkeypatch.setattr(recovery, "_raw_contract_complete", guard.strict_yield_contract_complete)
    monkeypatch.setattr(recovery, "_raw_contract_metrics", guard.strict_raw_contract_metrics)
    monkeypatch.setattr(recovery, "_candidate_score", guard.strict_candidate_score)
    monkeypatch.setattr(recovery._llm, "_try_provider", try_provider)

    result = recovery.call_quality_aware_premium_llm(
        config,
        "prompt",
        attempts=attempts,
        sleep_fn=lambda _seconds: None,
    )

    assert result == (fallback_two, "groq")
    assert tried == ["model-fallback-1", "model-fallback-2"]
    assert guard.strict_yield_contract_complete(result[0]) is True


def test_reference_url_validator_accepts_only_absolute_http_or_https_without_credentials():
    assert guard._validated_http_url("https://example.test/advisory?id=1#evidence") == "https://example.test/advisory?id=1#evidence"
    assert guard._validated_http_url("http://example.test/source") == "http://example.test/source"
    assert guard._validated_http_url("javascript:alert(1)") is None
    assert guard._validated_http_url("data:text/html,<script>alert(1)</script>") is None
    assert guard._validated_http_url("//example.test/source") is None
    assert guard._validated_http_url("https://") is None
    assert guard._validated_http_url("https://user:pass@example.test/source") is None
    assert guard._validated_http_url("https://example.test/source\njavascript:alert(1)") is None
    assert guard._validated_http_url("https://example.test:99999/source") is None


def test_reference_tail_recovery_rejects_dangerous_source_scheme_without_rendering_href():
    headings = [heading for heading in guard._MANDATORY_HEADINGS if heading != "References"]
    content = _report(headings)
    prompt = (
        "SOURCE URL: javascript:alert(document.domain)\n"
        "SOURCE TITLE: Adversarial feed item\n"
        "CDB_EVIDENCE_FAMILY: cve_advisory\n"
        "CDB_EXPLOITATION_STATUS: not_confirmed\n"
    )

    assert guard.strict_yield_contract_complete(content) is True
    repaired, added = guard.strict_tail_sections(content, prompt)

    assert repaired == content
    assert added == 0
    assert "javascript:" not in repaired
    assert "<h3>References</h3>" not in repaired
    assert guard._missing_mandatory(repaired) == {"references"}
