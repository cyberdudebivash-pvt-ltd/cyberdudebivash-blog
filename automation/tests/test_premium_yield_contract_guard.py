from automation import premium_publication as premium
from automation import premium_yield_contract_guard as guard


def _report(headings, words=2300):
    sections = "".join(
        f"<h3>{index}. {heading}</h3><p>evidence decision telemetry validation</p>"
        for index, heading in enumerate(headings, 1)
    )
    return sections + "<p>" + ("evidence " * words) + "</p>"


def test_preflight_refuses_non_tail_missing_mandatory_section_even_with_public_heading_floor():
    headings = [
        heading for heading in guard._MANDATORY_HEADINGS
        if heading not in {"Threat Hunting Queries", "Executive Recommendations", "References"}
    ]
    # Still far above the public 18-heading minimum and contains all public
    # core headings except the two allowed tail sections; the missing non-tail
    # section must make this ineligible for bounded terminal recovery.
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
    executive_offset = repaired.index("<h3>Executive Recommendations</h3>")
    gaps_offset = repaired.index("Intelligence Gaps &amp; Collection Requirements") if "Intelligence Gaps &amp; Collection Requirements" in repaired else repaired.index("Intelligence Gaps & Collection Requirements")
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
