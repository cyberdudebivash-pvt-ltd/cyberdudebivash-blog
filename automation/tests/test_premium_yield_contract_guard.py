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
