"""Regression coverage for production failure 33746008715.

The failed run selected five fresh/retry candidates and published zero because
recovery stopped model failover on responses that did not satisfy the actual
premium public semantic gate.  These tests keep recovery/publication contract
semantics aligned without lowering any customer-facing quality threshold.
"""

from automation import premium_incident_recovery as recovery
from automation import premium_publication as premium
from automation import premium_yield_contract_guard as guard


PARAGRAPH = "Evidence-specific analysis documents telemetry validation decisions for enterprise defenders."
LIST_ITEM = "Validate authoritative telemetry before changing production containment or remediation state."


def _dense_sections(headings):
    return "".join(
        f"<h3>{index}. {heading}</h3><p>{PARAGRAPH}</p><ul><li>{LIST_ITEM}</li></ul>"
        for index, heading in enumerate(headings, 1)
    ) + "<p>" + ("evidence " * 2300) + "</p>"


def test_runtime_guard_install_aligns_recovery_metrics_and_candidate_score(monkeypatch):
    # Isolate global runtime mutation to this test while proving the actual
    # production installer changes every recovery hook needed for P0.
    monkeypatch.setattr(recovery, "_raw_contract_metrics", lambda _content: (1, 1, 1))
    monkeypatch.setattr(recovery, "_raw_contract_complete", lambda _content: True)
    monkeypatch.setattr(recovery, "_candidate_score", lambda _content: (1, 1, 1))

    guard.install_yield_contract_guard()

    assert recovery._raw_contract_metrics is guard.strict_raw_contract_metrics
    assert recovery._raw_contract_complete is guard.strict_yield_contract_complete
    assert recovery._candidate_score is guard.strict_candidate_score


def test_semantic_contract_is_never_weaker_than_public_shape_gate_for_complete_25_section_body():
    content = _dense_sections(guard._MANDATORY_HEADINGS)
    metrics = guard._semantic_metrics(content)

    assert metrics["visible_words"] >= premium.MIN_VISIBLE_WORDS
    assert metrics["distinct_headings"] >= premium.MIN_DISTINCT_HEADINGS
    assert metrics["substantive_paragraphs"] >= premium.MIN_PARAGRAPHS
    assert metrics["substantive_list_items"] >= premium.MIN_LIST_ITEMS
    assert guard._missing_mandatory(content) == set()
    assert guard.strict_yield_contract_complete(content) is True


def test_post_164_false_positive_shape_is_rejected_before_model_failover_stops():
    # Model output can contain every required section name inside one malformed
    # composite heading while still carrying thousands of words and many
    # paragraphs/lists.  The old substring matcher treated that as complete;
    # the production public gate later saw only a handful of headings.
    composite = " | ".join(guard._MANDATORY_HEADINGS)
    content = f"<h3>{composite}</h3>"
    content += "".join(f"<p>{PARAGRAPH}</p>" for _ in range(20))
    content += "<ul>" + "".join(f"<li>{LIST_ITEM}</li>" for _ in range(20)) + "</ul>"
    content += "<p>" + ("evidence " * 2300) + "</p>"

    assert premium._word_count(content) >= premium.MIN_VISIBLE_WORDS
    paragraphs, list_items = premium._semantic_counts(content)
    assert paragraphs >= premium.MIN_PARAGRAPHS
    assert list_items >= premium.MIN_LIST_ITEMS
    assert guard.strict_yield_contract_complete(content) is False


def test_semantic_contract_rejects_25_headings_with_sparse_paragraph_and_list_structure():
    headings = "".join(
        f"<h3>{index}. {heading}</h3>"
        for index, heading in enumerate(guard._MANDATORY_HEADINGS, 1)
    )
    sparse = headings + "<p>" + ("evidence " * 2300) + "</p><ul><li>single sparse list item only</li></ul>"

    assert guard._missing_mandatory(sparse) == set()
    assert guard.strict_yield_contract_complete(sparse) is False
