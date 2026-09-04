"""Regression coverage for P0 Stage-3 premium release hardening."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import requests

from automation import premium_release_hardening as release
from automation import premium_publication as premium
from automation import report_integrity as integrity


def _dense_html(words_per_paragraph: int = 120, paragraphs: int = 18, list_items: int = 18) -> str:
    """Build deterministic semantic-density fixtures without relying on headings."""
    paragraph_text = " ".join(["analysis"] * words_per_paragraph)
    list_text = "evidence specific validation step"
    return (
        "".join(f"<p>{paragraph_text}</p>" for _ in range(paragraphs))
        + "<ul>"
        + "".join(f"<li>{list_text} {index}</li>" for index in range(list_items))
        + "</ul>"
    )


def test_semantic_candidate_score_prefers_balanced_gate_ready_density() -> None:
    """A gate-ready dense candidate must outrank a longer semantically thin one."""
    ready = _dense_html(words_per_paragraph=125, paragraphs=18, list_items=18)
    thin = _dense_html(words_per_paragraph=400, paragraphs=8, list_items=8)
    assert premium._word_count(thin) > premium._word_count(ready)
    assert release.semantic_candidate_score(ready) > release.semantic_candidate_score(thin)


def test_semantic_candidate_score_ignores_model_heading_ownership() -> None:
    """Legacy heading count must not influence Stage-3 fallback ranking."""
    body = _dense_html(words_per_paragraph=125, paragraphs=18, list_items=18)
    heading_heavy = "".join(f"<h3>Section {index}</h3>" for index in range(40)) + body
    assert release.semantic_candidate_score(body) == release.semantic_candidate_score(heading_heavy)


def test_compact_numeric_grounding_expands_exact_source_values(monkeypatch) -> None:
    """5K, 2.5M and word-scale source values must ground their exact integers."""
    monkeypatch.setattr(release, "_ORIGINAL_GROUNDED_NUMBERS", lambda text: {"7"})
    grounded = release.grounded_numbers_with_compact_suffixes(
        "5K Dropbox accounts, 2.5M records, 1.2 billion events, and 7 servers"
    )
    assert {"7", "5000", "2500000", "1200000000"}.issubset(grounded)


def test_compact_numeric_grounding_does_not_treat_spaced_unit_m_as_million(monkeypatch) -> None:
    """A normal expression such as '5 m cable' must not fabricate five million."""
    monkeypatch.setattr(release, "_ORIGINAL_GROUNDED_NUMBERS", lambda text: {"5"})
    grounded = release.grounded_numbers_with_compact_suffixes("a 5 m cable")
    assert "5000000" not in grounded
    assert "5" in grounded


def test_quantitative_gate_accepts_5k_source_for_5000_rendered_claim(monkeypatch) -> None:
    """The existing fail-closed quantitative gate must accept exact compact equivalence."""
    original = integrity._grounded_numbers
    monkeypatch.setattr(release, "_ORIGINAL_GROUNDED_NUMBERS", original)
    monkeypatch.setattr(integrity, "_grounded_numbers", release.grounded_numbers_with_compact_suffixes)
    article = SimpleNamespace(
        title="ThreatsDay: CEO phishing kits and 5K Dropbox account hacks",
        summary="The source reports 5K Dropbox accounts.",
        full_content="",
    )
    issues = integrity._check_quantitative_claims_are_grounded(
        "<p>The cited source reports 5,000 accounts.</p>",
        article,
    )
    assert issues == []


def test_quantitative_gate_still_blocks_unseen_number(monkeypatch) -> None:
    """Compact normalization must not create fuzzy tolerance for invented values."""
    original = integrity._grounded_numbers
    monkeypatch.setattr(release, "_ORIGINAL_GROUNDED_NUMBERS", original)
    monkeypatch.setattr(integrity, "_grounded_numbers", release.grounded_numbers_with_compact_suffixes)
    article = SimpleNamespace(
        title="Source reports 5K accounts",
        summary="5K accounts were referenced.",
        full_content="",
    )
    issues = integrity._check_quantitative_claims_are_grounded(
        "<p>The report affected 5,001 accounts.</p>",
        article,
    )
    assert len(issues) == 1
    assert "5,001 accounts" in issues[0]


def test_final_evidence_boundary_repairs_unconfirmed_exploitation(monkeypatch) -> None:
    """Unsupported active-exploitation wording must be downgraded before hashing."""
    monkeypatch.setattr(
        release,
        "_ORIGINAL_ASSEMBLE_HTML",
        lambda self, article, body_content, seo_data, context, image_url=None: (
            "<p>This vulnerability is actively exploited and exploitation has been observed.</p>"
        ),
    )
    context = SimpleNamespace(exploitation_status="unknown", family="cve_advisory")
    repaired = release.final_evidence_boundary_assemble_html(
        object(), object(), "", {}, context
    )
    for pattern in integrity._CONFIRMED_EXPLOITATION_PATTERNS:
        for match in release.re.finditer(pattern, repaired, release.re.IGNORECASE):
            assert integrity._is_negated_immediately_before(repaired, match.start())


def test_final_evidence_boundary_preserves_confirmed_exploitation(monkeypatch) -> None:
    """Confirmed source-backed exploitation language must remain untouched."""
    original_html = "<p>This vulnerability is actively exploited.</p>"
    monkeypatch.setattr(
        release,
        "_ORIGINAL_ASSEMBLE_HTML",
        lambda self, article, body_content, seo_data, context, image_url=None: original_html,
    )
    context = SimpleNamespace(exploitation_status="confirmed", family="cisa_kev")
    repaired = release.final_evidence_boundary_assemble_html(
        object(), object(), "", {}, context
    )
    assert repaired == original_html


def _response(status: int, body: str) -> requests.Response:
    """Construct a real requests.Response for HTTPError/429 parser tests."""
    response = requests.Response()
    response.status_code = status
    response._content = body.encode("utf-8")
    response.url = "https://api.groq.com/openai/v1/chat/completions"
    return response


def test_otpm_ceiling_parser_accepts_only_explicit_over_limit_failures() -> None:
    """Only a provider-declared requested>limit OTPM failure may create a hint."""
    response = _response(
        429,
        '{"error":{"message":"Request too large on output tokens per minute (OTPM): '
        'Limit 1,000, Requested 4,400. The request\'s expected output tokens exceed '
        'the enforced limit; reduce max_tokens and try again."}}',
    )
    assert release._otpm_ceiling(response) == 1000
    assert release._otpm_ceiling(_response(429, "ordinary rate limit")) is None
    assert release._otpm_ceiling(_response(500, response.text)) is None


def test_capability_aware_try_provider_skips_only_requests_above_observed_ceiling(monkeypatch) -> None:
    """A learned ceiling may skip long-form work without blocking smaller requests."""
    calls = []

    def original(**kwargs):
        """Record delegated provider calls for the test."""
        calls.append(kwargs)
        return "ok"

    monkeypatch.setattr(release, "_ORIGINAL_TRY_PROVIDER", original)
    monkeypatch.setattr(release, "_OTPM_CEILINGS", {("groq", "model-a"): 1000})
    attempts = []
    skipped = release.capability_aware_try_provider(
        name="groq",
        url="https://api.groq.com/openai/v1/chat/completions",
        api_key="secret",
        model="model-a",
        prompt="x",
        max_tokens=4400,
        extra_headers={},
        sleep_fn=lambda _: None,
        attempts=attempts,
    )
    assert skipped is None
    assert calls == []
    assert attempts[0]["error"] == "observed_otpm_ceiling"

    delegated = release.capability_aware_try_provider(
        name="groq",
        url="https://api.groq.com/openai/v1/chat/completions",
        api_key="secret",
        model="model-a",
        prompt="x",
        max_tokens=900,
        extra_headers={},
        sleep_fn=lambda _: None,
        attempts=[],
    )
    assert delegated == "ok"
    assert len(calls) == 1


def test_otpm_learning_occurs_only_after_original_call_raises(monkeypatch) -> None:
    """A successful bounded provider retry must not create a false capability hint."""
    monkeypatch.setattr(release, "_OTPM_CEILINGS", {})
    monkeypatch.setattr(release, "_ORIGINAL_RAW_OPENAI_CALL", lambda **kwargs: "success")
    result = release.learn_otpm_ceiling(
        url="https://api.groq.com/openai/v1/chat/completions",
        api_key="secret",
        model="model-a",
        prompt="x",
        max_tokens=4400,
        extra_headers={},
        sleep_fn=lambda _: None,
    )
    assert result == "success"
    assert release._OTPM_CEILINGS == {}


def test_otpm_learning_records_final_explicit_failure(monkeypatch) -> None:
    """A final explicit OTPM HTTPError must teach later candidates in this process."""
    response = _response(
        429,
        '{"error":{"message":"Request too large on output tokens per minute (OTPM): '
        'Limit 1000, Requested 4400. The request\'s expected output tokens exceed '
        'the enforced limit; reduce max_tokens and try again."}}',
    )

    def failing(**kwargs):
        """Raise the provider's final HTTPError with the real response attached."""
        error = requests.exceptions.HTTPError("429 Client Error", response=response)
        raise error

    monkeypatch.setattr(release, "_OTPM_CEILINGS", {})
    monkeypatch.setattr(release, "_ORIGINAL_RAW_OPENAI_CALL", failing)
    with pytest.raises(requests.exceptions.HTTPError):
        release.learn_otpm_ceiling(
            url="https://api.groq.com/openai/v1/chat/completions",
            api_key="secret",
            model="model-a",
            prompt="x",
            max_tokens=4400,
            extra_headers={},
            sleep_fn=lambda _: None,
        )
    assert release._OTPM_CEILINGS[("groq", "model-a")] == 1000
