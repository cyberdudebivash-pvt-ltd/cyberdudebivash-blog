import time
from unittest.mock import Mock, patch

from automation.config import Config
from automation.content_discovery import DiscoveredArticle
from automation import key_judgements
from automation import llm_client
from automation import premium_publication
from automation import premium_provider_budget
from automation.premium_provider_budget import (
    PREMIUM_COMPLETION_TOKENS,
    PREMIUM_PROMPT_CHAR_CEILING,
    PREMIUM_RATE_LIMIT_WAIT_CEILING_SECONDS,
    PREMIUM_SOURCE_CHAR_BUDGET,
    build_budgeted_premium_prompt,
    call_budgeted_premium_llm,
    call_paced_key_judgements_llm,
    install_provider_budget_overrides,
)


def _article(full_content: str) -> DiscoveredArticle:
    return DiscoveredArticle(
        url="https://example.test/security/advisory",
        title="Example enterprise security incident",
        summary="Example source summary",
        published_at="2026-09-02T00:00:00Z",
        content_hash="abc",
        labels=["Threat Intelligence", "Incident Response"],
        source="global_rss",
        full_content=full_content,
        source_publisher="Example Security Publisher",
    )


def test_budgeted_prompt_is_bounded_and_source_is_not_duplicated():
    source = "BEGIN-EVIDENCE " + ("evidence-data " * 3000) + " END-EVIDENCE"
    prompt = build_budgeted_premium_prompt(_article(source))

    assert len(prompt) <= PREMIUM_PROMPT_CHAR_CEILING
    assert prompt.count(">>> UNTRUSTED SOURCE DATA START") == 1
    assert prompt.count(">>> UNTRUSTED SOURCE DATA END") == 1
    assert "BEGIN-EVIDENCE" in prompt
    assert "END-EVIDENCE" in prompt
    assert len(source) > PREMIUM_SOURCE_CHAR_BUDGET
    assert "source excerpt budget boundary" in prompt


def test_budgeted_prompt_retains_full_enterprise_section_contract():
    prompt = build_budgeted_premium_prompt(_article("source evidence"))
    required = (
        "Executive Summary", "Key Judgements", "Verified Facts", "Threat Classification",
        "Evidence & Source Assessment", "Timeline & Chronology", "Business Impact",
        "Enterprise Exposure Assessment", "Technical Analysis", "MITRE ATT&CK Assessment",
        "Indicators & Observables", "Detection Engineering Guidance",
        "Detection Validation & Required Telemetry", "Threat Hunting Queries", "SOC Analyst Playbook",
        "Incident Response & Containment Decision Plan", "Remediation & Validation Plan",
        "Executive Decision Matrix", "Executive Recommendations",
        "Intelligence Gaps & Collection Requirements", "Analytic Confidence & Limitations",
        "Forecast / Outlook", "References",
    )
    for heading in required:
        assert heading in prompt


def test_budgeted_llm_call_never_reinflates_completion_reservation():
    old_pacing_state = premium_provider_budget._last_premium_call_started_at
    premium_provider_budget._last_premium_call_started_at = None
    try:
        config = Config(groq_api_key="test")
        with patch.object(premium_publication, "_ORIGINAL_LLM_CALL", return_value=("ok", "groq")) as call:
            result = call_budgeted_premium_llm(config, "prompt", max_tokens=999999, attempts=[])

        assert result == ("ok", "groq")
        assert call.call_args.kwargs["max_tokens"] == PREMIUM_COMPLETION_TOKENS
    finally:
        premium_provider_budget._last_premium_call_started_at = old_pacing_state


# Production incident 2026-09-03: a full syndication run makes up to 5 of
# these calls back-to-back with no pacing, so the 2nd+ candidate landed in
# the same Groq TPM window as the 1st and was rate-limited, then fell
# through two permanently-unfunded fallback providers straight to the thin
# template fallback -- which can never clear the premium public-report
# gate. These tests cover the proactive pacing fix using an injected
# sleep_fn so the suite never actually waits ~65 seconds.


def test_first_budgeted_call_in_a_fresh_run_does_not_pace():
    old_pacing_state = premium_provider_budget._last_premium_call_started_at
    premium_provider_budget._last_premium_call_started_at = None
    try:
        config = Config(groq_api_key="test")
        fake_sleep = Mock()
        with patch.object(premium_publication, "_ORIGINAL_LLM_CALL", return_value=("ok", "groq")):
            call_budgeted_premium_llm(config, "prompt", attempts=[], sleep_fn=fake_sleep)
        fake_sleep.assert_not_called()
    finally:
        premium_provider_budget._last_premium_call_started_at = old_pacing_state


def test_budgeted_call_immediately_after_a_prior_call_paces_to_the_ceiling():
    old_pacing_state = premium_provider_budget._last_premium_call_started_at
    premium_provider_budget._last_premium_call_started_at = time.monotonic()
    try:
        config = Config(groq_api_key="test")
        fake_sleep = Mock()
        with patch.object(premium_publication, "_ORIGINAL_LLM_CALL", return_value=("ok", "groq")):
            call_budgeted_premium_llm(config, "prompt", attempts=[], sleep_fn=fake_sleep)
        fake_sleep.assert_called_once()
        (waited,) = fake_sleep.call_args.args
        # Immediately after a prior call, the wait should be within a
        # small tolerance of the full ceiling (real wall-clock time passes
        # during the test itself, so allow a couple of seconds of slack).
        assert PREMIUM_RATE_LIMIT_WAIT_CEILING_SECONDS - 2 <= waited <= PREMIUM_RATE_LIMIT_WAIT_CEILING_SECONDS
    finally:
        premium_provider_budget._last_premium_call_started_at = old_pacing_state


def test_budgeted_call_after_the_window_has_elapsed_does_not_pace():
    old_pacing_state = premium_provider_budget._last_premium_call_started_at
    premium_provider_budget._last_premium_call_started_at = (
        time.monotonic() - PREMIUM_RATE_LIMIT_WAIT_CEILING_SECONDS - 5
    )
    try:
        config = Config(groq_api_key="test")
        fake_sleep = Mock()
        with patch.object(premium_publication, "_ORIGINAL_LLM_CALL", return_value=("ok", "groq")):
            call_budgeted_premium_llm(config, "prompt", attempts=[], sleep_fn=fake_sleep)
        fake_sleep.assert_not_called()
    finally:
        premium_provider_budget._last_premium_call_started_at = old_pacing_state


def test_installation_raises_retry_after_ceiling_without_changing_retry_count():
    old_ceiling = llm_client._MAX_BACKOFF_SECONDS
    old_prompt = premium_publication.build_premium_analyst_prompt
    old_call = premium_publication._premium_llm_call
    old_kj_call = key_judgements.call_llm
    old_retry_count = llm_client._MAX_RETRIES_ON_RATE_LIMIT
    try:
        install_provider_budget_overrides()
        assert llm_client._MAX_BACKOFF_SECONDS == PREMIUM_RATE_LIMIT_WAIT_CEILING_SECONDS
        assert llm_client._MAX_RETRIES_ON_RATE_LIMIT == old_retry_count
        assert premium_publication.build_premium_analyst_prompt is build_budgeted_premium_prompt
        assert premium_publication._premium_llm_call is call_budgeted_premium_llm
        assert key_judgements.call_llm is call_paced_key_judgements_llm
    finally:
        llm_client._MAX_BACKOFF_SECONDS = old_ceiling
        premium_publication.build_premium_analyst_prompt = old_prompt
        premium_publication._premium_llm_call = old_call
        key_judgements.call_llm = old_kj_call


# Production incident 2026-09-03 (continued): key_judgements.py issues its
# own, separate Groq request (from .llm_client import call_llm, never
# through authority_transformer.call_llm), so the pacing fix above alone
# never saw it. It shares the same _last_premium_call_started_at clock as
# call_budgeted_premium_llm -- these tests prove that sharing, not just
# that this call site paces in isolation.


def test_key_judgements_call_preserves_its_own_token_budget():
    old_pacing_state = premium_provider_budget._last_premium_call_started_at
    premium_provider_budget._last_premium_call_started_at = None
    try:
        config = Config(groq_api_key="test")
        fake_call = Mock(return_value=("{}", "groq"))
        with patch.object(premium_provider_budget, "_ORIGINAL_KEY_JUDGEMENTS_LLM_CALL", fake_call):
            result = call_paced_key_judgements_llm(config, "prompt", max_tokens=2000, attempts=[])
        assert result == ("{}", "groq")
        assert fake_call.call_args.kwargs["max_tokens"] == 2000
    finally:
        premium_provider_budget._last_premium_call_started_at = old_pacing_state


def test_key_judgements_call_paces_against_a_prior_primary_call():
    old_pacing_state = premium_provider_budget._last_premium_call_started_at
    try:
        config = Config(groq_api_key="test")
        fake_sleep = Mock()

        # Primary narrative call starts the shared clock ...
        premium_provider_budget._last_premium_call_started_at = None
        with patch.object(premium_publication, "_ORIGINAL_LLM_CALL", return_value=("ok", "groq")):
            call_budgeted_premium_llm(config, "prompt", attempts=[], sleep_fn=fake_sleep)
        fake_sleep.assert_not_called()

        # ... and the Key Judgements call immediately after it must pace
        # against that same clock, not fire unpaced.
        with patch.object(premium_provider_budget, "_ORIGINAL_KEY_JUDGEMENTS_LLM_CALL", return_value=("{}", "groq")):
            call_paced_key_judgements_llm(config, "prompt", attempts=[], sleep_fn=fake_sleep)
        fake_sleep.assert_called_once()
        (waited,) = fake_sleep.call_args.args
        assert PREMIUM_RATE_LIMIT_WAIT_CEILING_SECONDS - 2 <= waited <= PREMIUM_RATE_LIMIT_WAIT_CEILING_SECONDS
    finally:
        premium_provider_budget._last_premium_call_started_at = old_pacing_state


def test_primary_call_paces_against_a_prior_key_judgements_call():
    old_pacing_state = premium_provider_budget._last_premium_call_started_at
    try:
        config = Config(groq_api_key="test")
        fake_sleep = Mock()

        # Key Judgements call starts the shared clock ...
        premium_provider_budget._last_premium_call_started_at = None
        with patch.object(premium_provider_budget, "_ORIGINAL_KEY_JUDGEMENTS_LLM_CALL", return_value=("{}", "groq")):
            call_paced_key_judgements_llm(config, "prompt", attempts=[], sleep_fn=fake_sleep)
        fake_sleep.assert_not_called()

        # ... and the next candidate's primary call must pace against it.
        with patch.object(premium_publication, "_ORIGINAL_LLM_CALL", return_value=("ok", "groq")):
            call_budgeted_premium_llm(config, "prompt", attempts=[], sleep_fn=fake_sleep)
        fake_sleep.assert_called_once()
        (waited,) = fake_sleep.call_args.args
        assert PREMIUM_RATE_LIMIT_WAIT_CEILING_SECONDS - 2 <= waited <= PREMIUM_RATE_LIMIT_WAIT_CEILING_SECONDS
    finally:
        premium_provider_budget._last_premium_call_started_at = old_pacing_state
