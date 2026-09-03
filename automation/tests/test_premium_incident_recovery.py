from automation import premium_incident_recovery as recovery
from automation import premium_provider_budget as budget
from automation import premium_publication as premium
from automation.config import Config
from automation.content_discovery import DiscoveredArticle


def _article(**overrides):
    values = dict(
        url="https://example.test/advisory/CVE-2026-99999",
        title="CVE-2026-99999 Example Product remote security advisory",
        summary="Example Vendor reports a security issue affecting Example Product and provides remediation guidance.",
        published_at="2026-09-03T00:00:00Z",
        content_hash="recovery-abc123",
        labels=["Threat Intelligence", "Vulnerabilities", "CVE Analysis"],
        source="nvd",
        full_content=("Example Vendor Example Product CVE-2026-99999 evidence remediation telemetry. " * 180),
        source_publisher="Example Vendor",
        cve_id="CVE-2026-99999",
        cvss_score=8.1,
        cwe_ids=["CWE-20"],
        affected_vendor="Example Vendor",
        affected_product="Example Product",
        kev_listed=False,
    )
    values.update(overrides)
    return DiscoveredArticle(**values)


def _complete_raw_report(words=2000):
    core = sorted(premium._CORE_HEADINGS)
    auxiliary = [f"Operational Section {idx}" for idx in range(1, 10)]
    headings = core + auxiliary
    sections = "".join(f"<h3>{heading}</h3><p>evidence decision telemetry validation</p>" for heading in headings)
    filler = " ".join("evidence" for _ in range(words))
    return f"{sections}<p>{filler}</p>"


def test_completion_safe_prompt_rebalances_output_without_crossing_provider_ceiling(monkeypatch):
    monkeypatch.setattr(recovery, "_ORIGINAL_PROMPT_BUILDER", budget.build_budgeted_premium_prompt)

    prompt = recovery.build_completion_safe_prompt(_article())

    assert "Target 2,300-2,700 useful visible words" in prompt
    assert "reserve at least 20% of completion capacity for sections 21-25" in prompt
    assert "Executive Recommendations and References" in prompt
    assert "UNTRUSTED SOURCE DATA START" in prompt
    assert "UNTRUSTED SOURCE DATA END" in prompt
    assert len(prompt) <= budget.PREMIUM_PROMPT_CHAR_CEILING


def test_quality_aware_groq_failover_retries_structurally_truncated_success(monkeypatch):
    config = Config(
        groq_api_key="test-key",
        llm_model_groq="model-primary",
        llm_model_groq_fallbacks=("model-fallback-1", "model-fallback-2"),
    )
    attempts = []
    truncated = "<h3>Executive Summary</h3><p>" + ("evidence " * 2100) + "</p>"
    complete = _complete_raw_report()

    def first_call(config, prompt, max_tokens=3000, attempts=None, sleep_fn=None):
        attempts.append({"provider": "groq", "model": "model-primary", "ok": True, "error": None})
        return truncated, "groq"

    tried = []

    def try_provider(**kwargs):
        tried.append(kwargs["model"])
        kwargs["attempts"].append(
            {"provider": "groq", "model": kwargs["model"], "ok": True, "error": None}
        )
        return complete

    monkeypatch.setattr(recovery, "_ORIGINAL_PREMIUM_LLM_CALL", first_call)
    monkeypatch.setattr(recovery._llm, "_try_provider", try_provider)

    result = recovery.call_quality_aware_premium_llm(
        config,
        "prompt",
        attempts=attempts,
        sleep_fn=lambda _seconds: None,
    )

    assert result == (complete, "groq")
    assert tried == ["model-fallback-1"]
    assert attempts[-1]["model"] == "model-fallback-1"
    assert recovery._raw_contract_complete(result[0]) is True


def test_quality_aware_groq_failover_does_not_spend_extra_call_for_complete_first_response(monkeypatch):
    config = Config(
        groq_api_key="test-key",
        llm_model_groq="model-primary",
        llm_model_groq_fallbacks=("model-fallback-1",),
    )
    complete = _complete_raw_report()

    def first_call(config, prompt, max_tokens=3000, attempts=None, sleep_fn=None):
        attempts.append({"provider": "groq", "model": "model-primary", "ok": True, "error": None})
        return complete, "groq"

    monkeypatch.setattr(recovery, "_ORIGINAL_PREMIUM_LLM_CALL", first_call)

    def unexpected_try(**kwargs):
        raise AssertionError("unused Groq fallback must not be called for a complete first response")

    monkeypatch.setattr(recovery._llm, "_try_provider", unexpected_try)

    result = recovery.call_quality_aware_premium_llm(
        config,
        "prompt",
        attempts=[],
        sleep_fn=lambda _seconds: None,
    )

    assert result == (complete, "groq")


def test_availability_guard_fails_batch_wide_premium_gate_outage(monkeypatch):
    monkeypatch.setattr(recovery, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda report: "DEGRADED")

    report = {
        "dry_run": False,
        "discovered": 5,
        "published": 0,
        "failed": 5,
        "integrity_blocked": 5,
    }
    assert recovery._availability_guard_status(report) == "FAILED"


def test_availability_guard_preserves_legitimate_single_integrity_block(monkeypatch):
    monkeypatch.setattr(recovery, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda report: "DEGRADED")

    report = {
        "dry_run": False,
        "discovered": 1,
        "published": 0,
        "failed": 1,
        "integrity_blocked": 1,
    }
    assert recovery._availability_guard_status(report) == "DEGRADED"
