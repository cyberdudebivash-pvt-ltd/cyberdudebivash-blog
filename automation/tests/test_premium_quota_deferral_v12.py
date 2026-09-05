from automation import premium_quota_deferral_v12 as v12


def _systemic_report():
    return {
        "dry_run": False,
        "discovered": 5,
        "published": 0,
        "failed": 5,
        "integrity_blocked": 5,
        "posts": [{"status": "integrity_blocked"} for _ in range(5)],
    }


def test_quota_window_converts_only_systemic_capacity_failure_to_degraded(monkeypatch):
    report = _systemic_report()
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: {
        "active_cooldowns": [
            {"provider": "groq", "model": "qwen/qwen3.6-27b", "limit_type": "TPD"},
            {"provider": "groq", "model": "qwen/qwen3.8-27b", "limit_type": "TPD"},
        ]
    })
    monkeypatch.setattr(v12._v11, "telemetry_snapshot", lambda: {
        "seed_attempts": 5,
        "seed_successes": 0,
        "continuation_attempts": 0,
        "continuation_successes": 0,
    })

    assert v12.quota_aware_pipeline_run_status(report) == "DEGRADED"
    assert report["provider_capacity_deferred"] is True
    assert report["provider_capacity"]["active_cooldown_count"] == 2


def test_no_active_quota_window_keeps_systemic_failure_red(monkeypatch):
    report = _systemic_report()
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: {"active_cooldowns": []})
    monkeypatch.setattr(v12._v11, "telemetry_snapshot", lambda: {
        "seed_attempts": 5,
        "seed_successes": 0,
    })

    assert v12.quota_aware_pipeline_run_status(report) == "FAILED"
    assert "provider_capacity_deferred" not in report


def test_terminal_auth_error_never_downgrades(monkeypatch):
    report = _systemic_report()
    report["posts"][0]["status"] = "auth_error"
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: {
        "active_cooldowns": [{"provider": "groq", "model": "qwen/qwen3.6-27b"}]
    })
    monkeypatch.setattr(v12._v11, "telemetry_snapshot", lambda: {
        "seed_attempts": 5,
        "seed_successes": 0,
    })

    assert v12.quota_aware_pipeline_run_status(report) == "FAILED"


def test_successful_seed_does_not_mask_real_quality_failure(monkeypatch):
    report = _systemic_report()
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: {
        "active_cooldowns": [{"provider": "groq", "model": "qwen/qwen3.6-27b"}]
    })
    monkeypatch.setattr(v12._v11, "telemetry_snapshot", lambda: {
        "seed_attempts": 5,
        "seed_successes": 1,
    })

    assert v12.quota_aware_pipeline_run_status(report) == "FAILED"
