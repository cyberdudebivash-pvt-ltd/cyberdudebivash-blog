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


def _quota(active_count=2, durable_skips=5, quota_events=0):
    return {
        "durable_provider_skips": durable_skips,
        "quota_events": quota_events,
        "active_cooldowns": [
            {"provider": "groq", "model": f"model-{i}", "limit_type": "TPD"}
            for i in range(active_count)
        ],
    }


def _v11(seed_attempts=5, seed_successes=0, continuation_attempts=0, continuation_successes=0):
    return {
        "seed_attempts": seed_attempts,
        "seed_successes": seed_successes,
        "continuation_attempts": continuation_attempts,
        "continuation_successes": continuation_successes,
    }


def test_quota_window_converts_only_systemic_capacity_failure_to_degraded(monkeypatch):
    report = _systemic_report()
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: _quota())
    monkeypatch.setattr(v12._v11, "telemetry_snapshot", lambda: _v11())

    assert v12.quota_aware_pipeline_run_status(report) == "DEGRADED"
    assert report["provider_capacity_deferred"] is True
    assert report["provider_capacity"]["active_cooldown_count"] == 2
    assert report["provider_capacity"]["capacity_dominant"] is True
    assert report["provider_capacity"]["full_skip_saturation"] is True


def test_8629_partial_seed_plus_full_capacity_collapse_is_degraded(monkeypatch):
    """Exact production defect class: partial seed does not imply usable capacity."""
    report = _systemic_report()
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: _quota(active_count=4, durable_skips=10))
    monkeypatch.setattr(
        v12._v11,
        "telemetry_snapshot",
        lambda: _v11(seed_attempts=5, seed_successes=1, continuation_attempts=1, continuation_successes=0),
    )

    assert v12.quota_aware_pipeline_run_status(report) == "DEGRADED"
    assert report["provider_capacity"]["durable_provider_skips"] == 10
    assert report["provider_capacity"]["v11_seed_successes"] == 1


def test_8641_near_total_capacity_collapse_is_degraded_not_systemic_failure(monkeypatch):
    """Production #8641: 3 TPD cooldowns + 4/5 durable skips is capacity-dominant."""
    report = _systemic_report()
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(
        v12._quota,
        "telemetry_snapshot",
        lambda: _quota(active_count=3, durable_skips=4, quota_events=3),
    )
    monkeypatch.setattr(
        v12._v11,
        "telemetry_snapshot",
        lambda: _v11(seed_attempts=3, seed_successes=2, continuation_attempts=2, continuation_successes=0),
    )

    assert v12.quota_aware_pipeline_run_status(report) == "DEGRADED"
    assert report["provider_capacity_deferred"] is True
    assert report["provider_capacity"]["full_skip_saturation"] is False
    assert report["provider_capacity"]["near_skip_saturation"] is True
    assert report["provider_capacity"]["quota_events"] == 3


def test_no_active_quota_window_keeps_systemic_failure_red(monkeypatch):
    report = _systemic_report()
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: _quota(active_count=0, durable_skips=10))
    monkeypatch.setattr(v12._v11, "telemetry_snapshot", lambda: _v11())

    assert v12.quota_aware_pipeline_run_status(report) == "FAILED"
    assert "provider_capacity_deferred" not in report


def test_terminal_auth_error_never_downgrades(monkeypatch):
    report = _systemic_report()
    report["posts"][0]["status"] = "auth_error"
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: _quota(active_count=4, durable_skips=10))
    monkeypatch.setattr(v12._v11, "telemetry_snapshot", lambda: _v11())

    assert v12.quota_aware_pipeline_run_status(report) == "FAILED"


def test_single_unrelated_cooldown_does_not_mask_real_quality_failure(monkeypatch):
    report = _systemic_report()
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: _quota(active_count=1, durable_skips=1, quota_events=1))
    monkeypatch.setattr(v12._v11, "telemetry_snapshot", lambda: _v11(seed_successes=1))

    assert v12.quota_aware_pipeline_run_status(report) == "FAILED"


def test_successful_continuation_never_downgrades_quality_failure(monkeypatch):
    report = _systemic_report()
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: _quota(active_count=4, durable_skips=10))
    monkeypatch.setattr(
        v12._v11,
        "telemetry_snapshot",
        lambda: _v11(seed_successes=1, continuation_attempts=1, continuation_successes=1),
    )

    assert v12.quota_aware_pipeline_run_status(report) == "FAILED"


def test_insufficient_durable_skips_keeps_failure_red_without_multiple_quota_events(monkeypatch):
    report = _systemic_report()
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: _quota(active_count=4, durable_skips=4, quota_events=0))
    monkeypatch.setattr(v12._v11, "telemetry_snapshot", lambda: _v11(seed_successes=0))

    assert v12.quota_aware_pipeline_run_status(report) == "FAILED"


def test_near_saturation_with_only_two_cooldowns_does_not_mask_quality_failure(monkeypatch):
    report = _systemic_report()
    monkeypatch.setattr(v12, "_ORIGINAL_PIPELINE_RUN_STATUS", lambda _r: "FAILED")
    monkeypatch.setattr(v12._quota, "telemetry_snapshot", lambda: _quota(active_count=2, durable_skips=4, quota_events=4))
    monkeypatch.setattr(v12._v11, "telemetry_snapshot", lambda: _v11(seed_successes=1))

    assert v12.quota_aware_pipeline_run_status(report) == "FAILED"
