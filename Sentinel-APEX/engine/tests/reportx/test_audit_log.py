"""Tests for sentinel_engine.reportx.audit_log -- append-only guarantee
(Section 15: "never silently change certification state")."""

from __future__ import annotations

import inspect

from sentinel_engine.reportx.audit_log import AuditLogRecord, append_record, read_log


def _record(report_id: str = "r1", state: str = "PREMIUM_AUTOMATED_CERTIFIED") -> AuditLogRecord:
    return AuditLogRecord(
        report_id=report_id, artifact_sha256="a" * 64, release_id="rel-1", timestamp="2026-08-18T00:00:00Z",
        automated_controls="23/23", certification_state=state,
    )


class TestModuleExposesNoMutationPath:
    def test_no_update_or_delete_function_exists(self):
        import sentinel_engine.reportx.audit_log as mod
        public_names = [n for n in dir(mod) if not n.startswith("_")]
        assert not any("update" in n.lower() or "delete" in n.lower() or "overwrite" in n.lower() for n in public_names)

    def test_append_record_only_ever_opens_in_append_mode(self):
        import re
        source = inspect.getsource(append_record)
        open_calls = re.findall(r"open\([^)]*\)", source)
        assert open_calls, "expected at least one open() call in append_record"
        for call in open_calls:
            assert '"a"' in call or "'a'" in call, f"append_record must only open in append mode, found: {call}"


class TestAppendAndRead:
    def test_round_trips_a_single_record(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        append_record(log_path, _record())
        records = read_log(log_path)
        assert len(records) == 1
        assert records[0].report_id == "r1"
        assert records[0].certification_state == "PREMIUM_AUTOMATED_CERTIFIED"

    def test_multiple_appends_accumulate_never_overwrite(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        for i in range(5):
            append_record(log_path, _record(report_id=f"r{i}"))
        records = read_log(log_path)
        assert [r.report_id for r in records] == [f"r{i}" for i in range(5)]

    def test_a_correction_is_a_new_record_not_a_mutation(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        append_record(log_path, _record(report_id="r1", state="PREMIUM_AUTOMATED_CERTIFIED"))
        append_record(log_path, _record(report_id="r1", state="PREMIUM_READY_PENDING_HUMAN"))  # correction
        records = read_log(log_path)
        assert len(records) == 2  # both entries survive -- history is never mutated
        assert records[0].certification_state == "PREMIUM_AUTOMATED_CERTIFIED"
        assert records[1].certification_state == "PREMIUM_READY_PENDING_HUMAN"

    def test_read_log_on_nonexistent_file_is_an_empty_list_not_an_error(self, tmp_path):
        assert read_log(tmp_path / "does-not-exist.jsonl") == []

    def test_creates_parent_directories(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c" / "audit.jsonl"
        append_record(nested, _record())
        assert read_log(nested)
