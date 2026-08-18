"""Tests for `cli.py reportx-release` and `cli.py reportx-certify`.

Exercises the actual CLI entry points (cli.main()) end-to-end against the
real canary export artifacts this repo ships, chaining through the
EXISTING (unmodified) `reportx-review approve` command for every review
record used here -- every reviewer identity in this file is explicitly
"TEST-ONLY", exactly like test_reportx_review_cli.py's own convention.
None of this constitutes, or is meant to resemble, a real operator
approval.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import cli
from sentinel_engine.reportx.human_review import CertificationState, is_review_valid_for_artifact, resolve_certification_state
from sentinel_engine.reportx.release_certification import REQUIRED_CANARY_IDS, default_repo_root, manifest_from_dict

REPO_ROOT = default_repo_root()
EXPORTS_DIR = REPO_ROOT / "reportx-canary" / "exports"

CANARY_EXPORT_FILES = {
    "qilin-spoonful-of-comfort-premium-canary": "qilin-spoonful-of-comfort-premium-canary-export.json",
    "medusalocker-bija-industrie-premium-canary": "medusalocker-bija-industrie-premium-canary-export.json",
    "dragonforce-vermont-xcenter-premium-canary": "dragonforce-vermont-xcenter-premium-canary-export.json",
    "cve-2025-62593-ray-canary": "cve-2025-62593-ray-canary-export.json",
}


def _copy_exports_only(tmp_path: Path) -> Path:
    """Isolated copies of the four real canary exports with NO sibling
    REVIEW-RECORD.json -- unlike EXPORTS_DIR (the shared, real
    reportx-canary/exports/ directory), which may legitimately carry real
    review records and other real export artifacts committed by other
    work. Tests asserting "not yet approved"/"not certified" behavior must
    use this isolated copy, not EXPORTS_DIR directly, so they stay
    correct regardless of what's genuinely been approved in the shared
    directory."""
    for filename in CANARY_EXPORT_FILES.values():
        (tmp_path / filename).write_text((EXPORTS_DIR / filename).read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


def _approve_all_four_via_real_cli(tmp_path: Path) -> Path:
    """Copies all four real exports into tmp_path, runs the real
    `reportx-review approve` CLI (TEST-ONLY reviewer) on each so its
    sibling REVIEW-RECORD.json is discoverable by `reportx-release
    certify`'s auto-discovery convention, and returns tmp_path."""
    for canary_id, filename in CANARY_EXPORT_FILES.items():
        src = EXPORTS_DIR / filename
        dst = tmp_path / filename
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        review_out = tmp_path / f"{canary_id}-REVIEW-RECORD.json"
        rc = cli.main([
            "reportx-review", "approve", str(dst),
            "--reviewer", "TEST-ONLY CI Reviewer", "--role", "TEST-ONLY",
            "--out", str(review_out),
        ])
        assert rc == 0
    return tmp_path


class TestReleaseCertifyEndToEnd:
    def test_certifies_when_all_four_canaries_are_approved(self, tmp_path, capsys):
        work_dir = _approve_all_four_via_real_cli(tmp_path)
        manifest_out = tmp_path / "manifest.json"
        args = ["reportx-release", "certify", "--release-id", "cli-test-release"]
        for filename in CANARY_EXPORT_FILES.values():
            args += ["--canary", str(work_dir / filename)]
        args += [
            "--test-result", "engine:649:0", "--test-result", "js:1688:0",
            "--render-qa", "pass", "--system5-tests", "pass", "--anti-padding", "pass", "--npm-audit", "pass",
            "--reviewer", "TEST-ONLY Release Operator", "--out", str(manifest_out),
        ]
        rc = cli.main(args)
        assert rc == 0
        manifest = manifest_from_dict(json.loads(manifest_out.read_text()))
        assert manifest.is_certified
        assert set(manifest.certified_canary_ids) == set(REQUIRED_CANARY_IDS)
        captured = capsys.readouterr()
        assert "REPORTX_RELEASE_CERTIFIED" in captured.out

    def test_refuses_when_no_canary_is_approved(self, tmp_path, capsys):
        work_dir = _copy_exports_only(tmp_path)
        manifest_out = tmp_path / "manifest.json"
        args = ["reportx-release", "certify", "--release-id", "cli-test-unapproved"]
        for filename in CANARY_EXPORT_FILES.values():
            args += ["--canary", str(work_dir / filename)]
        args += [
            "--test-result", "engine:649:0",
            "--render-qa", "pass", "--system5-tests", "pass", "--anti-padding", "pass", "--npm-audit", "pass",
            "--reviewer", "TEST-ONLY Release Operator", "--out", str(manifest_out),
        ]
        rc = cli.main(args)
        assert rc == 1
        manifest = manifest_from_dict(json.loads(manifest_out.read_text()))
        assert not manifest.is_certified
        assert any("not PREMIUM_CERTIFIED" in f for f in manifest.failed_requirements)

    @pytest.mark.parametrize("flag,value", [("--render-qa", "fail"), ("--system5-tests", "fail"),
                                             ("--anti-padding", "fail"), ("--npm-audit", "fail")])
    def test_a_failed_boolean_gate_refuses_certification(self, tmp_path, flag, value):
        work_dir = _approve_all_four_via_real_cli(tmp_path)
        manifest_out = tmp_path / "manifest.json"
        gates = {"--render-qa": "pass", "--system5-tests": "pass", "--anti-padding": "pass", "--npm-audit": "pass"}
        gates[flag] = value
        args = ["reportx-release", "certify", "--release-id", "cli-test-gate"]
        for filename in CANARY_EXPORT_FILES.values():
            args += ["--canary", str(work_dir / filename)]
        args += ["--test-result", "engine:649:0"]
        for k, v in gates.items():
            args += [k, v]
        args += ["--reviewer", "TEST-ONLY", "--out", str(manifest_out)]
        rc = cli.main(args)
        assert rc == 1


class TestReleaseInspectStatusVerifyInvalidate:
    def _certify(self, tmp_path) -> Path:
        work_dir = _approve_all_four_via_real_cli(tmp_path)
        manifest_out = tmp_path / "manifest.json"
        args = ["reportx-release", "certify", "--release-id", "cli-lifecycle-test"]
        for filename in CANARY_EXPORT_FILES.values():
            args += ["--canary", str(work_dir / filename)]
        args += [
            "--test-result", "engine:649:0",
            "--render-qa", "pass", "--system5-tests", "pass", "--anti-padding", "pass", "--npm-audit", "pass",
            "--reviewer", "TEST-ONLY Release Operator", "--out", str(manifest_out),
        ]
        assert cli.main(args) == 0
        return manifest_out

    def test_inspect_prints_the_stored_manifest(self, tmp_path, capsys):
        manifest_out = self._certify(tmp_path)
        rc = cli.main(["reportx-release", "inspect", str(manifest_out)])
        assert rc == 0
        assert "REPORTX_RELEASE_CERTIFIED" in capsys.readouterr().out

    def test_status_is_read_only(self, tmp_path):
        manifest_out = self._certify(tmp_path)
        before = manifest_out.read_text()
        rc = cli.main(["reportx-release", "status", str(manifest_out)])
        assert rc == 0
        assert manifest_out.read_text() == before  # status never rewrites the file

    def test_verify_stays_certified_when_nothing_drifted(self, tmp_path):
        manifest_out = self._certify(tmp_path)
        rc = cli.main(["reportx-release", "verify", str(manifest_out)])
        assert rc == 0
        manifest = manifest_from_dict(json.loads(manifest_out.read_text()))
        assert manifest.is_certified

    def test_invalidate_forces_review_required_and_persists(self, tmp_path):
        manifest_out = self._certify(tmp_path)
        rc = cli.main(["reportx-release", "invalidate", str(manifest_out), "--reason", "TEST-ONLY: manual invalidation drill"])
        assert rc == 0
        manifest = manifest_from_dict(json.loads(manifest_out.read_text()))
        assert not manifest.is_certified
        assert any("manual invalidation drill" in f for f in manifest.failed_requirements)


class TestReportxCertifyCLI:
    def _certified_manifest(self, tmp_path) -> Path:
        work_dir = _approve_all_four_via_real_cli(tmp_path)
        manifest_out = tmp_path / "manifest.json"
        args = ["reportx-release", "certify", "--release-id", "cli-certify-test"]
        for filename in CANARY_EXPORT_FILES.values():
            args += ["--canary", str(work_dir / filename)]
        args += [
            "--test-result", "engine:649:0",
            "--render-qa", "pass", "--system5-tests", "pass", "--anti-padding", "pass", "--npm-audit", "pass",
            "--reviewer", "TEST-ONLY Release Operator", "--out", str(manifest_out),
        ]
        assert cli.main(args) == 0
        return manifest_out

    def test_single_artifact_certify_reaches_automated_certified(self, tmp_path, capsys):
        manifest_out = self._certified_manifest(tmp_path)
        target = EXPORTS_DIR / CANARY_EXPORT_FILES["qilin-spoonful-of-comfort-premium-canary"]
        rc = cli.main(["reportx-certify", str(target), "--release-manifest", str(manifest_out)])
        assert rc == 0
        assert "PREMIUM_AUTOMATED_CERTIFIED" in capsys.readouterr().out

    def test_single_artifact_certify_without_certified_release_refuses(self, tmp_path, capsys):
        # An uncertified manifest (all four still unapproved) refuses automated certification.
        work_dir = _copy_exports_only(tmp_path)
        manifest_out = tmp_path / "uncertified.json"
        args = ["reportx-release", "certify", "--release-id", "uncertified"]
        for filename in CANARY_EXPORT_FILES.values():
            args += ["--canary", str(work_dir / filename)]
        args += [
            "--test-result", "engine:649:0",
            "--render-qa", "pass", "--system5-tests", "pass", "--anti-padding", "pass", "--npm-audit", "pass",
            "--reviewer", "TEST-ONLY", "--out", str(manifest_out),
        ]
        cli.main(args)  # rc == 1, expected -- not certified

        target = work_dir / CANARY_EXPORT_FILES["cve-2025-62593-ray-canary"]
        rc = cli.main(["reportx-certify", str(target), "--release-manifest", str(manifest_out)])
        assert rc == 1
        out = capsys.readouterr().out
        assert "PREMIUM_READY_PENDING_HUMAN" in out
        assert "PREMIUM_AUTOMATED_CERTIFIED" not in out.split("\n")[0]

    def test_batch_certifies_every_export_in_a_directory(self, tmp_path, capsys):
        # _certified_manifest() copies exactly the four required canary
        # exports into tmp_path itself (via _approve_all_four_via_real_cli) --
        # batch against tmp_path, not the shared real EXPORTS_DIR, so this
        # test's exact-count assertion stays correct regardless of how many
        # other real export artifacts the shared directory legitimately
        # accumulates over time (e.g. the flagship product's own export).
        manifest_out = self._certified_manifest(tmp_path)
        audit_log = tmp_path / "audit.jsonl"
        rc = cli.main([
            "reportx-certify", "batch", str(tmp_path),
            "--release-manifest", str(manifest_out), "--audit-log", str(audit_log),
        ])
        assert rc == 0
        out = capsys.readouterr().out
        for canary_id in REQUIRED_CANARY_IDS:
            assert canary_id in out
        from sentinel_engine.reportx.audit_log import read_log
        records = read_log(audit_log)
        assert len(records) == 4
        assert all(r.release_id == "cli-certify-test" for r in records)


class TestRealApprovalTransitionsExactArtifactToPremiumCertified:
    """Section 17 test #12 -- via the real, unmodified CLI."""

    def test_cli_approve_resolves_to_premium_certified(self, tmp_path):
        src = EXPORTS_DIR / CANARY_EXPORT_FILES["qilin-spoonful-of-comfort-premium-canary"]
        export_copy = tmp_path / "export.json"
        export_copy.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        review_out = tmp_path / "review.json"

        rc = cli.main([
            "reportx-review", "approve", str(export_copy),
            "--reviewer", "TEST-ONLY CI Reviewer", "--role", "TEST-ONLY",
            "--out", str(review_out),
        ])
        assert rc == 0

        from sentinel_engine.reportx.human_review import ReviewDecision, ReviewRecord
        review_dict = json.loads(review_out.read_text())
        review = ReviewRecord(
            report_id=review_dict["report_id"], artifact_sha256=review_dict["artifact_sha256"],
            reviewer_identity=review_dict["reviewer_identity"], review_timestamp=review_dict["review_timestamp"],
            decision=ReviewDecision(review_dict["decision"]), review_version=review_dict["review_version"],
            is_test_only_fixture=True,
        )
        export = json.loads(export_copy.read_text())
        state = resolve_certification_state(True, True, review, export["bundle"]["rendered_text"])
        assert state == CertificationState.PREMIUM_CERTIFIED


class TestArtifactEditInvalidatesHumanApproval:
    """Section 17 test #13 -- via the real, unmodified CLI."""

    def test_editing_the_artifact_after_approval_invalidates_it(self, tmp_path):
        src = EXPORTS_DIR / CANARY_EXPORT_FILES["medusalocker-bija-industrie-premium-canary"]
        export_copy = tmp_path / "export.json"
        export_copy.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        review_out = tmp_path / "review.json"

        rc = cli.main([
            "reportx-review", "approve", str(export_copy),
            "--reviewer", "TEST-ONLY CI Reviewer", "--out", str(review_out),
        ])
        assert rc == 0

        from sentinel_engine.reportx.human_review import ReviewDecision, ReviewRecord
        review_dict = json.loads(review_out.read_text())
        review = ReviewRecord(
            report_id=review_dict["report_id"], artifact_sha256=review_dict["artifact_sha256"],
            reviewer_identity=review_dict["reviewer_identity"], review_timestamp=review_dict["review_timestamp"],
            decision=ReviewDecision(review_dict["decision"]), review_version=review_dict["review_version"],
            is_test_only_fixture=True,
        )
        export = json.loads(export_copy.read_text())
        original_text = export["bundle"]["rendered_text"]
        assert is_review_valid_for_artifact(review, original_text)

        edited_text = original_text + "\n"  # a single trailing whitespace edit
        assert not is_review_valid_for_artifact(review, edited_text)
        state = resolve_certification_state(True, True, review, edited_text)
        assert state == CertificationState.PREMIUM_READY_PENDING_HUMAN
        assert state != CertificationState.PREMIUM_CERTIFIED
