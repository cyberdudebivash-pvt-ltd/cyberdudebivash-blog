"""Release-level certification (P0 Release-Certification layer).

Section 5's invariant, made structural rather than aspirational: a human-
approved canary certifies that *this release* has demonstrated correct
behaviour across representative cases. It never certifies any individual
future report. This module is the only place that boolean gets decided, and
it decides it from real inputs -- actual 23-control results, actual
``ReviewRecord`` objects resolved through the unmodified
``human_review.resolve_certification_state()``, actual test-suite pass/fail
counts, actual file-content hashes -- never a hand-set flag.

Drift detection hashes real source bytes for every tracked component
(``TRACKED_COMPONENT_PATHS``, repo-root-relative) rather than maintaining a
hand-incremented version number nobody remembers to bump. If a tracked
file's content changes at all, its hash changes, and a previously-certified
release stops being usable for automated certification until it is
re-certified -- see ``detect_drift()``.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from . import __version__ as REPORTX_ENGINE_VERSION
from .human_review import CertificationState, ReviewRecord, resolve_certification_state

# Repo-root-relative paths for every component whose content changing means
# "the certified release no longer describes what's actually running."
# Covers System 3 (the claim/evidence/schema/validator layer), System 4 (the
# renderer), and System 5 (the JS adapter + composition engine) named in
# Section 8 -- deliberately omits report *content* files (canary modules,
# fixtures), which are not part of "the release" in this sense.
TRACKED_COMPONENT_PATHS: dict[str, str] = {
    "claim_schema": "Sentinel-APEX/engine/sentinel_engine/reportx/claim_model.py",
    "evidence_schema": "Sentinel-APEX/engine/sentinel_engine/reportx/evidence_integrity.py",
    "threat_schemas": "Sentinel-APEX/engine/sentinel_engine/reportx/threat_schemas.py",
    "commercial_validator": "Sentinel-APEX/engine/sentinel_engine/reportx/commercial_readiness.py",
    "quality_gates": "Sentinel-APEX/engine/sentinel_engine/reportx/qa_linter.py",
    "contradiction_engine": "Sentinel-APEX/engine/sentinel_engine/reportx/contradiction_engine.py",
    "claim_support_matrix": "Sentinel-APEX/engine/sentinel_engine/reportx/claim_support_matrix.py",
    "detection_governance": "Sentinel-APEX/engine/sentinel_engine/reportx/detection_validation.py",
    "human_review_governance": "Sentinel-APEX/engine/sentinel_engine/reportx/human_review.py",
    "product_depth": "Sentinel-APEX/engine/sentinel_engine/reportx/product_depth.py",
    "regulatory_policy": "Sentinel-APEX/engine/sentinel_engine/reportx/regulatory.py",
    "statistics_registry_policy": "Sentinel-APEX/engine/sentinel_engine/reportx/metrics_registry.py",
    "forecast_methodology": "Sentinel-APEX/engine/sentinel_engine/reportx/forecast.py",
    "analytic_scaffolding": "Sentinel-APEX/engine/sentinel_engine/reportx/analytic_scaffolding.py",
    "bundle_io": "Sentinel-APEX/engine/sentinel_engine/reportx/bundle_io.py",
    "renderer": "Sentinel-APEX/renderer/report-renderer.js",
    "renderer_certification": "Sentinel-APEX/renderer/certify-rendering.js",
    "system5_adapter": "api/_lib/reportx-adapter.js",
    "system5_composition_engine": "api/_lib/product-composition-engine.js",
}

# The 4 canaries Section 4 requires -- exactly the four real, evidence-backed
# premium reports this platform has ever built (REPORTX-CANARY-CERTIFICATION.md).
# A release cannot certify without every one of these, by name, at 23/23 AND
# PREMIUM_CERTIFIED -- adding a fifth required canary later is a deliberate,
# documented decision, not something this list silently grows into.
REQUIRED_CANARY_IDS: tuple[str, ...] = (
    "qilin-spoonful-of-comfort-premium-canary",
    "medusalocker-bija-industrie-premium-canary",
    "dragonforce-vermont-xcenter-premium-canary",
    "cve-2025-62593-ray-canary",
)


def default_repo_root() -> Path:
    """This file lives at <repo>/Sentinel-APEX/engine/sentinel_engine/reportx/
    release_certification.py -- five ``.parent`` hops reach the repo root."""
    return Path(__file__).resolve().parents[4]


def compute_component_hashes(repo_root: Path, paths: dict[str, str] | None = None) -> dict[str, str | None]:
    """Real SHA-256 of each tracked file's actual current bytes. ``None``
    (never a fabricated hash) for a path that doesn't exist on disk."""
    paths = paths if paths is not None else TRACKED_COMPONENT_PATHS
    hashes: dict[str, str | None] = {}
    for name, rel_path in paths.items():
        full = repo_root / rel_path
        if not full.is_file():
            hashes[name] = None
            continue
        hashes[name] = hashlib.sha256(full.read_bytes()).hexdigest()
    return hashes


def compute_dependency_lock_hash(repo_root: Path) -> str | None:
    """Hashes the one real dependency lock file this repository has
    (``package-lock.json`` — the JS side System 4/5 depend on). The Python
    engine package has no lock file of its own (stdlib-only); that is a
    documented fact (REPORTX-RELEASE-CERTIFICATION.md), not something this
    function papers over with a fabricated hash."""
    lock = repo_root / "package-lock.json"
    if not lock.is_file():
        return None
    return hashlib.sha256(lock.read_bytes()).hexdigest()


def current_git_commit_sha(repo_root: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(repo_root),
            capture_output=True, text=True, check=True, timeout=10,
        )
        return out.stdout.strip()
    except Exception:
        return ""


class ReleaseState(str, Enum):
    NOT_CERTIFIED = "NOT_CERTIFIED"
    REPORTX_RELEASE_CERTIFIED = "REPORTX_RELEASE_CERTIFIED"
    REPORTX_RELEASE_REVIEW_REQUIRED = "REPORTX_RELEASE_REVIEW_REQUIRED"


@dataclass(frozen=True)
class CanaryCertificationInput:
    """What ``certify_release()`` needs to know about one canary -- real
    23-control counts and a real (or absent) ``ReviewRecord``, never a
    hand-set boolean standing in for either."""

    canary_id: str
    artifact_sha256: str
    rendered_text: str
    commercial_readiness_pass_count: int
    commercial_readiness_total_count: int
    review: ReviewRecord | None = None

    def resolved_certification_state(self) -> CertificationState:
        return resolve_certification_state(
            automated_gates_passed=True, is_premium_tier=True,
            review=self.review, current_artifact_text=self.rendered_text,
        )


@dataclass(frozen=True)
class SuiteResult:
    suite_name: str
    passed: int
    failed: int

    @property
    def all_passed(self) -> bool:
        return self.failed == 0

    def to_dict(self) -> dict:
        return {"suite_name": self.suite_name, "passed": self.passed, "failed": self.failed}


@dataclass(frozen=True)
class ReleaseCertificationManifest:
    release_id: str
    reportx_engine_version: str
    git_commit_sha: str
    claim_schema_version: str
    quality_gate_version: str
    commercial_validator_version: str
    threat_schema_versions: str
    renderer_version: str
    system5_adapter_version: str
    component_hashes: dict[str, str | None]
    dependency_lock_hash: str | None
    certification_timestamp: str
    certified_canary_ids: tuple[str, ...]
    certified_canary_artifact_hashes: dict[str, str]
    certified_canary_review_record_hashes: dict[str, str]
    test_results: tuple[SuiteResult, ...]
    reviewer_identity: str
    release_decision: ReleaseState
    failed_requirements: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_certified(self) -> bool:
        return self.release_decision == ReleaseState.REPORTX_RELEASE_CERTIFIED

    def manifest_hash(self) -> str:
        """Hash of the manifest's own canonical serialization -- changing
        any field (including a component hash from a drift re-check) changes
        this hash, so the manifest file itself is tamper-evident."""
        canonical = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {
            "release_id": self.release_id,
            "reportx_engine_version": self.reportx_engine_version,
            "git_commit_sha": self.git_commit_sha,
            "claim_schema_version": self.claim_schema_version,
            "quality_gate_version": self.quality_gate_version,
            "commercial_validator_version": self.commercial_validator_version,
            "threat_schema_versions": self.threat_schema_versions,
            "renderer_version": self.renderer_version,
            "system5_adapter_version": self.system5_adapter_version,
            "component_hashes": self.component_hashes,
            "dependency_lock_hash": self.dependency_lock_hash,
            "certification_timestamp": self.certification_timestamp,
            "certified_canary_ids": list(self.certified_canary_ids),
            "certified_canary_artifact_hashes": self.certified_canary_artifact_hashes,
            "certified_canary_review_record_hashes": self.certified_canary_review_record_hashes,
            "test_results": [t.to_dict() for t in self.test_results],
            "reviewer_identity": self.reviewer_identity,
            "release_decision": self.release_decision.value,
            "failed_requirements": list(self.failed_requirements),
        }


def manifest_from_dict(d: dict) -> ReleaseCertificationManifest:
    return ReleaseCertificationManifest(
        release_id=d["release_id"], reportx_engine_version=d.get("reportx_engine_version", ""),
        git_commit_sha=d.get("git_commit_sha", ""), claim_schema_version=d.get("claim_schema_version", ""),
        quality_gate_version=d.get("quality_gate_version", ""),
        commercial_validator_version=d.get("commercial_validator_version", ""),
        threat_schema_versions=d.get("threat_schema_versions", ""),
        renderer_version=d.get("renderer_version", ""), system5_adapter_version=d.get("system5_adapter_version", ""),
        component_hashes=d.get("component_hashes", {}), dependency_lock_hash=d.get("dependency_lock_hash"),
        certification_timestamp=d.get("certification_timestamp", ""),
        certified_canary_ids=tuple(d.get("certified_canary_ids", [])),
        certified_canary_artifact_hashes=d.get("certified_canary_artifact_hashes", {}),
        certified_canary_review_record_hashes=d.get("certified_canary_review_record_hashes", {}),
        test_results=tuple(
            SuiteResult(t["suite_name"], t["passed"], t["failed"]) for t in d.get("test_results", [])
        ),
        reviewer_identity=d.get("reviewer_identity", ""),
        release_decision=ReleaseState(d["release_decision"]),
        failed_requirements=tuple(d.get("failed_requirements", [])),
    )


def certify_release(
    release_id: str,
    canaries: list[CanaryCertificationInput],
    test_results: list[SuiteResult],
    render_qa_passed: bool,
    system5_tests_passed: bool,
    anti_padding_passed: bool,
    npm_audit_passed: bool,
    reviewer_identity: str,
    repo_root: Path | None = None,
    required_canary_ids: tuple[str, ...] = REQUIRED_CANARY_IDS,
) -> ReleaseCertificationManifest:
    """Section 4's boolean AND, computed from real inputs. Every failure
    reason is recorded in ``failed_requirements`` -- there is no code path
    in this function that produces ``REPORTX_RELEASE_CERTIFIED`` while a
    requirement silently failed."""

    repo_root = repo_root if repo_root is not None else default_repo_root()
    failed: list[str] = []

    by_id = {c.canary_id: c for c in canaries}
    missing = [cid for cid in required_canary_ids if cid not in by_id]
    if missing:
        failed.append(f"missing required canaries: {sorted(missing)}")

    present_required = [by_id[cid] for cid in required_canary_ids if cid in by_id]

    not_23of23 = [
        c.canary_id for c in present_required
        if c.commercial_readiness_pass_count != c.commercial_readiness_total_count
    ]
    if not_23of23:
        failed.append(f"canaries not 23/23 PASS: {sorted(not_23of23)}")

    not_premium_certified = [
        f"{c.canary_id} ({c.resolved_certification_state().value})"
        for c in present_required
        if c.resolved_certification_state() != CertificationState.PREMIUM_CERTIFIED
    ]
    if not_premium_certified:
        failed.append(f"canaries not PREMIUM_CERTIFIED: {sorted(not_premium_certified)}")

    failed_suites = [t.suite_name for t in test_results if not t.all_passed]
    if failed_suites:
        failed.append(f"regression suites with failures: {sorted(failed_suites)}")
    if not test_results:
        failed.append("no regression test results supplied")

    if not render_qa_passed:
        failed.append("render QA did not pass")
    if not system5_tests_passed:
        failed.append("System 5 tests did not pass")
    if not anti_padding_passed:
        failed.append("cross-canary anti-padding did not pass")
    if not npm_audit_passed:
        failed.append("npm audit did not pass")

    decision = ReleaseState.NOT_CERTIFIED if failed else ReleaseState.REPORTX_RELEASE_CERTIFIED

    component_hashes = compute_component_hashes(repo_root)

    return ReleaseCertificationManifest(
        release_id=release_id,
        reportx_engine_version=REPORTX_ENGINE_VERSION,
        git_commit_sha=current_git_commit_sha(repo_root),
        claim_schema_version=component_hashes.get("claim_schema") or "",
        quality_gate_version=component_hashes.get("quality_gates") or "",
        commercial_validator_version=component_hashes.get("commercial_validator") or "",
        threat_schema_versions=component_hashes.get("threat_schemas") or "",
        renderer_version=component_hashes.get("renderer") or "",
        system5_adapter_version=component_hashes.get("system5_adapter") or "",
        component_hashes=component_hashes,
        dependency_lock_hash=compute_dependency_lock_hash(repo_root),
        certification_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        certified_canary_ids=tuple(c.canary_id for c in present_required),
        certified_canary_artifact_hashes={c.canary_id: c.artifact_sha256 for c in present_required},
        certified_canary_review_record_hashes={
            c.canary_id: hashlib.sha256(json.dumps(c.review.to_dict(), sort_keys=True).encode("utf-8")).hexdigest()
            for c in present_required if c.review is not None
        },
        test_results=tuple(test_results),
        reviewer_identity=reviewer_identity,
        release_decision=decision,
        failed_requirements=tuple(failed),
    )


@dataclass(frozen=True)
class DriftResult:
    drifted: bool
    changed_components: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {"drifted": self.drifted, "changed_components": list(self.changed_components)}


def detect_drift(manifest: ReleaseCertificationManifest, repo_root: Path | None = None) -> DriftResult:
    """Compares the manifest's recorded component hashes against the
    CURRENT file bytes on disk right now. Any tracked file added, removed,
    or edited since certification shows up here by name."""
    repo_root = repo_root if repo_root is not None else default_repo_root()
    current = compute_component_hashes(repo_root)
    changed = tuple(sorted(
        name for name, current_hash in current.items()
        if manifest.component_hashes.get(name) != current_hash
    ))
    return DriftResult(drifted=bool(changed), changed_components=changed)


def apply_drift_check(
    manifest: ReleaseCertificationManifest, repo_root: Path | None = None,
) -> ReleaseCertificationManifest:
    """Section 8: ``REPORTX_RELEASE_CERTIFIED -> REPORTX_RELEASE_REVIEW_REQUIRED``
    the moment a tracked component drifts. A manifest that was never
    certified in the first place (``NOT_CERTIFIED``) has nothing to drift
    away from, so it passes through unchanged."""
    if manifest.release_decision != ReleaseState.REPORTX_RELEASE_CERTIFIED:
        return manifest
    drift = detect_drift(manifest, repo_root)
    if not drift.drifted:
        return manifest
    return replace(
        manifest,
        release_decision=ReleaseState.REPORTX_RELEASE_REVIEW_REQUIRED,
        failed_requirements=manifest.failed_requirements + (
            f"component drift detected since certification: {list(drift.changed_components)}",
        ),
    )


def render_release_report(manifest: ReleaseCertificationManifest) -> str:
    lines = [
        "REPORTX RELEASE CERTIFICATION", "",
        f"Release ID: {manifest.release_id}",
        f"Engine version: {manifest.reportx_engine_version}",
        f"Git commit: {manifest.git_commit_sha}",
        f"Certified at: {manifest.certification_timestamp}",
        f"Reviewer of record: {manifest.reviewer_identity}",
        "",
        f"Certified canaries ({len(manifest.certified_canary_ids)}):",
    ]
    for cid in manifest.certified_canary_ids:
        artifact = manifest.certified_canary_artifact_hashes.get(cid, "")[:16]
        has_review = "review on file" if cid in manifest.certified_canary_review_record_hashes else "NO REVIEW ON FILE"
        lines.append(f"  - {cid}: artifact {artifact}... ({has_review})")
    lines += ["", "Test results:"]
    for t in manifest.test_results:
        status = "PASS" if t.all_passed else "FAIL"
        lines.append(f"  - {t.suite_name}: {t.passed} passed, {t.failed} failed [{status}]")
    lines += ["", f"RELEASE DECISION: {manifest.release_decision.value}"]
    if manifest.failed_requirements:
        lines += ["", "Failed requirements:"]
        lines += [f"  - {f}" for f in manifest.failed_requirements]
    lines += ["", f"Manifest hash: {manifest.manifest_hash()}"]
    return "\n".join(lines)
