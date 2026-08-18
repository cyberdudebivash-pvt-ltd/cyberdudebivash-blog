"""Append-only certification audit log (P0 Release-Certification layer,
Section 15).

"Never silently change certification state" is enforced structurally, not
by convention: this module exposes ``append_record()`` and ``read_log()``
only — there is no update or delete function anywhere in it. A correction
is a NEW record with a later timestamp, not a mutation of history. The log
is JSON Lines (one record per line) so appending never requires reading or
rewriting the existing file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AuditLogRecord:
    report_id: str
    artifact_sha256: str
    release_id: str
    timestamp: str
    automated_controls: str  # e.g. "23/23" or "21/23" summary
    certification_state: str
    escalation_reason: str = ""
    downgrade_reason: str = ""
    human_review_required: bool = False
    human_review_record_ref: str = ""

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id, "artifact_sha256": self.artifact_sha256,
            "release_id": self.release_id, "timestamp": self.timestamp,
            "automated_controls": self.automated_controls, "certification_state": self.certification_state,
            "escalation_reason": self.escalation_reason, "downgrade_reason": self.downgrade_reason,
            "human_review_required": self.human_review_required,
            "human_review_record_ref": self.human_review_record_ref,
        }


def record_from_dict(d: dict) -> AuditLogRecord:
    return AuditLogRecord(
        report_id=d["report_id"], artifact_sha256=d["artifact_sha256"], release_id=d.get("release_id", ""),
        timestamp=d["timestamp"], automated_controls=d.get("automated_controls", ""),
        certification_state=d["certification_state"], escalation_reason=d.get("escalation_reason", ""),
        downgrade_reason=d.get("downgrade_reason", ""),
        human_review_required=d.get("human_review_required", False),
        human_review_record_ref=d.get("human_review_record_ref", ""),
    )


def append_record(path: Path, record: AuditLogRecord) -> None:
    """The only write path this module offers. Opens in append mode
    exclusively — there is no ``"w"`` anywhere in this file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")


def read_log(path: Path) -> list[AuditLogRecord]:
    if not path.exists():
        return []
    records: list[AuditLogRecord] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            records.append(record_from_dict(json.loads(line)))
    return records
