"""Audit and safely quarantine high-risk legacy Blogger reports.

The default mode is read-only and emits a quality manifest. Apply mode is
deliberately explicit, preserves the original HTML in the manifest, and
replaces only posts with objective evidence-integrity violations.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .blogger_publisher import BloggerPublisher
from .config import Config


_ACTIVE_EXPLOITATION = re.compile(
    r"active exploitation confirmed|actively exploited in the wild|exploitation is confirmed active",
    re.IGNORECASE,
)
_KEV_NOT_LISTED = re.compile(r"(?:cisa\s+)?kev.{0,80}not listed|not listed.{0,80}(?:cisa\s+)?kev", re.IGNORECASE | re.DOTALL)
_PLACEHOLDERS = re.compile(
    r"not found sector|country of ai|00000000-0000-0000-0000-000000000000|\b(?:change[_ -]?me|todo|tbd)\b",
    re.IGNORECASE,
)
_HUMAN_ATTRIBUTION = re.compile(
    r"bivash kumar nayak\s*[—-]\s*chief security architect",
    re.IGNORECASE,
)
_RANSOMWARE_SCHEMA = re.compile(
    r"pre-exploitation|patch availability|web application exploitation|sigma detection rule",
    re.IGNORECASE,
)
_AI_SCHEMA = re.compile(
    r"office application shell spawn|phishing detection logic|web service spawning a command interpreter",
    re.IGNORECASE,
)
_UNSUPPORTED_SCALE = re.compile(r"2,400\+|10,000\+|40\+\s+TI sources|trusted by\s+\d[\d,]*\+", re.IGNORECASE)
_SOURCE_COMMENT = re.compile(r"<!--\s*Source:\s*(https?://[^\s>]+)\s*-->", re.IGNORECASE)


@dataclass
class LegacyFinding:
    post_id: str
    title: str
    url: str
    published: str
    updated: str
    source_url: Optional[str]
    original_content_sha256: str
    reasons: list[str]
    legacy_control_missing: bool
    eligible_for_quarantine: bool
    action: str = "none"
    original_content: Optional[str] = None


def _source_url(content: str) -> Optional[str]:
    match = _SOURCE_COMMENT.search(content)
    return html.unescape(match.group(1)) if match else None


def inspect_legacy_post(post: dict) -> LegacyFinding:
    """Return deterministic findings for one Blogger Post resource."""
    content = str(post.get("content") or "")
    title = str(post.get("title") or "")
    labels = {str(item).lower() for item in post.get("labels") or []}
    combined = f"{title}\n{content}"
    reasons: list[str] = []

    if _KEV_NOT_LISTED.search(content) and _ACTIVE_EXPLOITATION.search(content):
        reasons.append("kev_exploitation_contradiction")
    if _PLACEHOLDERS.search(combined):
        reasons.append("placeholder_output")
    if _HUMAN_ATTRIBUTION.search(content):
        reasons.append("unverified_human_attribution")

    is_ransomware = "ransomware" in title.lower() or "ransomware" in labels
    if is_ransomware and _RANSOMWARE_SCHEMA.search(content):
        reasons.append("ransomware_schema_contamination")

    is_ai = "ai security" in labels or bool(re.search(r"\b(?:AI|LLM|large language model)\b", title, re.IGNORECASE))
    if is_ai and _AI_SCHEMA.search(content):
        reasons.append("ai_schema_contamination")
    if _UNSUPPORTED_SCALE.search(content):
        reasons.append("unsupported_commercial_scale_claim")

    reasons = sorted(set(reasons))
    return LegacyFinding(
        post_id=str(post.get("id") or ""),
        title=title,
        url=str(post.get("url") or ""),
        published=str(post.get("published") or ""),
        updated=str(post.get("updated") or ""),
        source_url=_source_url(content),
        original_content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        reasons=reasons,
        legacy_control_missing='data-report-id="CDB-CTI-' not in content,
        eligible_for_quarantine=bool(reasons),
    )


def build_quarantine_notice(finding: LegacyFinding, quarantined_at: str) -> str:
    """Create a transparent, source-preserving replacement for unsafe output."""
    reason_rows = "".join(f"<li>{html.escape(reason.replace('_', ' ').title())}</li>" for reason in finding.reasons)
    source = (
        f'<a href="{html.escape(finding.source_url, quote=True)}" target="_blank" rel="noopener noreferrer">Open the cited source record</a>'
        if finding.source_url
        else "The legacy record did not preserve a machine-readable source URL."
    )
    return f"""
<article data-publication-status="withdrawn-evidence-review" style="max-width:900px;margin:32px auto;padding:28px;background:#090d14;border:1px solid #f59e0b;border-radius:10px;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <div style="color:#f59e0b;font-family:monospace;font-size:12px;font-weight:900;letter-spacing:1.4px">AUTOMATED REPORT WITHDRAWN — EVIDENCE REVIEW</div>
  <h2 style="margin:14px 0;color:#fff">This legacy report is not approved for operational or customer use.</h2>
  <p style="line-height:1.7;color:#cbd5e1">The previous automated body predated the current evidence-integrity controls and contained one or more objective integrity defects. It has been quarantined rather than silently corrected. This notice is not a claim that the cited security event is false.</p>
  <div style="margin:18px 0;padding:16px;background:#111827;border-left:3px solid #ef4444">
    <strong>Integrity findings</strong>
    <ul style="line-height:1.8">{reason_rows}</ul>
  </div>
  <p style="line-height:1.7">{source}</p>
  <div style="margin-top:20px;padding-top:14px;border-top:1px solid #334155;color:#94a3b8;font-family:monospace;font-size:11px;line-height:1.7">
    Original content SHA-256: {finding.original_content_sha256}<br>
    Quarantined UTC: {html.escape(quarantined_at)}<br>
    Review status: Automated quarantine — human reassessment required<br>
    Certification: Withdrawn — not a certified customer deliverable
  </div>
</article>
""".strip()


def audit_recent_posts(
    publisher: BloggerPublisher,
    max_posts: int,
    apply: bool = False,
    now: Optional[datetime] = None,
) -> dict:
    if max_posts < 1 or max_posts > 500:
        raise ValueError("max_posts must be between 1 and 500")
    checked_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    posts = publisher.list_recent_posts(max_results=max_posts)
    findings = [inspect_legacy_post(post) for post in posts]
    candidates = [item for item in findings if item.eligible_for_quarantine]

    if apply:
        by_id = {str(post.get("id") or ""): post for post in posts}
        for finding in candidates:
            post = by_id[finding.post_id]
            finding.original_content = str(post.get("content") or "")
            labels = list(dict.fromkeys([*(post.get("labels") or []), "Integrity Review Required", "Automated Report Withdrawn"]))
            publisher.update_post(
                post_id=finding.post_id,
                title=finding.title,
                content=build_quarantine_notice(finding, checked_at),
                labels=labels,
            )
            finding.action = "quarantined"
            time.sleep(0.5)

    return {
        "schema_version": "1.0",
        "checked_at": checked_at,
        "mode": "quarantine" if apply else "dry_run",
        "posts_scanned": len(posts),
        "legacy_controls_missing": sum(item.legacy_control_missing for item in findings),
        "quarantine_candidates": len(candidates),
        "quarantined": sum(item.action == "quarantined" for item in findings),
        "findings": [asdict(item) for item in findings],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit or quarantine high-risk legacy Blogger reports")
    parser.add_argument("--max-posts", type=int, default=50)
    parser.add_argument("--apply", action="store_true", help="Replace eligible unsafe bodies with withdrawal notices")
    parser.add_argument("--manifest", default="logs/legacy-quality-manifest.json")
    args = parser.parse_args()

    config = Config.from_env()
    missing = config.validate()
    if missing:
        parser.error(f"missing required Blogger configuration: {', '.join(missing)}")

    report = audit_recent_posts(BloggerPublisher(config), args.max_posts, apply=args.apply)
    path = Path(args.manifest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("mode", "posts_scanned", "legacy_controls_missing", "quarantine_candidates", "quarantined")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
