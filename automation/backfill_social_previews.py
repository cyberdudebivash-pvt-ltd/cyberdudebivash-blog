"""
CYBERDUDEBIVASH® SENTINEL APEX — Legacy Social Preview Remediation Utility

Repairs already-published Blogger posts whose social-preview lead image is a
data: URI (the defect fixed for NEW posts by authority_transformer.py's
_generate_svg_thumbnail()/image_url threading — see PR #126) or missing
entirely, and/or whose embedded JSON-LD still references the underlying
Blogspot hosting URL instead of the public cti.cyberdudebivash.in identity
(the defect fixed for NEW posts in seo_optimizer.py's Organization sameAs).

DRY RUN BY DEFAULT. Nothing is written to Blogger unless --apply is passed.
Every run produces a JSON migration manifest recording, per post: detected
defects, the exact planned/actual content change, before/after content
hashes, and (when applied) a live fetch-back verification result — so every
change is auditable and reversible (the manifest's before_content field is
the rollback payload: PATCH it straight back via patch_post_preview()).

This does not rewrite report intelligence content. It only ever touches (a)
the src attribute of a post's first <img> tag, or inserts one when entirely
missing, and (b) the exact literal Blogspot canonical-leak string inside a
post's own JSON-LD -- both narrow, exact-match, provably-safe substitutions,
never a full content regeneration.

Usage:
    python -m automation.backfill_social_previews --post-id 123456789
    python -m automation.backfill_social_previews --post-id 123456789 --apply
    python -m automation.backfill_social_previews --limit 25
    python -m automation.backfill_social_previews --limit 25 --apply --sleep 3
    python -m automation.backfill_social_previews --limit 100 --apply --resume
"""
from __future__ import annotations

import argparse
import hashlib
import html as _html_escape
import json
import re
import sys
import time
from pathlib import Path
from typing import Optional

from .authority_transformer import _build_dynamic_og_image_url
from .blogger_publisher import BloggerPublisher
from .category_mapper import primary_category
from .config import Config
from .logger import setup_logger
from .seo_optimizer import _extract_cve_ids, _extract_cvss

logger = setup_logger("backfill_social_previews")

DEFAULT_MANIFEST_PATH = "data/backfill-manifest.json"

_IMG_TAG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_SRC_ATTR_RE = re.compile(r"""src=(["'])(.*?)\1""", re.IGNORECASE)
_REPORT_ID_RE = re.compile(r'data-report-id="(CDB-CTI-[A-Za-z0-9-]+)"')
_BLOGSPOT_LEAK = "https://cyberbivash.blogspot.com"


def _severity_from_cvss(cvss: Optional[str]) -> str:
    """Same thresholds as authority_transformer._derive_severity(), applied
    to a bare CVSS string rather than a DiscoveredArticle -- a legacy
    Blogger post has no such object, only its already-published
    title/content/labels fetched back from the API."""
    if not cvss:
        return "HIGH"
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return "HIGH"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def detect_defects(content: str) -> list[str]:
    """Inspect one post's live content HTML and return the list of
    known, safely-repairable social-preview defect codes it has. Empty
    list means the post already meets the current contract."""
    defects = []
    m = _IMG_TAG_RE.search(content or "")
    if not m:
        defects.append("MISSING_IMAGE")
    else:
        src_m = _SRC_ATTR_RE.search(m.group(0))
        src = src_m.group(2) if src_m else ""
        if src.startswith("data:"):
            defects.append("DATA_URI_IMAGE")
        elif not src.startswith("https://"):
            defects.append("NON_HTTPS_IMAGE")
    if _BLOGSPOT_LEAK in (content or ""):
        defects.append("BLOGSPOT_CANONICAL_LEAK")
    return defects


def compute_repair(post: dict, config: Config) -> dict:
    """Given a fetched Blogger post ({"content", "title", "labels", ...}),
    return {"content": <repaired content>, "changes": [...], "defects_found": [...]}.
    Pure function -- no I/O, no Blogger calls -- so it's trivially unit
    testable and reusable for a dry-run preview without ever writing
    anything."""
    content = post.get("content") or ""
    title = post.get("title") or ""
    labels = post.get("labels") or []
    defects = detect_defects(content)
    changes: list[str] = []

    if any(d in defects for d in ("DATA_URI_IMAGE", "MISSING_IMAGE", "NON_HTTPS_IMAGE")):
        text_for_extraction = f"{title} {content}"
        cves = _extract_cve_ids(text_for_extraction)
        cvss = _extract_cvss(text_for_extraction)
        severity = _severity_from_cvss(cvss)
        report_id_m = _REPORT_ID_RE.search(content)
        # Reuse the report's own already-embedded identity -- never invent a
        # second ID for the same report just because the original source
        # article record isn't available to this backfill pass.
        report_id = report_id_m.group(1) if report_id_m else None

        image_url = _build_dynamic_og_image_url(
            config, title=title, severity=severity,
            cve_id=cves[0] if cves else "", cvss=cvss,
            type_label=primary_category(labels) or "THREAT INTEL",
            report_id=report_id, published_at=post.get("published"),
        )
        alt_text = _html_escape.escape(title[:80], quote=True)
        safe_src = _html_escape.escape(image_url, quote=True)
        new_img_tag = (
            f'<img src="{safe_src}" alt="{alt_text}" width="1200" height="630" '
            f'style="width:100%;max-width:1200px;height:auto;display:block;'
            f'margin:0 auto 24px;border-radius:8px" loading="eager"/>'
        )
        m = _IMG_TAG_RE.search(content)
        if m:
            content = content[: m.start()] + new_img_tag + content[m.end() :]
            changes.append(f"replaced first <img> src with real HTTPS card: {image_url}")
        else:
            content = new_img_tag + "\n\n" + content
            changes.append(f"inserted missing lead <img> pointing at: {image_url}")

    if "BLOGSPOT_CANONICAL_LEAK" in defects:
        content = content.replace(_BLOGSPOT_LEAK, config.public_cti_url)
        changes.append(f"replaced Blogspot canonical leak with {config.public_cti_url}")

    return {"content": content, "changes": changes, "defects_found": defects}


def _load_manifest(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {"version": 1, "entries": {}}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _save_manifest(path: str, manifest: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)


def _iter_candidate_posts(publisher: BloggerPublisher, post_id: Optional[str], limit: int):
    """Yields raw Blogger post dicts to evaluate. --post-id targets exactly
    one post (Phase B canary); otherwise walks list_posts_page() forward,
    newest first, until `limit` posts have been yielded or posts run out --
    bounded, resumable batches (Phase C/D/E), never an unbounded full-table
    scan in one run."""
    if post_id:
        yield publisher.get_post(post_id)
        return

    yielded = 0
    page_token = None
    while yielded < limit:
        page = publisher.list_posts_page(page_token=page_token, max_results=min(25, limit - yielded))
        items = page.get("items") or []
        if not items:
            break
        for item in items:
            if yielded >= limit:
                break
            yield item
            yielded += 1
        page_token = page.get("nextPageToken")
        if not page_token:
            break


def run(config: Config, *, post_id: Optional[str], limit: int, apply: bool,
        resume: bool, manifest_path: str, sleep_seconds: float) -> dict:
    publisher = BloggerPublisher(config)
    manifest = _load_manifest(manifest_path) if (resume or apply) else {"version": 1, "entries": {}}
    entries = manifest.setdefault("entries", {})

    report = {"apply": apply, "scanned": 0, "clean": 0, "repaired_dry_run": 0,
              "applied": 0, "skipped_resume": 0, "failed": 0, "errors": []}

    for post in _iter_candidate_posts(publisher, post_id, limit):
        pid = post.get("id")
        report["scanned"] += 1

        if resume and pid in entries and entries[pid].get("status") in ("applied", "verified", "skipped_no_defects"):
            report["skipped_resume"] += 1
            continue

        try:
            before_content = post.get("content") or ""
            repair = compute_repair(post, config)
            entry = {
                "post_id": pid,
                "url": post.get("url"),
                "title": post.get("title"),
                "published": post.get("published"),
                "before_content_sha256": _sha256(before_content),
                "before_images": post.get("images", []),
                "defects_found": repair["defects_found"],
                "changes": repair["changes"],
                "mode": "dry_run",
                "status": "",
                "verification": {},
                "error": None,
            }

            if not repair["defects_found"]:
                entry["status"] = "skipped_no_defects"
                report["clean"] += 1
                entries[pid] = entry
                continue

            report["repaired_dry_run"] += 1
            entry["status"] = "planned"

            if apply:
                entry["mode"] = "apply"
                image_url = None
                m = _IMG_TAG_RE.search(repair["content"])
                if m:
                    src_m = _SRC_ATTR_RE.search(m.group(0))
                    image_url = _html_escape.unescape(src_m.group(2)) if src_m else None

                result = publisher.patch_post_preview(pid, content=repair["content"], image_url=image_url)
                entry["after_content_sha256"] = _sha256(repair["content"])
                entry["after_images"] = result.get("images", [])
                entry["updated_timestamp"] = result.get("updated")

                # Fetch-back verification: confirm Blogger actually persisted
                # the fix, not just that it accepted the PATCH request (same
                # "acceptance != live" discipline blogger_publisher.get_post()
                # already documents for the main publish path).
                live = publisher.get_post(pid)
                live_content = live.get("content") or ""
                live_defects = detect_defects(live_content)
                verified = not any(d in live_defects for d in repair["defects_found"])
                entry["verification"] = {
                    "fetched": True, "verified": verified,
                    "remaining_defects": live_defects,
                }
                entry["status"] = "applied" if verified else "applied_unverified"
                report["applied"] += 1
                if not verified:
                    report["errors"].append(f"{pid}: patch applied but fetch-back still shows {live_defects}")

            entries[pid] = entry

        except Exception as exc:
            # Per-post isolation: one bad post must never abort the batch --
            # every other candidate still gets evaluated, and the manifest
            # records exactly which one(s) failed and why.
            report["failed"] += 1
            report["errors"].append(f"{pid}: {exc}")
            entries[pid] = {
                "post_id": pid, "status": "failed", "error": str(exc),
                "mode": "apply" if apply else "dry_run",
            }
            logger.error("Backfill failed for post", extra={"post_id": pid, "error": str(exc)})

        if apply and sleep_seconds > 0:
            time.sleep(sleep_seconds)

    if resume or apply:
        _save_manifest(manifest_path, manifest)

    logger.info("Backfill run complete", extra=report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill legacy Blogger social-preview defects")
    parser.add_argument("--apply", action="store_true", help="Actually write changes (default: dry run)")
    parser.add_argument("--limit", type=int, default=5, help="Max posts to scan when not using --post-id")
    parser.add_argument("--post-id", type=str, default=None, help="Target exactly one Blogger post ID")
    parser.add_argument("--resume", action="store_true", help="Skip posts already applied/verified in the manifest")
    parser.add_argument("--manifest", type=str, default=DEFAULT_MANIFEST_PATH, help="Manifest file path")
    parser.add_argument("--sleep", type=float, default=2.0, help="Seconds to sleep between applied writes")
    args = parser.parse_args()

    config = Config.from_env()
    missing = config.validate()
    if missing:
        print(f"Missing required config: {missing}", file=sys.stderr)
        return 1

    report = run(
        config, post_id=args.post_id, limit=args.limit, apply=args.apply,
        resume=args.resume, manifest_path=args.manifest, sleep_seconds=args.sleep,
    )
    print(json.dumps(report, indent=2))
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
