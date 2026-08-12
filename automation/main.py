"""
CYBERDUDEBIVASH® SENTINEL APEX — Blogger Syndication Engine
Main orchestration pipeline. Runs content discovery → transformation → publication.

Usage:
    python -m automation.main              # Full pipeline
    python -m automation.main --dry-run    # Validate without publishing
    python -m automation.main --health     # Health check only
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .authority_transformer import AuthorityTransformer
from .blogger_publisher import BloggerPublisher, BloggerPublishError, BloggerAuthError, BloggerRateLimitError
from .config import Config
from .content_discovery import ContentDiscoveryEngine, DiscoveredArticle, PublicationState
from .logger import setup_logger
from .report_integrity import PublicationIntegrityError
from .search_console_submitter import SearchConsoleSubmitter
from .social_amplifier import SocialAmplifier

logger = setup_logger("main")


def _write_run_report(report: dict, logs_dir: str) -> None:
    """Persist a JSON run report for observability and auditing."""
    Path(logs_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = Path(logs_dir) / f"run-{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info("Run report written", extra={"path": str(path)})


def _requeue_unattempted(
    remaining: list[DiscoveredArticle],
    state: PublicationState,
    reason: str,
) -> int:
    """Queue articles that were discovered but never attempted this run
    because a fatal error (auth or rate-limit) stopped the pipeline early.

    Without this, only the one article that triggered the error was ever
    queued for retry — every other not-yet-attempted article in the batch
    depended on being rediscovered from its original source next run, which
    isn't guaranteed for sources with a small rolling window (e.g. RSS
    feeds). Log analysis across all historical runs showed this early-break
    path is common (roughly 1 in 5 runs overall, effectively every run in
    the most recent week), so the gap was worth closing rather than noting.
    """
    for article in remaining:
        state.add_to_retry_queue(article, f"not attempted — pipeline stopped early: {reason}")
    return len(remaining)


def _merge_retry_and_fresh(
    retry_articles: list[DiscoveredArticle],
    fresh_articles: list[DiscoveredArticle],
    state: PublicationState,
) -> list[DiscoveredArticle]:
    """Prefer current discovery data over stale retries for the same source.

    Editorial normalization can change a content hash while the canonical
    source URL remains stable. Publishing both variants creates duplicate
    reports and can keep obsolete placeholder content in the retry queue.
    """
    fresh_hashes = {article.content_hash for article in fresh_articles}
    fresh_urls = {article.url.strip() for article in fresh_articles if article.url}
    retry_deduped = [
        article for article in retry_articles
        if not state.is_published(article.content_hash)
        and not state.is_source_url_published(article.url)
        and article.content_hash not in fresh_hashes
        and article.url.strip() not in fresh_urls
    ]
    return retry_deduped + fresh_articles


def run_health_check(config: Config) -> bool:
    """Verify all external dependencies are reachable."""
    logger.info("Running health check")
    issues = config.validate()
    if issues:
        logger.error("Missing required config", extra={"missing": issues})
        return False

    publisher = BloggerPublisher(config)
    ok = publisher.health_check()
    if not ok:
        logger.error("Blogger health check failed")
        return False

    logger.info("All health checks passed")
    return True


def run_pipeline(config: Config, dry_run: bool = False) -> dict:
    """Execute the full syndication pipeline."""
    run_start = datetime.now(timezone.utc).isoformat()
    report = {
        "run_start": run_start,
        "run_end": None,
        "dry_run": dry_run,
        "discovered": 0,
        "published": 0,
        "failed": 0,
        "skipped": 0,
        "requeued": 0,
        "integrity_blocked": 0,
        "posts": [],
        "errors": [],
    }

    logger.info("Pipeline started", extra={"dry_run": dry_run, "run_start": run_start})

    # Validate config
    missing = config.validate()
    if missing and not dry_run:
        msg = f"Missing required secrets: {missing}"
        logger.error(msg)
        report["errors"].append(msg)
        report["run_end"] = datetime.now(timezone.utc).isoformat()
        return report

    # Initialise components
    discovery = ContentDiscoveryEngine(config)
    transformer = AuthorityTransformer(config)
    publisher = BloggerPublisher(config) if not dry_run else None
    submitter = SearchConsoleSubmitter(config)
    amplifier = SocialAmplifier(config)

    # --- Retry Queue: prepend previously-failed articles for retry ---
    retry_items = discovery.state.get_retry_queue()
    retry_articles = []
    for item in retry_items:
        try:
            retry_articles.append(DiscoveredArticle.from_dict(item))
        except KeyError:
            pass  # Malformed queue entry — skip silently

    if retry_articles:
        logger.info("Loaded retry queue", extra={"retry_count": len(retry_articles)})

    # --- Content Discovery ---
    fresh_articles = discovery.discover()
    # Retry articles first (skip if already published or in fresh batch)
    articles = _merge_retry_and_fresh(retry_articles, fresh_articles, discovery.state)
    articles = articles[: config.max_posts_per_run]
    report["discovered"] = len(articles)

    if not articles:
        logger.info("No new articles to syndicate this run")
        report["run_end"] = datetime.now(timezone.utc).isoformat()
        return report

    # --- Transform and Publish ---
    for idx, article in enumerate(articles):
        post_result = {
            "source_url": article.url,
            "title": article.title,
            "content_hash": article.content_hash,
            "status": "pending",
            "blogger_post_id": None,
            "blogger_url": None,
            "error": None,
        }

        try:
            # Transform content
            transformed = transformer.transform(article)
            post_result["blogger_title"] = transformed["title"]
            post_result["labels"] = transformed["labels"]
            post_result["content_source"] = transformed["content_source"]
            post_result["llm_attempts"] = transformed.get("llm_attempts", [])
            for field in (
                "report_id",
                "source_record_hash",
                "report_family",
                "review_status",
                "certification_status",
                "detection_status",
                "generated_at",
            ):
                post_result[field] = transformed.get(field)

            if dry_run:
                logger.info(
                    "DRY RUN — would publish",
                    extra={"title": transformed["title"][:60], "labels": transformed["labels"]},
                )
                post_result["status"] = "dry_run"
                report["skipped"] += 1
            else:
                # Publish to Blogger
                blogger_post = publisher.publish_post(
                    title=transformed["title"],
                    content=transformed["content"],
                    labels=transformed["labels"],
                    is_draft=False,
                    image_url=transformed.get("image_url"),
                )

                blogger_post_id = blogger_post["id"]
                blogger_url = blogger_post.get("url", "")

                # Persist state
                discovery.state.mark_published(
                    article,
                    blogger_post_id,
                    blogger_url,
                    publication_metadata=transformed,
                )

                # Submit to Google Search Console
                if blogger_url:
                    submitter.submit_url(blogger_url)

                # Social amplification — Twitter/X auto-post
                social_result = amplifier.amplify({
                    "title": article.title,
                    "blogger_title": transformed["title"],
                    "labels": transformed["labels"],
                    "blogger_url": blogger_url,
                })

                post_result.update({
                    "status": "published",
                    "blogger_post_id": blogger_post_id,
                    "blogger_url": blogger_url,
                    "social": social_result,
                })
                report["published"] += 1

                logger.info(
                    "Article syndicated",
                    extra={
                        "title": transformed["title"][:60],
                        "blogger_url": blogger_url,
                        "post_id": blogger_post_id,
                        "social": social_result,
                    },
                )

                # Brief pause between posts to respect API rate limits
                if article != articles[-1]:
                    time.sleep(2.0)

        except PublicationIntegrityError as e:
            logger.error(
                "Publication integrity gate blocked report",
                extra={"url": article.url, "issues": e.issues},
            )
            post_result["status"] = "integrity_blocked"
            post_result["error"] = str(e)
            post_result["integrity_issues"] = e.issues
            report["errors"].append(str(e))
            discovery.state.record_failure(article.url, str(e))
            discovery.state.add_to_retry_queue(article, str(e))
            report["failed"] += 1
            report["integrity_blocked"] += 1

        except BloggerAuthError as e:
            logger.error("Authentication error — stopping pipeline", extra={"error": str(e)})
            post_result["status"] = "auth_error"
            post_result["error"] = str(e)
            report["errors"].append(str(e))
            discovery.state.record_failure(article.url, str(e))
            report["failed"] += 1
            report["posts"].append(post_result)
            report["requeued"] += _requeue_unattempted(articles[idx + 1:], discovery.state, str(e))
            break  # Auth errors are fatal; stop the run

        except BloggerRateLimitError as e:
            # Blogger's quota is exhausted for the window, not for this one
            # article — every remaining article in this run would burn more
            # calls on a doomed retry (and risk tripping Google's abuse
            # detection, per the hint in BloggerAuthError above). Record this
            # article for retry next run and stop instead of working through
            # the rest of the batch.
            logger.error(
                "Rate limit exhausted — stopping run early to avoid burning further quota",
                extra={"url": article.url, "error": str(e)},
            )
            post_result["status"] = "rate_limited"
            post_result["error"] = str(e)
            report["errors"].append(str(e))
            discovery.state.record_failure(article.url, str(e))
            discovery.state.add_to_retry_queue(article, str(e))
            report["failed"] += 1
            report["posts"].append(post_result)
            report["requeued"] += _requeue_unattempted(articles[idx + 1:], discovery.state, str(e))
            break  # Quota exhaustion is effectively fatal for this run

        except BloggerPublishError as e:
            logger.error("Publish failed", extra={"url": article.url, "error": str(e)})
            post_result["status"] = "publish_error"
            post_result["error"] = str(e)
            report["errors"].append(str(e))
            discovery.state.record_failure(article.url, str(e))
            discovery.state.add_to_retry_queue(article, str(e))
            report["failed"] += 1

        except Exception as e:
            logger.exception("Unexpected error processing article", extra={"url": article.url})
            post_result["status"] = "error"
            post_result["error"] = str(e)
            report["errors"].append(str(e))
            discovery.state.record_failure(article.url, str(e))
            discovery.state.add_to_retry_queue(article, str(e))
            report["failed"] += 1

        report["posts"].append(post_result)

    report["run_end"] = datetime.now(timezone.utc).isoformat()

    logger.info(
        "Pipeline complete",
        extra={
            "discovered": report["discovered"],
            "published": report["published"],
            "failed": report["failed"],
            "skipped": report["skipped"],
            "integrity_blocked": report["integrity_blocked"],
        },
    )

    _write_run_report(report, config.logs_dir)
    return report


def _pipeline_exit_code(report: dict) -> int:
    """Return non-zero for every partial or complete pipeline failure."""
    return 1 if int(report.get("failed", 0)) > 0 else 0


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH® SENTINEL APEX Blogger Syndication Engine"
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate without publishing")
    parser.add_argument("--health", action="store_true", help="Run health check only")
    parser.add_argument("--max-posts", type=int, default=None, help="Override max posts per run")
    args = parser.parse_args()

    config = Config.from_env()
    if args.max_posts:
        config.max_posts_per_run = args.max_posts

    setup_logger("main", config.logs_dir)

    if args.health:
        ok = run_health_check(config)
        return 0 if ok else 1

    report = run_pipeline(config, dry_run=args.dry_run)

    # Any blocked or failed article must surface as a workflow failure even
    # when other articles published successfully. Partial success cannot hide
    # an evidence-integrity, authentication, quota, or publication defect.
    return _pipeline_exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
