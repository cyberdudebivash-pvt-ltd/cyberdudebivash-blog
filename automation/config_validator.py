"""
CYBERDUDEBIVASH® SENTINEL APEX — Extended Config Validation
Complements Config.validate() (which only checks the 4 required Blogger
credentials) with sanity checks on the rest of the configuration surface —
positive numeric ranges, well-formed URLs. Returns a list of human-readable
issues; an empty list means the config passed. Never raises — callers
decide whether issues are fatal.
"""

from urllib.parse import urlparse

from .config import Config

_POSITIVE_INT_FIELDS = ["max_posts_per_run", "retry_attempts"]
_POSITIVE_FLOAT_FIELDS = ["retry_base_delay"]
_URL_FIELDS = [
    "source_rss_url", "source_live_intel_url", "source_sitemap_url",
    "source_base_url", "target_blog_url", "blogger_api_base",
    "brand_url", "sentinel_apex_url", "api_url", "tools_url", "corporate_url",
]


def _is_well_formed_url(value: str) -> bool:
    if not value:
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return bool(parsed.scheme in ("http", "https") and parsed.netloc)


def validate_extended(config: Config) -> list[str]:
    """Return a list of validation issues (empty = passes)."""
    issues: list[str] = []

    for field in _POSITIVE_INT_FIELDS:
        value = getattr(config, field, None)
        if not isinstance(value, int) or value <= 0:
            issues.append(f"{field} must be a positive integer, got {value!r}")

    for field in _POSITIVE_FLOAT_FIELDS:
        value = getattr(config, field, None)
        if not isinstance(value, (int, float)) or value <= 0:
            issues.append(f"{field} must be a positive number, got {value!r}")

    for field in _URL_FIELDS:
        value = getattr(config, field, None)
        if not _is_well_formed_url(value):
            issues.append(f"{field} is not a well-formed http(s) URL: {value!r}")

    if config.max_article_age_hours <= 0:
        issues.append(f"max_article_age_hours must be positive, got {config.max_article_age_hours!r}")

    return issues
