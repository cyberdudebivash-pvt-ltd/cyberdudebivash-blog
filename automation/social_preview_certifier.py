"""
CYBERDUDEBIVASH® SENTINEL APEX — Social Preview Certification Engine

Deterministic CERTIFIED/BLOCKED validation of a report's social-preview
metadata contract, so a defect (a data: URI image, a Blogspot canonical
leak, a missing description) is a detected, logged, auditable fact rather
than something that only surfaces when a human happens to paste the URL
into LinkedIn. Never silently downgrades a failure to a warning without the
caller asking for that -- see certify_metadata()'s `enforce` parameter and
STAGED_ROLLOUT below for why this ships wired in observe mode, not blocking.

Two independent certifiers, because they have different I/O costs:

  certify_metadata() -- static/structural checks only (no network I/O).
  Fast and deterministic enough to run synchronously in the publish path
  for every single report. This is what main.py's pipeline calls.

  certify_live_html() -- parses an already-fetched live page's rendered
  <head>/body (the same shape backfill_social_previews.detect_defects()
  works from) for defects only a real fetch-back can catch -- e.g. a
  theme-level override neither this module nor authority_transformer.py
  ever gets to see pre-publish. Used by audit tooling and the backfill
  utility's fetch-back step, not the synchronous publish path (a network
  dependency has no place gating every publish attempt).

STAGED ROLLOUT (spec-required documentation of the enforcement decision):
  observe (current)  -> log every CERTIFIED/BLOCKED verdict, never block
                          publication regardless of verdict.
  warn                -> same, plus a visible warning in the run report
                          for BLOCKED reports (still never blocks).
  shadow gate          -> compute the verdict identically to blocking mode
                          and record what WOULD have been blocked, without
                          actually withholding publication.
  blocking             -> BLOCKED reports do not publish.
  This ships in "observe": report_integrity.validate_publication() already
  fail-closes on real content-integrity defects (placeholder text,
  fabricated statistics, contradiction checks) with a mature, tested gate;
  bolting an unproven new gate straight onto "blocking" risks halting a
  production pipeline that publishes ~12x/day over a false positive in
  week one. Promote a stage only after its predecessor has run clean
  against real traffic for a real observation window.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

_DATA_URI_RE = re.compile(r"^data:", re.IGNORECASE)
_LOCALHOST_PATTERNS = (
    "localhost", "127.0.0.1", "0.0.0.0", "::1", ".local",
    "ngrok.io", "ngrok-free.app", ".vercel.app",
)
_BLOGSPOT_LEAK = "blogspot.com"
_SAFE_IMAGE_PATH_PREFIXES = ("/api/og", "/og-image.png")


@dataclass
class CertificationResult:
    verdict: str  # "CERTIFIED" | "BLOCKED"
    checks: list[dict] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "checks": self.checks, "reasons": self.reasons}


def _check(checks: list[dict], reasons: list[str], name: str, passed: bool, failure_detail: str = "") -> None:
    """failure_detail describes what's WRONG and is only ever meaningful
    (and only ever recorded) when passed is False — a passing check's
    `checks` entry carries no detail text, so nothing in a CERTIFIED
    result's check list reads like an unexplained failure."""
    checks.append({"name": name, "passed": passed, "detail": "" if passed else failure_detail})
    if not passed:
        reasons.append(f"{name}: {failure_detail}" if failure_detail else name)


def _is_https_url(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme == "https" and bool(parsed.netloc)


def _host_matches(url: str, expected_domain: str) -> bool:
    try:
        return urlparse(url).netloc.lower() == expected_domain.lower()
    except ValueError:
        return False


def certify_metadata(
    *,
    image_url: str,
    title: str,
    description: str,
    canonical_url: Optional[str] = None,
    expected_domain: Optional[str] = None,
    og_type: str = "article",
    twitter_card: str = "summary_large_image",
    image_width: Optional[int] = 1200,
    image_height: Optional[int] = 630,
) -> CertificationResult:
    """Certify the metadata a report is ABOUT to be published with (the
    same values authority_transformer.transform() and seo_optimizer.generate()
    just computed) -- catches a regression before it reaches Blogger, not
    after. Pure/no I/O: safe to call on every publish.

    canonical_url/expected_domain are optional because Blogger does not
    assign a post's real canonical URL until after publish_post() returns
    (checking a page's actual live canonical belongs to certify_live_html,
    post-publish) -- pass them only when the caller genuinely knows the
    final URL ahead of time (e.g. a pipeline that computes its own slug and
    serves the page itself, unlike Blogger)."""
    checks: list[dict] = []
    reasons: list[str] = []

    _check(checks, reasons, "image_is_https_url", _is_https_url(image_url),
           f"image_url={image_url!r} is not an https:// URL")
    _check(checks, reasons, "image_not_data_uri", not bool(image_url and _DATA_URI_RE.match(image_url)),
           "image_url is a data: URI — no social crawler accepts this for og:image")
    _check(checks, reasons, "image_not_localhost_or_dev",
           not any(p in (image_url or "").lower() for p in _LOCALHOST_PATTERNS),
           f"image_url={image_url!r} looks like a localhost/dev/preview URL")
    if image_url and _is_https_url(image_url):
        known_good_path = any(urlparse(image_url).path.startswith(p) for p in _SAFE_IMAGE_PATH_PREFIXES)
        _check(checks, reasons, "image_known_good_dimensions_source", known_good_path,
               "image_url is not served by this platform's own dynamic/static OG image "
               "endpoints — its actual 1200x630 dimensions cannot be certified without a "
               "live fetch (see certify_live_html for that check)")
    if image_width is not None:
        _check(checks, reasons, "image_width_declared_1200", image_width == 1200,
               f"declared image width {image_width} != 1200")
    if image_height is not None:
        _check(checks, reasons, "image_height_declared_630", image_height == 630,
               f"declared image height {image_height} != 630")

    if canonical_url is not None:
        _check(checks, reasons, "canonical_is_https", _is_https_url(canonical_url),
               f"canonical_url={canonical_url!r} is not an https:// URL")
        if expected_domain:
            _check(checks, reasons, "canonical_matches_expected_domain",
                   _host_matches(canonical_url, expected_domain),
                   f"canonical_url host does not match expected public identity {expected_domain!r}")
        _check(checks, reasons, "canonical_no_blogspot_leakage",
               _BLOGSPOT_LEAK not in (canonical_url or "").lower(),
               "canonical_url leaks the underlying Blogspot hosting domain")

    _check(checks, reasons, "title_present", bool(title and title.strip()), "title is empty")
    _check(checks, reasons, "title_bounded_length", bool(title) and len(title) <= 200,
           f"title is {len(title or '')} chars, expected <= 200")

    _check(checks, reasons, "description_present", bool(description and description.strip()),
           "description is empty")
    _check(checks, reasons, "description_bounded_length", bool(description) and len(description) <= 300,
           f"description is {len(description or '')} chars, expected <= 300")
    _check(checks, reasons, "description_no_blogspot_leakage",
           _BLOGSPOT_LEAK not in (description or "").lower(),
           "description leaks the underlying Blogspot hosting domain")

    _check(checks, reasons, "og_type_is_article", og_type == "article",
           f"og:type={og_type!r}, expected 'article' for a report page")
    _check(checks, reasons, "twitter_card_is_summary_large_image",
           twitter_card == "summary_large_image",
           f"twitter:card={twitter_card!r}, expected 'summary_large_image'")

    verdict = "CERTIFIED" if not reasons else "BLOCKED"
    return CertificationResult(verdict=verdict, checks=checks, reasons=reasons)


def certify_live_html(html: str, *, expected_domain: str) -> CertificationResult:
    """Certify what a page ACTUALLY renders, parsed from already-fetched
    live HTML (e.g. from a crawler-UA fetch or backfill's get_post()
    content). Catches defects certify_metadata() structurally cannot see —
    most importantly a theme-level override discarding correct
    Python-computed values (this is exactly how the current
    og:description-is-blog-wide-boilerplate defect was found: it never
    shows up pre-publish, only in what Blogger's theme actually serves)."""
    checks: list[dict] = []
    reasons: list[str] = []

    # A real parser, not hand-rolled regex, for the same reason
    # backfill_social_previews.py only ever regexes a single already-isolated
    # <img> tag rather than trying to correlate two attributes across a
    # whole document: attribute order and quoting style vary (Blogger's own
    # markup mixes both), and a regex built to handle that correlation
    # correctly is exactly the "now you have two problems" trap. bs4 is
    # already a proven dependency of this codebase (authority_transformer.py).
    soup = BeautifulSoup(html or "", "html.parser")

    def _meta(prop_or_name: str, attr: str = "property") -> Optional[str]:
        tag = soup.find("meta", attrs={attr: prop_or_name})
        return tag.get("content") if tag else None

    og_image = _meta("og:image")
    og_url = _meta("og:url")
    og_title = _meta("og:title")
    og_description = _meta("og:description")
    twitter_image = _meta("twitter:image", attr="name")
    twitter_card = _meta("twitter:card", attr="name")

    _check(checks, reasons, "live_og_image_present", bool(og_image), "no og:image tag found in live HTML")
    _check(checks, reasons, "live_og_image_not_data_uri",
           not bool(og_image and _DATA_URI_RE.match(og_image)),
           "live og:image is a data: URI")
    _check(checks, reasons, "live_twitter_image_present", bool(twitter_image),
           "no twitter:image tag found in live HTML")
    _check(checks, reasons, "live_twitter_image_not_data_uri",
           not bool(twitter_image and _DATA_URI_RE.match(twitter_image)),
           "live twitter:image is a data: URI")
    _check(checks, reasons, "live_og_url_matches_domain",
           bool(og_url) and _host_matches(og_url, expected_domain),
           f"live og:url host does not match expected public identity {expected_domain!r}")
    _check(checks, reasons, "live_og_title_present", bool(og_title and og_title.strip()),
           "live og:title is empty")
    _check(checks, reasons, "live_og_description_present",
           bool(og_description and og_description.strip()), "live og:description is empty")
    _check(checks, reasons, "live_twitter_card_summary_large_image",
           twitter_card == "summary_large_image",
           f"live twitter:card={twitter_card!r}, expected 'summary_large_image'")
    head_html = str(soup.head) if soup.head else (html or "")
    _check(checks, reasons, "live_no_blogspot_leakage_in_head",
           _BLOGSPOT_LEAK not in head_html.lower(),
           "live <head> still references the Blogspot hosting domain")

    verdict = "CERTIFIED" if not reasons else "BLOCKED"
    return CertificationResult(verdict=verdict, checks=checks, reasons=reasons)
