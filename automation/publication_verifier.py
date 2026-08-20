"""Post-publication fetch-back verification (ReportX Phase 1Q, mandate
Section 26).

Immediately after a fresh Blogger publish succeeds, fetches the post back
via a real, separate Blogger API call and compares what Blogger now
actually persists against the exact artifact that was certified and
submitted. A successful ``publish_post()`` response only proves Blogger
ACCEPTED the request (and, since Phase 1P, that it self-reports LIVE) --
neither proves the STORED content matches what was sent, since Blogger's
own HTML sanitizer is known to silently strip or rewrite markup on save.

Deliberately a separate concern from ``automation.legacy_quality_auditor``,
which periodically batch-scans OLD posts for generic integrity-defect
patterns on its own retrospective schedule. This module verifies ONE
freshly-published post against its OWN specific intended content, inline in
the publish pipeline, immediately after that specific publish.

This module never modifies or quarantines a live post itself -- it only
observes and reports (Observable Everything, CLAUDE.md Principle 7). Turning
a detected defect into an automatic corrective action on an already-live
post is a separate, deliberate decision this module does not make.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .blogger_publisher import BloggerPublisher
from .legacy_quality_auditor import _PLACEHOLDERS, _source_url

# Reused, not redeclared -- report_contract.py's canonical report-identity
# attribute, and legacy_quality_auditor.py's own legacy_control_missing
# signal already keys off the identical substring. A second, independently
# drifting copy of this string would be exactly the kind of duplicate
# source of truth Principle 3 (Single Source of Truth) exists to prevent.
_PROVENANCE_MARKER = 'data-report-id="CDB-CTI-'

# A collapse this large means Blogger silently stripped a large fraction of
# the article, not a benign whitespace/attribute-quoting normalization --
# picked wide enough that ordinary, harmless serialization differences
# (self-closing tags, attribute order, entity encoding) can never trip it,
# narrow enough that a real truncation still does. A documented judgment
# call, not derived from a live Blogger sample: no live publish was
# authorized this round, so this threshold is unverified against real
# Blogger-side normalization behavior -- see the Phase 1Q certification
# doc's own limitations section.
_CONTENT_COLLAPSE_THRESHOLD = 0.5


@dataclass(frozen=True)
class FetchBackResult:
    post_id: str
    fetched: bool
    verified: bool
    defects: tuple[str, ...] = field(default_factory=tuple)
    intended_content_length: int = 0
    live_content_length: int = 0
    exact_content_match: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "post_id": self.post_id,
            "fetched": self.fetched,
            "verified": self.verified,
            "defects": list(self.defects),
            "intended_content_length": self.intended_content_length,
            "live_content_length": self.live_content_length,
            "exact_content_match": self.exact_content_match,
            "error": self.error,
        }


def verify_fetch_back(
    live_post: dict,
    post_id: str,
    intended_title: str,
    intended_content: str,
    intended_labels: list[str],
) -> FetchBackResult:
    """Pure comparison of an already-fetched live post against the intended
    artifact -- separated from ``fetch_back_and_verify()`` so the comparison
    logic itself can be unit-tested without any HTTP mocking."""
    live_content = str(live_post.get("content") or "")
    live_title = str(live_post.get("title") or "")
    live_labels = {str(item) for item in (live_post.get("labels") or [])}
    intended_labels_set = set(intended_labels)

    defects: list[str] = []

    if live_title != intended_title:
        defects.append("title_mismatch")
    if live_labels != intended_labels_set:
        defects.append("labels_mismatch")
    if _PROVENANCE_MARKER in intended_content and _PROVENANCE_MARKER not in live_content:
        defects.append("provenance_marker_stripped")
    if _source_url(intended_content) and not _source_url(live_content):
        defects.append("source_url_comment_stripped")
    if _PLACEHOLDERS.search(live_content):
        defects.append("placeholder_pattern_in_live_content")

    intended_length = len(intended_content)
    live_length = len(live_content)
    if intended_length > 0 and live_length < intended_length * _CONTENT_COLLAPSE_THRESHOLD:
        defects.append("content_length_collapsed")

    return FetchBackResult(
        post_id=post_id,
        fetched=True,
        verified=not defects,
        defects=tuple(sorted(defects)),
        intended_content_length=intended_length,
        live_content_length=live_length,
        exact_content_match=(live_content == intended_content),
    )


def fetch_back_and_verify(
    publisher: BloggerPublisher,
    post_id: str,
    intended_title: str,
    intended_content: str,
    intended_labels: list[str],
) -> FetchBackResult:
    """Never raises -- a verification failure must never be confused with a
    publish failure, since the post is already live by the time this runs.
    Any exception fetching or comparing the live post is captured as an
    honest "not evaluated" result (a distinct defect code from a real,
    confirmed content defect), never silently swallowed and never escalated
    into a pipeline failure that would make an already-successful publish
    look like it failed."""
    try:
        live_post = publisher.get_post(post_id)
    except Exception as exc:  # noqa: BLE001 -- see docstring: must never propagate
        return FetchBackResult(
            post_id=post_id, fetched=False, verified=False,
            defects=("fetch_back_request_failed",), error=str(exc)[:300],
        )

    try:
        return verify_fetch_back(live_post, post_id, intended_title, intended_content, intended_labels)
    except Exception as exc:  # noqa: BLE001
        return FetchBackResult(
            post_id=post_id, fetched=True, verified=False,
            defects=("fetch_back_comparison_failed",), error=str(exc)[:300],
        )
