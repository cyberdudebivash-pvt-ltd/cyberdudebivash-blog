"""The bridge adapter: ``automation.content_discovery.DiscoveredArticle``
(System 1/2's live-feed ingestion shape) -> ReportX's
``EvidenceGraph``/``Claim``/``SourceRecord``/``ThreatProduct`` shape.

This is the one genuinely missing piece
``REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md`` identified: every other
stage of the Intelligence Factory pipeline already exists in
``sentinel_engine.reportx`` or in ``automation.report_integrity``/
``automation.report_renderer``. This module never re-derives what those
modules already compute correctly — family classification, exploitation/
patch status, vulnerability class, and the fail-closed publication gate
all come from ``automation.report_integrity`` unchanged. This module's own
job is narrow: turn one already-classified ``DiscoveredArticle`` into a
real, hash-verified, epistemically-honest ``EvidenceGraph``.

Every claim this module constructs is deliberately conservative: single-
source claims stay at ``REPORTED`` (never ``CONFIRMED``) for every
high-impact claim type (Section 10's policy, enforced elsewhere by
``claim_model.py`` — this module doesn't have to duplicate that check, it
just never tries to claim more certainty than one source supports).
``CONFIRMED`` is used only where the source is definitionally authoritative
for that exact fact (NVD assigning a CVE ID; CISA adding a KEV entry) —
not for the surrounding narrative.
"""

from __future__ import annotations

import sys
from pathlib import Path

# automation/ lives at the repo root, four levels above this file
# (reportx/ -> sentinel_engine/ -> engine/ -> Sentinel-APEX/ -> repo root) --
# not on sys.path by default when this package is imported from within
# Sentinel-APEX/engine/ alone (e.g. under pytest). Mirrors the same
# sys.path bootstrap cli.py and the reportx-canary scripts already use.
_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from automation.content_discovery import DiscoveredArticle  # noqa: E402
from automation.report_integrity import ReportContext, build_report_context  # noqa: E402

from .claim_model import (
    Claim,
    ClaimType,
    EpistemicState,
    EvidenceGraph,
    EvidenceRecord,
    ObservedVsContext,
    Reliability,
    SourceRecord,
    SourceRole,
    SourceType,
    infer_temporal_precision,
)
from .evidence_integrity import compute_content_sha256, compute_excerpt_fingerprint
from .threat_schemas import CISAKEVRecord, CVERecord, RansomwareVictimClaim, ThreatProduct

PRIMARY_SOURCE_ID = "src-primary"

_HIGH_RELIABILITY_SOURCES = frozenset({"nvd", "cisa_kev", "cisa_advisory", "mitre"})
_MODERATE_RELIABILITY_SOURCES = frozenset({"ransomware_intel", "threat_actor_intel", "breach_intel", "cti_vendor"})

_SOURCE_TYPE_MAP: dict[str, SourceType] = {
    "nvd": SourceType.NVD,
    "cisa_kev": SourceType.CISA,
    "cisa_advisory": SourceType.CISA,
    "ransomware_intel": SourceType.LEAK_SITE_AGGREGATOR,
    "breach_intel": SourceType.JOURNALISM,
    "threat_actor_intel": SourceType.CTI_VENDOR_RESEARCH,
}


def source_reliability(article: DiscoveredArticle) -> Reliability:
    """Populates the existing, previously-unused ``SourceRecord.reliability``
    field (Finding 3, ``REPORTX-LEGACY-PIPELINE-AUDIT.md``) from the same
    ``article.source`` discriminator ``report_integrity._family()`` already
    uses -- no new classification logic invented.

    COMMERCIAL-QUALITY-2026-08-18: a curated, named RSS publisher (any
    article carrying ``source_publisher``, e.g. "BleepingComputer", "Dark
    Reading" -- see ``automation/rss_aggregator.py``'s hand-maintained feed
    list) is graded the same as this file's own existing "named CTI
    vendor" policy (``_MODERATE_RELIABILITY_SOURCES``), not left at the
    connector-level ``UNKNOWN``/"F" grade every ``global_rss`` article got
    regardless of which of ~40 distinct, individually-vetted outlets it
    actually came from. This does not (yet) differentiate reliability
    *between* those outlets -- doing that defensibly needs an editorial
    trust policy per outlet, a separate follow-up -- it only stops treating
    a known, deliberately-curated publisher the same as a completely
    unknown one."""
    if article.source in _HIGH_RELIABILITY_SOURCES:
        return Reliability.HIGH
    if article.source in _MODERATE_RELIABILITY_SOURCES or article.source_publisher:
        return Reliability.MODERATE
    return Reliability.UNKNOWN


def build_source_record(article: DiscoveredArticle, context: ReportContext) -> SourceRecord:
    content_sha256 = None
    excerpt_fingerprint_sha256 = None
    fingerprint_fallback_reason = None
    if article.full_content:
        content_sha256 = compute_content_sha256(article.full_content)
    else:
        # Honest fallback, not a fabricated full-content hash: content_discovery.py
        # did not populate full_content for this article, so the excerpt tier
        # hashes the real text this bridge actually has -- the summary.
        excerpt_fingerprint_sha256 = compute_excerpt_fingerprint([article.summary])
        fingerprint_fallback_reason = (
            "automation.content_discovery did not populate full_content for this "
            "source; hashing the retrieved summary excerpt instead of a fabricated "
            "full-content hash."
        )

    return SourceRecord(
        source_id=PRIMARY_SOURCE_ID,
        url=article.url,
        publisher=article.source_publisher or article.source,
        source_type=_SOURCE_TYPE_MAP.get(article.source, SourceType.OTHER),
        source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at=context.generated_at,
        source_date=article.published_at or None,
        temporal_precision=infer_temporal_precision(article.published_at),
        content_sha256=content_sha256,
        reliability=source_reliability(article),
        excerpt_fingerprint_sha256=excerpt_fingerprint_sha256,
        fingerprint_fallback_reason=fingerprint_fallback_reason,
    )


def _add_claim_with_evidence(
    graph: EvidenceGraph, article: DiscoveredArticle, *, claim_id: str, claim_type: ClaimType,
    text: str, status: EpistemicState, observed_vs_context: ObservedVsContext, analyst_notes: str = "",
) -> None:
    evidence_id = f"e-{claim_id}"
    graph.add_evidence(EvidenceRecord(
        evidence_id=evidence_id, source_id=PRIMARY_SOURCE_ID,
        excerpt=(article.summary or text)[:500], locator=article.url,
    ))
    claim = Claim(
        claim_id=claim_id, claim_type=claim_type, text=text, status=status,
        evidence_refs=[evidence_id], source_refs=[PRIMARY_SOURCE_ID],
        observed_vs_context=observed_vs_context, analyst_notes=analyst_notes,
    )
    graph.add_claim(claim)
    graph.recompute_corroboration(claim.claim_id)


def build_claims(graph: EvidenceGraph, article: DiscoveredArticle, context: ReportContext) -> None:
    """Family-conditioned claim construction -- reuses
    ``report_integrity``'s already-computed exploitation/patch status/
    vulnerability class rather than re-deriving them, and never asserts
    more than one source supports (Section 10)."""

    _add_claim_with_evidence(
        graph, article, claim_id="c-summary", claim_type=ClaimType.VULNERABILITY_FACT,
        text=article.summary, status=EpistemicState.REPORTED, observed_vs_context=ObservedVsContext.OBSERVED,
        analyst_notes="Single-source summary from the cited record; REPORTED pending independent corroboration.",
    )

    if context.family in ("cve_advisory", "cisa_advisory", "cisa_kev"):
        if article.cve_id:
            _add_claim_with_evidence(
                graph, article, claim_id="c-cve-id", claim_type=ClaimType.VULNERABILITY_FACT,
                text=f"This record is assigned {article.cve_id}.", status=EpistemicState.CONFIRMED,
                observed_vs_context=ObservedVsContext.OBSERVED,
                analyst_notes="CVE ID assignment is confirmed directly against the CVE record itself, "
                              "not an inference from surrounding prose.",
            )

        exploitation_state_map = {
            "confirmed": EpistemicState.CONFIRMED, "not_confirmed": EpistemicState.NOT_ASSESSED,
            "unknown": EpistemicState.UNKNOWN, "not_applicable": EpistemicState.NOT_APPLICABLE,
        }
        exploitation_status = exploitation_state_map.get(context.exploitation_status, EpistemicState.NOT_ASSESSED)
        # EXPLOITATION is a Section-10 high-impact claim type: even where
        # report_integrity.py's own classifier says "confirmed" (e.g. a
        # positive KEV listing), a bare KEV flag from one source stays at
        # REPORTED here rather than CONFIRMED -- CISA's KEV catalog is
        # authoritative for "this CVE is KEV-listed," which is captured as
        # its own CONFIRMED claim below; "exploitation occurred" is a
        # broader claim this one source alone does not settle.
        if exploitation_status == EpistemicState.CONFIRMED:
            exploitation_status = EpistemicState.REPORTED
        _add_claim_with_evidence(
            graph, article, claim_id="c-exploitation-status", claim_type=ClaimType.EXPLOITATION,
            text=context.exploitation_label, status=exploitation_status,
            observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="Exploitation is a Section 10 high-impact claim type; capped at REPORTED on a "
                          "single source regardless of the source's own confidence framing.",
        )

        if article.kev_listed is True:
            _add_claim_with_evidence(
                graph, article, claim_id="c-kev-listed", claim_type=ClaimType.DETECTION_STATE,
                text="This CVE is listed in the CISA Known Exploited Vulnerabilities catalog.",
                status=EpistemicState.CONFIRMED, observed_vs_context=ObservedVsContext.OBSERVED,
                analyst_notes="CISA's own KEV catalog is authoritative for its own listing decision.",
            )

        patch_state_map = {
            "available": EpistemicState.REPORTED, "required_action": EpistemicState.REPORTED,
            "unconfirmed": EpistemicState.UNKNOWN, "not_applicable": EpistemicState.NOT_APPLICABLE,
        }
        _add_claim_with_evidence(
            graph, article, claim_id="c-patch-status", claim_type=ClaimType.VULNERABILITY_FACT,
            text=context.patch_label, status=patch_state_map.get(context.patch_status, EpistemicState.UNKNOWN),
            observed_vs_context=ObservedVsContext.OBSERVED,
        )

    elif context.family == "ransomware_claim":
        victim_name = article.title
        _add_claim_with_evidence(
            graph, article, claim_id="c-victim-claim", claim_type=ClaimType.VICTIM_IDENTITY,
            text=f"A leak-site listing names this organization as a victim: {victim_name}.",
            status=EpistemicState.REPORTED, observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="Third-party leak-site claim, independently unverified -- REPORTED, not CONFIRMED "
                          "(Section 10: VICTIM_IDENTITY is a high-impact claim type).",
        )
        actor_label = next((label for label in article.labels if label and label.lower() != "ransomware"), None)
        if actor_label:
            _add_claim_with_evidence(
                graph, article, claim_id="c-actor-attribution", claim_type=ClaimType.ACTOR_ATTRIBUTION,
                text=f"The leak-site listing attributes this claim to the group publicly tracked as {actor_label}.",
                status=EpistemicState.REPORTED, observed_vs_context=ObservedVsContext.OBSERVED,
                analyst_notes="Attribution rests on the leak-site's own labeling, not independent confirmation.",
            )

    # Every family, always: an honest, explicit unresolved question, never
    # silently omitted (matches every real canary's own Intelligence Gaps
    # discipline) -- whether the underlying event has any independent,
    # second-source confirmation beyond this one record.
    _add_claim_with_evidence(
        graph, article, claim_id="c-independent-corroboration", claim_type=ClaimType.VULNERABILITY_FACT,
        text="Whether an independent second source corroborates this record has not been assessed.",
        status=EpistemicState.NOT_ASSESSED, observed_vs_context=ObservedVsContext.CONTEXT,
    )


def build_threat_product(article: DiscoveredArticle, context: ReportContext) -> ThreatProduct | None:
    """Only constructs a ``ThreatProduct`` for the families that already
    have a real schema (Reuse Before Build) -- ``None`` for every other
    family, which is the honest answer, not a gap papered over with the
    wrong schema."""
    if context.family == "cisa_kev":
        return CISAKEVRecord(
            product_id=context.report_id, cve_id=article.cve_id or "",
            vendor_project=article.affected_vendor, product=article.affected_product,
            date_added=article.kev_date_added, due_date=article.kev_due_date,
            required_action=article.kev_required_action,
            known_ransomware_campaign_use=EpistemicState.NOT_ASSESSED,
            reference_source_ids=[PRIMARY_SOURCE_ID],
        )
    if context.family in ("cve_advisory", "cisa_advisory") and article.cve_id:
        return CVERecord(
            product_id=context.report_id, cve_id=article.cve_id,
            cna_or_vendor=article.affected_vendor, product=article.affected_product,
            cvss_v31=article.cvss_score, cvss_v31_vector=article.cvss_vector,
            cwe=", ".join(article.cwe_ids) if article.cwe_ids else None,
            epss_score=article.epss_score, epss_percentile=article.epss_percentile,
            kev_state=EpistemicState.CONFIRMED if article.kev_listed else (
                EpistemicState.NOT_APPLICABLE if article.kev_listed is False else EpistemicState.NOT_ASSESSED
            ),
            confirmed_exploitation_status=(
                EpistemicState.REPORTED if context.exploitation_status == "confirmed" else EpistemicState.NOT_ASSESSED
            ),
            reference_source_ids=[PRIMARY_SOURCE_ID],
        )
    if context.family == "ransomware_claim":
        from .threat_schemas import ActorHistoricalContext, GenericReadiness, VictimObservation

        actor_label = next((label for label in article.labels if label and label.lower() != "ransomware"), "")
        return RansomwareVictimClaim(
            product_id=context.report_id,
            victim_observation=VictimObservation(
                group_named_by_source=actor_label or None, victim_name=article.title,
                claim_date=article.published_at,
                claim_temporal_precision=infer_temporal_precision(article.published_at),
                leak_site_claim_status=EpistemicState.REPORTED,
                source_claim_ids=["c-victim-claim"],
            ),
            actor_context=ActorHistoricalContext(actor_aliases=[actor_label] if actor_label else []),
            generic_readiness=GenericReadiness(),
        )
    return None


def build_evidence_graph(article: DiscoveredArticle, context: ReportContext) -> EvidenceGraph:
    graph = EvidenceGraph()
    graph.add_source(build_source_record(article, context))
    build_claims(graph, article, context)
    return graph
