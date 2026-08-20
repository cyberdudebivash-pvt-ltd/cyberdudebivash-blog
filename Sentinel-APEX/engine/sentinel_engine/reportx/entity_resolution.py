"""Phase 1G -- canonical entity resolution for REPORTX.

Scope decision, stated explicitly: this module resolves entities for
REPORTX (the ``automation``/``sentinel_engine.reportx`` pipeline) only. A
separate, more elaborate entity/attribution/campaign-clustering stack
already exists in ``api/_lib/`` (``threat-graph.js``, ``campaign-engine.js``,
``enrichment-pipeline.js``) serving Pipeline B's own live-intel API
(``fetch-live-intel.js`` -> ``api/intel/*.json``). That stack is
deliberately not touched or duplicated here: CLAUDE.md's ecosystem
governance draws a hard line between the CTI platform/blog's own live API
surface and REPORTX's Blogger-published dossiers, and Principle 3 (Single
Source of Truth) argues against building a second, REPORTX-side copy of
attribution logic that already exists and is more sophisticated on the
Pipeline B side for a system REPORTX doesn't share data with.

Every entity constructed here is either (a) taken directly from an
already-classified, structured ``DiscoveredArticle`` field (CVE ID,
ransomware group/sector/country -- the same fields ``discovery_bridge.py``
already turns into claims), or (b) extracted from the article's own cited
summary text via ``sentinel_engine.entities``'s existing curated lexicon
(Reuse Before Build -- this module does not reimplement entity extraction).
Nothing here is ever derived from LLM-generated narrative (Key Judgements,
rendered report prose) -- only from the source article itself, matching the
mandate's "do not create entities based solely on LLM-generated names."

No fuzzy/alias/edit-distance matching is performed between distinct raw
name strings (e.g. two different ransomware-group name spellings are never
merged). This is a deliberate, evidence-based choice: no verified alias
source exists for ``article.ransomware_group`` today (unlike the curated,
hand-verified lexicon in ``entities.py``, which already resolves its own
aliases safely), and false-merging distinct real-world actors is an
explicit CTI integrity failure this mandate warns against. Only
unambiguous identity normalization (Unicode NFC, casefold, whitespace
collapse) is applied -- see ``_canonical_id()``.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Optional

from ..entities import LEXICON, extract_entities
from .claim_model import EvidenceGraph
from .discovery_bridge import PRIMARY_SOURCE_ID

# Same pattern as enrichment.py's own CVE validator -- reused verbatim
# rather than re-derived, so a "valid CVE" means the same thing everywhere.
_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

# Same dependency-light duplication rationale as internal_linker.py's,
# report_contract.py's, and discovery_bridge.py's own copies of this exact
# constant (each file's docstring explains why it isn't imported instead:
# no single owner across automation/ and sentinel_engine/, and each copy
# exists to guard against the same regression independently). This module
# lives inside sentinel_engine.reportx already, alongside discovery_bridge.py,
# but keeps its own copy rather than importing discovery_bridge.py's
# underscore-prefixed (not-public-API) constant, for the same reason.
_PLACEHOLDER_ACTOR_NAMES = frozenset({"Unknown Group"})

# Mirrors threat_feeds.py's _PLACEHOLDER_TAXONOMY for the same fields
# (ransomware_sector/ransomware_country) -- articles reaching this module
# have already passed through threat_feeds.py's _clean_taxonomy() once at
# ingestion, but this guard is kept here too rather than trusted blindly,
# consistent with every other placeholder guard in this pipeline never
# assuming an upstream check was applied.
_PLACEHOLDER_TAXONOMY = frozenset({
    "unknown", "not found", "not found sector", "unspecified",
    "unspecified sector", "n/a", "na", "none", "null", "-",
})

_CONFIDENCE_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


@dataclass(frozen=True)
class CanonicalEntity:
    """A resolved, evidence-linked entity. Field set matches the mandate's
    Phase 1G contract: canonical_id, canonical_name, aliases, entity_type,
    source_refs, evidence_refs, confidence, first_seen, last_seen."""

    canonical_id: str
    canonical_name: str
    entity_type: str
    aliases: tuple = ()
    source_refs: tuple = ()
    evidence_refs: tuple = ()
    confidence: str = "LOW"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "canonical_id": self.canonical_id,
            "canonical_name": self.canonical_name,
            "entity_type": self.entity_type,
            "aliases": list(self.aliases),
            "source_refs": list(self.source_refs),
            "evidence_refs": list(self.evidence_refs),
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


def _canonical_id(entity_type: str, name: str) -> str:
    """Case/whitespace-insensitive identity, deliberately WITHOUT fuzzy or
    alias-based folding -- see the module docstring. Unicode NFC
    normalization collapses combining-character sequences that render
    identically (e.g. e + combining-acute vs the precomposed e-acute
    codepoint), which is a safe, unambiguous equivalence. It does NOT fold
    "confusable" characters from different scripts (e.g. Cyrillic 'а'
    vs Latin 'a') -- those remain distinct ids by design, so a lookalike
    string can never silently merge into a real entity's identity."""
    normalized = unicodedata.normalize("NFC", name).casefold()
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return f"{entity_type}:{normalized}"


def _evidence_refs_for(evidence_graph: Optional[EvidenceGraph], *claim_ids: str) -> tuple:
    if evidence_graph is None:
        return ()
    return tuple(
        f"e-{claim_id}" for claim_id in claim_ids
        if f"e-{claim_id}" in evidence_graph.evidence
    )


def _cve_entity(article, evidence_graph) -> Optional[CanonicalEntity]:
    cve_id = (article.cve_id or "").upper().strip()
    if not cve_id or not _RE_CVE.match(cve_id):
        return None
    return CanonicalEntity(
        canonical_id=_canonical_id("cve", cve_id),
        canonical_name=cve_id,
        entity_type="cve",
        source_refs=(PRIMARY_SOURCE_ID,),
        evidence_refs=_evidence_refs_for(evidence_graph, "c-cve-id"),
        # Structured field straight from the source API (NVD/CISA/GitHub
        # Advisories) -- not regex-inferred from prose, so HIGH is honest.
        confidence="HIGH",
        first_seen=article.published_at,
        last_seen=article.published_at,
    )


def _ransomware_actor_entity(article, evidence_graph) -> Optional[CanonicalEntity]:
    group = (article.ransomware_group or "").strip()
    if not group or group in _PLACEHOLDER_ACTOR_NAMES:
        return None
    return CanonicalEntity(
        canonical_id=_canonical_id("ransomware_actor", group),
        canonical_name=group,
        entity_type="ransomware_actor",
        source_refs=(PRIMARY_SOURCE_ID,),
        evidence_refs=_evidence_refs_for(evidence_graph, "c-actor-attribution"),
        # Matches build_claims()'s own ceiling: a leak-site's self-reported
        # attribution is REPORTED, never CONFIRMED, on a single source.
        confidence="MEDIUM",
        first_seen=article.published_at,
        last_seen=article.published_at,
    )


def _taxonomy_entity(entity_type: str, raw_value, article) -> Optional[CanonicalEntity]:
    cleaned = (raw_value or "").strip()
    if not cleaned or cleaned.casefold() in _PLACEHOLDER_TAXONOMY:
        return None
    return CanonicalEntity(
        canonical_id=_canonical_id(entity_type, cleaned),
        canonical_name=cleaned,
        entity_type=entity_type,
        source_refs=(PRIMARY_SOURCE_ID,),
        # No dedicated claim/evidence record backs sector/country today
        # (build_claims() doesn't construct one) -- LOW, not fabricated
        # evidence_refs.
        confidence="LOW",
        first_seen=article.published_at,
        last_seen=article.published_at,
    )


def _lexicon_entities(article) -> tuple:
    """Malware/tool/vendor/product/threat-actor mentions found in the
    article's own title+summary via the existing curated lexicon
    (entities.py) -- never from LLM-generated content. LOW confidence:
    text-matched, not a structured field."""
    text = f"{article.title or ''} {article.summary or ''}"
    out = []
    for ent in extract_entities(text):
        aliases = LEXICON.get(ent.name, (ent.type, ()))[1]
        out.append(CanonicalEntity(
            canonical_id=_canonical_id(ent.type, ent.name),
            canonical_name=ent.name,
            entity_type=ent.type,
            aliases=tuple(aliases),
            source_refs=(PRIMARY_SOURCE_ID,),
            confidence="LOW",
            first_seen=article.published_at,
            last_seen=article.published_at,
        ))
    return tuple(out)


def resolve_canonical_entities(article, evidence_graph: Optional[EvidenceGraph] = None) -> tuple:
    """Resolve every canonical entity this article's evidence honestly
    supports. Never fabricates an entity for a placeholder, empty, or
    malformed field. Entity types covered this phase: cve, ransomware_actor,
    sector, country, plus whatever entity_type values entities.py's LEXICON
    contains (threat_actor, malware, tool, vendor, product). Vendor/product
    from article.affected_vendor/affected_product (CVE families), victim
    organizations, domains/IPs/hashes/URLs, and infrastructure are not
    resolved in this phase -- confirmed absent of any existing
    alias/canonicalization mechanism to build on (reconnaissance finding,
    not an oversight); tracked as follow-up rather than shipped unverified."""
    resolved: dict = {}

    def _add(entity: Optional[CanonicalEntity]) -> None:
        if entity is None:
            return
        existing = resolved.get(entity.canonical_id)
        if existing is None or _CONFIDENCE_RANK.get(entity.confidence, 0) > _CONFIDENCE_RANK.get(existing.confidence, 0):
            resolved[entity.canonical_id] = entity

    _add(_cve_entity(article, evidence_graph))
    _add(_ransomware_actor_entity(article, evidence_graph))
    _add(_taxonomy_entity("sector", getattr(article, "ransomware_sector", None), article))
    _add(_taxonomy_entity("country", getattr(article, "ransomware_country", None), article))
    for ent in _lexicon_entities(article):
        _add(ent)

    return tuple(sorted(resolved.values(), key=lambda e: (e.entity_type, e.canonical_name)))
