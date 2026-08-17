"""Source-integrity / evidence-hash policy (ReportX Section 33 row 2).

Two honest tiers, never a fabricated one:

1. **Full content hash** (``SourceRecord.content_sha256``) — SHA-256 of the
   actual raw bytes retrieved for this source. This is the strong case:
   the source's own content, byte-for-byte, was captured and hashed. It
   requires actually fetching raw bytes (e.g. a direct HTTP fetch), not a
   model-summarized excerpt of the page — hashing a paraphrase and calling
   it a "content hash" would misrepresent what was actually hashed.

2. **Canonical excerpt fingerprint** (``excerpt_fingerprint_sha256``) — the
   explicit, reproducible fallback for a source that genuinely cannot be
   fully archived (JS-only rendering no fetch tool can execute, an access
   block, a legal/ToS constraint on redistribution). This hashes the
   EXCERPT TEXT actually captured and relied upon (``EvidenceRecord``
   excerpts tied to that source) — real bytes this session actually
   possesses, not a hash of content never seen. ``fingerprint_fallback_reason``
   is mandatory whenever this tier is used instead of a full content hash,
   so the fallback itself is explained, not a silent downgrade.

Neither tier is ever fabricated: a source with no ``content_sha256`` AND
no ``excerpt_fingerprint_sha256`` simply fails this gate -- there is no
third, weaker path that manufactures a hash of something never retrieved.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .claim_model import EvidenceGraph, SourceRecord


def compute_content_sha256(raw_content: bytes | str) -> str:
    """Hash actual retrieved bytes (or text already known to be the raw
    content, e.g. read back from a file the fetch was saved to)."""
    if isinstance(raw_content, str):
        raw_content = raw_content.encode("utf-8")
    return hashlib.sha256(raw_content).hexdigest()


def compute_excerpt_fingerprint(excerpts: list[str]) -> str:
    """Deterministic fingerprint of the real excerpt text captured for one
    source -- sorted so the result doesn't depend on insertion order, and
    joined with a separator that can't collide with excerpt content
    itself in practice for this use case (a hash collision from ordering
    ambiguity is not the threat model here; reproducibility across two
    independent runs over the same excerpt set is)."""
    canonical = "\n\x1f\n".join(sorted(e.strip() for e in excerpts if e.strip()))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_source_excerpt_fingerprint(graph: EvidenceGraph, source_id: str) -> str | None:
    """Convenience: gathers every EvidenceRecord excerpt actually citing
    this source_id and fingerprints them together. Returns None if the
    source has no evidence excerpts captured at all -- there is nothing
    real to fingerprint yet."""
    excerpts = [ev.excerpt for ev in graph.evidence.values() if ev.source_id == source_id]
    if not excerpts:
        return None
    return compute_excerpt_fingerprint(excerpts)


@dataclass
class SourceIntegrityFinding:
    source_id: str
    reason: str

    def to_dict(self) -> dict:
        return {"source_id": self.source_id, "reason": self.reason}


@dataclass
class SourceIntegrityGateResult:
    findings: list[SourceIntegrityFinding] = field(default_factory=list)
    full_content_hash_count: int = 0
    excerpt_fingerprint_count: int = 0

    @property
    def passed(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "findings": [f.to_dict() for f in self.findings],
            "full_content_hash_count": self.full_content_hash_count,
            "excerpt_fingerprint_count": self.excerpt_fingerprint_count,
        }


def evaluate_source_integrity_gate(sources: list[SourceRecord]) -> SourceIntegrityGateResult:
    """A source with a ``url`` is "hashable" and must carry EITHER a real
    ``content_sha256`` OR a real ``excerpt_fingerprint_sha256`` PLUS its
    mandatory ``fingerprint_fallback_reason``. A source with neither tier
    populated fails -- there is no default that manufactures integrity
    evidence for a source nobody actually fingerprinted."""
    result = SourceIntegrityGateResult()
    for s in sources:
        if not s.url:
            continue  # nothing to hash -- excluded from the denominator, not counted as a failure
        if s.content_sha256:
            result.full_content_hash_count += 1
            continue
        if s.excerpt_fingerprint_sha256:
            if not s.fingerprint_fallback_reason:
                result.findings.append(SourceIntegrityFinding(
                    s.source_id,
                    "excerpt_fingerprint_sha256 is set but fingerprint_fallback_reason is missing -- "
                    "the fallback must be explained, not a silent downgrade from a full content hash.",
                ))
                continue
            result.excerpt_fingerprint_count += 1
            continue
        result.findings.append(SourceIntegrityFinding(
            s.source_id, "no content_sha256 and no excerpt_fingerprint_sha256 recorded.",
        ))
    return result
