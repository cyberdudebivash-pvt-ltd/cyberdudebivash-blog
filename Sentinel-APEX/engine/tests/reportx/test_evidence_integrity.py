from sentinel_engine.reportx.claim_model import (
    EvidenceGraph,
    EvidenceRecord,
    Reliability,
    SourceRecord,
    SourceRole,
    SourceType,
)
from sentinel_engine.reportx.evidence_integrity import (
    compute_content_sha256,
    compute_excerpt_fingerprint,
    compute_source_excerpt_fingerprint,
    evaluate_source_integrity_gate,
)


class TestComputeContentSha256:
    def test_hashes_real_bytes(self):
        import hashlib
        h = compute_content_sha256(b"hello world")
        # Verified against Python's own hashlib directly, not hand-typed --
        # a hand-typed expected constant is exactly the kind of unverified
        # "evidence" this whole module exists to avoid producing.
        assert h == hashlib.sha256(b"hello world").hexdigest()

    def test_accepts_str_and_encodes_utf8(self):
        assert compute_content_sha256("hello world") == compute_content_sha256(b"hello world")

    def test_different_content_produces_different_hash(self):
        assert compute_content_sha256("a") != compute_content_sha256("b")


class TestComputeExcerptFingerprint:
    def test_deterministic_regardless_of_input_order(self):
        a = compute_excerpt_fingerprint(["excerpt one", "excerpt two"])
        b = compute_excerpt_fingerprint(["excerpt two", "excerpt one"])
        assert a == b

    def test_different_excerpts_produce_different_fingerprints(self):
        a = compute_excerpt_fingerprint(["excerpt one"])
        b = compute_excerpt_fingerprint(["excerpt two"])
        assert a != b

    def test_empty_or_whitespace_only_excerpts_are_ignored(self):
        a = compute_excerpt_fingerprint(["real excerpt"])
        b = compute_excerpt_fingerprint(["real excerpt", "", "   "])
        assert a == b


class TestComputeSourceExcerptFingerprint:
    def test_gathers_all_evidence_excerpts_for_one_source(self):
        graph = EvidenceGraph()
        graph.add_source(SourceRecord(
            source_id="s1", url="https://example.com", publisher="Example",
            source_type=SourceType.JOURNALISM, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
            retrieved_at="2026-08-18T00:00:00Z",
        ))
        graph.add_evidence(EvidenceRecord(evidence_id="e1", source_id="s1", excerpt="First excerpt."))
        graph.add_evidence(EvidenceRecord(evidence_id="e2", source_id="s1", excerpt="Second excerpt."))
        fp = compute_source_excerpt_fingerprint(graph, "s1")
        assert fp is not None
        assert fp == compute_excerpt_fingerprint(["First excerpt.", "Second excerpt."])

    def test_returns_none_when_source_has_no_evidence_captured(self):
        graph = EvidenceGraph()
        graph.add_source(SourceRecord(
            source_id="s1", url="https://example.com", publisher="Example",
            source_type=SourceType.JOURNALISM, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
            retrieved_at="2026-08-18T00:00:00Z",
        ))
        assert compute_source_excerpt_fingerprint(graph, "s1") is None


def _source(source_id: str, **overrides) -> SourceRecord:
    defaults = dict(
        source_id=source_id, url="https://example.com", publisher="Example",
        source_type=SourceType.JOURNALISM, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-18T00:00:00Z",
    )
    defaults.update(overrides)
    return SourceRecord(**defaults)


class TestEvaluateSourceIntegrityGate:
    def test_full_content_hash_passes(self):
        gate = evaluate_source_integrity_gate([_source("s1", content_sha256="a" * 64)])
        assert gate.passed
        assert gate.full_content_hash_count == 1
        assert gate.excerpt_fingerprint_count == 0

    def test_excerpt_fingerprint_with_reason_passes(self):
        gate = evaluate_source_integrity_gate([_source(
            "s1", excerpt_fingerprint_sha256="b" * 64,
            fingerprint_fallback_reason="Source is a JS-rendered SPA; direct fetch could not retrieve raw content.",
        )])
        assert gate.passed
        assert gate.excerpt_fingerprint_count == 1
        assert gate.full_content_hash_count == 0

    def test_excerpt_fingerprint_without_reason_fails(self):
        gate = evaluate_source_integrity_gate([_source("s1", excerpt_fingerprint_sha256="b" * 64)])
        assert not gate.passed
        assert "fallback must be explained" in gate.findings[0].reason

    def test_neither_hash_present_fails(self):
        gate = evaluate_source_integrity_gate([_source("s1")])
        assert not gate.passed
        assert gate.findings[0].source_id == "s1"

    def test_source_with_no_url_is_excluded_not_failed(self):
        gate = evaluate_source_integrity_gate([_source("s1", url="")])
        assert gate.passed
        assert gate.findings == []

    def test_content_sha256_takes_priority_over_excerpt_fingerprint(self):
        # A source can legitimately carry both (e.g. full content captured
        # AND an excerpt fingerprint kept for defense in depth) -- the
        # full-content tier is what's counted, not double-counted or
        # treated as ambiguous.
        gate = evaluate_source_integrity_gate([_source(
            "s1", content_sha256="a" * 64, excerpt_fingerprint_sha256="b" * 64,
        )])
        assert gate.passed
        assert gate.full_content_hash_count == 1
        assert gate.excerpt_fingerprint_count == 0

    def test_mixed_sources_report_correct_counts(self):
        sources = [
            _source("s1", content_sha256="a" * 64),
            _source("s2", excerpt_fingerprint_sha256="b" * 64, fingerprint_fallback_reason="Access blocked (HTTP 403)."),
            _source("s3"),  # neither -- fails
        ]
        gate = evaluate_source_integrity_gate(sources)
        assert not gate.passed
        assert gate.full_content_hash_count == 1
        assert gate.excerpt_fingerprint_count == 1
        assert len(gate.findings) == 1
        assert gate.findings[0].source_id == "s3"
