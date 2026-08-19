"""Tests for sentinel_engine.reportx.discovery_bridge -- the
DiscoveredArticle -> EvidenceGraph adapter (Intelligence Factory
architecture, the one genuinely missing piece).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from automation.content_discovery import DiscoveredArticle
from automation.report_integrity import build_report_context

from sentinel_engine.reportx.claim_model import CorroborationState, EpistemicState, Reliability
from sentinel_engine.reportx.discovery_bridge import (
    build_evidence_graph,
    build_source_record,
    build_threat_product,
    source_reliability,
)
from sentinel_engine.reportx.threat_schemas import CISAKEVRecord, CVERecord, RansomwareVictimClaim


def _cve_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-99999",
        title="CVE-2026-99999 test vulnerability",
        summary="A test vulnerability allows remote code execution via crafted input.",
        published_at="2026-08-17T11:16:44Z",
        content_hash="deadbeef",
        labels=["Vulnerabilities"],
        source="nvd",
        cve_id="CVE-2026-99999", cvss_score=9.1, cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_ids=["CWE-78"], kev_listed=False,
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


def _ransomware_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://www.ransomware.live/id/test",
        title="Acme Test Corp", summary="qilin has listed Acme Test Corp as a new victim on its leak site.",
        published_at="2026-08-18T00:00:00Z", content_hash="cafef00d",
        # labels carries the site's own taxonomy tags (matches every real
        # ransomware_intel article, which also always carries a brand tag
        # like "CYBERDUDEBIVASH" -- see test_actor_attribution_uses_ransomware_group_not_labels
        # below); ransomware_group is threat_feeds.py's real, separately-
        # sanitized actor field (always populated for a real ransomware_intel
        # article -- RansomwareIntelSource defaults it to "Unknown Group"
        # rather than leaving it unset) and is the field discovery_bridge.py
        # must read for attribution, not labels.
        labels=["Ransomware", "CYBERDUDEBIVASH"], source="ransomware_intel", ransomware_group="qilin",
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


class TestSourceReliability:
    def test_authoritative_sources_are_high(self):
        for source in ("nvd", "cisa_kev", "cisa_advisory", "mitre"):
            assert source_reliability(_cve_article(source=source)) == Reliability.HIGH

    def test_third_party_aggregators_are_moderate(self):
        assert source_reliability(_ransomware_article()) == Reliability.MODERATE

    def test_unrecognized_source_is_unknown_not_fabricated_high(self):
        assert source_reliability(_cve_article(source="some_new_feed")) == Reliability.UNKNOWN

    def test_known_curated_rss_publisher_is_moderate_not_unknown(self):
        # COMMERCIAL-QUALITY-2026-08-18: independently verified live that
        # every global_rss article graded Reliability.UNKNOWN ("F")
        # regardless of which of ~40 distinct, individually-curated outlets
        # (BleepingComputer, Dark Reading, ...) it actually came from --
        # source_reliability() keyed only on the connector name
        # ("global_rss"), discarding the real, known publisher entirely.
        article = _cve_article(source="global_rss", source_publisher="Dark Reading")
        assert source_reliability(article) == Reliability.MODERATE

    def test_rss_article_with_no_known_publisher_stays_unknown(self):
        # Not every RSS-shaped article has a curated publisher (e.g. a feed
        # outside the hand-maintained list) -- must not default everything
        # unconditionally to MODERATE just because it's RSS-shaped.
        article = _cve_article(source="global_rss", source_publisher=None)
        assert source_reliability(article) == Reliability.UNKNOWN


class TestSourceRecord:
    def test_publisher_prefers_the_real_named_outlet_over_the_connector(self):
        article = _cve_article(source="global_rss", source_publisher="Dark Reading")
        context = build_report_context(article)
        record = build_source_record(article, context)
        assert record.publisher == "Dark Reading"

    def test_publisher_falls_back_to_the_connector_when_no_named_outlet_is_known(self):
        article = _cve_article(source="nvd", source_publisher=None)
        context = build_report_context(article)
        record = build_source_record(article, context)
        assert record.publisher == "nvd"

    def test_full_content_hashes_real_content(self):
        article = _cve_article(full_content="the complete retrieved article text")
        context = build_report_context(article)
        record = build_source_record(article, context)
        assert record.content_sha256 is not None
        assert record.excerpt_fingerprint_sha256 is None

    def test_missing_full_content_uses_honest_excerpt_fallback_not_a_fabricated_hash(self):
        article = _cve_article(full_content=None)
        context = build_report_context(article)
        record = build_source_record(article, context)
        assert record.content_sha256 is None
        assert record.excerpt_fingerprint_sha256 is not None
        assert record.fingerprint_fallback_reason


class TestClaimConstruction:
    def test_cve_article_produces_conservative_epistemic_states(self):
        article = _cve_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context)
        assert graph.claims["c-cve-id"].status == EpistemicState.CONFIRMED  # NVD is authoritative for its own ID
        # EXPLOITATION is a Section 10 high-impact claim type -- never CONFIRMED on one source
        assert graph.claims["c-exploitation-status"].status != EpistemicState.CONFIRMED

    def test_kev_listed_produces_a_confirmed_kev_claim(self):
        article = _cve_article(kev_listed=True, source="cisa_kev")
        context = build_report_context(article)
        graph = build_evidence_graph(article, context)
        assert "c-kev-listed" in graph.claims
        assert graph.claims["c-kev-listed"].status == EpistemicState.CONFIRMED

    def test_ransomware_victim_claim_stays_reported_never_confirmed(self):
        article = _ransomware_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context)
        assert graph.claims["c-victim-claim"].status == EpistemicState.REPORTED
        assert graph.claims["c-victim-claim"].claim_type.value == "VICTIM_IDENTITY"

    def test_actor_attribution_uses_ransomware_group_not_the_site_taxonomy_label(self):
        # Real regression, found via real-data testing of the newly-wired
        # evidence_graph output (RX-P1C-WIRE): this claim used to be built
        # from `next(label for label in article.labels if label != "ransomware")`
        # -- article.labels carries site taxonomy tags every article gets
        # (e.g. "CYBERDUDEBIVASH"), not the actor name, so a real article
        # whose first non-"ransomware" label happened to be a taxonomy tag
        # got misattributed to that tag instead of the real actor. The
        # fixture's labels=[...,"CYBERDUDEBIVASH"] reproduces exactly that
        # shape; the correct source is ransomware_group.
        article = _ransomware_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context)
        claim = graph.claims["c-actor-attribution"]
        assert "qilin" in claim.text
        assert "CYBERDUDEBIVASH" not in claim.text

    def test_unknown_group_placeholder_does_not_become_a_named_actor_attribution(self):
        # Mirrors the identical, already-fixed regression class in
        # internal_linker.py/report_contract.py (both: "Unknown Group" is
        # threat_feeds.py's real fallback string for a genuinely unnamed
        # actor, never a real identity) -- this module read the wrong field
        # entirely before this fix, so it never had this guard either.
        article = _ransomware_article(ransomware_group="Unknown Group")
        context = build_report_context(article)
        graph = build_evidence_graph(article, context)
        assert "c-actor-attribution" not in graph.claims

    def test_every_claim_carries_real_evidence_and_source_refs(self):
        article = _cve_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context)
        for claim in graph.claims.values():
            assert claim.evidence_refs, f"{claim.claim_id} has no evidence_refs"
            assert claim.source_refs, f"{claim.claim_id} has no source_refs"

    def test_independent_corroboration_gap_is_always_present_and_honest(self):
        for article in (_cve_article(), _ransomware_article()):
            context = build_report_context(article)
            graph = build_evidence_graph(article, context)
            gap = graph.claims["c-independent-corroboration"]
            assert gap.status == EpistemicState.NOT_ASSESSED


class TestIndependentSourceCorroboration:
    """Round 7: build_evidence_graph's optional state_file parameter --
    real, already-persisted independent-source corroboration (data/
    published_posts.json), never a live network fetch, and a strict no-op
    for every caller that doesn't pass it -- including every other test in
    this file, which keeps working unchanged."""

    @staticmethod
    def _write_state(path: Path, posts: dict) -> str:
        path.write_text(json.dumps({"posts": posts}), encoding="utf-8")
        return str(path)

    def test_no_state_file_is_a_pure_no_op(self):
        article = _cve_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context)
        assert list(graph.sources.keys()) == ["src-primary"]

    def test_independent_match_adds_a_second_source_and_corroborates_the_cve_claims(self, tmp_path):
        state_file = self._write_state(tmp_path / "published_posts.json", {
            "hash1": {
                "source_url": "https://www.bleepingcomputer.com/x", "source_title": "x",
                "cves": ["CVE-2026-99999"], "published_at": "2026-08-01T00:00:00Z",
                "source": "global_rss", "source_publisher": "BleepingComputer",
            },
        })
        article = _cve_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context, state_file=state_file)

        assert "src-corroboration-1" in graph.sources
        assert graph.claims["c-cve-id"].corroboration_state == CorroborationState.MULTI_SOURCE_INDEPENDENT
        assert graph.claims["c-summary"].corroboration_state == CorroborationState.MULTI_SOURCE_INDEPENDENT
        gap = graph.claims["c-independent-corroboration"]
        assert gap.status == EpistemicState.CONFIRMED
        assert "BleepingComputer" in gap.text

    def test_high_impact_claims_stay_single_sourced_even_with_a_match(self, tmp_path):
        # A bare CVE-ID match establishes the CVE's identity is corroborated
        # -- it does NOT establish agreement on exploitation status, which
        # must keep Section 10's single-source discipline.
        state_file = self._write_state(tmp_path / "published_posts.json", {
            "hash1": {
                "source_url": "https://www.bleepingcomputer.com/x", "source_title": "x",
                "cves": ["CVE-2026-99999"], "published_at": "2026-08-01T00:00:00Z",
                "source": "global_rss", "source_publisher": "BleepingComputer",
            },
        })
        article = _cve_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context, state_file=state_file)
        assert graph.claims["c-exploitation-status"].corroboration_state == CorroborationState.SINGLE_SOURCE

    def test_ambiguous_current_publisher_fails_closed_even_with_a_real_match(self, tmp_path):
        # CodeRabbit review: "global_rss" is the aggregation CONNECTOR
        # (~40 distinct outlets), not a publisher. If THIS article's own
        # real publisher is unknown, we cannot honestly tell a same-outlet
        # re-crawl from a genuinely independent one -- must fail closed
        # (never even attempt the lookup), not just get lucky that the
        # historical entry's publisher happens to differ lexically.
        state_file = self._write_state(tmp_path / "published_posts.json", {
            "hash1": {
                "source_url": "https://www.bleepingcomputer.com/x", "source_title": "x",
                "cves": ["CVE-2026-99999"], "published_at": "2026-08-01T00:00:00Z",
                "source": "global_rss", "source_publisher": "BleepingComputer",
            },
        })
        article = _cve_article(source="global_rss", source_publisher=None)
        context = build_report_context(article)
        graph = build_evidence_graph(article, context, state_file=state_file)
        assert list(graph.sources.keys()) == ["src-primary"]
        assert graph.claims["c-independent-corroboration"].status == EpistemicState.NOT_ASSESSED

    def test_corroborating_source_retrieved_at_is_this_reports_own_clock(self, tmp_path):
        # CodeRabbit review: match["published_at"] is when OUR pipeline
        # published the OLDER post, not when we retrieved this
        # corroborating fact -- using it as retrieved_at recorded false
        # provenance. retrieved_at must be this report's own generation
        # time, always, regardless of the historical entry's timestamp.
        state_file = self._write_state(tmp_path / "published_posts.json", {
            "hash1": {
                "source_url": "https://www.bleepingcomputer.com/x", "source_title": "x",
                "cves": ["CVE-2026-99999"], "published_at": "2019-01-01T00:00:00Z",
                "source": "global_rss", "source_publisher": "BleepingComputer",
            },
        })
        article = _cve_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context, state_file=state_file)
        corroborating = graph.sources["src-corroboration-1"]
        assert corroborating.retrieved_at == context.generated_at
        assert corroborating.retrieved_at != "2019-01-01T00:00:00Z"

    def test_no_match_leaves_the_gap_claim_honestly_unassessed(self, tmp_path):
        state_file = self._write_state(tmp_path / "published_posts.json", {})
        article = _cve_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context, state_file=state_file)
        assert list(graph.sources.keys()) == ["src-primary"]
        assert graph.claims["c-independent-corroboration"].status == EpistemicState.NOT_ASSESSED

    def test_ransomware_family_has_no_cve_id_and_is_unaffected(self, tmp_path):
        state_file = self._write_state(tmp_path / "published_posts.json", {
            "hash1": {
                "source_url": "https://www.bleepingcomputer.com/x", "source_title": "x",
                "cves": ["CVE-2026-99999"], "published_at": "2026-08-01T00:00:00Z",
                "source": "global_rss", "source_publisher": "BleepingComputer",
            },
        })
        article = _ransomware_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context, state_file=state_file)
        assert list(graph.sources.keys()) == ["src-primary"]

    def test_corroborating_source_carries_a_real_fingerprint_not_a_missing_hash(self, tmp_path):
        # Regression for a real defect caught live while building this
        # feature: a synthesized second source with neither content_sha256
        # nor an excerpt fingerprint fails commercial_readiness's own
        # evidence_hash integrity control.
        state_file = self._write_state(tmp_path / "published_posts.json", {
            "hash1": {
                "source_url": "https://www.bleepingcomputer.com/x", "source_title": "x",
                "cves": ["CVE-2026-99999"], "published_at": "2026-08-01T00:00:00Z",
                "source": "global_rss", "source_publisher": "BleepingComputer",
            },
        })
        article = _cve_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context, state_file=state_file)
        corroborating = graph.sources["src-corroboration-1"]
        assert corroborating.content_sha256 or corroborating.excerpt_fingerprint_sha256
        if corroborating.excerpt_fingerprint_sha256:
            assert corroborating.fingerprint_fallback_reason


class TestThreatProductMapping:
    def test_cve_advisory_maps_to_cve_record(self):
        article = _cve_article()
        context = build_report_context(article)
        product = build_threat_product(article, context)
        assert isinstance(product, CVERecord)
        assert product.cve_id == "CVE-2026-99999"
        assert product.cvss_v31 == 9.1

    def test_cisa_kev_maps_to_cisa_kev_record(self):
        article = _cve_article(source="cisa_kev", kev_listed=True, kev_date_added="2026-08-17")
        context = build_report_context(article)
        product = build_threat_product(article, context)
        assert isinstance(product, CISAKEVRecord)
        assert product.date_added == "2026-08-17"

    def test_ransomware_claim_maps_to_ransomware_victim_claim(self):
        article = _ransomware_article()
        context = build_report_context(article)
        product = build_threat_product(article, context)
        assert isinstance(product, RansomwareVictimClaim)
        assert product.victim_observation.victim_name == "Acme Test Corp"
        # Same regression as test_actor_attribution_uses_ransomware_group_not_the_site_taxonomy_label
        # above, checked at the ThreatProduct layer this time: both
        # build_claims() and build_threat_product() shared the identical
        # article.labels-based bug before this fix.
        assert product.victim_observation.group_named_by_source == "qilin"
        assert product.actor_context.actor_aliases == ["qilin"]

    def test_unmapped_family_returns_none_not_a_wrong_schema(self):
        article = DiscoveredArticle(
            url="https://example.com/breach", title="Example breach notice",
            summary="A company disclosed a data breach affecting customer records.",
            published_at="2026-08-18T00:00:00Z", content_hash="x", labels=[], source="breach_intel",
        )
        context = build_report_context(article)
        assert build_threat_product(article, context) is None
