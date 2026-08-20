"""Tests for sentinel_engine.reportx.entity_resolution -- Phase 1G canonical
entity resolution. The central claims under test: every entity produced is
traceable to a real, structured article field or the existing curated
lexicon (never fabricated), every placeholder/empty value is rejected
rather than promoted to a fake entity, and distinct raw name strings are
never fuzzy-merged into a false-positive shared identity."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from automation.content_discovery import DiscoveredArticle
from automation.report_integrity import build_report_context

from sentinel_engine.reportx.discovery_bridge import build_evidence_graph
from sentinel_engine.reportx.entity_resolution import (
    CanonicalEntity,
    _canonical_id,
    resolve_canonical_entities,
)


def _cve_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-99999",
        title="CVE-2026-99999 test vulnerability",
        summary="A test vulnerability in Fortinet FortiGate allows remote code execution via crafted input.",
        published_at="2026-08-17T11:16:44Z",
        content_hash="deadbeef",
        labels=["Vulnerabilities"], source="nvd",
        cve_id="CVE-2026-99999", cvss_score=9.1, cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_ids=["CWE-78"], kev_listed=False,
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


def _ransomware_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://www.ransomware.live/id/test",
        title="Acme Test Corp",
        summary="qilin has listed Acme Test Corp as a new victim on its leak site.",
        published_at="2026-08-18T00:00:00Z", content_hash="cafef00d",
        labels=["Ransomware", "CYBERDUDEBIVASH"], source="ransomware_intel",
        ransomware_group="qilin", ransomware_sector="Healthcare", ransomware_country="US",
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


def _entity_of_type(entities, entity_type):
    return [e for e in entities if e.entity_type == entity_type]


class TestCanonicalId:
    def test_case_and_whitespace_insensitive(self):
        assert _canonical_id("ransomware_actor", "LockBit") == _canonical_id("ransomware_actor", "  lockbit ")
        assert _canonical_id("ransomware_actor", "Lock  Bit") == _canonical_id("ransomware_actor", "Lock Bit")

    def test_different_entity_types_never_collide_on_the_same_name(self):
        assert _canonical_id("malware", "LockBit") != _canonical_id("ransomware_actor", "LockBit")

    def test_unicode_lookalike_does_not_merge(self):
        # Cyrillic 'о' (U+043E) substituted for the Latin 'o' (U+006F) in
        # "LockBit" -- a spoofed/confusable string must NOT collapse into
        # the real actor's canonical id (a security-relevant false-
        # attribution risk). Built via explicit codepoints, not a
        # visually-similar literal in source, so the test is unambiguous.
        latin = "LockBit"
        cyrillic_lookalike = "L" + "о" + "ckBit"
        assert latin != cyrillic_lookalike  # sanity: they really are different strings
        assert _canonical_id("ransomware_actor", latin) != _canonical_id("ransomware_actor", cyrillic_lookalike)

    def test_nfc_normalization_of_equivalent_codepoint_sequences(self):
        # 'e' + combining acute accent (U+0065 U+0301) vs the precomposed
        # 'é' (U+00E9) render identically and are a safe, unambiguous merge.
        decomposed = "café"
        precomposed = "café"
        assert _canonical_id("vendor", decomposed) == _canonical_id("vendor", precomposed)


class TestCveEntity:
    def test_valid_cve_resolves_high_confidence(self):
        entities = resolve_canonical_entities(_cve_article())
        cves = _entity_of_type(entities, "cve")
        assert len(cves) == 1
        assert cves[0].canonical_name == "CVE-2026-99999"
        assert cves[0].confidence == "HIGH"
        assert cves[0].first_seen == "2026-08-17T11:16:44Z"

    def test_malformed_cve_produces_no_entity(self):
        for bad in ("CVE-26-1234", "CVE-2026-1", "not-a-cve", "CVE-2026-", ""):
            entities = resolve_canonical_entities(_cve_article(cve_id=bad))
            assert _entity_of_type(entities, "cve") == [], f"malformed CVE {bad!r} must not resolve"

    def test_no_cve_id_produces_no_entity(self):
        entities = resolve_canonical_entities(_cve_article(cve_id=None))
        assert _entity_of_type(entities, "cve") == []

    def test_lowercase_cve_id_is_normalized_to_uppercase_canonical_name(self):
        entities = resolve_canonical_entities(_cve_article(cve_id="cve-2026-99999"))
        cves = _entity_of_type(entities, "cve")
        assert cves[0].canonical_name == "CVE-2026-99999"

    def test_evidence_refs_populated_against_a_real_evidence_graph(self):
        article = _cve_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context)
        entities = resolve_canonical_entities(article, graph)
        cves = _entity_of_type(entities, "cve")
        assert cves[0].evidence_refs == ("e-c-cve-id",)
        assert "e-c-cve-id" in graph.evidence

    def test_no_evidence_graph_means_empty_evidence_refs_not_fabricated(self):
        entities = resolve_canonical_entities(_cve_article(), evidence_graph=None)
        cves = _entity_of_type(entities, "cve")
        assert cves[0].evidence_refs == ()


class TestRansomwareActorEntity:
    def test_real_group_resolves_medium_confidence(self):
        entities = resolve_canonical_entities(_ransomware_article())
        actors = _entity_of_type(entities, "ransomware_actor")
        assert len(actors) == 1
        assert actors[0].canonical_name == "qilin"
        assert actors[0].confidence == "MEDIUM"

    def test_unknown_group_placeholder_produces_no_entity(self):
        entities = resolve_canonical_entities(_ransomware_article(ransomware_group="Unknown Group"))
        assert _entity_of_type(entities, "ransomware_actor") == []

    def test_empty_group_produces_no_entity(self):
        entities = resolve_canonical_entities(_ransomware_article(ransomware_group=""))
        assert _entity_of_type(entities, "ransomware_actor") == []

    def test_none_group_produces_no_entity(self):
        entities = resolve_canonical_entities(_ransomware_article(ransomware_group=None))
        assert _entity_of_type(entities, "ransomware_actor") == []

    def test_evidence_refs_populated_against_a_real_evidence_graph(self):
        article = _ransomware_article()
        context = build_report_context(article)
        graph = build_evidence_graph(article, context)
        entities = resolve_canonical_entities(article, graph)
        actors = _entity_of_type(entities, "ransomware_actor")
        assert actors[0].evidence_refs == ("e-c-actor-attribution",)


class TestTaxonomyEntities:
    def test_real_sector_and_country_resolve_low_confidence(self):
        entities = resolve_canonical_entities(_ransomware_article())
        sectors = _entity_of_type(entities, "sector")
        countries = _entity_of_type(entities, "country")
        assert sectors and sectors[0].canonical_name == "Healthcare" and sectors[0].confidence == "LOW"
        assert countries and countries[0].canonical_name == "US"

    def test_placeholder_taxonomy_values_produce_no_entity(self):
        for placeholder in ("unknown", "N/A", "Not Found Sector", "-", "unspecified"):
            entities = resolve_canonical_entities(_ransomware_article(ransomware_sector=placeholder))
            assert _entity_of_type(entities, "sector") == [], f"{placeholder!r} must not resolve"


class TestLexiconEntities:
    def test_malware_and_vendor_extracted_from_article_text(self):
        article = _cve_article(summary="A test vulnerability in Fortinet FortiGate allows RCE.")
        entities = resolve_canonical_entities(article)
        vendors = _entity_of_type(entities, "vendor")
        assert any(e.canonical_name == "Fortinet" for e in vendors)

    def test_lexicon_aliases_are_carried_onto_the_canonical_entity(self):
        article = _ransomware_article(summary="lockbit has listed Acme Test Corp as a new victim.")
        entities = resolve_canonical_entities(article)
        malware = _entity_of_type(entities, "malware")
        lockbit = next((e for e in malware if e.canonical_name == "LockBit"), None)
        assert lockbit is not None
        assert "LockBit 3.0" in lockbit.aliases

    def test_no_lexicon_hits_in_plain_text_produces_no_lexicon_entities(self):
        article = _cve_article(title="Generic title", summary="Nothing here matches any known name.")
        entities = resolve_canonical_entities(article)
        assert _entity_of_type(entities, "vendor") == []
        assert _entity_of_type(entities, "malware") == []


class TestResolveCanonicalEntitiesIntegration:
    def test_empty_article_produces_empty_tuple_not_a_crash(self):
        article = DiscoveredArticle(
            url="https://example.test/generic", title="Generic security news",
            summary="Nothing structured here.", published_at="2026-08-18T00:00:00Z",
            content_hash="0000", labels=["Threat Intelligence"], source="global_rss",
        )
        entities = resolve_canonical_entities(article)
        assert entities == ()

    def test_results_are_sorted_by_type_then_name(self):
        entities = resolve_canonical_entities(_ransomware_article(summary="lockbit has listed Acme Test Corp."))
        pairs = [(e.entity_type, e.canonical_name) for e in entities]
        assert pairs == sorted(pairs)

    def test_every_resolved_entity_serializes_cleanly(self):
        entities = resolve_canonical_entities(_ransomware_article())
        for e in entities:
            d = e.to_dict()
            assert d["canonical_id"] and d["canonical_name"] and d["entity_type"]
            assert isinstance(d["aliases"], list)
            assert isinstance(d["evidence_refs"], list)


class TestAdversarial:
    """The mandate's explicit Phase 1G adversarial list (Section 10)."""

    def test_unknown_group_vs_unknown_group_never_correlates(self):
        # Two different articles both carrying the literal placeholder must
        # each independently produce zero ransomware_actor entities -- never
        # two entities that a downstream step could mistake for the same
        # (or, worse, two different) real actor.
        a1 = resolve_canonical_entities(_ransomware_article(ransomware_group="Unknown Group"))
        a2 = resolve_canonical_entities(_ransomware_article(ransomware_group="Unknown Group", url="https://x/2"))
        assert _entity_of_type(a1, "ransomware_actor") == []
        assert _entity_of_type(a2, "ransomware_actor") == []

    def test_same_actor_different_alias_spellings_stay_distinct_by_design(self):
        # No verified alias source exists for article.ransomware_group (see
        # module docstring) -- "LockBit" and "LockBit 3.0" as raw
        # ransomware_group values MUST resolve to two different canonical
        # ids. This is the deliberately safe behavior, not a bug: merging
        # them would require an alias source this pipeline doesn't have,
        # and false-merging is the CTI integrity failure the mandate warns
        # against.
        e1 = resolve_canonical_entities(_ransomware_article(ransomware_group="LockBit"))
        e2 = resolve_canonical_entities(_ransomware_article(ransomware_group="LockBit 3.0"))
        id1 = _entity_of_type(e1, "ransomware_actor")[0].canonical_id
        id2 = _entity_of_type(e2, "ransomware_actor")[0].canonical_id
        assert id1 != id2

    def test_two_different_actors_with_similar_names_stay_distinct(self):
        e1 = resolve_canonical_entities(_ransomware_article(ransomware_group="APT28"))
        e2 = resolve_canonical_entities(_ransomware_article(ransomware_group="APT29"))
        id1 = _entity_of_type(e1, "ransomware_actor")[0].canonical_id
        id2 = _entity_of_type(e2, "ransomware_actor")[0].canonical_id
        assert id1 != id2

    def test_malformed_cve_never_resolves(self):
        entities = resolve_canonical_entities(_cve_article(cve_id="CVE-NOT-REAL"))
        assert _entity_of_type(entities, "cve") == []

    def test_case_only_duplicates_correctly_merge(self):
        # Case normalization is a safe, unambiguous identity rule (unlike
        # alias resolution) -- "qilin" and "QILIN" are the same string.
        e1 = resolve_canonical_entities(_ransomware_article(ransomware_group="qilin"))
        e2 = resolve_canonical_entities(_ransomware_article(ransomware_group="QILIN"))
        id1 = _entity_of_type(e1, "ransomware_actor")[0].canonical_id
        id2 = _entity_of_type(e2, "ransomware_actor")[0].canonical_id
        assert id1 == id2

    def test_unicode_lookalike_actor_name_does_not_merge_with_the_real_one(self):
        spoofed_name = "L" + "о" + "ckBit"  # Cyrillic 'о' (U+043E), not Latin
        assert spoofed_name != "LockBit"  # sanity: really a different string
        real = resolve_canonical_entities(_ransomware_article(ransomware_group="LockBit"))
        spoofed = resolve_canonical_entities(_ransomware_article(ransomware_group=spoofed_name))
        id_real = _entity_of_type(real, "ransomware_actor")[0].canonical_id
        id_spoofed = _entity_of_type(spoofed, "ransomware_actor")[0].canonical_id
        assert id_real != id_spoofed

    def test_empty_entities_across_every_field_produces_nothing(self):
        article = _ransomware_article(
            ransomware_group=None, ransomware_sector=None, ransomware_country=None,
            title="", summary="",
        )
        assert resolve_canonical_entities(article) == ()

    def test_synthetic_placeholder_strings_across_all_guarded_fields(self):
        article = _ransomware_article(
            ransomware_group="Unknown Group", ransomware_sector="n/a", ransomware_country="null",
        )
        entities = resolve_canonical_entities(article)
        assert _entity_of_type(entities, "ransomware_actor") == []
        assert _entity_of_type(entities, "sector") == []
        assert _entity_of_type(entities, "country") == []

    def test_vendor_product_version_and_victim_are_not_resolved_this_phase(self):
        # Documented scope boundary (module docstring): no verified
        # vendor/product alias source or victim-org normalization exists
        # anywhere in the codebase (confirmed by reconnaissance), so this
        # phase does not fabricate resolution for them. This test guards
        # against silently, accidentally implementing a half-correct
        # version of either without the adversarial rigor the mandate
        # requires for both.
        article = _cve_article(affected_vendor="Fortinet", affected_product="FortiGate 7.0.1")
        entities = resolve_canonical_entities(article)
        # "Fortinet" IS resolved -- but only via the lexicon text-match path
        # (it appears in this article's summary too), not from
        # affected_vendor/affected_product directly.
        assert not any(e.canonical_name == "FortiGate 7.0.1" for e in entities)
