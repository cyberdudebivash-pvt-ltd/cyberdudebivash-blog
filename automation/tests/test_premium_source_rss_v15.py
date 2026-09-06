from automation import content_discovery
from automation import premium_source_rss_v15 as source_rss
from automation import rss_aggregator
from automation.config import Config
from automation.content_discovery import PublicationState


def _rss_with_encoded(body: str, description: str = "Short preview") -> str:
    return f"""<?xml version="1.0"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <item>
      <title>Source Rich Threat Report</title>
      <link>https://publisher.example/report</link>
      <description><![CDATA[{description}]]></description>
      <content:encoded><![CDATA[{body}]]></content:encoded>
      <pubDate>Sun, 06 Sep 2026 20:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>"""


def test_content_encoded_is_preserved_without_expanding_summary():
    body = "<p>Detailed evidence paragraph.</p>" * 500
    items = source_rss.parse_source_rich_feed_items(_rss_with_encoded(body))

    assert len(items) == 1
    assert items[0]["summary"] == "Short preview"
    assert items[0]["full_feed_content_kind"] == "content:encoded"
    assert "Detailed evidence paragraph." in items[0]["full_feed_content"]
    assert len(items[0]["full_feed_content"]) > len(items[0]["summary"])


def test_atom_content_is_preserved_as_full_source_body():
    xml = """<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Atom Threat Research</title>
    <link rel="alternate" href="https://publisher.example/atom-report" />
    <summary>Short atom summary</summary>
    <content type="html"><![CDATA[<p>Long atom evidence body with technical detail.</p>]]></content>
    <updated>2026-09-06T20:00:00Z</updated>
  </entry>
</feed>"""
    items = source_rss.parse_source_rich_feed_items(xml)

    assert items[0]["url"] == "https://publisher.example/atom-report"
    assert items[0]["summary"] == "Short atom summary"
    assert items[0]["full_feed_content_kind"] == "atom:content"
    assert items[0]["full_feed_content"] == "Long atom evidence body with technical detail."


def test_source_body_is_sanitized_and_bounded():
    payload = "<script>evil()</script><p>evidence </p>" + ("trusted-source-word " * 4000)
    items = source_rss.parse_source_rich_feed_items(_rss_with_encoded(payload))
    body = items[0]["full_feed_content"]

    assert "evil()" not in body
    assert len(body) <= source_rss.MAX_SOURCE_BODY_CHARS
    assert body.endswith("...")


def test_external_article_uses_full_feed_body_but_keeps_summary(tmp_path, monkeypatch):
    body = "Evidence sentence with useful technical context. " * 500
    item = source_rss.parse_source_rich_feed_items(_rss_with_encoded(body))[0]
    cfg = Config()
    cfg.state_file = str(tmp_path / "state.json")
    cfg.max_article_age_hours = 10_000
    state = PublicationState(cfg.state_file)
    feed = rss_aggregator._Feed("Example Research", "https://publisher.example/feed")

    original = rss_aggregator.GlobalRSSAggregator._to_article
    monkeypatch.setattr(source_rss, "_ORIGINAL_TO_ARTICLE", original)
    article = source_rss._source_rich_to_article(feed, item, state)

    assert article is not None
    assert article.summary == "Short preview"
    assert "Feed Evidence Type: content:encoded" in article.full_content
    assert "Evidence sentence with useful technical context." in article.full_content
    assert article.source_publisher == "Example Research"


def test_installer_patches_external_alias_only(monkeypatch):
    # The first-party canonical path imports content_discovery._parse_feed_items
    # directly. v15 must not alter that function because canonical Blogger/report
    # HTML is generated output, not automatically trusted source evidence.
    original_shared = content_discovery._parse_feed_items
    original_alias = rss_aggregator._parse_feed_items
    original_to_article = rss_aggregator.GlobalRSSAggregator._to_article
    monkeypatch.setattr(source_rss, "_INSTALLED", False)
    monkeypatch.setattr(source_rss, "_ORIGINAL_PARSE", None)
    monkeypatch.setattr(source_rss, "_ORIGINAL_TO_ARTICLE", None)

    try:
        source_rss.install_source_rich_rss_v15()
        assert content_discovery._parse_feed_items is original_shared
        assert rss_aggregator._parse_feed_items is source_rss.parse_source_rich_feed_items
        assert rss_aggregator.GlobalRSSAggregator._to_article is source_rss._source_rich_to_article
    finally:
        rss_aggregator._parse_feed_items = original_alias
        rss_aggregator.GlobalRSSAggregator._to_article = original_to_article
        source_rss._INSTALLED = False
        source_rss._ORIGINAL_PARSE = None
        source_rss._ORIGINAL_TO_ARTICLE = None


def test_legacy_summary_truncation_contract_remains_1500_chars():
    long_preview = "Preview sentence for labels and cards. " * 100
    items = source_rss.parse_source_rich_feed_items(
        _rss_with_encoded("Full evidence", description=long_preview)
    )

    assert len(items[0]["summary"]) <= source_rss.SUMMARY_LIMIT_CHARS
    assert items[0]["summary"].endswith("...")
