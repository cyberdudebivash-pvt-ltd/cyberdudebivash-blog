from datetime import datetime, timezone

from automation.canonical_rss import discover_local_canonical_rss
from automation.config import Config
from automation.content_discovery import PublicationState


def _rss(pub_date: str) -> str:
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <item>
      <title>Critical malware campaign analysis</title>
      <link>https://blog.cyberdudebivash.in/posts/malware-campaign.html</link>
      <pubDate>{pub_date}</pubDate>
      <description><![CDATA[<p>Malware campaign analysis with enterprise response guidance.</p>]]></description>
      <category>Malware Research</category>
    </item>
  </channel>
</rss>'''


def test_local_rss_is_consumed_without_remote_propagation(tmp_path):
    now_rfc = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    rss_path = tmp_path / "rss.xml"
    rss_path.write_text(_rss(now_rfc), encoding="utf-8")

    config = Config()
    config.state_file = str(tmp_path / "state.json")
    config.max_article_age_hours = 72
    state = PublicationState(config.state_file)

    articles = discover_local_canonical_rss(config, state, rss_path=rss_path)

    assert len(articles) == 1
    item = articles[0]
    assert item.source == "rss"
    assert item.source_publisher == "CYBERDUDEBIVASH"
    assert item.url == "https://blog.cyberdudebivash.in/posts/malware-campaign.html"
    assert "Malware Research" in item.labels
    assert "Threat Intelligence" in item.labels


def test_local_rss_respects_published_state(tmp_path):
    now_rfc = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    rss_path = tmp_path / "rss.xml"
    rss_path.write_text(_rss(now_rfc), encoding="utf-8")

    config = Config()
    config.state_file = str(tmp_path / "state.json")
    state = PublicationState(config.state_file)

    first = discover_local_canonical_rss(config, state, rss_path=rss_path)
    assert len(first) == 1
    state.mark_published(first[0], "post-1", "https://example.blogspot.com/post-1")

    second = discover_local_canonical_rss(config, state, rss_path=rss_path)
    assert second == []


def test_malformed_local_rss_fails_open(tmp_path):
    rss_path = tmp_path / "rss.xml"
    rss_path.write_text("<rss><broken>", encoding="utf-8")

    config = Config()
    config.state_file = str(tmp_path / "state.json")
    state = PublicationState(config.state_file)

    assert discover_local_canonical_rss(config, state, rss_path=rss_path) == []
