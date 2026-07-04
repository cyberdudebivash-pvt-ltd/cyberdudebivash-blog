from pathlib import Path

from sentinel_engine.models import IOCType, SourceDocument
from sentinel_engine.normalizer import has_scraper_noise, normalize, strip_noise

FIXTURES = Path(__file__).parent / "fixtures"


def test_strip_reddit_scraper_noise():
    raw = "Real analysis text here. submitted by /u/someone [link] [comments]"
    cleaned = strip_noise(raw)
    assert "submitted by" not in cleaned
    assert "[link]" not in cleaned
    assert "Real analysis text here." in cleaned


def test_has_scraper_noise_detection():
    assert has_scraper_noise("blah submitted by /u/x [link] [comments]")
    assert not has_scraper_noise("clean analyst-written paragraph")


def test_chrome_lines_removed():
    raw = "💡 Sponsor the Lab\nBREAKING THREATS\nActual sentence about the campaign.\n"
    cleaned = strip_noise(raw)
    assert "Sponsor the Lab" not in cleaned
    assert "BREAKING THREATS" not in cleaned
    assert "Actual sentence about the campaign." in cleaned


def test_normalize_raw_source_end_to_end():
    raw = (FIXTURES / "raw-source-sample.txt").read_text()
    doc = normalize(SourceDocument(raw_text=raw, source_url="https://example.org/a"))

    assert "submitted by" not in doc.text
    assert "SYNTHETIC TEST FIXTURE" not in doc.text  # all-caps marker stripped
    assert doc.cves == ["CVE-2024-4577"]

    ioc_types = {i.type for i in doc.iocs}
    assert {IOCType.URL, IOCType.IPV4, IOCType.SHA256, IOCType.EMAIL, IOCType.CVE} <= ioc_types

    tids = {t.technique_id for t in doc.techniques}
    assert "T1190" in tids   # exploited a public-facing PHP flaw
    assert "T1059.001" in tids  # encoded PowerShell
    assert "T1490" in tids   # shadow copy deletion
    assert "T1486" in tids   # ransomware encryption

    names = {e.name for e in doc.entities}
    assert "LockBit" in names
    assert "Cobalt Strike" in names

    assert doc.title.startswith("Ransomware crew exploits CVE-2024-4577")
