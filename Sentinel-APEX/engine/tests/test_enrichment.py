from sentinel_engine.enrichment import EPSS_API, KEV_FEED, NVD_API, Enricher

CVE = "CVE-2024-4577"

NVD_PAYLOAD = {
    "vulnerabilities": [{
        "cve": {
            "descriptions": [{"lang": "en", "value": "PHP-CGI argument injection."}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }]
            },
        }
    }]
}
EPSS_PAYLOAD = {"data": [{"epss": "0.97", "percentile": "0.999"}]}
KEV_PAYLOAD = {"vulnerabilities": [{"cveID": CVE}]}


def _stub_fetch(url):
    if url == NVD_API.format(cve=CVE):
        return NVD_PAYLOAD
    if url == EPSS_API.format(cve=CVE):
        return EPSS_PAYLOAD
    if url == KEV_FEED:
        return KEV_PAYLOAD
    return None


def test_full_enrichment_with_stub_sources():
    record = Enricher(fetch_json=_stub_fetch).enrich_cve(CVE)
    assert record.status == "enriched"
    assert record.cvss_score == 9.8
    assert record.epss_score == 0.97
    assert record.kev_listed is True
    assert len(record.sources) == 3


def test_offline_enrichment_never_fabricates():
    record = Enricher(fetch_json=lambda url: None).enrich_cve(CVE)
    assert record.status == "unavailable"
    assert record.cvss_score is None
    assert record.epss_score is None
    assert record.kev_listed is None  # unknown, not False
    assert record.sources == []


def test_kev_absence_is_false_when_catalog_reachable():
    def fetch(url):
        return KEV_PAYLOAD if url == KEV_FEED else None

    record = Enricher(fetch_json=fetch).enrich_cve("CVE-2020-0001")
    assert record.kev_listed is False


def test_malformed_cve_id_rejected():
    record = Enricher(fetch_json=_stub_fetch).enrich_cve("not-a-cve")
    assert record.status == "unavailable"


def test_malformed_payloads_degrade_gracefully():
    record = Enricher(fetch_json=lambda url: {"unexpected": "shape"}).enrich_cve(CVE)
    assert record.cvss_score is None
    assert record.status == "unavailable"
