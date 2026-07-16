"""
CYBERDUDEBIVASH® SENTINEL APEX — Vulnerability Enrichment
Attaches real EPSS exploitation-probability scores and CISA KEV cross-reference
data onto discovered articles, regardless of which source discovered them.

Fields stay None when a lookup fails or the CVE isn't tracked by either feed —
never fabricated or estimated. Both FIRST.org EPSS and CISA KEV are free,
unauthenticated public feeds; failures degrade gracefully and never break the
publish pipeline.
"""

from typing import Optional

import requests

from .content_discovery import DiscoveredArticle, _extract_cve_ids_from_text
from .logger import setup_logger

logger = setup_logger("enrichment")

_EPSS_API_URL = "https://api.first.org/data/v1/epss"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_epss_batch(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch EPSS score + percentile for up to 100 CVEs in one request. Returns {} on failure."""
    if not cve_ids:
        return {}
    try:
        resp = requests.get(
            _EPSS_API_URL,
            params={"cve": ",".join(cve_ids[:100])},
            timeout=15,
            headers={"User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.warning("EPSS batch fetch failed", extra={"error": str(e), "count": len(cve_ids)})
        return {}

    result: dict[str, dict] = {}
    for item in data.get("data", []):
        cve = str(item.get("cve", "")).upper()
        if not cve:
            continue
        try:
            result[cve] = {
                "epss_score": float(item["epss"]),
                "epss_percentile": float(item["percentile"]),
            }
        except (KeyError, ValueError, TypeError):
            continue
    return result


def fetch_kev_catalog() -> dict[str, dict]:
    """Fetch the full CISA KEV catalog. Returns {cve_id: {...}}, {} on failure."""
    try:
        resp = requests.get(
            _CISA_KEV_URL,
            timeout=30,
            headers={"User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.warning("CISA KEV catalog fetch failed", extra={"error": str(e)})
        return {}

    catalog: dict[str, dict] = {}
    for v in data.get("vulnerabilities", []):
        cve_id = str(v.get("cveID", "")).strip().upper()
        if not cve_id:
            continue
        catalog[cve_id] = {
            "kev_date_added": v.get("dateAdded", ""),
            "kev_due_date": v.get("dueDate", ""),
            "kev_required_action": v.get("requiredAction", ""),
        }
    return catalog


def enrich_articles(articles: list[DiscoveredArticle]) -> list[DiscoveredArticle]:
    """
    Attach real EPSS + CISA KEV data to any article whose CVE ID can be
    identified — regardless of discovery source. Mutates and returns the
    same list. At most 2 network calls total, batched across all articles.

    Source-populated fields (e.g. kev_listed already set True by
    CISAKEVSource) are never overwritten — this only fills gaps.
    """
    cve_by_index: dict[int, str] = {}
    all_cve_ids: set[str] = set()

    for idx, article in enumerate(articles):
        cve_id = article.cve_id
        if not cve_id:
            found = _extract_cve_ids_from_text(f"{article.title} {article.summary}")
            cve_id = found[0] if found else None
        if cve_id:
            cve_by_index[idx] = cve_id
            all_cve_ids.add(cve_id)

    if not all_cve_ids:
        return articles

    epss_data = fetch_epss_batch(sorted(all_cve_ids))
    kev_catalog = fetch_kev_catalog()

    for idx, cve_id in cve_by_index.items():
        article = articles[idx]
        if not article.cve_id:
            article.cve_id = cve_id

        epss = epss_data.get(cve_id)
        if epss:
            article.epss_score = epss["epss_score"]
            article.epss_percentile = epss["epss_percentile"]

        if article.kev_listed is None:
            kev = kev_catalog.get(cve_id)
            if kev:
                article.kev_listed = True
                article.kev_date_added = kev["kev_date_added"]
                article.kev_due_date = kev["kev_due_date"]
                article.kev_required_action = kev["kev_required_action"]
            elif kev_catalog:
                # Catalog fetched successfully and this CVE genuinely isn't
                # in it — a real "not listed", not an unknown.
                article.kev_listed = False
            # else: catalog fetch failed entirely — leave kev_listed=None
            # (unknown) rather than assert a false negative.

    return articles
