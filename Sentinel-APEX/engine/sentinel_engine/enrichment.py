"""CVE enrichment from authoritative sources: NVD (CVSS), FIRST (EPSS),
CISA (KEV).

The fetcher is injectable so every enricher is testable offline. When a
source is unreachable the corresponding fields stay ``None`` and the record
is marked ``unavailable`` — the engine NEVER fabricates scores, exploitation
status, or metadata. That constraint is what keeps published intelligence
trustworthy.
"""

from __future__ import annotations

import json
import re
import urllib.request
from typing import Callable, Optional

from .models import CVEEnrichment

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
EPSS_API = "https://api.first.org/data/v1/epss?cve={cve}"
KEV_FEED = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

FetchJson = Callable[[str], Optional[dict]]


def default_fetch_json(url: str, timeout: float = 15.0) -> Optional[dict]:
    """Fetch JSON over HTTPS; any failure returns None (no exceptions leak)."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "SentinelAPEX-IntelEngine/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


class Enricher:
    def __init__(self, fetch_json: FetchJson | None = None):
        self._fetch = fetch_json or default_fetch_json
        self._kev_ids: Optional[set[str]] = None  # lazy, cached per instance

    def enrich_cve(self, cve_id: str) -> CVEEnrichment:
        cve_id = cve_id.upper().strip()
        if not _RE_CVE.match(cve_id):
            return CVEEnrichment(cve_id=cve_id, status="unavailable")

        record = CVEEnrichment(cve_id=cve_id)
        self._apply_nvd(record)
        self._apply_epss(record)
        self._apply_kev(record)
        if record.sources:
            record.status = "enriched"
        return record

    # --- individual sources -------------------------------------------------

    def _apply_nvd(self, record: CVEEnrichment) -> None:
        data = self._fetch(NVD_API.format(cve=record.cve_id))
        if not data:
            return
        try:
            vulns = data.get("vulnerabilities") or []
            if not vulns:
                return
            cve = vulns[0]["cve"]
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    record.description = desc.get("value")
                    break
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
                if metrics.get(key):
                    cvss = metrics[key][0]["cvssData"]
                    record.cvss_score = float(cvss["baseScore"])
                    record.cvss_vector = cvss.get("vectorString")
                    break
            record.sources.append(NVD_API.format(cve=record.cve_id))
        except (KeyError, IndexError, TypeError, ValueError):
            return

    def _apply_epss(self, record: CVEEnrichment) -> None:
        data = self._fetch(EPSS_API.format(cve=record.cve_id))
        if not data:
            return
        try:
            rows = data.get("data") or []
            if not rows:
                return
            record.epss_score = float(rows[0]["epss"])
            record.epss_percentile = float(rows[0]["percentile"])
            record.sources.append(EPSS_API.format(cve=record.cve_id))
        except (KeyError, IndexError, TypeError, ValueError):
            return

    def _apply_kev(self, record: CVEEnrichment) -> None:
        if self._kev_ids is None:
            data = self._fetch(KEV_FEED)
            # a payload without the expected catalog shape is treated as
            # unreachable — never conclude "not listed" from bad data
            if data and isinstance(data.get("vulnerabilities"), list):
                try:
                    self._kev_ids = {
                        v["cveID"].upper()
                        for v in data["vulnerabilities"]
                        if isinstance(v, dict) and v.get("cveID")
                    }
                except (KeyError, TypeError):
                    self._kev_ids = None
        if self._kev_ids is None:
            record.kev_listed = None  # catalog unreachable: unknown, not false
            return
        record.kev_listed = record.cve_id in self._kev_ids
        record.sources.append(KEV_FEED)
