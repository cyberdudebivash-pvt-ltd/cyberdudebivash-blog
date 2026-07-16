"""CYBERDUDEBIVASH® SENTINEL APEX — NVD CVE Source"""

from datetime import datetime, timezone, timedelta
from typing import Optional

import requests

from .config import Config
from .content_discovery import (
    DiscoveredArticle,
    PublicationState,
    _compute_hash,
    _infer_labels,
)
from .logger import setup_logger

logger = setup_logger("nvd_source")

_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDCVESource:
    """Fetches recent CRITICAL and HIGH CVEs from the NVD REST API."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def discover(self, state: PublicationState) -> list[DiscoveredArticle]:
        """Return new DiscoveredArticle entries from NVD, CRITICAL first then HIGH, capped at 10."""
        critical = self._fetch_by_severity("CRITICAL", state)
        high = self._fetch_by_severity("HIGH", state)
        combined = (critical + high)[:10]
        return combined

    def _fetch_by_severity(self, severity: str, state: PublicationState) -> list[DiscoveredArticle]:
        """Fetch CVEs of the given severity from NVD and convert to DiscoveredArticles."""
        try:
            hours_back = min(self.config.max_article_age_hours, 48)
            now = datetime.now(timezone.utc)
            start = now - timedelta(hours=hours_back)

            params = {
                "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "cvssV3Severity": severity,
                "resultsPerPage": 20,
            }

            headers: dict = {"User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0"}
            if self.config.nvd_api_key:
                headers["apiKey"] = self.config.nvd_api_key

            resp = requests.get(_NVD_API_URL, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error("NVD CVEs fetch failed", extra={"severity": severity, "error": str(e)})
            return []

        articles: list[DiscoveredArticle] = []

        for item in data.get("vulnerabilities", []):
            try:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                # Extract English description
                description = ""
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Extract CVSS score and vector — prefer v3.1, fall back to v3.0
                metrics = cve.get("metrics", {})
                cvss_score: Optional[float] = None
                cvss_vector: Optional[str] = None

                for metric_key in ("cvssMetricV31", "cvssMetricV30"):
                    metric_list = metrics.get(metric_key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = cvss_data.get("vectorString")
                        break

                # Extract CWEs
                cwes: list[str] = []
                for weakness in cve.get("weaknesses", []):
                    for wd in weakness.get("description", []):
                        value = wd.get("value", "")
                        if value.startswith("CWE-") and value not in cwes:
                            cwes.append(value)

                # Extract affected products from CPE criteria
                affected_products: list[str] = []
                for config_node in cve.get("configurations", []):
                    for node in config_node.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            criteria = cpe_match.get("criteria", "")
                            # cpe:2.3:*:vendor:product:...
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                vendor_part = parts[3]
                                product_part = parts[4]
                                if vendor_part and vendor_part != "*":
                                    label_str = f"{vendor_part.replace('_', ' ').title()} {product_part.replace('_', ' ').title()}".strip()
                                    if label_str not in affected_products:
                                        affected_products.append(label_str)

                # Build title
                score_str = str(cvss_score) if cvss_score is not None else severity
                title = f"{cve_id} — CVSS {score_str} {severity} Severity | Patch Required"

                # Build summary
                summary_parts = [description]
                if cvss_score is not None:
                    summary_parts.append(f"CVSS Score: {cvss_score}")
                if cwes:
                    summary_parts.append(f"CWE: {', '.join(cwes)}")
                if affected_products:
                    summary_parts.append(f"Affected: {' | '.join(affected_products[:5])}")
                summary = " ".join(summary_parts)

                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                content_hash = _compute_hash(url, cve_id + title)

                if state.is_published(content_hash):
                    continue

                # Parse published date
                pub_date_str = cve.get("published", "")
                try:
                    pub_date = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00"))
                    pub_iso = pub_date.isoformat()
                except Exception:
                    pub_iso = datetime.now(timezone.utc).isoformat()

                # Build labels
                labels = _infer_labels(title, summary)
                for required_label in ["Vulnerabilities", "CYBERDUDEBIVASH", "Threat Intelligence"]:
                    if required_label not in labels:
                        labels.append(required_label)
                if severity == "CRITICAL" and "Critical CVE" not in labels:
                    labels.append("Critical CVE")

                # Build full structured content
                full_content_lines = [
                    f"CVE ID: {cve_id}",
                    f"Description: {description}",
                ]
                if cvss_score is not None:
                    full_content_lines.append(f"CVSS Score: {cvss_score}")
                if cvss_vector:
                    full_content_lines.append(f"CVSS Vector: {cvss_vector}")
                if cwes:
                    full_content_lines.append(f"CWEs: {', '.join(cwes)}")
                if affected_products:
                    full_content_lines.append(f"Affected Products: {' | '.join(affected_products)}")
                full_content = "\n".join(full_content_lines)

                articles.append(
                    DiscoveredArticle(
                        url=url,
                        title=title,
                        summary=summary,
                        published_at=pub_iso,
                        content_hash=content_hash,
                        labels=labels,
                        source="nvd",
                        full_content=full_content,
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        cwe_ids=cwes or None,
                        affected_vendor=affected_products[0].split(" ", 1)[0] if affected_products else None,
                        affected_product=affected_products[0] if affected_products else None,
                    )
                )
            except Exception as e:
                logger.warning("Failed to parse NVD CVE entry", extra={"error": str(e)})
                continue

        logger.info(
            "NVD CVEs fetched",
            extra={"severity": severity, "count": len(articles)},
        )
        return articles
