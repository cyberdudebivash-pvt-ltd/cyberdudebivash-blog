"""CYBERDUDEBIVASH® SENTINEL APEX — CISA Known Exploited Vulnerabilities Source"""

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

logger = setup_logger("cisa_kev_source")

_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVSource:
    """Fetches and parses CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def discover(self, state: PublicationState) -> list[DiscoveredArticle]:
        """Return new DiscoveredArticle entries from the CISA KEV catalog."""
        try:
            resp = requests.get(
                _CISA_KEV_URL,
                timeout=30,
                headers={"User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0"},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error("CISA KEV fetch failed", extra={"error": str(e)})
            return []

        vulns = data.get("vulnerabilities", [])
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.config.max_article_age_hours)

        articles: list[DiscoveredArticle] = []

        for v in vulns:
            # Parse and filter by date
            date_added_str = v.get("dateAdded", "")
            if not date_added_str:
                continue
            try:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            if date_added < cutoff:
                continue

            cve_id = v.get("cveID", "").strip()
            if not cve_id:
                continue

            vendor = v.get("vendorProject", "")
            product = v.get("product", "")
            vuln_name = v.get("vulnerabilityName", "")
            description = v.get("shortDescription", "")
            required_action = v.get("requiredAction", "")
            due_date = v.get("dueDate", "")
            notes = v.get("notes", "") or ""

            title = (
                f"CISA KEV Alert: {cve_id} — {vuln_name} | Active Exploitation Confirmed"
            )
            summary = (
                f"{description} "
                f"CISA has added {cve_id} ({vendor} {product}) to the Known Exploited "
                f"Vulnerabilities catalog, confirming active exploitation in the wild. "
                f"Federal agencies required to remediate by {due_date}. "
                f"Required action: {required_action}"
            )

            url = (
                f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                f"?search_api_fulltext={cve_id}"
            )

            content_hash = _compute_hash(f"cisa-kev-{cve_id}", title)

            if state.is_published(content_hash):
                continue

            labels = _infer_labels(title, summary)
            for required_label in ["CISA KEV", "Vulnerabilities", "CYBERDUDEBIVASH", "Threat Intelligence"]:
                if required_label not in labels:
                    labels.append(required_label)

            # Build full structured content
            full_content_lines = [
                f"CVE ID: {cve_id}",
                f"Vendor/Product: {vendor} — {product}",
                f"Vulnerability Name: {vuln_name}",
                f"Date Added to KEV: {date_added_str}",
                f"Federal Remediation Deadline: {due_date}",
                f"Description: {description}",
                f"Required Action: {required_action}",
            ]
            if notes:
                full_content_lines.append(f"CISA Notes: {notes}")

            full_content = "\n".join(full_content_lines)

            articles.append(
                DiscoveredArticle(
                    url=url,
                    title=title,
                    summary=summary,
                    published_at=date_added.isoformat(),
                    content_hash=content_hash,
                    labels=labels,
                    source="cisa_kev",
                    full_content=full_content,
                    cve_id=cve_id,
                    affected_vendor=vendor or None,
                    affected_product=product or None,
                    kev_listed=True,
                    kev_date_added=date_added_str,
                    kev_due_date=due_date or None,
                    kev_required_action=required_action or None,
                )
            )

        logger.info(
            "CISA KEV parsed",
            extra={"new_entries": len(articles), "total_catalog": len(vulns)},
        )
        return articles
