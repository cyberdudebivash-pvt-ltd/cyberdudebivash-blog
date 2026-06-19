"""
CYBERDUDEBIVASH® SENTINEL APEX — Authority Content Transformer
Transforms source articles into enterprise-grade threat intelligence reports.
Uses Claude AI when ANTHROPIC_API_KEY is available; falls back to structured templates.
"""

import json
import re
from datetime import datetime, timezone
from typing import Optional

from .category_mapper import primary_category
from .config import Config
from .content_discovery import DiscoveredArticle
from .internal_linker import InternalLinker
from .logger import setup_logger
from .monetization_injector import MonetizationInjector
from .seo_optimizer import SEOOptimizer, _extract_cve_ids, _extract_cvss

logger = setup_logger("authority_transformer")


def _safe_ai_enhance(config: Config, article: DiscoveredArticle) -> Optional[str]:
    """Call Claude API to generate analyst-grade threat intelligence content."""
    if not config.anthropic_api_key:
        return None

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=config.anthropic_api_key)

        prompt = f"""You are the CYBERDUDEBIVASH® SENTINEL APEX AI Security Analyst, an expert in cyber threat intelligence, vulnerability analysis, AI security, and enterprise security operations.

Transform the following cybersecurity article into an enterprise-grade threat intelligence report. Write in the style of a senior CTI analyst at a Fortune 500 security team.

ARTICLE TITLE: {article.title}
ARTICLE URL: {article.url}
ARTICLE SUMMARY: {article.summary[:2000]}
LABELS/CATEGORY: {', '.join(article.labels)}

Generate a comprehensive threat intelligence report with EXACTLY these sections in HTML format (use <h3>, <p>, <ul>, <li> tags — NO inline styles):

<h3>Executive Summary</h3>
[2-3 sentences. C-suite and board-level. Quantify risk where possible.]

<h3>Threat Analysis</h3>
[Technical deep-dive for SOC analysts. Explain the attack vector, affected systems, exploitation methodology. Reference CVE IDs if present.]

<h3>Business Impact Assessment</h3>
[Risk for enterprises: financial, operational, reputational. Quantify where data supports it.]

<h3>SOC Recommendations — Immediate Actions</h3>
<ul>[Bullet list of immediate actionable steps. Be specific: apply patch X, block IP range Y, enable rule Z.]</ul>

<h3>MITRE ATT&CK Mapping</h3>
<ul>[Map to relevant MITRE tactics/techniques. Format: Tactic: Technique (TXXXX). Only include techniques clearly evidenced by the article.]</ul>

<h3>Detection Opportunities</h3>
[Log sources to monitor, network signatures, behavioral indicators. Only reference what's derivable from the article content.]

<h3>Threat Hunting Recommendations</h3>
<ul>[Actionable hunt hypotheses for threat hunters. Be specific.]</ul>

<h3>CYBERDUDEBIVASH® Analyst Commentary</h3>
[Expert perspective on why this matters, trend context, and strategic implications for enterprise defenders.]

<h3>AI Security Impact</h3>
[Only include this section if the article relates to AI/LLM/ML threats or AI systems. Otherwise omit.]

<h3>Enterprise Recommendations</h3>
<ul>[Strategic 90-day remediation guidance for enterprise security teams.]</ul>

<h3>Key Takeaways</h3>
<ul>[5 bullet points summarizing the most critical insights.]</ul>

CRITICAL RULES:
- Do NOT fabricate CVE IDs, CVSS scores, threat actor names, or technical details not evidenced in the article
- Do NOT invent statistics or make up breach details
- Write at analyst level — no marketing fluff, no generic advice
- Every recommendation must be specific and actionable
- Keep total length between 600-1200 words
- Return ONLY the HTML sections, no preamble
"""

        message = client.messages.create(
            model=config.claude_model,
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}],
        )
        content = message.content[0].text.strip()
        logger.info("Claude API enhancement succeeded", extra={"title": article.title[:60]})
        return content

    except ImportError:
        logger.warning("anthropic package not installed — using template fallback")
        return None
    except Exception as e:
        logger.error("Claude API call failed", extra={"error": str(e)})
        return None


def _template_enhance(article: DiscoveredArticle, config: Config) -> str:
    """Template-based content enhancement when Claude API is unavailable."""
    cves = _extract_cve_ids(article.title + " " + article.summary)
    cvss = _extract_cvss(article.title + " " + article.summary)
    category = primary_category(article.labels)

    cve_str = ", ".join(cves) if cves else "this vulnerability"
    cvss_str = f"CVSS {cvss}" if cvss else "elevated"

    # Determine threat type context
    text = (article.title + " " + article.summary).lower()
    is_ransomware = "ransomware" in text
    is_ai = "ai " in text or "llm" in text or "prompt injection" in text
    is_apt = "apt" in text or "nation-state" in text or "nation state" in text
    is_patch = "patch" in text or "update" in text or "cisa" in text

    mitre_techniques = []
    if is_ransomware:
        mitre_techniques = [
            "Initial Access: Phishing (T1566)",
            "Execution: Command and Scripting Interpreter (T1059)",
            "Defense Evasion: Obfuscated Files or Information (T1027)",
            "Impact: Data Encrypted for Impact (T1486)",
            "Exfiltration: Exfiltration Over C2 Channel (T1041)",
        ]
    elif is_apt:
        mitre_techniques = [
            "Reconnaissance: Active Scanning (T1595)",
            "Initial Access: Exploit Public-Facing Application (T1190)",
            "Persistence: Create or Modify System Process (T1543)",
            "Collection: Data from Local System (T1005)",
            "Exfiltration: Exfiltration Over Alternative Protocol (T1048)",
        ]
    elif cves:
        mitre_techniques = [
            "Initial Access: Exploit Public-Facing Application (T1190)",
            "Privilege Escalation: Exploitation for Privilege Escalation (T1068)",
            "Lateral Movement: Exploitation of Remote Services (T1210)",
        ]
    else:
        mitre_techniques = [
            "Initial Access: Phishing (T1566)",
            "Execution: User Execution (T1204)",
        ]

    mitre_html = "\n".join(f"<li>{t}</li>" for t in mitre_techniques)

    soc_actions = []
    if cves:
        soc_actions.append(f"Immediately apply vendor patches for {cve_str}")
        soc_actions.append("Search SIEM/EDR for exploitation IOCs related to this vulnerability")
    if is_ransomware:
        soc_actions.extend([
            "Verify immutable backup integrity and test restoration procedures",
            "Audit privileged account access and enforce MFA on all admin accounts",
            "Enable network segmentation to limit ransomware lateral movement",
        ])
    if is_apt:
        soc_actions.extend([
            "Conduct threat hunt across endpoints for persistence indicators",
            "Review egress traffic for C2 communication patterns",
            "Audit identity and access management logs for suspicious authentication",
        ])
    soc_actions.extend([
        "Update threat intelligence platform with associated IOCs",
        "Brief incident response team on threat context and escalation criteria",
    ])
    soc_html = "\n".join(f"<li>{a}</li>" for a in soc_actions[:6])

    enterprise_recs = [
        "Prioritize patch deployment for affected systems within 72-hour SLA",
        "Conduct tabletop exercise simulating this attack scenario",
        "Review detection rule coverage against MITRE ATT&CK techniques above",
        "Evaluate threat intelligence feed integration with SENTINEL APEX API",
        "Assess third-party vendor exposure to this threat vector",
    ]
    if is_ai:
        enterprise_recs.insert(0, "Conduct AI Security Assessment against OWASP LLM Top 10 framework")
    ent_html = "\n".join(f"<li>{r}</li>" for r in enterprise_recs[:5])

    ai_section = ""
    if is_ai:
        ai_section = f"""
<h3>AI Security Impact</h3>
<p>This threat has direct implications for enterprise AI deployments. Organizations utilizing LLMs, AI agents, or RAG (Retrieval-Augmented Generation) systems must evaluate exposure to prompt injection, data leakage, and model manipulation attack paths.
CYBERDUDEBIVASH® AI Security Hub provides dedicated AI security assessments aligned to OWASP LLM Top 10, NIST AI RMF, and ISO 42001 to help organizations secure AI systems before attackers exploit them.</p>
"""

    return f"""
<h3>Executive Summary</h3>
<p>{article.summary[:400].rstrip('.')}. This represents a {cvss_str}-risk threat requiring immediate attention from enterprise security teams.
CYBERDUDEBIVASH® SENTINEL APEX has identified this as a high-priority intelligence item requiring coordinated response across SOC, vulnerability management, and executive stakeholders.</p>

<h3>Threat Analysis</h3>
<p>{article.summary[:800]}</p>
<p>Security teams should treat this as an active threat requiring immediate defensive posture adjustment. Attack surface exposure must be quantified across all potentially affected assets.</p>

<h3>Business Impact Assessment</h3>
<p>Organizations with unmitigated exposure face potential operational disruption, data breach liability, regulatory compliance risk, and reputational damage.
The threat vector identified in this intelligence bulletin represents a significant risk to enterprise infrastructure, particularly for organizations operating {category}-affected systems.
Immediate risk quantification against your asset inventory is recommended.</p>

<h3>SOC Recommendations — Immediate Actions</h3>
<ul>
{soc_html}
</ul>

<h3>MITRE ATT&CK Mapping</h3>
<ul>
{mitre_html}
</ul>

<h3>Detection Opportunities</h3>
<p>Security teams should configure detections across the following data sources: Windows Event Logs (Security, System, Application), endpoint telemetry (EDR/XDR), network flow data, and authentication logs.
Deploy or tune existing SIEM rules to cover the MITRE techniques mapped above. CYBERDUDEBIVASH® SENTINEL APEX provides 2,400+ production-ready Sigma and YARA detection rules for immediate SIEM deployment.</p>

<h3>Threat Hunting Recommendations</h3>
<ul>
<li>Hunt for anomalous process execution patterns consistent with initial access techniques</li>
<li>Review privileged account authentication for signs of credential abuse or lateral movement</li>
<li>Inspect network egress for unexpected connections to external infrastructure</li>
<li>Analyze endpoint persistence mechanisms for signs of long-term threat actor dwell time</li>
</ul>

<h3>CYBERDUDEBIVASH® Analyst Commentary</h3>
<p>This intelligence item reflects a continuing trend in the threat landscape. Threat actors are increasingly leveraging {category.lower()} attack vectors to compromise enterprise environments.
Organizations that maintain real-time threat intelligence integration — such as through SENTINEL APEX — gain significantly earlier warning than those relying on periodic advisories alone.
Enterprise security maturity requires transitioning from reactive to intelligence-driven defensive operations.</p>
{ai_section}
<h3>Enterprise Recommendations</h3>
<ul>
{ent_html}
</ul>

<h3>Key Takeaways</h3>
<ul>
<li>This threat requires immediate evaluation against your organization's specific attack surface</li>
<li>Patch and mitigate all identified vulnerable systems within your SLA window</li>
<li>Validate detection coverage using the MITRE ATT&CK techniques identified above</li>
<li>Brief executive stakeholders on potential business impact and remediation timeline</li>
<li>Leverage CYBERDUDEBIVASH® SENTINEL APEX for continuous threat intelligence monitoring</li>
</ul>
""".strip()


class AuthorityTransformer:
    """Transforms source articles into enterprise-grade Blogger-ready HTML."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.monetization = MonetizationInjector(config)
        self.linker = InternalLinker(config)
        self.seo = SEOOptimizer(config)

    def transform(self, article: DiscoveredArticle) -> dict:
        """Return full transformed post ready for Blogger publication."""
        logger.info("Transforming article", extra={"title": article.title[:80], "url": article.url})

        # Generate core content
        ai_content = _safe_ai_enhance(self.config, article)
        if ai_content:
            body_content = ai_content
            content_source = "claude_ai"
        else:
            body_content = _template_enhance(article, self.config)
            content_source = "template"

        # Generate SEO metadata
        seo_data = self.seo.generate(
            title=article.title,
            summary=article.summary,
            url=article.url,
            labels=article.labels,
            published_at=article.published_at,
        )

        # Build full HTML
        html = self._assemble_html(article, body_content, seo_data)

        # Build Blogger post object
        blogger_labels = article.labels[:20]  # Blogger max labels

        logger.info(
            "Transformation complete",
            extra={
                "title": article.title[:60],
                "content_source": content_source,
                "labels": blogger_labels,
            },
        )

        return {
            "title": self._build_blogger_title(article),
            "content": html,
            "labels": blogger_labels,
            "meta_title": seo_data["meta_title"],
            "meta_description": seo_data["meta_description"],
            "keywords": seo_data["keywords"],
            "source_url": article.url,
            "content_hash": article.content_hash,
            "content_source": content_source,
        }

    def _build_blogger_title(self, article: DiscoveredArticle) -> str:
        """Optimise title for Blogger/SEO — max 85 chars."""
        title = article.title.strip()
        cves = _extract_cve_ids(title)
        # Ensure CVE IDs are prominent
        if cves and cves[0].upper() not in title.upper():
            title = f"{cves[0]} — {title}"
        if len(title) > 85:
            title = title[:82].rsplit(" ", 1)[0] + "..."
        return title

    def _assemble_html(self, article: DiscoveredArticle, body_content: str, seo_data: dict) -> str:
        """Assemble the complete Blogger-compatible HTML article."""
        json_ld = seo_data.get("json_ld", {})
        json_ld_str = json.dumps(json_ld, indent=2) if json_ld else ""

        faq_schema = self.seo.build_faq_schema(article.title, article.summary, article.labels)
        faq_str = json.dumps(faq_schema, indent=2) if faq_schema else ""

        cves = _extract_cve_ids(article.title + " " + article.summary)
        cvss = _extract_cvss(article.title + " " + article.summary)
        category = primary_category(article.labels)
        pub_date = datetime.now(timezone.utc).strftime("%B %d, %Y")

        # Build metadata bar
        meta_items = [f"📅 {pub_date}", f"📂 {category}", "🛡 CYBERDUDEBIVASH®"]
        if cves:
            meta_items.insert(0, f"🔍 {', '.join(cves[:2])}")
        if cvss:
            meta_items.insert(1 if cves else 0, f"⚠ CVSS {cvss}")
        meta_bar = " &nbsp;|&nbsp; ".join(meta_items)

        related_block = self.linker.build_related_resources_block(
            article.title, article.summary, article.labels
        )
        ext_refs = self.linker.build_external_references(article.title, article.summary)
        hashtags = self.linker.build_hashtag_block(article.labels)

        schema_blocks = ""
        if json_ld_str:
            schema_blocks += f'<script type="application/ld+json">\n{json_ld_str}\n</script>\n'
        if faq_str:
            schema_blocks += f'<script type="application/ld+json">\n{faq_str}\n</script>\n'

        html = f"""{self.monetization.get_style_block()}
{schema_blocks}
<!-- CYBERDUDEBIVASH® SENTINEL APEX — Syndicated Intelligence Report -->
<!-- Source: {article.url} -->
<!-- Generated: {datetime.now(timezone.utc).isoformat()} -->

{self.monetization.inject_header_cta()}

<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#e2e8f0;margin:20px 0;padding:14px 18px;background:#050d1a;border-radius:6px;font-size:12px;color:#64748b">
  {meta_bar}
</div>

<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#e2e8f0;line-height:1.8;font-size:15px">

{body_content}

</div>

{self.monetization.inject_mid_products_cta()}

{related_block}

{self.monetization.inject_services_block()}

{self.monetization.inject_detection_packs_cta()}

{ext_refs}

{self.monetization.inject_read_more_cta(article.url)}

{hashtags}

{self.monetization.inject_about_block()}

<div style="margin-top:20px;padding:12px 16px;background:#050d1a;border-top:1px solid #1e3a5f22;font-size:11px;color:#334155;font-family:monospace">
  Intelligence syndicated from <a href="{article.url}" target="_blank" rel="noopener" style="color:#334155">{article.url}</a> by CYBERDUDEBIVASH® SENTINEL APEX Syndication Engine v1.0
</div>
"""
        return html
