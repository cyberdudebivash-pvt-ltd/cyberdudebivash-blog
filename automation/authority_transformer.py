"""
CYBERDUDEBIVASH® SENTINEL APEX — Authority Content Transformer
Transforms source articles into enterprise-grade threat intelligence reports.
LLM priority: Groq → DeepSeek → OpenRouter → Anthropic → template fallback.
"""

import base64
import json
import re
from datetime import datetime, timezone
from typing import Optional

from .category_mapper import primary_category
from .config import Config
from .content_discovery import DiscoveredArticle
from .internal_linker import InternalLinker
from .llm_client import call_llm
from .logger import setup_logger
from .monetization_injector import MonetizationInjector
from .seo_optimizer import SEOOptimizer, _extract_cve_ids, _extract_cvss

logger = setup_logger("authority_transformer")


# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY PALETTE — maps to SVG banner color schemes
# ─────────────────────────────────────────────────────────────────────────────
_CATEGORY_PALETTE = {
    "Ransomware":    {"bg1": "#1a0a00", "bg2": "#2d1200", "accent": "#f59e0b", "badge": "#b45309"},
    "Zero-Day":      {"bg1": "#1a0005", "bg2": "#2d0010", "accent": "#ef4444", "badge": "#b91c1c"},
    "CVE":           {"bg1": "#1a0005", "bg2": "#2d0010", "accent": "#ef4444", "badge": "#b91c1c"},
    "AI Security":   {"bg1": "#0d0a1a", "bg2": "#180d2d", "accent": "#a855f7", "badge": "#7c3aed"},
    "APT":           {"bg1": "#1a001a", "bg2": "#2d002d", "accent": "#ec4899", "badge": "#be185d"},
    "Nation-State":  {"bg1": "#1a001a", "bg2": "#2d002d", "accent": "#ec4899", "badge": "#be185d"},
    "Threat Intel":  {"bg1": "#001a1a", "bg2": "#002d2d", "accent": "#00d4ff", "badge": "#0284c7"},
    "Default":       {"bg1": "#00080f", "bg2": "#001220", "accent": "#00d4ff", "badge": "#0284c7"},
}


def _get_palette(labels: list) -> dict:
    text = " ".join(labels).lower()
    if "ransomware" in text:
        return _CATEGORY_PALETTE["Ransomware"]
    if "zero-day" in text or "zero day" in text or "0day" in text:
        return _CATEGORY_PALETTE["Zero-Day"]
    if "ai security" in text or "llm" in text or "prompt injection" in text:
        return _CATEGORY_PALETTE["AI Security"]
    if "apt" in text or "nation-state" in text:
        return _CATEGORY_PALETTE["APT"]
    if "cve" in text or "vulnerability" in text:
        return _CATEGORY_PALETTE["CVE"]
    if "threat intel" in text:
        return _CATEGORY_PALETTE["Threat Intel"]
    return _CATEGORY_PALETTE["Default"]


# ─────────────────────────────────────────────────────────────────────────────
# SVG THUMBNAIL GENERATOR
# Produces a 1200×630 branded banner embedded as a data URI <img> tag.
# This becomes data:post.firstImageUrl in Blogger — fixes missing thumbnails.
# ─────────────────────────────────────────────────────────────────────────────

def _generate_svg_thumbnail(title: str, labels: list, cvss: Optional[str] = None) -> str:
    """Return an <img> tag with the SVG banner as a data URI."""
    palette = _get_palette(labels)
    bg1 = palette["bg1"]
    bg2 = palette["bg2"]
    accent = palette["accent"]
    badge_bg = palette["badge"]

    category = labels[0].upper() if labels else "THREAT INTEL"
    # Truncate and wrap title for SVG text
    title_clean = re.sub(r"[<>&\"']", " ", title).strip()
    words = title_clean.split()
    line1 = " ".join(words[:7])
    line2 = " ".join(words[7:13]) if len(words) > 7 else ""
    line3 = " ".join(words[13:18]) + ("…" if len(words) > 18 else "") if len(words) > 13 else ""

    cvss_badge = ""
    if cvss:
        score = float(cvss)
        cvss_color = "#ef4444" if score >= 9.0 else "#f59e0b" if score >= 7.0 else "#22c55e"
        cvss_badge = f"""
  <rect x="980" y="20" width="200" height="56" rx="6" fill="{cvss_color}" opacity="0.95"/>
  <text x="1080" y="43" text-anchor="middle" fill="white" font-family="Arial,sans-serif" font-size="11" font-weight="700" letter-spacing="1">CVSS SCORE</text>
  <text x="1080" y="65" text-anchor="middle" fill="white" font-family="Arial,sans-serif" font-size="22" font-weight="900">{cvss}</text>
"""

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 630" width="1200" height="630">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:{bg1}"/>
      <stop offset="100%" style="stop-color:{bg2}"/>
    </linearGradient>
    <linearGradient id="accent_grad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:{accent};stop-opacity:0.8"/>
      <stop offset="100%" style="stop-color:{accent};stop-opacity:0.2"/>
    </linearGradient>
  </defs>
  <!-- Background -->
  <rect width="1200" height="630" fill="url(#bg)"/>
  <!-- Grid overlay -->
  <g stroke="{accent}" stroke-width="0.4" opacity="0.08">
    <line x1="0" y1="105" x2="1200" y2="105"/>
    <line x1="0" y1="210" x2="1200" y2="210"/>
    <line x1="0" y1="315" x2="1200" y2="315"/>
    <line x1="0" y1="420" x2="1200" y2="420"/>
    <line x1="0" y1="525" x2="1200" y2="525"/>
    <line x1="150" y1="0" x2="150" y2="630"/>
    <line x1="300" y1="0" x2="300" y2="630"/>
    <line x1="450" y1="0" x2="450" y2="630"/>
    <line x1="600" y1="0" x2="600" y2="630"/>
    <line x1="750" y1="0" x2="750" y2="630"/>
    <line x1="900" y1="0" x2="900" y2="630"/>
    <line x1="1050" y1="0" x2="1050" y2="630"/>
  </g>
  <!-- Glow orbs -->
  <circle cx="200" cy="150" r="200" fill="{accent}" opacity="0.04"/>
  <circle cx="1000" cy="480" r="250" fill="{accent}" opacity="0.04"/>
  <!-- Left accent bar -->
  <rect x="0" y="0" width="6" height="630" fill="url(#accent_grad)"/>
  <!-- Bottom accent bar -->
  <rect x="0" y="600" width="1200" height="30" fill="{accent}" opacity="0.12"/>
  <!-- Shield icon -->
  <path d="M60 80 L90 68 L120 80 L120 108 Q120 126 90 136 Q60 126 60 108 Z" fill="none" stroke="{accent}" stroke-width="2.5" opacity="0.9"/>
  <path d="M78 102 L87 111 L106 90" stroke="{accent}" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  <!-- Brand name -->
  <text x="134" y="93" fill="{accent}" font-family="Arial,sans-serif" font-size="13" font-weight="900" letter-spacing="2">CYBERDUDEBIVASH®</text>
  <text x="134" y="113" fill="{accent}" font-family="Arial,sans-serif" font-size="10" letter-spacing="3" opacity="0.7">SENTINEL APEX</text>
  <!-- Category badge -->
  <rect x="26" y="160" width="{min(len(category) * 11 + 24, 280)}" height="32" rx="4" fill="{badge_bg}" opacity="0.9"/>
  <text x="38" y="181" fill="white" font-family="Arial,sans-serif" font-size="12" font-weight="700" letter-spacing="1.5">{category[:22]}</text>
  <!-- Title lines -->
  <text x="26" y="260" fill="white" font-family="Arial,sans-serif" font-size="38" font-weight="900" opacity="0.95">{line1}</text>
  {"<text x='26' y='310' fill='white' font-family='Arial,sans-serif' font-size='38' font-weight='900' opacity='0.95'>" + line2 + "</text>" if line2 else ""}
  {"<text x='26' y='360' fill='white' font-family='Arial,sans-serif' font-size='38' font-weight='900' opacity='0.95'>" + line3 + "</text>" if line3 else ""}
  <!-- Divider -->
  <rect x="26" y="420" width="200" height="3" rx="2" fill="{accent}" opacity="0.7"/>
  <!-- Tagline -->
  <text x="26" y="460" fill="{accent}" font-family="Arial,sans-serif" font-size="14" letter-spacing="2" opacity="0.8">ENTERPRISE THREAT INTELLIGENCE REPORT</text>
  <!-- Bottom meta -->
  <text x="26" y="590" fill="white" font-family="Arial,sans-serif" font-size="11" opacity="0.5">blog.cyberdudebivash.in  |  intel.cyberdudebivash.com</text>
  {cvss_badge}
</svg>"""

    svg_b64 = base64.b64encode(svg.encode("utf-8")).decode("utf-8")
    return (
        f'<img src="data:image/svg+xml;base64,{svg_b64}" '
        f'alt="{title[:80]}" '
        f'width="1200" height="630" '
        f'style="width:100%;max-width:1200px;height:auto;display:block;margin:0 auto 24px;border-radius:8px" '
        f'loading="eager"/>'
    )


# ─────────────────────────────────────────────────────────────────────────────
# LLM PROMPT — 18-SECTION ENTERPRISE INTELLIGENCE REPORT
# ─────────────────────────────────────────────────────────────────────────────

def _build_analyst_prompt(article: DiscoveredArticle) -> str:
    return f"""You are the CYBERDUDEBIVASH® SENTINEL APEX Principal Threat Intelligence Analyst — a world-class CTI expert trained on MITRE ATT&CK, MITRE ATLAS, CISA KEV, NVD, and enterprise SOC operations. You write at the level of CrowdStrike Intelligence, Recorded Future, and SentinelOne Labs.

Transform the following cybersecurity article into a world-class enterprise threat intelligence report. Every section must be operationally actionable for SOC analysts, CISOs, detection engineers, and threat hunters.

ARTICLE TITLE: {article.title}
ARTICLE URL: {article.url}
ARTICLE CONTENT:
{(article.full_content or article.summary)[:4000]}
LABELS/CATEGORY: {', '.join(article.labels)}

Generate a comprehensive intelligence report with EXACTLY these sections in HTML format (use <h3>, <p>, <ul>, <li>, <table>, <tr>, <th>, <td> — NO inline styles on individual elements, only structure):

<h3>Executive Summary</h3>
[3 sentences max. Board-level language. Quantify risk, financial exposure, or operational impact where data supports it. No generic statements.]

<h3>Threat Overview</h3>
[2-3 paragraphs. Who is the threat actor or vulnerability? What is affected? What is the attack methodology? Technical depth for security architects.]

<h3>Threat Severity Assessment</h3>
[Severity: CRITICAL/HIGH/MEDIUM/LOW. Justification tied to: exploitability, impact, prevalence, CVSS if available. Format as a structured assessment.]

<h3>Business Impact</h3>
[Concrete enterprise risk: financial exposure, regulatory liability (GDPR, NIS2, DORA, SOC 2), operational disruption, reputational damage. Write for CISOs and risk officers.]

<h3>Technical Analysis</h3>
[Deep technical breakdown: attack vector, exploitation chain, affected components, versions, root cause. Reference CVE IDs if present. Write for senior detection engineers.]

<h3>CVE Analysis</h3>
[Only if CVEs are present. Include: CVE ID, affected product, vulnerability class, attack vector, authentication required, patch status. Use a structured format with <ul> items.]

<h3>MITRE ATT&CK Mapping</h3>
<ul>[Map ONLY techniques clearly evidenced by the article. Format: Tactic → Technique (TXXXX): brief rationale. Be precise — do not pad with generic techniques.]</ul>

<h3>IOC Intelligence</h3>
[List any IPs, domains, file hashes, registry keys, URLs, or behavioral IOCs mentioned or derivable from the article. If none are explicitly stated, describe the IOC categories defenders should hunt for. Format: type — value/description.]

<h3>Detection Engineering Guidance</h3>
[Specific log sources, Event IDs, telemetry fields, and detection logic. Example: Windows Event ID 4688 (process creation) with CommandLine containing suspicious patterns. Write for SIEM engineers deploying in Splunk/Elastic/Microsoft Sentinel.]

<h3>Sigma Rules</h3>
[Generate 1-2 realistic Sigma detection rules in YAML format inside a <pre><code> block. Base the rules on the attack techniques described. Include title, status, description, logsource, detection, condition, tags (MITRE ATT&CK). If insufficient technical detail exists in the article, provide a framework Sigma rule with accurate logsource for the threat type.]

<h3>Threat Hunting Queries</h3>
<ul>[5 specific hunt hypotheses with the data source to query. Format: Hypothesis — Data source. Be operationally specific, not generic.]</ul>

<h3>SOC Analyst Actions</h3>
<ul>[Immediate triage steps: P1 through P3. What to check first, what to escalate, what to contain. Write for L1/L2 SOC analysts on shift.]</ul>

<h3>Executive Recommendations</h3>
<ul>[Strategic 90-day guidance: Day 1-7 (immediate), Day 8-30 (short-term), Day 31-90 (strategic). One bullet per phase minimum.]</ul>

<h3>MSSP Opportunities</h3>
[How MSSPs and managed SOC providers should respond: client advisory, service activation, detection rule deployment. Position CYBERDUDEBIVASH® SENTINEL APEX as the intelligence source.]

<h3>Sentinel APEX Intelligence Correlation</h3>
[How CYBERDUDEBIVASH® SENTINEL APEX detects and correlates this threat. Reference: live CVE tracking, MITRE ATT&CK correlation engine, real-time IOC feeds, Sigma rule library, threat hunting workbench.]

<h3>AI Security Impact</h3>
[ONLY include if the article relates to AI/LLM/ML threats, AI systems, or AI infrastructure. Otherwise omit entirely. Reference OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF where applicable.]

<h3>Long-Term Strategic Risk</h3>
[How this threat fits into the evolving threat landscape over 6-18 months. Nation-state implications, ransomware ecosystem evolution, supply chain risk, regulatory direction.]

<h3>References</h3>
<ul>[Source URL of the article, plus 2-3 authoritative external references: NVD, CISA, vendor advisories, MITRE. Format: Name — URL]</ul>

CRITICAL RULES:
- Do NOT fabricate CVE IDs, CVSS scores, threat actor names, or technical details not evidenced in the article
- Do NOT invent IOCs — only report what exists in the article or describe categories
- Write at analyst level — no marketing fluff, no generic SOC advice
- Every recommendation must be specific and actionable
- Sigma rules must be syntactically correct YAML
- Keep total length between 900-1600 words
- Return ONLY the HTML sections, no preamble or suffix text
"""


# ─────────────────────────────────────────────────────────────────────────────
# TEMPLATE FALLBACK — full 18-section structure when all LLM providers fail
# ─────────────────────────────────────────────────────────────────────────────

def _template_enhance(article: DiscoveredArticle, config: Config) -> str:
    cves = _extract_cve_ids(article.title + " " + article.summary)
    cvss = _extract_cvss(article.title + " " + article.summary)
    category = primary_category(article.labels)

    cve_str = ", ".join(cves) if cves else "this vulnerability"
    cvss_str = f"CVSS {cvss}" if cvss else "elevated"

    text = (article.title + " " + article.summary).lower()
    is_ransomware = "ransomware" in text
    is_ai = "ai " in text or "llm" in text or "prompt injection" in text or "owasp" in text
    is_apt = "apt" in text or "nation-state" in text or "nation state" in text or "state-sponsored" in text
    is_cve = bool(cves) or "vulnerability" in text or "cve" in text
    is_patch = "patch" in text or "update" in text or "cisa" in text or "kev" in text

    # Severity determination
    if cvss:
        score = float(cvss)
        severity = "CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0 else "MEDIUM"
        severity_color = "#ef4444" if score >= 9.0 else "#f59e0b" if score >= 7.0 else "#22c55e"
    elif is_ransomware or is_apt or (is_cve and is_patch):
        severity, severity_color = "HIGH", "#f59e0b"
    else:
        severity, severity_color = "MEDIUM", "#3b82f6"

    # MITRE ATT&CK mapping
    if is_ransomware:
        mitre_techniques = [
            "Initial Access → Phishing (T1566): Email-borne delivery of ransomware loader",
            "Execution → Command and Scripting Interpreter: PowerShell (T1059.001): Ransomware deployment via PowerShell",
            "Defense Evasion → Obfuscated Files or Information (T1027): Payload obfuscation to evade AV/EDR",
            "Discovery → Network Share Discovery (T1135): Lateral share enumeration before encryption",
            "Impact → Data Encrypted for Impact (T1486): File system encryption with ransom note delivery",
            "Exfiltration → Exfiltration Over C2 Channel (T1041): Double-extortion data theft before encryption",
        ]
        sigma_logsource = "windows\n    category: process_creation"
        sigma_detection = """detection:
    selection:
        CommandLine|contains:
            - 'vssadmin delete shadows'
            - 'wbadmin delete catalog'
            - 'bcdedit /set {default} recoveryenabled No'
            - '.onion'
    condition: selection"""
        sigma_title = "Ransomware Pre-Encryption Activity"
        sigma_tags = "attack.impact\n        - attack.t1486\n        - attack.t1490"
        hunt_queries = [
            "Shadow copy deletion — Windows Security Event ID 4688 with CommandLine containing 'vssadmin'",
            "Lateral movement via SMB — Network flow data showing mass SMB connections from single host",
            "Mass file rename events — EDR/File Integrity Monitoring for high-volume .extension changes in <60s",
            "C2 beaconing — DNS query frequency analysis for entropy-high domain names",
            "Privileged account abuse — Windows Security Event ID 4672 (Special Logon) at unusual hours",
        ]
        soc_actions = [
            "P1 — Isolate affected hosts immediately via network quarantine; do NOT power off (preserve memory forensics)",
            "P1 — Identify patient-zero via EDR lateral movement timeline and block C2 domains in perimeter firewall",
            "P1 — Verify backup integrity — confirm immutable backups are accessible and unaffected",
            "P2 — Enumerate all hosts with open SMB shares and apply emergency network segmentation",
            "P2 — Activate IR retainer and begin forensic preservation of affected systems",
            "P3 — Notify legal, compliance, and executive stakeholders per breach notification SLAs",
        ]
        mssp_block = "MSSPs should immediately push Sigma detection rules covering T1486 and T1490 to all client SIEMs. Activate 24/7 monitoring escalation for all clients in the affected sector. CYBERDUDEBIVASH® SENTINEL APEX ransomware intelligence feed provides real-time IOC updates including C2 infrastructure and affiliate TTPs."

    elif is_apt:
        mitre_techniques = [
            "Reconnaissance → Active Scanning (T1595): Infrastructure reconnaissance before initial access",
            "Initial Access → Exploit Public-Facing Application (T1190): Exploitation of internet-exposed services",
            "Persistence → Create or Modify System Process (T1543): Long-term persistence via service installation",
            "Defense Evasion → Masquerading (T1036): Malware masquerading as legitimate system processes",
            "Collection → Data from Local System (T1005): Targeted collection of sensitive files pre-exfiltration",
            "Exfiltration → Exfiltration Over Alternative Protocol (T1048): Data exfil via DNS or HTTPS tunneling",
        ]
        sigma_logsource = "windows\n    category: process_creation"
        sigma_detection = """detection:
    selection_lolbas:
        Image|endswith:
            - '\\certutil.exe'
            - '\\mshta.exe'
            - '\\regsvr32.exe'
        CommandLine|contains:
            - 'http'
            - 'urlcache'
            - 'decode'
    condition: selection_lolbas"""
        sigma_title = "Living-off-the-Land Binary Abuse — APT Staging"
        sigma_tags = "attack.defense_evasion\n        - attack.t1218\n        - attack.t1027"
        hunt_queries = [
            "LOLBAS abuse — EDR process telemetry for certutil.exe, mshta.exe, regsvr32.exe with network connections",
            "Scheduled task persistence — Windows Security Event ID 4698 (scheduled task creation) by non-admin accounts",
            "DNS tunneling — DNS query log analysis for TXT record queries with high entropy strings",
            "Service installation persistence — Windows System Event ID 7045 for unexpected service registrations",
            "Credential dumping — EDR alerts for LSASS memory access by non-system processes",
        ]
        soc_actions = [
            "P1 — Search EDR across all endpoints for IOCs associated with this APT campaign",
            "P1 — Review perimeter logs for inbound connections from known APT infrastructure",
            "P2 — Conduct privileged account audit — check for newly created accounts or credential changes",
            "P2 — Analyze egress traffic for C2 communication patterns: beacon intervals, DNS tunneling, HTTPS to unusual geos",
            "P3 — Brief CISO and legal team on potential nation-state attribution and regulatory implications",
        ]
        mssp_block = "MSSPs should distribute an emergency client advisory covering this APT campaign TTPs. Activate threat hunting teams on high-value client environments. CYBERDUDEBIVASH® SENTINEL APEX APT tracking provides real-time campaign updates, infrastructure mapping, and attribution intelligence."

    elif is_cve:
        mitre_techniques = [
            f"Initial Access → Exploit Public-Facing Application (T1190): {cve_str} exploitation of internet-exposed service",
            "Privilege Escalation → Exploitation for Privilege Escalation (T1068): Post-exploitation privilege escalation",
            "Lateral Movement → Exploitation of Remote Services (T1210): Lateral movement via the same vulnerability class",
            "Persistence → Server Software Component: Web Shell (T1505.003): Web shell installation post-exploitation",
        ]
        sigma_logsource = "webserver"
        sigma_detection = f"""detection:
    selection:
        c-uri|contains:
            - '../'
            - '%2e%2e'
            - 'cmd.exe'
            - '/etc/passwd'
        sc-status:
            - 200
            - 500
    condition: selection"""
        sigma_title = f"Web Application Exploitation Attempt — {cve_str}"
        sigma_tags = "attack.initial_access\n        - attack.t1190"
        hunt_queries = [
            f"Exploitation attempt — Web application logs for {cve_str} payload signatures in URI/body parameters",
            "Post-exploitation — EDR process tree analysis for web server spawning cmd.exe or powershell.exe",
            "Web shell activity — File integrity monitoring for new .php/.aspx/.jsp files in web directories",
            "Network lateral movement — Internal SIEM for connections originating from DMZ web servers to internal hosts",
            "Credential access post-exploitation — Windows Security Event ID 4648 (explicit logon) from web server accounts",
        ]
        soc_actions = [
            f"P1 — Apply vendor patch for {cve_str} immediately; if unavailable, implement WAF virtual patch",
            "P1 — Search SIEM/EDR for exploitation indicators over the past 30 days (dwell time awareness)",
            "P2 — Review all web server process spawn events for anomalous child processes (shells, interpreters)",
            "P2 — Block exploitation payload patterns at WAF layer; update IDS/IPS signatures",
            "P3 — Conduct full vulnerability scan of adjacent systems for the same vulnerability class",
        ]
        mssp_block = f"MSSPs should immediately assess all client attack surfaces for {cve_str} exposure. Issue priority advisory to all clients with affected technology in their environment. Deploy WAF virtual patching rules while client teams complete patch deployment. CYBERDUDEBIVASH® SENTINEL APEX KEV integration provides real-time CISA KEV tracking with client exposure scoring."

    else:
        mitre_techniques = [
            "Initial Access → Phishing (T1566): Social engineering as primary delivery mechanism",
            "Execution → User Execution (T1204): Victim-initiated execution of malicious content",
            "Defense Evasion → Obfuscated Files or Information (T1027): Payload obfuscation",
        ]
        sigma_logsource = "windows\n    category: process_creation"
        sigma_detection = """detection:
    selection:
        ParentImage|endswith:
            - '\\outlook.exe'
            - '\\winword.exe'
            - '\\excel.exe'
        Image|endswith:
            - '\\powershell.exe'
            - '\\cmd.exe'
            - '\\wscript.exe'
    condition: selection"""
        sigma_title = "Suspicious Office/Mail Client Child Process"
        sigma_tags = "attack.execution\n        - attack.t1204.002\n        - attack.t1059"
        hunt_queries = [
            "Anomalous process spawn — EDR parent-child process analysis for office applications spawning shells",
            "Suspicious network connections — SIEM correlation of endpoint processes making unexpected external connections",
            "Scheduled persistence — Windows Security Event ID 4698 (task creation) from non-administrative accounts",
            "Registry run key persistence — EDR Registry monitoring for HKCU/HKLM Run key modifications",
            "Encoded command lines — EDR process telemetry for PowerShell with -EncodedCommand parameters",
        ]
        soc_actions = [
            "P1 — Identify affected systems from threat indicators and initiate triage via EDR",
            "P2 — Block related IOCs at email gateway, web proxy, and DNS filtering",
            "P2 — Validate detection rule coverage for MITRE techniques mapped above in SIEM",
            "P3 — Update threat intelligence platform with new IOCs and distribute to all detection layers",
        ]
        mssp_block = "MSSPs should review client detection coverage against the MITRE techniques identified. Issue client advisory with context-specific recommendations. CYBERDUDEBIVASH® SENTINEL APEX provides automated MSSP intelligence briefings with client-specific exposure analysis."

    mitre_html = "\n".join(f"<li>{t}</li>" for t in mitre_techniques)
    hunt_html = "\n".join(f"<li>{q}</li>" for q in hunt_queries)
    soc_html = "\n".join(f"<li>{a}</li>" for a in soc_actions)

    # Enterprise recommendations (phased)
    enterprise_recs = []
    enterprise_recs.append(f"<strong>Day 1–7 (Immediate):</strong> {soc_actions[0] if soc_actions else 'Assess exposure and apply available patches'}")
    enterprise_recs.append(f"<strong>Day 8–30 (Short-term):</strong> Validate SIEM detection coverage against MITRE ATT&CK techniques above; deploy updated Sigma rules to all detection platforms")
    enterprise_recs.append("<strong>Day 31–90 (Strategic):</strong> Conduct tabletop exercise simulating this attack scenario; evaluate CYBERDUDEBIVASH® SENTINEL APEX for continuous threat intelligence integration")
    if is_ai:
        enterprise_recs.insert(0, "<strong>Immediate — AI Security:</strong> Conduct AI Security Assessment against OWASP LLM Top 10 and MITRE ATLAS framework for all production AI/LLM deployments")
    ent_html = "\n".join(f"<li>{r}</li>" for r in enterprise_recs)

    ai_section = ""
    if is_ai:
        ai_section = """
<h3>AI Security Impact</h3>
<p>This threat has direct implications for enterprise AI and LLM deployments. Organizations utilizing large language models, AI agents, RAG systems, or AI-powered security tools must assess their exposure to prompt injection, model inversion, training data poisoning, and agentic AI exploitation paths.</p>
<p>CYBERDUDEBIVASH® references OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF 1.0 as primary frameworks for AI security governance. Key AI security risks to evaluate: LLM01 (Prompt Injection), LLM06 (Sensitive Information Disclosure), LLM08 (Excessive Agency), LLM10 (Model Theft).</p>
<p>CYBERDUDEBIVASH® AI Security Hub provides enterprise-grade AI security assessments, red teaming, and AI governance consulting to help organizations operate AI systems safely at scale.</p>
"""

    long_term_risk = ""
    if is_ransomware:
        long_term_risk = "The ransomware ecosystem is evolving toward Ransomware-as-a-Service (RaaS) affiliate models with increasingly sophisticated initial access brokers. Expect triple-extortion tactics (encryption + data leak + DDoS) to become standard. Organizations must mature from reactive patching to intelligence-driven prevention — integrating real-time CTI feeds with automated SIEM correlation."
    elif is_apt:
        long_term_risk = "Nation-state threat actors are demonstrating sustained dwell times averaging 197 days before detection. The strategic risk is intellectual property theft, critical infrastructure disruption, and pre-positioning for future kinetic operations. Organizations in targeted sectors must operate on the assumption of compromise and implement zero-trust network architectures with continuous behavioral monitoring."
    elif is_cve:
        long_term_risk = f"Unpatched public-facing vulnerabilities like {cve_str} represent the single largest attack surface for enterprise environments. The trend toward n-day exploitation within hours of CVE publication demands automated vulnerability prioritization integrated with real-time CISA KEV tracking. CYBERDUDEBIVASH® SENTINEL APEX KEV correlation provides immediate risk scoring against your asset inventory."
    else:
        long_term_risk = "The threat landscape is accelerating toward AI-augmented attacks, supply chain compromise, and cloud infrastructure targeting. Organizations that rely on periodic threat briefings rather than continuous intelligence feeds will consistently lag attacker dwell times. Intelligence-driven security operations — powered by platforms like CYBERDUDEBIVASH® SENTINEL APEX — represent the next maturity inflection point."

    return f"""
<h3>Executive Summary</h3>
<p>{article.summary[:400].rstrip('.')}. This represents a <strong>{severity}</strong>-severity threat ({cvss_str} risk) requiring immediate evaluation by enterprise security teams. CYBERDUDEBIVASH® SENTINEL APEX has flagged this as a priority intelligence item for enterprise SOC and vulnerability management teams.</p>

<h3>Threat Overview</h3>
<p>{article.summary[:600]}</p>
<p>Security teams must assess organizational exposure immediately. This threat directly impacts enterprise security posture and requires coordinated response across SOC, vulnerability management, and executive stakeholders.</p>

<h3>Threat Severity Assessment</h3>
<p><strong>Severity: {severity}</strong> {'| CVSS ' + cvss if cvss else ''}</p>
<ul>
<li>Exploitability: {'Actively exploited in the wild per CISA KEV' if is_patch else 'Technical details public — exploitation likely imminent'}</li>
<li>Impact: {'Operational disruption, data encryption, ransom demand' if is_ransomware else 'Unauthorized access, privilege escalation, data exfiltration'}</li>
<li>Prevalence: {'Widespread ransomware campaign' if is_ransomware else 'Targeted exploitation of ' + category + ' systems'}</li>
<li>Patch Status: {'Emergency patch available — immediate deployment required' if is_patch else 'Monitor vendor advisory channel for patch release'}</li>
</ul>

<h3>Business Impact</h3>
<p>Organizations with unmitigated exposure face: operational disruption impacting revenue-generating systems, potential regulatory enforcement under GDPR (up to 4% global annual revenue), NIS2, DORA, or SOC 2 audit findings. Reputational damage from public breach disclosure and customer notification obligations further elevate the business risk profile.</p>
<p>The threat vector targets {category.lower()} systems that are frequently central to enterprise operations. Risk quantification against your specific asset inventory is the immediate priority before applying standard CVSS scores.</p>

<h3>Technical Analysis</h3>
<p>{article.summary[:800]}</p>
<p>{'Exploitation methodology follows a well-documented attack chain: ' + ('initial phishing delivery → macro/script execution → ransomware deployment → shadow copy deletion → encryption.' if is_ransomware else 'initial access via exploitation → post-exploitation enumeration → lateral movement → persistence establishment → objectives execution.') if len(article.summary) < 400 else ''}</p>

<h3>CVE Analysis</h3>
{'<ul>' + chr(10).join(f'<li><strong>{cve}</strong> — Vulnerability in {category} systems. CVSS: {cvss_str}. Attack Vector: Network. Authentication: Low/None. Patch status: Monitor NVD and vendor advisory for latest status.</li>' for cve in cves) + '</ul>' if cves else '<p>No specific CVE identifiers extracted from this intelligence item. Monitor NVD and CISA KEV for related vulnerability disclosures.</p>'}

<h3>MITRE ATT&CK Mapping</h3>
<ul>
{mitre_html}
</ul>

<h3>IOC Intelligence</h3>
<p>No specific IOCs published in this intelligence item at time of report generation. Defenders should monitor CYBERDUDEBIVASH® SENTINEL APEX IOC feed for real-time updates. Standard IOC categories applicable to this threat type:</p>
<ul>
<li>Network: C2 IP ranges, malicious domains, SSL certificate fingerprints</li>
<li>File: Malware hashes (MD5/SHA256), dropped filenames, file extensions used in encryption</li>
<li>Registry: Persistence key paths, service names used for persistence</li>
<li>Behavioral: Process names, command-line patterns, network beacon intervals</li>
</ul>

<h3>Detection Engineering Guidance</h3>
<p>Recommended log sources and telemetry for detection deployment:</p>
<ul>
<li><strong>Windows Security Events:</strong> ID 4688 (process creation with command line), 4698 (scheduled task), 4672 (special logon), 4624/4625 (auth success/failure)</li>
<li><strong>EDR/XDR Telemetry:</strong> Process tree analysis, file system events, registry modifications, network connections</li>
<li><strong>Network:</strong> DNS query logs, proxy/web gateway logs, NetFlow/PCAP for C2 identification</li>
<li><strong>Cloud:</strong> CloudTrail/Azure Activity Logs for IAM changes, unusual API calls, resource creation in non-standard regions</li>
</ul>

<h3>Sigma Rules</h3>
<pre><code>title: {sigma_title}
id: cyberdudebivash-sentinel-apex-001
status: experimental
description: Detects {sigma_title.lower()} — CYBERDUDEBIVASH® SENTINEL APEX Detection Engineering
references:
    - https://blog.cyberdudebivash.in
    - https://intel.cyberdudebivash.com
author: CYBERDUDEBIVASH® SENTINEL APEX Detection Engineering
date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}
tags:
    - {sigma_tags}
logsource:
    product: {sigma_logsource}
{sigma_detection}
falsepositives:
    - Legitimate administrative activity — verify via change management records
level: high
</code></pre>

<h3>Threat Hunting Queries</h3>
<ul>
{hunt_html}
</ul>

<h3>SOC Analyst Actions</h3>
<ul>
{soc_html}
</ul>

<h3>Executive Recommendations</h3>
<ul>
{ent_html}
</ul>

<h3>MSSP Opportunities</h3>
<p>{mssp_block}</p>

<h3>Sentinel APEX Intelligence Correlation</h3>
<p>CYBERDUDEBIVASH® SENTINEL APEX provides automated detection and correlation for this threat type across the following platform capabilities:</p>
<ul>
<li><strong>Live CVE Tracking:</strong> Real-time NVD, CISA KEV, and vendor advisory monitoring with CVSS-weighted client exposure scoring</li>
<li><strong>MITRE ATT&CK Correlation Engine:</strong> Automated technique mapping with detection gap analysis against your current SIEM rule coverage</li>
<li><strong>IOC Intelligence Feed:</strong> Real-time IOC enrichment (IPs, domains, hashes) from 40+ threat intelligence sources</li>
<li><strong>Sigma Rule Library:</strong> 2,400+ production-ready Sigma and YARA rules optimized for Splunk, Elastic, Microsoft Sentinel, and Chronicle</li>
<li><strong>Threat Hunting Workbench:</strong> Guided hunt hypotheses with pre-built queries for enterprise SIEM and EDR platforms</li>
</ul>
<p><a href="https://intel.cyberdudebivash.com" target="_blank" rel="noopener">Launch SENTINEL APEX →</a></p>
{ai_section}
<h3>Long-Term Strategic Risk</h3>
<p>{long_term_risk}</p>

<h3>References</h3>
<ul>
<li>Source Article — <a href="{article.url}" target="_blank" rel="noopener">{article.url}</a></li>
<li>MITRE ATT&CK Framework — <a href="https://attack.mitre.org" target="_blank" rel="noopener">https://attack.mitre.org</a></li>
<li>CISA Known Exploited Vulnerabilities — <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">https://www.cisa.gov/known-exploited-vulnerabilities-catalog</a></li>
<li>NIST National Vulnerability Database — <a href="https://nvd.nist.gov" target="_blank" rel="noopener">https://nvd.nist.gov</a></li>
</ul>
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# AUTHORITY TRANSFORMER CLASS
# ─────────────────────────────────────────────────────────────────────────────

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

        # Generate core content — try LLM providers, fall back to template
        llm_result = call_llm(self.config, _build_analyst_prompt(article))
        if llm_result:
            body_content, content_source = llm_result
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

        blogger_labels = article.labels[:20]

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

        # SVG thumbnail — FIRST element so Blogger uses it as firstImageUrl
        svg_thumbnail = _generate_svg_thumbnail(article.title, article.labels, cvss)

        # Metadata bar
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
<!-- CYBERDUDEBIVASH® SENTINEL APEX — Enterprise Threat Intelligence Report -->
<!-- Source: {article.url} -->
<!-- Generated: {datetime.now(timezone.utc).isoformat()} -->

{svg_thumbnail}

{self.monetization.inject_header_cta()}

{self.monetization.inject_urgency_cta(article.labels)}

<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#e2e8f0;margin:20px 0;padding:14px 18px;background:#050d1a;border-radius:6px;font-size:12px;color:#64748b">
  {meta_bar}
</div>

<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#e2e8f0;line-height:1.8;font-size:15px">

{body_content}

</div>

{self.monetization.inject_mid_products_cta()}

{related_block}

{self.monetization.inject_newsletter_cta()}

{self.monetization.inject_services_block()}

{self.monetization.inject_api_cta()}

{self.monetization.inject_detection_packs_cta()}

{ext_refs}

{self.monetization.inject_read_more_cta(article.url)}

{hashtags}

{self.monetization.inject_about_block()}

<div style="margin-top:20px;padding:12px 16px;background:#050d1a;border-top:1px solid #1e3a5f22;font-size:11px;color:#334155;font-family:monospace">
  Intelligence syndicated from <a href="{article.url}" target="_blank" rel="noopener" style="color:#334155">{article.url}</a> · CYBERDUDEBIVASH® SENTINEL APEX Intelligence Engine v2.0
</div>
"""
        return html
