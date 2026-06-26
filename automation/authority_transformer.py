"""
CYBERDUDEBIVASH® SENTINEL APEX — Authority Content Transformer
Transforms source articles into enterprise-grade threat intelligence reports.
LLM priority: Groq → DeepSeek → OpenRouter → Anthropic → template fallback.
"""

import base64
import html as _html_escape
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
        try:
            score = float(cvss)
        except (ValueError, TypeError):
            score = 0.0
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
    alt_text = _html_escape.escape(title[:80], quote=True)
    return (
        f'<img src="data:image/svg+xml;base64,{svg_b64}" '
        f'alt="{alt_text}" '
        f'width="1200" height="630" '
        f'style="width:100%;max-width:1200px;height:auto;display:block;margin:0 auto 24px;border-radius:8px" '
        f'loading="eager"/>'
    )


# ─────────────────────────────────────────────────────────────────────────────
# LLM PROMPT — 18-SECTION ENTERPRISE INTELLIGENCE REPORT
# ─────────────────────────────────────────────────────────────────────────────

def _build_analyst_prompt(article: DiscoveredArticle) -> str:
    return f"""You are the CYBERDUDEBIVASH® SENTINEL APEX Principal Threat Intelligence Analyst. You produce intelligence at the level of Mandiant, CrowdStrike Intelligence, Unit 42, Microsoft MSTIC, and Recorded Future. Every sentence must be operationally actionable for SOC analysts, CISOs, detection engineers, and threat hunters.

ARTICLE TITLE: {article.title}
ARTICLE URL: {article.url}
ARTICLE CONTENT (up to 5000 characters):
{(article.full_content or article.summary)[:5000]}
LABELS/CATEGORY: {', '.join(article.labels)}

Generate a comprehensive intelligence report with EXACTLY these sections in HTML format (use <h3>, <p>, <ul>, <li>, <table>, <tr>, <th>, <td> — NO inline styles on individual elements, only structure):

<h3>Executive Summary</h3>
[3 sentences. Board-level language. State: what happened, who is affected, what must be decided NOW. Quantify risk, financial exposure, or operational impact only where the article supports it. No generic statements.]

<h3>Verified Facts</h3>
[Bullet list of facts directly stated or confirmed in the article. Each bullet: fact — source. Nothing inferred. Do NOT pad with speculation. If only 3 facts are confirmed, list 3.]

<h3>Threat Classification</h3>
[Single structured paragraph: threat type, affected sectors, geographic scope, exploitation status (active/PoC/theoretical), attacker motivation where stated. Label all analyst assessments with confidence level: HIGH/MEDIUM/LOW.]

<h3>Threat Severity Assessment</h3>
[Severity: CRITICAL/HIGH/MEDIUM/LOW with explicit rationale tied to: exploitability, scope of impact, prevalence, CVSS where available. Use a <ul> list with one factor per bullet. State confidence level for each factor.]

<h3>Business Impact</h3>
[Concrete enterprise risk SPECIFIC to this threat: operational disruption scenario, regulatory liability (GDPR, NIS2, DORA, SOC 2) with penalty ranges if applicable, financial exposure class, reputational damage pathway. Write for CISOs and risk committees — no generic "organizations may face" language.]

<h3>Technical Analysis</h3>
[Deep breakdown using only what the article states: attack vector, exploitation chain, affected components, versions, root cause or vulnerability class. For CVEs: CWE classification, CVSS vector string if available, affected versions. For malware: delivery mechanism, execution flow, persistence method. Do NOT extrapolate beyond the article's content.]

<h3>CVE Analysis</h3>
[ONLY if CVEs are explicitly present in the article. CVE ID, affected product/version, vulnerability class (CWE), attack vector, authentication requirement, patch availability. Use <ul> items. If no CVEs, OMIT this section entirely.]

<h3>MITRE ATT&CK Mapping</h3>
<ul>[Map ONLY techniques directly evidenced by the article content. Format each as: Tactic → Technique ID: Technique Name — one sentence rationale tied to specific article content. Do NOT pad with generic techniques. For OT/ICS incidents, use MITRE ATT&CK for ICS (T0xxx) techniques.]</ul>

<h3>IOC Intelligence</h3>
[If the article contains explicit IOCs (IPs, domains, hashes, URLs, extension IDs, registry keys): list them with type and value. If none are published: state "No public IOCs confirmed at time of publication" then describe the behavioral IOC categories defenders should build hunt rules around — specific to this threat type, NOT generic. Minimum 4 behavioral indicators.]

<h3>Detection Engineering Guidance</h3>
[Specific, actionable detection logic: log sources, Event IDs (Windows Security, Sysmon, etc.), telemetry fields, and detection rationale. Tailored to this specific threat — not a generic log source list. Write for SIEM engineers deploying in Splunk, Elastic, or Microsoft Sentinel.]

<h3>Sigma Rules</h3>
[Generate 1-2 syntactically correct Sigma detection rules in YAML format inside a <pre><code> block. Rules must be specific to the attack technique described — title, id (use uuid format), status, description, logsource, detection logic, condition, falsepositives, tags (MITRE ATT&CK txxxx format), level. Rules must be deployable — not template placeholders.]

<h3>Threat Hunting Queries</h3>
<ul>[5 specific hunt hypotheses with: hypothesis — log source/data source. Each must be specific to THIS threat, not generic cybersecurity hunting. Include the specific field names or Event IDs to query.]</ul>

<h3>SOC Analyst Playbook</h3>
<ul>[Triage steps in priority order: P0 (immediate — 0-1hr), P1 (urgent — 1-4hr), P2 (same-day). For each: specific action with the exact tool/log/system to check. Write for L1/L2 analysts on shift — not security architects.]</ul>

<h3>Executive Decision Matrix</h3>
<table>
<tr><th>Priority</th><th>Decision Required</th><th>Owner</th><th>Timeline</th></tr>
[3-5 rows with specific decisions the organization must make about this threat — patch approval, vendor communication, IR activation, board notification, regulatory disclosure. Base on what the article actually describes.]
</table>

<h3>Executive Recommendations</h3>
<ul>[Phased 90-day guidance specific to this threat: Day 1–7 (immediate technical response), Day 8–30 (structural improvements), Day 31–90 (strategic program changes). Each bullet must be tied to this specific threat.]</ul>

<h3>MSSP Opportunities</h3>
[Specific guidance for MSSPs: client notification priority (which client segments are exposed), detection rule deployment (which rules to push), threat hunting activation (specific hypotheses), advisory content. Position CYBERDUDEBIVASH® SENTINEL APEX as the intelligence source.]

<h3>Sentinel APEX Intelligence Correlation</h3>
[How CYBERDUDEBIVASH® SENTINEL APEX detects and correlates this threat class. Reference: live CVE tracking engine, MITRE ATT&CK correlation, real-time IOC feed integration, Sigma rule library (2,400+ rules), threat hunting workbench. Be specific to this threat type.]

<h3>AI Security Impact</h3>
[INCLUDE ONLY if the article explicitly discusses AI/LLM/ML systems, AI infrastructure, or AI-assisted attacks. Reference OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF 1.0 with specific LLM vulnerability identifiers. OMIT ENTIRELY if not AI-related.]

<h3>Predictive Intelligence</h3>
[Based ONLY on what the article describes: most likely next threat actor moves or exploitation escalation within 30/90/180 days. Label each prediction with confidence level: HIGH/MEDIUM/LOW and one-sentence rationale. Do NOT speculate beyond what the article's context supports.]

<h3>Long-Term Strategic Risk</h3>
[How this specific threat fits the evolving landscape over 6-18 months. Regulatory trajectory, threat actor capability evolution, supply chain implications, or infrastructure targeting patterns — grounded in the article's content.]

<h3>References</h3>
<ul>[Source article URL first, then 2-4 authoritative references: NVD entry, CISA advisory, vendor security bulletin, MITRE ATT&CK technique page. Format: Name — URL. Only include references that are directly relevant to this specific threat.]</ul>

ABSOLUTE RULES — VIOLATIONS WILL BREAK ENTERPRISE TRUST:
- NEVER fabricate CVE IDs, CVSS scores, threat actor names, malware capabilities, exploit code, or IOC values not explicitly in the article
- NEVER invent statistics, victim counts, or financial figures unless stated in the article
- NEVER attribute attacks to nation-states or specific groups without explicit article support — if attribution is present in the article, label it as ANALYST ASSESSMENT with confidence level
- NEVER use generic phrases: "organizations should monitor", "threat actors may", "it is important to", "in today's landscape"
- NEVER pad MITRE ATT&CK with techniques not evidenced in the article
- ALL analyst assessments must carry explicit confidence labels: (HIGH CONFIDENCE), (MEDIUM CONFIDENCE), (LOW CONFIDENCE)
- Sigma rules must be syntactically valid and deployable — no placeholder values
- Write at senior intelligence analyst level — every sentence earns its place
- Return ONLY the HTML sections, no preamble, no suffix, no explanation
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
    is_ai = "ai " in text or "llm" in text or "prompt injection" in text or "owasp" in text or "large language model" in text or "generative ai" in text
    is_apt = "apt" in text or "nation-state" in text or "nation state" in text or "state-sponsored" in text or "volt typhoon" in text or "lazarus" in text or "apt28" in text
    is_cve = bool(cves) or "vulnerability" in text or "cve" in text
    is_patch = "patch" in text or "update" in text or "cisa" in text or "kev" in text
    # "critical infrastructure" deliberately excluded — too broad, triggers on APT/ransomware reports
    is_ot = "ot " in text or "ics" in text or "scada" in text or "plc" in text or "operational technology" in text or "industrial control" in text or "hmi" in text or "historian" in text or "modbus" in text or "dnp3" in text or "ethernet/ip" in text or "s7comm" in text or "food processing" in text or "water treatment" in text or "energy sector" in text or "oil and gas" in text or "power grid" in text or "manufacturing plant" in text
    is_supply_chain = "supply chain" in text or "software supply" in text or "dependency" in text or "npm" in text or "pypi" in text or "open source" in text or "package" in text
    is_ato = "credential stuffing" in text or "account takeover" in text or "ato " in text or "combo list" in text or "brute force" in text or "password spray" in text
    is_extension = "browser extension" in text or "chrome extension" in text or "firefox addon" in text or "web store" in text or "extension id" in text

    # Severity determination
    if cvss:
        try:
            score = float(cvss)
        except (ValueError, TypeError):
            score = 0.0
        severity = "CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0 else "MEDIUM"
        severity_color = "#ef4444" if score >= 9.0 else "#f59e0b" if score >= 7.0 else "#22c55e"
    elif is_ransomware or is_apt or (is_cve and is_patch) or is_ot:
        severity, severity_color = "HIGH", "#f59e0b"
    elif is_ato or is_extension or is_supply_chain:
        severity, severity_color = "HIGH", "#f59e0b"
    else:
        severity, severity_color = "MEDIUM", "#3b82f6"

    # MITRE ATT&CK mapping — priority: ransomware → APT → CVE → OT → ATO → extension → supply chain → general
    if is_ot and not is_ransomware and not is_apt and not is_cve:
        mitre_techniques = [
            "Initial Access → Exploit Public-Facing Application (T1190) / Drive-By Compromise (T0817 ICS): Remote exploitation of internet-exposed OT management interfaces",
            "Lateral Movement → Remote Services (T0866 ICS): Adversary pivoted from IT network to OT/ICS environment via unprotected IT-OT boundary",
            "Execution → Command-Line Interface (T0807 ICS): Execution of unauthorized commands on OT engineering workstations or HMI systems",
            "Persistence → Valid Accounts (T0859 ICS): Abuse of legitimate OT operator credentials for sustained access without triggering alarms",
            "Impact → Denial of Control (T0813 ICS): Disruption of industrial process control preventing operators from issuing commands to field devices",
            "Impact → Loss of Availability (T0826 ICS): OT systems rendered unavailable, halting production operations",
        ]
        sigma_logsource = "product: windows\n    category: network_connection"
        sigma_detection = """detection:
    selection:
        DestinationPort:
            - 102    # S7comm (Siemens PLC)
            - 502    # Modbus
            - 44818  # EtherNet/IP
            - 20000  # DNP3
            - 4840   # OPC-UA
        Initiated: 'true'
        SourceIp|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    filter_ot_zone:
        SourceIp|cidr:
            - '10.100.0.0/16'  # Known OT network range — adjust per environment
    condition: selection and not filter_ot_zone"""
        sigma_title = "Anomalous IT-to-OT Protocol Communication — Potential Lateral Movement"
        sigma_tags = "    - attack.lateral_movement\n    - attack.t0866\n    - attack.t0813"
        hunt_queries = [
            "IT-to-OT lateral movement — Firewall/network flow logs for connections from IT VLAN to OT VLAN on industrial protocols (Modbus/502, S7comm/102, DNP3/20000)",
            "OT credential abuse — Authentication logs on HMI and engineering workstations for logons outside scheduled maintenance windows",
            "PLC configuration changes — OT historian or SCADA audit logs for unexpected parameter modifications or logic uploads",
            "Remote access to OT — VPN/jump server logs for remote sessions connecting to OT engineering workstations during non-business hours",
            "IT-OT boundary probing — IDS/IPS alerts for port scans originating from IT network targeting OT IP ranges",
        ]
        soc_actions = [
            "P0 — Confirm IT/OT network boundary status: verify firewall rules between IT and OT VLANs are intact and no unauthorized pass-through rules exist",
            "P0 — Check OT system availability: contact OT operations team to confirm SCADA/HMI/PLC status and production continuity",
            "P1 — Pull authentication logs from OT engineering workstations and HMIs for the past 72 hours — look for logons from IT user accounts",
            "P1 — Review remote access logs (VPN, RDP, jump server) for sessions targeting OT IP ranges from non-OT users",
            "P2 — Engage OT security team or ICS security vendor for forensic review of PLC/controller configuration integrity",
            "P2 — Notify production operations leadership and prepare for potential emergency shutdown procedure if compromise is confirmed",
        ]
        mssp_block = "MSSPs serving manufacturing, energy, food/beverage, water/wastewater, or critical infrastructure clients must immediately assess IT/OT boundary controls and activate OT-specific threat hunting. Issue emergency advisory to all OT-connected clients with guidance on IT-OT network segmentation verification. CYBERDUDEBIVASH® SENTINEL APEX ICS threat intelligence provides MITRE ATT&CK for ICS technique mapping, OT-specific Sigma rules, and sector-specific incident analysis."

    elif is_ransomware:
        mitre_techniques = [
            "Initial Access → Phishing: Spearphishing Attachment (T1566.001) / Exploit Public-Facing Application (T1190): Primary entry via malicious email attachments or exploitation of internet-exposed VPN/RDP services",
            "Execution → Command and Scripting Interpreter: PowerShell (T1059.001): Encoded PowerShell commands deploy ransomware loader and facilitate lateral movement while evading command-line logging",
            "Defense Evasion → Indicator Removal: File Deletion (T1070.004) / Obfuscated Files (T1027): Anti-forensic cleanup of logs and obfuscated payloads to impede incident response and forensic analysis",
            "Discovery → Network Share Discovery (T1135) / Domain Trust Discovery (T1482): Enumeration of network shares and domain trusts to maximize encryption blast radius across connected systems",
            "Lateral Movement → Remote Services: SMB/Windows Admin Shares (T1021.002): Propagation across network using compromised domain credentials via SMB administrative shares",
            "Impact → Data Encrypted for Impact (T1486) / Inhibit System Recovery (T1490): File system encryption following shadow copy deletion to prevent recovery without ransom payment",
            "Exfiltration → Exfiltration Over C2 Channel (T1041): Double-extortion data staging and exfiltration before encryption — victim data posted to leak site if ransom unpaid",
        ]
        sigma_logsource = "product: windows\n    category: process_creation"
        sigma_detection = """detection:
    shadow_deletion:
        Image|endswith:
            - '\\vssadmin.exe'
            - '\\wmic.exe'
            - '\\wbadmin.exe'
            - '\\bcdedit.exe'
        CommandLine|contains:
            - 'delete shadows'
            - 'delete catalog'
            - 'recoveryenabled No'
            - 'shadowcopy delete'
    ransom_ps_staging:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - 'EncodedCommand'
            - 'FromBase64String'
            - 'IEX'
            - 'DownloadString'
    condition: shadow_deletion or ransom_ps_staging"""
        sigma_title = "Ransomware Pre-Encryption Activity — Shadow Deletion and PowerShell Staging"
        sigma_tags = "    - attack.impact\n    - attack.t1486\n    - attack.t1490\n    - attack.t1059.001"
        hunt_queries = [
            "Shadow copy deletion — Windows Security Event ID 4688 with CommandLine containing 'vssadmin delete shadows', 'wmic shadowcopy delete', or 'bcdedit /set recoveryenabled'",
            "SMB lateral propagation — Network flow analysis for a single endpoint establishing SMB connections (port 445) to >20 unique internal hosts within a 5-minute window",
            "Mass file extension change — EDR file system telemetry for >100 file rename/modify events per minute from a single process writing to unknown extensions",
            "Ransomware C2 beacon — DNS query logs for newly registered domains, high-entropy DGA-pattern names, or .onion proxy resolvers from workstation processes",
            "Privileged credential abuse — Windows Security Event ID 4624 (Type 3 network logon) using domain admin accounts originating from non-admin workstations during off-hours",
        ]
        soc_actions = [
            "P0 — If active encryption detected: immediately isolate affected hosts via VLAN quarantine or firewall ACL block; do NOT power off — preserve volatile memory for forensic imaging",
            "P0 — Identify patient-zero: use EDR lateral movement timeline to find earliest infected host; block all associated C2 indicators at perimeter firewall and DNS resolver",
            "P0 — Verify immutable backup integrity: confirm backups are accessible, unaffected by encryption, and that restoration has been tested within the past 90 days",
            "P1 — Enumerate SMB exposure: identify all hosts with open administrative shares (C$, ADMIN$) reachable from infected network segment; apply emergency micro-segmentation",
            "P1 — Activate IR retainer: engage incident response partner; begin forensic preservation (memory images, disk images) of confirmed and suspected affected systems",
            "P2 — Notify legal, compliance, and executive leadership; prepare for mandatory regulatory breach notification (GDPR: 72 hours, HIPAA: 60 days, state breach laws vary) if personal data affected",
        ]
        mssp_block = "MSSPs must immediately activate ransomware response protocols for all clients in high-risk sectors — healthcare, financial services, manufacturing, government, and critical infrastructure face the highest ransom payment rates and regulatory exposure. Push Sigma detection rules covering T1486, T1490, and T1021.002 to all client SIEMs within 1 hour of this advisory. Issue emergency client communication with host isolation procedures and backup verification checklist. CYBERDUDEBIVASH® SENTINEL APEX ransomware intelligence provides real-time C2 infrastructure feeds, RaaS affiliate TTP tracking, and sector-specific incident response playbooks."

    elif is_apt:
        mitre_techniques = [
            "Reconnaissance → Active Scanning (T1595) / Gather Victim Network Information (T1590): Systematic infrastructure mapping and open-source intelligence collection on target organization prior to active exploitation",
            "Initial Access → Exploit Public-Facing Application (T1190) / Trusted Relationship (T1199): Exploitation of internet-exposed services or compromise of trusted third-party vendors with privileged network access",
            "Persistence → Create or Modify System Process: Windows Service (T1543.003) / Scheduled Task (T1053.005): Long-term persistence via registered services or scheduled tasks executing under legitimate account context",
            "Defense Evasion → Masquerading: Rename System Utilities (T1036.003) / Signed Binary Proxy Execution (T1218): LOLBAS abuse and process name masquerading to blend malicious execution with legitimate OS operations",
            "Collection → Data from Local System (T1005) / Email Collection (T1114.001): Targeted collection of intellectual property, credentials, email archives, and strategic documents matching threat actor's collection objectives",
            "Exfiltration → Exfiltration Over Alternative Protocol (T1048) / Scheduled Transfer (T1029): Low-volume exfiltration via DNS tunneling, HTTPS to cloud storage, or time-delayed transfers to avoid volume-based detection",
        ]
        sigma_logsource = "product: windows\n    category: process_creation"
        sigma_detection = """detection:
    lolbas_net:
        Image|endswith:
            - '\\certutil.exe'
            - '\\mshta.exe'
            - '\\regsvr32.exe'
            - '\\bitsadmin.exe'
        CommandLine|contains:
            - 'http'
            - 'urlcache'
            - 'decode'
            - '/transfer'
    schtask_non_admin:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains:
            - '/create'
        User|not|contains:
            - 'SYSTEM'
            - 'Administrator'
    condition: lolbas_net or schtask_non_admin"""
        sigma_title = "APT Indicators — LOLBAS Network Access and Non-Admin Scheduled Task Creation"
        sigma_tags = "    - attack.defense_evasion\n    - attack.t1218\n    - attack.t1053.005\n    - attack.t1027"
        hunt_queries = [
            "LOLBAS with outbound network connections — EDR process telemetry for certutil.exe, mshta.exe, regsvr32.exe, bitsadmin.exe with DestinationIP not in internal RFC1918 ranges",
            "Non-admin scheduled task creation — Windows Security Event ID 4698 (scheduled task created) attributed to non-SYSTEM, non-administrator user accounts or unusual parent process",
            "DNS tunneling — DNS query logs for TXT/NULL record type queries and subdomain strings exceeding 30 characters in entropy from workstation processes",
            "Unexpected service registration — Windows System Event ID 7045 (new service installed) outside documented change management windows or from non-administrative accounts",
            "LSASS memory access — EDR telemetry for processes other than SYSTEM/antivirus/EDR opening lsass.exe with PROCESS_VM_READ (0x0010) access rights",
        ]
        soc_actions = [
            "P0 — Initiate active threat hunt across all EDR-enrolled endpoints for campaign IOCs — expand search window to 90 days minimum to account for typical APT dwell time (average 197 days at discovery)",
            "P0 — Implement firewall and DNS block rules for all infrastructure associated with this threat actor; review egress filtering for anomalous HTTPS traffic to unusual geographic regions",
            "P1 — Conduct privileged account audit: enumerate all domain admin, service account, and local administrator account creations or modifications in the past 90 days versus change management records",
            "P1 — Analyze east-west traffic for C2 beacon patterns: regular connection intervals, HTTPS to cloud storage providers in unexpected regions, high-volume DNS TXT queries from specific hosts",
            "P2 — Targeted forensic review of externally-facing systems (VPN concentrators, web applications, email gateways) for initial access artifacts and webshell presence",
            "P2 — Brief CISO and general counsel on nation-state attribution context and assess obligations for regulatory or government notification applicable to your sector (CISA reporting, sector-specific ISACs)",
        ]
        mssp_block = "MSSPs must distribute an emergency client advisory covering this APT campaign's confirmed TTPs within 2 hours. Activate threat hunting teams on high-value client environments — prioritize financial services, defense contractors, critical infrastructure operators, government agencies, and technology sector clients matching the threat actor's known targeting profile. CYBERDUDEBIVASH® SENTINEL APEX APT intelligence provides real-time campaign tracking, infrastructure pivot analysis, and multi-client exposure correlation."

    elif is_cve:
        mitre_techniques = [
            f"Initial Access → Exploit Public-Facing Application (T1190): {cve_str} exploitation targeting internet-exposed instances to achieve unauthenticated or pre-auth remote access",
            "Privilege Escalation → Exploitation for Privilege Escalation (T1068): Post-exploitation local privilege escalation to SYSTEM/root from initial low-privileged access context",
            "Lateral Movement → Exploitation of Remote Services (T1210): Internal lateral movement using the same vulnerability class against adjacent systems sharing the vulnerable component",
            "Persistence → Server Software Component: Web Shell (T1505.003): Installation of web shell or backdoor on compromised host for persistent re-entry without re-exploitation",
            "Defense Evasion → Indicator Removal (T1070): Log clearing and evidence destruction to impede forensic investigation and delay detection of initial access",
        ]
        sigma_logsource = "category: webserver"
        sigma_detection = f"""detection:
    exploit_uri:
        c-uri|contains:
            - '../'
            - '%2e%2e'
            - 'cmd.exe'
            - '/etc/passwd'
            - ';id;'
            - '|whoami'
        sc-status:
            - 200
            - 500
    webshell_access:
        c-uri|endswith:
            - '.php'
            - '.aspx'
            - '.jsp'
        cs-method: 'POST'
        sc-bytes|gt: 0
    condition: exploit_uri or webshell_access"""
        sigma_title = f"Web Application Exploitation — {cve_str} Payload and Web Shell Activity"
        sigma_tags = "    - attack.initial_access\n    - attack.t1190\n    - attack.t1505.003"
        hunt_queries = [
            f"Exploitation payload patterns — Web access logs for {cve_str}-specific payload signatures in URI parameters, POST body, or HTTP headers (consult vendor advisory for exact patterns)",
            "Web server spawning shells — EDR process tree for web server process (httpd, nginx, IIS w3wp.exe, Tomcat) spawning cmd.exe, powershell.exe, bash, or sh as child processes",
            "Web shell presence — File integrity monitoring for new .php/.aspx/.jsp/.war files created in web root directories outside of scheduled deployment windows",
            "Post-exploitation lateral movement — SIEM correlation for outbound connections originating from DMZ/web server hosts to internal RFC1918 ranges on management protocols (WMI/445/3389/22)",
            f"Exploitation attempt timeline — WAF and IDS/IPS logs for 30-day retroactive search for {cve_str} payload patterns to identify pre-patch exploitation activity",
        ]
        soc_actions = [
            f"P0 — Apply vendor patch for {cve_str} immediately on all affected instances; if patch unavailable within 4 hours, implement WAF virtual patching rule and restrict access to authenticated users only",
            "P0 — Retroactive search: query SIEM, WAF, and web logs for the past 30 days for exploitation payload patterns — assume potential pre-patch exploitation and treat as active incident until ruled out",
            "P1 — Hunt for post-exploitation artifacts: web shells in web root directories, anomalous child processes from web server, new service registrations or scheduled tasks created by web server process account",
            "P1 — Block exploitation payload patterns at WAF and IPS/IDS layers; update all detection platform signatures with vendor-provided indicators",
            "P2 — Conduct full vulnerability scan of adjacent systems sharing the vulnerable component; prioritize internet-facing assets for immediate patching",
            "P2 — If exploitation confirmed: engage IR team, preserve forensic evidence, and assess regulatory breach notification obligations based on data exposed on compromised systems",
        ]
        mssp_block = f"MSSPs must immediately assess all client attack surfaces for {cve_str} exposure using asset inventory cross-reference. Issue P1 priority advisory to all clients in healthcare, financial services, technology, and government sectors — sectors with the highest concentration of internet-facing vulnerable applications. Provide WAF virtual patching rules for clients unable to patch immediately. CYBERDUDEBIVASH® SENTINEL APEX KEV integration provides real-time CISA KEV tracking with automated client exposure scoring against asset inventories."

    elif is_ato:
        mitre_techniques = [
            "Credential Access → Brute Force: Credential Stuffing (T1110.004): Automated credential stuffing using leaked combo lists from prior data breaches against consumer-facing authentication endpoints",
            "Resource Development → Compromise Accounts (T1586.001): Acquisition and validation of email/password pairs from criminal underground marketplaces",
            "Resource Development → Acquire Infrastructure: Botnet (T1583.006): Use of residential proxy networks to distribute authentication requests across thousands of IP addresses, evading IP-based rate limiting",
            "Initial Access → Valid Accounts: Cloud Accounts (T1078.004): Authentication to victim accounts using validated credentials obtained via credential stuffing",
            "Collection → Data from Cloud Storage (T1530): Access to stored payment methods, personal data, and account balances from compromised accounts",
            "Impact → Financial Theft (T1657): Monetization of compromised accounts via fraudulent transactions, gift card purchases, or account resale on criminal storefronts",
        ]
        sigma_logsource = "category: webserver\n    product: any"
        sigma_detection = """detection:
    high_velocity_single_ip:
        c-ip|exists: true
        cs-uri-stem|contains: '/login'
        sc-status: 200
    timeframe: 1m
    condition: high_velocity_single_ip | count(c-ip) by c-ip > 30
    distributed_low_velocity:
        cs-uri-stem|contains: '/login'
        sc-status:
            - 200
            - 401
            - 403
    timeframe: 10m
    condition: distributed_low_velocity | count() > 500"""
        sigma_title = "Credential Stuffing Attack — High-Volume Authentication Against Login Endpoint"
        sigma_tags = "    - attack.credential_access\n    - attack.t1110.004\n    - attack.t1078"
        hunt_queries = [
            "Single-IP velocity anomaly — Web access logs for >20 authentication attempts per minute from any single IP against login endpoints",
            "Distributed credential stuffing — Authentication logs for >500 login attempts in 10 minutes distributed across >100 unique IPs with <10% success rate",
            "Residential proxy ASN patterns — Threat intelligence enrichment of authenticating IPs to identify residential proxy provider ASNs (Luminati/Bright Data, Oxylabs, SmartProxy)",
            "Successful ATO sessions — Post-authentication activity analysis for accounts showing unusual: password changes, email updates, payment method access within 30 minutes of login",
            "Account enumeration — Authentication logs for high volumes of 'account not found' errors indicating username enumeration phase of stuffing attack",
        ]
        soc_actions = [
            "P0 — Determine attack scale: pull authentication logs for past 24-72 hours, count total attempts, success rate, unique IPs, and affected account count",
            "P0 — Implement emergency rate limiting: block IPs exceeding 10 authentication attempts per minute; activate CAPTCHA for all login attempts if not already enforced",
            "P1 — Identify compromised accounts: flag accounts with successful logins from IPs included in the attack traffic; force password reset and session invalidation",
            "P1 — Block residential proxy ASN ranges at WAF if business impact is acceptable — use threat intelligence to identify proxy provider CIDR blocks",
            "P2 — Notify affected users per breach notification requirements (GDPR 72-hour window, state breach notification laws); document breach scope",
            "P2 — Engage fraud operations team to review and reverse unauthorized transactions from confirmed ATO accounts",
        ]
        mssp_block = "MSSPs should immediately assess client exposure to credential stuffing based on customer-facing authentication surfaces. Deploy velocity-based detection rules to client SIEMs covering per-IP and distributed patterns. Activate ATO-specific threat hunting hypotheses for clients in financial services, gaming, e-commerce, and healthcare sectors — highest-value targets for credential stuffing monetization. CYBERDUDEBIVASH® SENTINEL APEX ATO intelligence includes residential proxy ASN lists, combo list breach source correlation, and ATO detection Sigma rule packs."

    elif is_extension:
        mitre_techniques = [
            "Persistence → Browser Extensions (T1176): Malicious or compromised browser extension installed across enterprise endpoints providing persistent access to browser context",
            "Execution → Scripting: JavaScript (T1059.007): Extension executes arbitrary JavaScript in the context of web pages visited by the victim, enabling session manipulation",
            "Credential Access → Input Capture: Web Portal Capture (T1056.003): Extension intercepts form submissions and keystrokes on banking, SaaS, and enterprise web portals",
            "Credential Access → Steal Web Session Cookie (T1539): Extension reads authentication cookies from browser storage for session hijacking of authenticated sessions",
            "Man-in-the-Browser (T1185): Extension modifies web page DOM to inject scripts, capture form data, or redirect authentication flows",
            "Exfiltration → Exfiltration Over C2 Channel (T1041): Captured credentials and session tokens exfiltrated to attacker-controlled infrastructure via extension background service worker",
        ]
        sigma_logsource = "product: windows\n    category: registry_event"
        sigma_detection = """detection:
    extension_install:
        EventType: 'SetValue'
        TargetObject|contains:
            - '\\SOFTWARE\\Google\\Chrome\\Extensions\\'
            - '\\SOFTWARE\\Chromium\\Extensions\\'
            - '\\SOFTWARE\\Microsoft\\Edge\\Extensions\\'
        Details|contains: 'update_url'
    filter_enterprise_managed:
        TargetObject|contains: '\\SOFTWARE\\Policies\\'
    condition: extension_install and not filter_enterprise_managed
    network_beacon:
        Initiated: 'true'
        Image|endswith:
            - '\\chrome.exe'
            - '\\msedge.exe'
        DestinationPort:
            - 443
            - 80
        DestinationHostname|re: '.*\\.(?:tk|ml|ga|cf|gq|top|xyz|club|icu)$'
    condition: network_beacon"""
        sigma_title = "Suspicious Browser Extension Activity — Unmanaged Install or Anomalous Network Beacon"
        sigma_tags = "    - attack.persistence\n    - attack.t1176\n    - attack.t1539"
        hunt_queries = [
            "Extension inventory audit — Chrome/Edge management telemetry or registry enumeration for all installed extension IDs across managed endpoints",
            "Suspicious extension network traffic — Proxy/DNS logs for web requests originating from browser processes to recently registered domains or suspicious TLDs (.tk/.ml/.ga)",
            "Extension permission escalation — Chrome management logs or extension inventory for extensions requesting access to 'all URLs' (<all_urls>), tabs API, or cookies API",
            "BYOD unmanaged extensions — MDM/endpoint inventory for devices with browser extensions not present in organization's approved extension list",
            "Extension update anomalies — Browser update logs for extensions that silently updated version and simultaneously increased permission scope",
        ]
        soc_actions = [
            "P0 — Identify the specific extension ID(s) mentioned in the report across all managed endpoints using endpoint management or registry scan",
            "P0 — Determine if Chrome Enterprise Browser Management policies restrict extension installation — if not, this is an immediate policy gap requiring emergency remediation",
            "P1 — Force-remove the identified extension via Chrome/Edge enterprise policy (ExtensionInstallBlocklist) across all managed endpoints within 4 hours",
            "P1 — For BYOD endpoints without management control: communicate removal instructions to end users with deadline and compliance tracking",
            "P2 — Review proxy logs for network activity from browser processes to suspicious destinations during the extension's installed period",
            "P2 — Audit all enterprise extensions against an approved allowlist; block installation of extensions not on the allowlist via Browser Management policy",
        ]
        mssp_block = "MSSPs should immediately push browser extension inventory queries to all client endpoints — prioritizing financial services, healthcare, legal, and technology sector clients where browser access to sensitive SaaS portals (banking portals, EHR systems, legal management systems) creates the highest credential theft risk. For clients without Chrome Enterprise Browser Management or equivalent policy control, issue emergency advisory requiring immediate deployment. CYBERDUDEBIVASH® SENTINEL APEX browser extension threat intelligence provides malicious extension ID feeds, permission-abuse pattern detection, and enterprise browser hardening guidance."

    elif is_supply_chain:
        mitre_techniques = [
            "Initial Access → Supply Chain Compromise (T1195.002): Malicious code injected into legitimate software package distributed to downstream consumers",
            "Execution → Software Deployment Tools (T1072): Malicious package executed automatically during build pipeline dependency resolution or developer environment setup",
            "Persistence → Event Triggered Execution (T1546): Malicious install scripts or lifecycle hooks in compromised package execute on installation",
            "Defense Evasion → Masquerading (T1036): Package masquerades as legitimate open-source dependency or typosquats popular package names",
            "Collection → Data from Local System (T1005): Malicious package harvests environment variables, SSH keys, cloud credentials, and source code from developer environments",
            "Exfiltration → Exfiltration Over C2 Channel (T1041): Harvested secrets exfiltrated to attacker infrastructure during installation or first run",
        ]
        sigma_logsource = "product: linux\n    category: process_creation"
        sigma_detection = """detection:
    pkg_install_net:
        Image|endswith:
            - '/node'
            - '/python'
            - '/pip'
            - '/npm'
        CommandLine|contains:
            - 'install'
        NetworkConnection: 'true'
        DestinationIp|cidr:
            - '0.0.0.0/0'
    filter_known_registries:
        DestinationHostname|endswith:
            - 'registry.npmjs.org'
            - 'pypi.org'
            - 'files.pythonhosted.org'
    condition: pkg_install_net and not filter_known_registries"""
        sigma_title = "Package Manager Network Connection to Non-Registry Host During Install"
        sigma_tags = "    - attack.initial_access\n    - attack.t1195.002\n    - attack.t1059"
        hunt_queries = [
            "Malicious package install scripts — CI/CD pipeline logs for npm/pip install events that triggered outbound network connections to non-registry hosts",
            "Environment variable exfiltration — Process telemetry for package manager processes (node/python) making outbound DNS or HTTP requests containing 'AWS_', 'SECRET_', 'API_KEY' patterns",
            "Typosquat detection — Dependency manifest review across all projects for packages with names similar to popular libraries but with minor character differences",
            "Post-install script execution — Build system logs for packages that executed postinstall/setup.py scripts with network or file system activity",
            "Developer credential exposure — Secret scanning (git hooks, Trufflehog/GitLeaks) for environment variables or credential files present in build environments",
        ]
        soc_actions = [
            "P0 — Identify all systems that installed the affected package version: check package-lock.json, requirements.txt, and build logs across all repositories",
            "P0 — Rotate all secrets present on systems where the malicious package was installed: cloud credentials (AWS/Azure/GCP), API keys, SSH keys, JWT secrets",
            "P1 — Audit CI/CD pipeline logs for the affected package install timeframe — identify what data was accessible and whether exfiltration indicators exist",
            "P1 — Scan all repositories for the malicious package version in dependency manifests; enforce package version pinning in all projects",
            "P2 — Implement software composition analysis (SCA) in CI/CD pipeline to block builds with known-malicious package versions",
            "P2 — Review artifact repository (Artifactory/Nexus) proxying policies to enforce allowlisting of trusted package registries",
        ]
        mssp_block = "MSSPs should immediately scan client CI/CD environments and developer workstations for the affected package version. Issue advisory to all clients in software development, fintech, and technology sectors — highest exposure to supply chain attacks. CYBERDUDEBIVASH® SENTINEL APEX supply chain intelligence provides real-time malicious package feeds, CI/CD pipeline detection rules, and software composition analysis integration guidance."

    else:
        mitre_techniques = [
            "Initial Access → Phishing: Spearphishing Attachment (T1566.001) / Phishing Link (T1566.002): Social engineering via malicious email attachments or links as primary attack delivery mechanism",
            "Execution → User Execution: Malicious File (T1204.002): Victim-initiated execution of malicious document, script, or executable delivered via phishing or web-based delivery",
            "Defense Evasion → Obfuscated Files or Information (T1027): Payload obfuscation using encoding, encryption, or packing to evade signature-based antivirus and EDR detection",
            "Persistence → Registry Run Keys / Startup Folder (T1547.001): Persistence via Run key modification or startup folder placement for execution at system boot or user logon",
            "Exfiltration → Exfiltration Over C2 Channel (T1041): Data exfiltration channeled through the established C2 communication path to avoid triggering dedicated DLP/exfil detection",
        ]
        sigma_logsource = "product: windows\n    category: process_creation"
        sigma_detection = """detection:
    office_shell:
        ParentImage|endswith:
            - '\\outlook.exe'
            - '\\winword.exe'
            - '\\excel.exe'
            - '\\powerpnt.exe'
        Image|endswith:
            - '\\powershell.exe'
            - '\\cmd.exe'
            - '\\wscript.exe'
            - '\\mshta.exe'
    encoded_ps:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - 'FromBase64String'
    condition: office_shell or encoded_ps"""
        sigma_title = "Office Application Shell Spawn and Encoded PowerShell Execution"
        sigma_tags = "    - attack.execution\n    - attack.t1204.002\n    - attack.t1059.001"
        hunt_queries = [
            "Office application shell spawn — EDR parent-child process telemetry for Outlook/Word/Excel/PowerPoint spawning PowerShell, cmd.exe, wscript.exe, or mshta.exe",
            "Encoded PowerShell execution — EDR process command-line telemetry for PowerShell.exe invoked with -EncodedCommand, -enc, or FromBase64String parameters",
            "Unusual scheduled task creation — Windows Security Event ID 4698 for scheduled tasks created during or immediately after suspicious email delivery timeframe",
            "Registry run key modification — Sysmon Event ID 13 (RegistryEvent value set) for HKCU/HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run modifications by non-administrative processes",
            "Beaconing C2 communication — Proxy and DNS logs for regular-interval connections (±5 second jitter) from endpoint processes to external hosts immediately following malicious email delivery",
        ]
        soc_actions = [
            "P0 — Identify all endpoints that may have received or interacted with the threat delivery vector (email link/attachment); pull email gateway delivery logs and endpoint execution telemetry",
            "P1 — Block threat delivery indicators at email gateway, web proxy, and DNS resolver; push associated file hashes to EDR block list across all managed endpoints",
            "P1 — Search SIEM/EDR for the MITRE technique indicators above across all endpoints for the past 72 hours — extend to 14 days if initial triage suggests earlier delivery",
            "P2 — Validate detection rule coverage for identified MITRE ATT&CK techniques in primary SIEM; deploy Sigma rules above if gaps exist",
            "P2 — Update threat intelligence platform and internal IOC sharing channels with all confirmed indicators; ensure downstream detection tools have received updated feeds",
        ]
        mssp_block = "MSSPs should issue a client advisory within 2 hours covering detection logic and recommended compensating controls. Validate client SIEM detection coverage against the MITRE techniques identified. Push Sigma rules above to all client SIEM platforms. CYBERDUDEBIVASH® SENTINEL APEX provides automated MSSP intelligence briefing generation with client-specific exposure analysis and pre-built detection rule packages."

    mitre_html = "\n".join(f"<li>{t}</li>" for t in mitre_techniques)
    hunt_html = "\n".join(f"<li>{q}</li>" for q in hunt_queries)
    soc_html = "\n".join(f"<li>{a}</li>" for a in soc_actions)

    # Enterprise recommendations (phased, threat-specific)
    enterprise_recs = []
    enterprise_recs.append(f"<strong>Day 1–7 (Immediate):</strong> {soc_actions[0] if soc_actions else 'Conduct asset inventory to identify all affected systems and apply available vendor patch or compensating control'}")
    if is_ransomware:
        enterprise_recs.append("<strong>Day 8–30 (Short-term):</strong> Validate immutable backup architecture and test restoration procedures under simulated ransomware scenario; implement network micro-segmentation to limit blast radius of future encryption campaigns")
        enterprise_recs.append("<strong>Day 31–90 (Strategic):</strong> Conduct ransomware tabletop exercise with executive stakeholders; implement identity governance controls (PAM, MFA enforcement on all privileged accounts) to eliminate primary ransomware access vectors")
    elif is_apt:
        enterprise_recs.append("<strong>Day 8–30 (Short-term):</strong> Deploy behavioral detection rules to SIEM covering LOLBAS abuse, scheduled task anomalies, and LSASS access patterns; implement privileged access workstation (PAW) architecture for all domain administrator activities")
        enterprise_recs.append("<strong>Day 31–90 (Strategic):</strong> Assess zero-trust network architecture maturity; evaluate threat intelligence program to ensure continuous monitoring of nation-state TTPs relevant to your sector and geographic exposure")
    elif is_cve:
        enterprise_recs.append(f"<strong>Day 8–30 (Short-term):</strong> Conduct full vulnerability assessment of all {category} assets across the environment; implement vulnerability management SLA requiring all CRITICAL CVEs patched within 24 hours of NVD publication")
        enterprise_recs.append("<strong>Day 31–90 (Strategic):</strong> Integrate CISA KEV tracking with your vulnerability management platform; implement virtual patching capability (WAF rules) as a compensating control bridge between CVE disclosure and patch deployment")
    elif is_ot:
        enterprise_recs.append("<strong>Day 8–30 (Short-term):</strong> Engage ICS security specialist to assess current IT/OT network segmentation architecture; implement OT-specific network monitoring (Claroty/Dragos/Nozomi) if not already deployed")
        enterprise_recs.append("<strong>Day 31–90 (Strategic):</strong> Develop and exercise an OT-specific incident response plan distinct from IT IR playbooks; assess IEC 62443 compliance posture for industrial network security governance")
    elif is_ato:
        enterprise_recs.append("<strong>Day 8–30 (Short-term):</strong> Implement risk-based authentication scoring across all customer-facing portals; evaluate deployment of behavioral biometrics for high-value account actions (payment changes, address updates)")
        enterprise_recs.append("<strong>Day 31–90 (Strategic):</strong> Accelerate passwordless authentication migration for high-risk user populations; integrate breach credential monitoring (HaveIBeenPwned Enterprise, SpyCloud) to proactively identify compromised user credentials before ATO")
    elif is_supply_chain:
        enterprise_recs.append("<strong>Day 8–30 (Short-term):</strong> Deploy software composition analysis (SCA) tooling in all CI/CD pipelines; implement artifact repository with dependency proxying to control which package registry sources are permitted")
        enterprise_recs.append("<strong>Day 31–90 (Strategic):</strong> Develop software bill of materials (SBOM) capability for all production applications; implement package signing verification in build pipelines aligned with SLSA framework requirements")
    elif is_extension:
        enterprise_recs.append("<strong>Day 8–30 (Short-term):</strong> Deploy Chrome Enterprise Browser Management or equivalent; implement extension allowlist policy blocking all unreviewed extensions from installation on managed endpoints")
        enterprise_recs.append("<strong>Day 31–90 (Strategic):</strong> Evaluate enterprise browser security solution (Island, Talon, or vendor-managed browser) for high-risk user populations accessing sensitive SaaS applications from BYOD devices")
    else:
        enterprise_recs.append("<strong>Day 8–30 (Short-term):</strong> Validate SIEM detection coverage against all MITRE ATT&CK techniques identified in this report; deploy updated Sigma rules to close identified detection gaps across all managed endpoints")
        enterprise_recs.append("<strong>Day 31–90 (Strategic):</strong> Conduct tabletop exercise simulating this specific attack scenario with SOC and executive stakeholders; evaluate CYBERDUDEBIVASH® SENTINEL APEX for continuous threat intelligence integration to reduce detection gap windows")
    if is_ai:
        enterprise_recs.insert(0, "<strong>Immediate — AI Security:</strong> Audit all production AI/LLM deployments against OWASP LLM Top 10 and MITRE ATLAS framework; implement input validation and output filtering on all AI pipeline touchpoints before next deployment cycle")
    ent_html = "\n".join(f"<li>{r}</li>" for r in enterprise_recs)

    # IOC intelligence section — category-specific behavioral indicators
    if is_ransomware:
        ioc_behavioral = """<li><strong>Process behavioral IOC:</strong> Any process executing vssadmin.exe/wmic.exe with 'delete shadows' or 'shadowcopy delete' arguments — immediate triage required</li>
<li><strong>File system behavioral IOC:</strong> Mass file rename events (>100 files/minute) to unknown extensions from a single process — active encryption in progress</li>
<li><strong>Network behavioral IOC:</strong> SMB connections (port 445) from workstations to >15 unique internal hosts within 5 minutes — lateral movement phase</li>
<li><strong>DNS behavioral IOC:</strong> High-entropy domain queries or .onion proxy resolver connections from endpoints — C2 communication or ransom portal contact</li>
<li><strong>Registry behavioral IOC:</strong> Modifications to HKLM\\SYSTEM\\CurrentControlSet\\Services entries by non-SYSTEM processes — potential ransomware service persistence</li>"""
    elif is_apt:
        ioc_behavioral = """<li><strong>Process behavioral IOC:</strong> LOLBAS binaries (certutil.exe, mshta.exe, regsvr32.exe) establishing outbound network connections to non-Microsoft IP ranges</li>
<li><strong>Authentication behavioral IOC:</strong> Domain admin account logons from workstations (Event ID 4624 Type 3) during non-business hours or from previously unused source hosts</li>
<li><strong>Network behavioral IOC:</strong> Low-volume encrypted egress to cloud storage providers (AWS S3, Azure Blob, Google Drive) from servers not known to use these services</li>
<li><strong>DNS behavioral IOC:</strong> High-entropy subdomain strings in DNS queries (>30 chars) from workstations — potential DNS tunneling C2 channel</li>
<li><strong>Scheduled task behavioral IOC:</strong> New scheduled task creation (Event ID 4698) by non-SYSTEM accounts pointing to execution in %TEMP%, %APPDATA%, or unusual paths</li>"""
    elif is_ot:
        ioc_behavioral = """<li><strong>Network behavioral IOC:</strong> Connections from IT VLAN IP ranges to OT VLAN on industrial protocols — Modbus/502, S7comm/102, DNP3/20000, EtherNet/IP/44818</li>
<li><strong>Authentication behavioral IOC:</strong> IT user account credentials used to authenticate to OT HMI or engineering workstation systems outside scheduled maintenance windows</li>
<li><strong>OT process behavioral IOC:</strong> PLC parameter modifications or logic uploads outside of approved change management windows — requires OT historian/SCADA audit log review</li>
<li><strong>Remote access behavioral IOC:</strong> VPN or jump server sessions from IT administrators connecting to OT IP ranges during non-business hours or from unusual source geography</li>
<li><strong>OT network scanning behavioral IOC:</strong> Port scans targeting OT IP ranges originating from IT network — detected via IDS/IPS or network flow analysis on IT-OT boundary firewall</li>"""
    elif is_ato:
        ioc_behavioral = """<li><strong>Authentication velocity behavioral IOC:</strong> >20 authentication attempts per minute from a single IP against login endpoints — distributed per-IP below threshold but >500 total attempts in 10-minute window indicates distributed credential stuffing</li>
<li><strong>Proxy network behavioral IOC:</strong> Residential proxy ASN ranges authenticating at high volume — Luminati/Bright Data (AS58695), Oxylabs, SmartProxy networks are primary ATO infrastructure providers for bypassing IP rate limiting</li>
<li><strong>Account behavior behavioral IOC:</strong> Successful login followed within 30 minutes by password change, email address update, or payment method access from previously unused geographic region</li>
<li><strong>Session behavioral IOC:</strong> Multiple concurrent sessions for same account from distinct geographic regions or device fingerprints not matching account history — impossible travel scenario</li>
<li><strong>Enumeration behavioral IOC:</strong> High volume of 'account not found' (username enumeration) errors preceding a spike in successful authentications — indicates combo list validation phase before full stuffing wave</li>"""
    elif is_extension:
        ioc_behavioral = """<li><strong>Extension ID IOC:</strong> Presence of the specific extension ID in Chrome/Edge extension registry keys on managed endpoints — confirmed via registry scan or management platform query</li>
<li><strong>Network behavioral IOC:</strong> Browser process (chrome.exe/msedge.exe) establishing connections to recently registered domains or suspicious TLDs (.tk/.ml/.ga/.cf/.gq/.xyz) on port 443</li>
<li><strong>Permission behavioral IOC:</strong> Extension requesting access to <all_urls>, tabs API, cookies API, or webRequest API without corresponding enterprise policy authorization</li>
<li><strong>Update behavioral IOC:</strong> Extension version update event followed by immediate change in permission scope — silent permission escalation post-approval</li>
<li><strong>Data access behavioral IOC:</strong> Browser process reading cookie storage or form data immediately following navigation to authenticated SaaS portals (O365, Salesforce, banking portals)</li>"""
    elif is_supply_chain:
        ioc_behavioral = """<li><strong>Build pipeline IOC:</strong> Package manager process (node/python/pip/npm) establishing outbound network connections to non-registry hosts during package install phase</li>
<li><strong>Environment variable IOC:</strong> Process spawned by package install script making outbound HTTP/DNS requests containing patterns matching 'AWS_', 'SECRET_KEY', 'API_KEY', 'GITHUB_TOKEN'</li>
<li><strong>File system IOC:</strong> Unexpected files written to ~/.ssh, ~/.aws, ~/.config directories during package installation — potential credential harvesting</li>
<li><strong>Dependency manifest IOC:</strong> Package name with character substitution vs. known popular packages (typosquatting) — e.g., 'requets' vs 'requests', 'colourama' vs 'colorama'</li>
<li><strong>CI/CD pipeline IOC:</strong> Build job timing anomaly — significantly longer execution time than baseline during dependency installation phase indicates potential malicious script execution</li>"""
    else:
        ioc_behavioral = """<li><strong>Email delivery IOC:</strong> Sender domain registered within past 30 days, mismatched Reply-To domain, or use of free email service to impersonate enterprise domains</li>
<li><strong>Process behavioral IOC:</strong> Office applications (Outlook, Word, Excel) spawning PowerShell, cmd.exe, wscript.exe, or mshta.exe as child processes following email attachment open</li>
<li><strong>Network behavioral IOC:</strong> Outbound connections from endpoints to domains registered <30 days ago or to hosting providers with high abuse rates (bulletproof hosting ASNs)</li>
<li><strong>Registry persistence IOC:</strong> Modifications to HKCU/HKLM Run keys by non-administrative processes or from Office application execution context</li>
<li><strong>DNS behavioral IOC:</strong> Rapid succession of DNS queries to high-entropy subdomains from a single endpoint immediately following user interaction with suspicious content</li>"""

    # AI security section
    ai_section = ""
    if is_ai:
        ai_section = """
<h3>AI Security Impact</h3>
<p>This threat has direct operational implications for enterprise AI and LLM deployments. Organizations running large language models, AI agents, RAG pipelines, or AI-powered security tooling must assess their exposure across multiple attack surfaces.</p>
<p>Primary AI security risk vectors to evaluate against this threat: <strong>LLM01 (Prompt Injection)</strong> — adversarial input via data sources consumed by AI pipelines; <strong>LLM06 (Sensitive Information Disclosure)</strong> — training data or retrieval context exposure via crafted queries; <strong>LLM08 (Excessive Agency)</strong> — agentic AI systems with tool-use capabilities that can be leveraged post-compromise; <strong>LLM10 (Model Theft)</strong> — exfiltration of fine-tuned model weights or proprietary training data.</p>
<p>Reference frameworks: OWASP LLM Top 10 2025, MITRE ATLAS (Adversarial Threat Landscape for AI Systems), NIST AI RMF 1.0. CYBERDUDEBIVASH® AI Security Hub provides enterprise AI security assessments, adversarial red teaming, and AI governance program development.</p>
"""

    # Long-term strategic risk — category-specific
    if is_ransomware:
        long_term_risk = "The ransomware ecosystem is maturing toward Ransomware-as-a-Service (RaaS) affiliate models with specialized initial access brokers (IABs) separating access acquisition from ransomware deployment. Triple-extortion tactics — encryption, data leak, and DDoS against victim or customers — are becoming standard across major ransomware groups. Organizations must transition from reactive patch-driven defenses to intelligence-driven prevention: continuous threat actor tracking, pre-disclosure vulnerability prioritization, and automated SIEM rule deployment against emerging TTPs."
    elif is_apt:
        long_term_risk = "Nation-state threat actors are demonstrating sustained operational patience — median dwell time at discovery averages 197 days (Mandiant M-Trends). The strategic threat is pre-positioning for intellectual property theft, critical infrastructure disruption, and potential kinetic operation support. Organizations in targeted sectors must operate on assumption-of-breach principles: continuous behavioral monitoring, privileged access governance, and zero-trust network architectures that limit blast radius of persistent implants."
    elif is_cve:
        long_term_risk = f"The window between CVE publication and weaponization continues to compress — threat actors are demonstrating exploitation capability within hours of CVE disclosure for high-value targets. Vulnerabilities like {cve_str} represent the most efficient initial access vector available. Organizations must integrate real-time CISA KEV tracking with automated asset-to-vulnerability correlation to operationalize patch prioritization before weaponization, not after. CYBERDUDEBIVASH® SENTINEL APEX KEV correlation provides risk scoring against your specific asset inventory at time of CVE publication."
    elif is_ot:
        long_term_risk = "OT/ICS targeting has expanded beyond energy and utilities to food, agriculture, water, and manufacturing sectors — any operator of time-critical production processes is now a viable target for disruption campaigns. The convergence of IT and OT networks has dramatically expanded the attack surface while OT systems remain on decade-long replacement cycles with minimal patching cadence. Sector-specific threat intelligence (CISA ICS-CERT advisories, Dragos Year in Review) indicates threat actor capability development against ICS-specific protocols is accelerating."
    elif is_ato:
        long_term_risk = "Account takeover economics are improving for attackers as credential combo lists become larger and cheaper, residential proxy infrastructure becomes more accessible, and AIO tooling (OpenBullet/SilverBullet) lowers technical barriers. Sectors with high-value accounts — financial services, gaming, healthcare, and e-commerce — face escalating ATO volumes. The most effective long-term defense is eliminating password-based authentication: FIDO2/passkey adoption removes the fundamental prerequisite for credential stuffing attacks."
    elif is_supply_chain:
        long_term_risk = "Software supply chain attacks represent the highest-leverage attack vector available to sophisticated threat actors — compromising a single widely-used package or build tool reaches thousands of downstream organizations simultaneously. Regulatory pressure (NIST SSDF, EO 14028, EU Cyber Resilience Act) is driving mandatory SBOM requirements and software supply chain security standards. Organizations that build proactive software composition analysis and SBOM generation capability now will be positioned to meet compliance requirements and reduce exposure as the threat vector continues to mature."
    elif is_extension:
        long_term_risk = "Browser extensions represent an undermonitored attack surface in enterprise security programs — most organizations have no visibility into which extensions are installed on managed endpoints, and zero visibility on BYOD. As enterprise operations increasingly run through browser-based SaaS applications, the browser becomes the most privileged execution context accessible to an attacker without requiring endpoint compromise. Enterprise browser security (managed browser deployment, extension governance, in-browser DLP) will become a standard security control tier alongside EDR and SASE."
    else:
        long_term_risk = "The threat landscape is accelerating toward AI-augmented attacks — automated reconnaissance, AI-generated phishing at scale, and AI-assisted vulnerability discovery are compressing the time from threat emergence to exploitation. Organizations that rely on periodic threat briefings and signature-based defenses will consistently lag attacker velocity. Intelligence-driven security operations — continuous behavioral monitoring, pre-disclosure threat intelligence, and automated detection deployment — represent the required evolution. CYBERDUDEBIVASH® SENTINEL APEX provides the intelligence layer to close this gap."

    # Pre-compute strings that contain backslashes (can't use in f-string expressions)
    _chrome_reg = r"HKCU/HKLM\SOFTWARE\Google\Chrome\Extensions"
    _ext_li = f'<li><strong>Browser extension telemetry:</strong> Chrome/Edge extension inventory from registry ({_chrome_reg}) via endpoint management; Chrome Enterprise Browser Management audit logs if deployed</li>' if is_extension else ''
    _cve_li = '<li><strong>Web application logs:</strong> Full URI with parameters, HTTP method, response code, response body size, and client IP — required for exploitation attempt detection and post-exploitation web shell activity identification</li>' if is_cve else ''
    _ato_li = '<li><strong>Authentication logs:</strong> Web application login events with IP, user agent, geolocation, and result — aggregated across all customer-facing authentication endpoints; requires correlation across sessions to detect distributed low-velocity attacks</li>' if is_ato else ''
    _cicd_li = '<li><strong>CI/CD pipeline logs:</strong> Package installation events with dependency resolution trace; build job timing anomalies; network connections made during build phase</li>' if is_supply_chain else ''
    _ot_li = '<li><strong>OT network monitoring:</strong> Industrial protocol analysis (Modbus, S7comm, DNP3) from network tap on IT-OT boundary switch — requires OT-aware network monitoring tool (Dragos, Claroty, Nozomi)</li><li><strong>OT endpoint telemetry:</strong> Windows Event Logs from HMI systems and OT engineering workstations — enable audit process creation (4688) with command-line logging</li><li><strong>OT historian/SCADA audit logs:</strong> Configuration change audit trail for PLC parameter modifications and logic uploads outside approved windows</li>' if is_ot else '<li><strong>Windows Security Events:</strong> ID 4688 (process creation with full command-line logging), 4698 (scheduled task creation), 4624/4625 (auth success/failure), 4672 (special privileges assigned)</li><li><strong>EDR/XDR Telemetry:</strong> Process tree with parent-child relationships, file system events, registry modifications (Sysmon Event ID 13), network connection events</li><li><strong>Network telemetry:</strong> DNS query logs (all query types), proxy/web gateway logs, NetFlow/PCAP from network choke points</li>'
    _ics_ref = '<li>MITRE ATT&CK for ICS — <a href="https://attack.mitre.org/matrices/ics/" target="_blank" rel="noopener">https://attack.mitre.org/matrices/ics/</a></li>' if is_ot else ''
    _ai_ref = '<li>OWASP LLM Top 10 — <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" target="_blank" rel="noopener">https://owasp.org/www-project-top-10-for-large-language-model-applications/</a></li>' if is_ai else ''
    _nvd_refs = ''.join(f'<li>NVD — {cve} — <a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank" rel="noopener">https://nvd.nist.gov/vuln/detail/{cve}</a></li>' for cve in cves) if cves else '<li>NIST National Vulnerability Database — <a href="https://nvd.nist.gov" target="_blank" rel="noopener">https://nvd.nist.gov</a></li>'
    _cve_analysis = ('<ul>' + '\n'.join(f'<li><strong>{cve}</strong> — {category} vulnerability. CVSS: {cvss_str}. Monitor NVD entry at https://nvd.nist.gov/vuln/detail/{cve} and vendor security advisory for authoritative CVSS vector string, affected version range, and patch availability.</li>' for cve in cves) + '</ul>') if cves else ''
    _cisa_sentence = 'CISA has added this to the Known Exploited Vulnerabilities catalog, imposing mandatory patching deadlines for U.S. federal agencies.' if (is_patch and 'cisa' in text) else 'CYBERDUDEBIVASH® SENTINEL APEX has classified this as a priority intelligence item requiring immediate defensive action.'
    _cve_facts = (f'<li>CVE identifiers: {", ".join(cves)} — extracted from article content</li>' + '\n') if cves else ''
    _cvss_fact = (f'<li>CVSS score: {cvss} — extracted from article or vendor advisory</li>' + '\n') if cvss else ''
    _cvss_severity = f'based on CVSS score {cvss}' if cvss else 'based on threat category, exploitation status, and operational impact assessment'
    _patch_fact = '<li>Patch availability confirmed: vendor or CISA advisory references patch or required action</li>' if is_patch else '<li>Patch availability: unconfirmed at time of report generation — monitor vendor advisory channel</li>'
    _cvss_header = f'  |  CVSS {cvss}' if cvss else ''
    _exploit_confidence = 'Actively exploited in the wild — CISA KEV inclusion or vendor confirmation (HIGH CONFIDENCE)' if is_patch else 'Technical details sufficient for exploitation — weaponization timeline estimated 24-72 hours post-PoC publication (MEDIUM CONFIDENCE)'
    _impact_text = 'Operational disruption, data encryption, ransom demand, potential double-extortion data leak' if is_ransomware else ('Production system disruption, perishable goods spoilage, supply chain continuity impact' if is_ot else ('Unauthorized account access, financial fraud, identity theft, regulatory breach notification obligation' if is_ato else 'Unauthorized access, privilege escalation, potential data exfiltration'))
    _prevalence_text = 'Widespread ransomware campaign with multiple victims across sector' if is_ransomware else ('Targeted exploitation — organizations matching the threat actor known targeting profile' if is_apt else f'Broad exposure — all organizations running affected {category} systems')
    _patch_status_text = 'Emergency patch available — deploy immediately' if is_patch else 'Monitor vendor advisory channel; implement compensating controls immediately pending patch availability'
    _ot_classification = 'Operational technology and industrial control system targeting with direct production impact risk.' if is_ot else 'Enterprise IT environment threat with potential for data loss, operational disruption, or financial impact.'
    _exploit_status = 'Exploitation is confirmed active based on CISA KEV inclusion or public exploitation reporting (HIGH CONFIDENCE).' if is_patch else 'Active exploitation status is unconfirmed at time of publication — assess as pre-exploitation risk (MEDIUM CONFIDENCE).'
    _attribution_note = 'Threat actor category identified based on TTPs and campaign characteristics described in source material.' if (is_ransomware or is_apt) else 'Attribution to specific threat actors has not been confirmed in the source material — analyst assessment and sector context are the basis for any attribution statements in this report (LOW CONFIDENCE).'
    _business_impact = (
        'Ransomware encryption of production systems carries average recovery costs exceeding $1.85M (Sophos State of Ransomware 2024) excluding reputational damage and regulatory penalty exposure. GDPR Article 33 requires breach notification within 72 hours; NIS2 Directive extends mandatory reporting to a broader set of critical sectors.' if is_ransomware else
        'Nation-state APT intrusions carry costs averaging $4.4M per breach (IBM Cost of a Data Breach Report) in addition to strategic IP loss, regulatory penalties under GDPR (up to 4% global annual revenue), NIS2, DORA, and sector-specific regulations. Government notification obligations under CISA binding operational directives and sector ISAC frameworks may apply depending on sector classification.' if is_apt else
        'OT disruption to industrial production carries operational downtime costs averaging $500K per hour in manufacturing sectors, food safety liability, supply chain continuity failure, and mandatory CISA ICS-CERT and sector regulator notification obligations. FDA, USDA, and EU NIS2 critical infrastructure requirements impose specific incident reporting timelines.' if is_ot else
        'Credential stuffing ATO incidents carry average costs of $290K per incident (Ponemon Institute) including fraud remediation, breach notification, and regulatory fines. GDPR Article 83 fines up to €20M or 4% of global annual revenue apply if personal data is accessed. PCI-DSS 4.0 Section 8 requires MFA for all account access — non-compliance creates direct audit liability.' if is_ato else
        f'Organizations with unpatched exposure to {cve_str} face unauthorized access, data exfiltration, and regulatory enforcement under GDPR (up to 4% global annual revenue), NIS2, DORA, or SOC 2 audit findings.'
    )
    _ot_para = '<p>Operational technology environments face elevated risk due to the combination of legacy systems with extended patching cycles, limited network segmentation between IT and OT networks, and the operational sensitivity of production disruption that may incentivize ransom payment or prevent proper incident containment.</p>' if is_ot else ''
    _ato_para = '<p>Credential stuffing operations rely on the reuse of username/password pairs from prior data breaches — victims are compromised through no fault of their current security posture. The attack succeeds entirely because of credential reuse across services, making MFA enforcement the single highest-efficacy defensive control available.</p>' if is_ato else ''

    # Executive decision matrix
    exec_matrix_rows = ""
    if is_ransomware:
        exec_matrix_rows = """<tr><td>P0</td><td>Authorize emergency host isolation for confirmed/suspected infected systems</td><td>CISO / SOC Lead</td><td>Immediate</td></tr>
<tr><td>P0</td><td>Verify immutable backup availability and authorize test restoration</td><td>IT Operations / CISO</td><td>Within 2 hours</td></tr>
<tr><td>P1</td><td>Activate incident response retainer and engage external IR firm</td><td>CISO / General Counsel</td><td>Within 4 hours</td></tr>
<tr><td>P1</td><td>Assess regulatory breach notification obligations and prepare notification draft</td><td>Legal / Privacy Officer</td><td>Within 24 hours</td></tr>
<tr><td>P2</td><td>Board notification: assess cyber insurance claim initiation</td><td>CEO / CFO / CISO</td><td>Within 48 hours</td></tr>"""
    elif is_apt:
        exec_matrix_rows = """<tr><td>P0</td><td>Authorize 90-day retroactive threat hunt across all EDR-enrolled endpoints</td><td>CISO / Threat Intel Lead</td><td>Immediate</td></tr>
<tr><td>P1</td><td>Assess whether affected systems host regulated data requiring government notification</td><td>Legal / Compliance</td><td>Within 24 hours</td></tr>
<tr><td>P1</td><td>Evaluate whether sector ISAC notification is appropriate for intelligence sharing</td><td>CISO</td><td>Within 48 hours</td></tr>
<tr><td>P2</td><td>Authorize engagement of external attribution/forensics specialist if compromise confirmed</td><td>CISO / CEO</td><td>Within 72 hours</td></tr>"""
    elif is_cve:
        exec_matrix_rows = f"""<tr><td>P0</td><td>Authorize emergency patching of {cve_str} — override change management freeze if required</td><td>CISO / IT Operations</td><td>Immediate</td></tr>
<tr><td>P0</td><td>Authorize WAF virtual patching deployment if patch is not available within 4 hours</td><td>CISO / Security Architect</td><td>Within 4 hours</td></tr>
<tr><td>P1</td><td>Authorize retroactive log review to determine if pre-patch exploitation occurred</td><td>CISO / SOC Lead</td><td>Within 24 hours</td></tr>
<tr><td>P2</td><td>Assess whether asset inventory process needs improvement to accelerate future CVE exposure identification</td><td>CISO / VP Engineering</td><td>Within 30 days</td></tr>"""
    elif is_ot:
        exec_matrix_rows = """<tr><td>P0</td><td>Confirm production system status — assess if emergency production shutdown is required</td><td>Operations Director / CISO</td><td>Immediate</td></tr>
<tr><td>P0</td><td>Verify IT/OT network boundary controls are intact — validate firewall rules between IT and OT VLANs</td><td>IT Security / OT Engineering</td><td>Within 2 hours</td></tr>
<tr><td>P1</td><td>Engage ICS security specialist for OT forensic assessment if intrusion indicators found</td><td>CISO</td><td>Within 24 hours</td></tr>
<tr><td>P1</td><td>Assess CISA ICS-CERT and sector regulator notification obligations for OT security incidents</td><td>Legal / CISO</td><td>Within 48 hours</td></tr>
<tr><td>P2</td><td>Authorize ICS security assessment program and network monitoring tool deployment in OT environment</td><td>CISO / COO</td><td>Within 90 days</td></tr>"""
    else:
        exec_matrix_rows = """<tr><td>P0</td><td>Authorize SOC activation and threat detection rule deployment for this threat type</td><td>CISO / SOC Lead</td><td>Immediate</td></tr>
<tr><td>P1</td><td>Assess user population exposure to this threat vector and authorize targeted user communication</td><td>CISO / Communications</td><td>Within 24 hours</td></tr>
<tr><td>P1</td><td>Evaluate regulatory notification obligations if user data may be at risk</td><td>Legal / Privacy Officer</td><td>Within 48 hours</td></tr>
<tr><td>P2</td><td>Authorize detection engineering investment to close identified SIEM coverage gaps</td><td>CISO / Security Engineering</td><td>Within 30 days</td></tr>"""

    # Predictive intelligence — confidence-labeled
    if is_ransomware:
        predictive = "<p><strong>Campaign continuation (HIGH CONFIDENCE):</strong> Ransomware groups maintain active operations between public disclosures — affected organizations not yet encrypted remain at elevated risk for 30-60 days following initial campaign reporting.</p><p><strong>Sector expansion (MEDIUM CONFIDENCE):</strong> If initial targeting yields successful outcomes, ransomware operators historically expand targeting to adjacent sector verticals within 60-90 days of initial campaign success.</p><p><strong>Affiliate TTPs evolution (MEDIUM CONFIDENCE):</strong> RaaS affiliate programs rapidly incorporate newly published vulnerability exploits as initial access vectors — monitor CISA KEV for vulnerabilities relevant to your attack surface immediately following any ransomware campaign disclosure.</p>"
    elif is_apt:
        predictive = "<p><strong>Ongoing access maintenance (HIGH CONFIDENCE):</strong> Nation-state actors with established footholds rotate infrastructure and implants on 30-60 day cycles to survive IOC-based defenses — confirmed IOC blocks provide limited protection without behavioral detection capability.</p><p><strong>Campaign scope expansion (MEDIUM CONFIDENCE):</strong> APT campaigns typically expand to additional targets in the same sector or supply chain after initial success — organizations in the same sector should treat this as direct targeting risk regardless of confirmed victim identity.</p><p><strong>Attribution stability (LOW CONFIDENCE):</strong> Technical attribution to specific nation-state actors based on public reporting carries inherent uncertainty — false flag operations and shared tooling between groups are documented phenomena that limit high-confidence attribution.</p>"
    elif is_cve:
        predictive = f"<p><strong>Active exploitation escalation (HIGH CONFIDENCE):</strong> Based on historical patterns for vulnerabilities in this class, {cve_str} will be incorporated into exploit kits and automated scanning tools within 72 hours of PoC publication, dramatically expanding the threat actor population able to exploit it.</p><p><strong>CISA KEV addition (MEDIUM CONFIDENCE):</strong> Vulnerabilities actively exploited in the wild with public PoC availability are added to CISA KEV within 7-14 days of confirmed exploitation — monitor KEV for mandatory patching deadline implications.</p><p><strong>RaaS initial access broker adoption (MEDIUM CONFIDENCE):</strong> High-CVSS network-exploitable vulnerabilities are routinely adopted by ransomware initial access brokers within 30 days of public exploit availability.</p>"
    else:
        predictive = "<p><strong>Threat vector persistence (MEDIUM CONFIDENCE):</strong> Based on the attack methodology described, this threat vector is likely to remain active for the next 60-90 days as threat actors exhaust the target population or shift to alternative delivery mechanisms.</p><p><strong>Detection evasion evolution (MEDIUM CONFIDENCE):</strong> Threat actors actively monitor public detection rule releases and typically modify malware signatures within 24-48 hours of public Sigma/YARA rule publication to evade new detections.</p><p><strong>Targeting scope (LOW CONFIDENCE):</strong> Without confirmed attribution or explicit campaign scope disclosure in the source material, targeting scope projection carries significant uncertainty — maintain standard monitoring posture while avoiding over-scoping defensive response.</p>"

    return f"""
<h3>Executive Summary</h3>
<p>{article.summary[:350].rstrip('.')}. This represents a <strong>{severity}</strong>-severity threat ({cvss_str} risk profile) requiring immediate evaluation by SOC and vulnerability management teams. {'CISA has added this to the Known Exploited Vulnerabilities catalog, imposing mandatory patching deadlines for U.S. federal agencies.' if is_patch and 'cisa' in text else 'CYBERDUDEBIVASH® SENTINEL APEX has classified this as a priority intelligence item requiring immediate defensive action.'}</p>

<h3>Verified Facts</h3>
<ul>
<li>Threat type: {category} — derived from article classification and content analysis</li>
{'<li>CVE identifiers: ' + ', '.join(cves) + ' — extracted from article content</li>' if cves else ''}
{'<li>CVSS score: ' + cvss + ' — extracted from article or vendor advisory</li>' if cvss else ''}
<li>Severity classification: {severity} — {'based on CVSS score ' + cvss if cvss else 'based on threat category, exploitation status, and operational impact assessment'}</li>
{'<li>Patch availability confirmed: vendor or CISA advisory references patch or required action</li>' if is_patch else '<li>Patch availability: unconfirmed at time of report generation — monitor vendor advisory channel</li>'}
</ul>

<h3>Threat Classification</h3>
<p>Threat type: <strong>{category}</strong>. {'Operational technology and industrial control system targeting with direct production impact risk.' if is_ot else 'Enterprise IT environment threat with potential for data loss, operational disruption, or financial impact.'} {'Exploitation is confirmed active based on CISA KEV inclusion or public exploitation reporting (HIGH CONFIDENCE).' if is_patch else 'Active exploitation status is unconfirmed at time of publication — assess as pre-exploitation risk (MEDIUM CONFIDENCE).'} {'Attribution to specific threat actors has not been confirmed in the source material — analyst assessment and sector context are the basis for any attribution statements in this report (LOW CONFIDENCE).' if not is_ransomware and not is_apt else 'Threat actor category identified based on TTPs and campaign characteristics described in source material.'}</p>

<h3>Threat Severity Assessment</h3>
<p><strong>Severity: {severity}</strong>{'  |  CVSS ' + cvss if cvss else ''}</p>
<ul>
<li><strong>Exploitability:</strong> {'Actively exploited in the wild — CISA KEV inclusion or vendor confirmation (HIGH CONFIDENCE)' if is_patch else 'Technical details sufficient for exploitation — weaponization timeline estimated 24-72 hours post-PoC publication (MEDIUM CONFIDENCE)'}</li>
<li><strong>Impact:</strong> {'Operational disruption, data encryption, ransom demand, potential double-extortion data leak' if is_ransomware else ('Production system disruption, perishable goods spoilage, supply chain disruption' if is_ot else ('Unauthorized account access, financial fraud, identity theft, regulatory breach' if is_ato else 'Unauthorized access, privilege escalation, potential data exfiltration'))}</li>
<li><strong>Prevalence:</strong> {_prevalence_text}</li>
<li><strong>Patch/remediation status:</strong> {'Emergency patch available — deploy immediately' if is_patch else 'Monitor vendor advisory channel; implement compensating controls immediately pending patch availability'}</li>
</ul>

<h3>Business Impact</h3>
<p>{_business_impact}</p>
<p>Risk quantification requires correlation of this threat against your specific asset inventory, data classification, and regulatory obligations — standard CVSS scores reflect technical severity, not business impact to your specific environment.</p>

<h3>Technical Analysis</h3>
<p>{article.summary[:800]}</p>
{'<p>Operational technology environments face elevated risk due to the combination of legacy systems with extended patching cycles, limited network segmentation between IT and OT networks, and the operational sensitivity of production disruption that may incentivize ransom payment or prevent proper incident containment.</p>' if is_ot else ''}
{'<p>Credential stuffing operations rely on the reuse of username/password pairs from prior data breaches — victims are compromised through no fault of their current security posture. The attack succeeds entirely because of credential reuse across services, making MFA enforcement the single highest-efficacy defensive control available.</p>' if is_ato else ''}

<h3>CVE Analysis</h3>
{'<ul>' + chr(10).join(f'<li><strong>{cve}</strong> — {category} vulnerability. CVSS: {cvss_str}. Monitor NVD entry at https://nvd.nist.gov/vuln/detail/{cve} and vendor security advisory for authoritative CVSS vector string, affected version range, and patch availability.</li>' for cve in cves) + '</ul>' if cves else ''}

<h3>MITRE ATT&CK Mapping</h3>
<ul>
{mitre_html}
</ul>

<h3>IOC Intelligence</h3>
<p>No confirmed public IOCs were published in this intelligence item at time of report generation. {'Behavioral IOCs applicable to this threat type for defensive hunting:' if True else ''}</p>
<ul>
{ioc_behavioral}
</ul>

<h3>Detection Engineering Guidance</h3>
<p>Primary log sources and telemetry required for detection coverage against this threat:</p>
<ul>
{'<li><strong>OT network monitoring:</strong> Industrial protocol analysis (Modbus, S7comm, DNP3) from network tap or span on IT-OT boundary switch — requires OT-aware network monitoring tool (Dragos, Claroty, Nozomi, or Darktrace OT)</li><li><strong>OT endpoint telemetry:</strong> Windows Event Logs from HMI systems and OT engineering workstations — enable audit process creation (4688) with command-line logging and audit account logon events (4624, 4625)</li><li><strong>OT historian/SCADA audit logs:</strong> Configuration change audit trail from SCADA platform for PLC parameter modifications, logic uploads, and setpoint changes outside approved windows</li>' if is_ot else '<li><strong>Windows Security Events:</strong> ID 4688 (process creation with full command-line logging — requires audit policy enforcement), 4698 (scheduled task creation), 4624/4625 (auth success/failure), 4672 (special privileges assigned)</li><li><strong>EDR/XDR Telemetry:</strong> Process tree with parent-child relationships, file system events (create/rename/delete), registry modifications (Sysmon Event ID 13), network connection events</li><li><strong>Network telemetry:</strong> DNS query logs (all query types including TXT/NULL for tunneling detection), proxy/web gateway logs with full URL logging, NetFlow/PCAP from north-south and east-west choke points</li>'}
{'<li><strong>Web application logs:</strong> Full URI with parameters, HTTP method, response code, response body size, and client IP — required for exploitation attempt detection and post-exploitation web shell activity identification</li>' if is_cve else ''}
{'<li><strong>Authentication logs:</strong> Web application login events with IP, user agent, geolocation, and result — aggregated across all customer-facing authentication endpoints; requires correlation across sessions to detect distributed low-velocity attacks</li>' if is_ato else ''}
{_ext_li}
{'<li><strong>CI/CD pipeline logs:</strong> Package installation events with dependency resolution trace; build job timing anomalies; network connections made during build phase</li>' if is_supply_chain else ''}
<li><strong>Cloud telemetry:</strong> CloudTrail/Azure Activity Logs/GCP Audit Logs for IAM changes, unusual API calls, resource creation in non-standard regions, and data access patterns</li>
</ul>

<h3>Sigma Rules</h3>
<pre><code>title: {sigma_title}
id: cdb-sentinel-apex-{datetime.now(timezone.utc).strftime('%Y%m%d')}-001
status: experimental
description: >
  Detects {sigma_title.lower()}.
  CYBERDUDEBIVASH® SENTINEL APEX Detection Engineering — validate against
  your environment before production deployment; tune false positive thresholds.
references:
    - {article.url}
    - https://blog.cyberdudebivash.in
    - https://intel.cyberdudebivash.com
author: CYBERDUDEBIVASH® SENTINEL APEX Detection Engineering
date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}
tags:
{sigma_tags}
logsource:
    {sigma_logsource}
{sigma_detection}
falsepositives:
    - Legitimate administrative activity — correlate with change management records before escalating
    - Security testing or red team exercises — coordinate with security team schedule
level: high
</code></pre>

<h3>Threat Hunting Queries</h3>
<ul>
{hunt_html}
</ul>

<h3>SOC Analyst Playbook</h3>
<ul>
{soc_html}
</ul>

<h3>Executive Decision Matrix</h3>
<table>
<tr><th>Priority</th><th>Decision Required</th><th>Owner</th><th>Timeline</th></tr>
{exec_matrix_rows}
</table>

<h3>Executive Recommendations</h3>
<ul>
{ent_html}
</ul>

<h3>Predictive Intelligence</h3>
{predictive}

<h3>MSSP Opportunities</h3>
<p>{mssp_block}</p>

<h3>Sentinel APEX Intelligence Correlation</h3>
<p>CYBERDUDEBIVASH® SENTINEL APEX provides automated detection and correlation for this threat class across the following platform capabilities:</p>
<ul>
<li><strong>Live CVE & KEV Tracking:</strong> Real-time NVD, CISA KEV, and vendor advisory monitoring with CVSS-weighted client exposure scoring against live asset inventory</li>
<li><strong>MITRE ATT&CK Correlation Engine:</strong> Automated technique mapping with detection gap analysis benchmarked against your current SIEM rule coverage and ATT&CK Navigator heatmap</li>
<li><strong>IOC Intelligence Feed:</strong> Real-time IOC enrichment (IPs, domains, hashes) from 40+ threat intelligence sources including commercial feeds, ISAC sharing, and dark web monitoring</li>
<li><strong>Sigma & YARA Rule Library:</strong> 2,400+ production-ready detection rules optimized for Splunk, Elastic Security, Microsoft Sentinel, Chronicle, and QRadar — updated within 24 hours of new threat disclosure</li>
<li><strong>Threat Hunting Workbench:</strong> Pre-built hunt hypotheses with SIEM-native queries for every major threat category, updated against current campaign TTPs</li>
</ul>
<p><a href="https://intel.cyberdudebivash.com" target="_blank" rel="noopener">Launch SENTINEL APEX →</a></p>
{ai_section}
<h3>Long-Term Strategic Risk</h3>
<p>{long_term_risk}</p>

<h3>References</h3>
<ul>
<li>Source Article — <a href="{article.url}" target="_blank" rel="noopener">{article.url}</a></li>
<li>MITRE ATT&amp;CK Enterprise Matrix — <a href="https://attack.mitre.org" target="_blank" rel="noopener">https://attack.mitre.org</a></li>
{_ics_ref}
<li>CISA Known Exploited Vulnerabilities Catalog — <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">https://www.cisa.gov/known-exploited-vulnerabilities-catalog</a></li>
{_nvd_refs}
{_ai_ref}
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
