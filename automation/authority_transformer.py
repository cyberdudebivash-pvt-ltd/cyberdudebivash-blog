"""
CYBERDUDEBIVASH® SENTINEL APEX — Authority Content Transformer v2.0
Transforms source articles into enterprise-grade threat intelligence reports.
LLM priority: Groq → DeepSeek → OpenRouter → Anthropic → template fallback.
"""

import base64
import json
import re
import textwrap
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

# ---------------------------------------------------------------------------
# Category color palettes for SVG thumbnails
# ---------------------------------------------------------------------------
_CATEGORY_PALETTES = {
    "Ransomware":       {"bg1": "#1a0800", "bg2": "#2d1000", "accent": "#f59e0b", "accent2": "#ef4444", "label_bg": "#92400e"},
    "Zero-Day":         {"bg1": "#1a0000", "bg2": "#2d0000", "accent": "#ef4444", "accent2": "#f97316", "label_bg": "#7f1d1d"},
    "CVE":              {"bg1": "#1a0000", "bg2": "#2d0000", "accent": "#ef4444", "accent2": "#f97316", "label_bg": "#7f1d1d"},
    "AI Security":      {"bg1": "#0d0020", "bg2": "#160035", "accent": "#a855f7", "accent2": "#ec4899", "label_bg": "#4c1d95"},
    "APT":              {"bg1": "#0f0020", "bg2": "#1a0035", "accent": "#c026d3", "accent2": "#a855f7", "label_bg": "#6b21a8"},
    "Nation-State":     {"bg1": "#0f0020", "bg2": "#1a0035", "accent": "#c026d3", "accent2": "#a855f7", "label_bg": "#6b21a8"},
    "Threat Intel":     {"bg1": "#001a20", "bg2": "#002d35", "accent": "#06b6d4", "accent2": "#0ea5e9", "label_bg": "#164e63"},
    "Cloud Security":   {"bg1": "#00101a", "bg2": "#001a2d", "accent": "#0ea5e9", "accent2": "#06b6d4", "label_bg": "#0c4a6e"},
    "Malware":          {"bg1": "#100018", "bg2": "#1a0028", "accent": "#8b5cf6", "accent2": "#ec4899", "label_bg": "#4c1d95"},
    "default":          {"bg1": "#000d1a", "bg2": "#001428", "accent": "#00d4ff", "accent2": "#0ea5e9", "label_bg": "#164e63"},
}


def _get_palette(labels: list[str]) -> dict:
    text = " ".join(labels).lower()
    for key, pal in _CATEGORY_PALETTES.items():
        if key.lower() in text:
            return pal
    return _CATEGORY_PALETTES["default"]


def _wrap_svg_text(text: str, max_chars: int, max_lines: int) -> list[str]:
    """Word-wrap text for SVG tspan elements."""
    words = text.split()
    lines, current = [], ""
    for word in words:
        test = (current + " " + word).strip()
        if len(test) <= max_chars:
            current = test
        else:
            if current:
                lines.append(current)
            current = word
        if len(lines) >= max_lines:
            break
    if current and len(lines) < max_lines:
        if len(current) > max_chars:
            current = current[: max_chars - 1] + "…"
        lines.append(current)
    return lines[:max_lines]


def generate_svg_thumbnail(title: str, category: str, labels: list[str], cvss: Optional[str] = None) -> str:
    """Generate a branded 1200×630 SVG thumbnail encoded as a data URI."""
    pal = _get_palette(labels)
    bg1, bg2 = pal["bg1"], pal["bg2"]
    accent, accent2 = pal["accent"], pal["accent2"]
    label_bg = pal["label_bg"]

    title_lines = _wrap_svg_text(title, 38, 3)
    title_svgs = ""
    for i, line in enumerate(title_lines):
        y = 340 + i * 58
        title_svgs += f'<text x="60" y="{y}" font-family="Arial,sans-serif" font-size="40" font-weight="700" fill="#ffffff">{line}</text>\n'

    cvss_badge = ""
    if cvss:
        try:
            score = float(cvss)
            cvss_color = "#ef4444" if score >= 9 else "#f97316" if score >= 7 else "#f59e0b" if score >= 4 else "#22c55e"
            cvss_badge = f'''
<rect x="1060" y="20" width="120" height="54" rx="6" fill="{cvss_color}" opacity="0.95"/>
<text x="1120" y="43" text-anchor="middle" font-family="Arial,sans-serif" font-size="11" fill="#fff" font-weight="700">CVSS</text>
<text x="1120" y="64" text-anchor="middle" font-family="Arial,sans-serif" font-size="22" fill="#fff" font-weight="900">{cvss}</text>'''
        except (ValueError, TypeError):
            pass

    category_short = category.upper()[:18]

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 630" width="1200" height="630">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{bg1}"/>
      <stop offset="100%" stop-color="{bg2}"/>
    </linearGradient>
    <linearGradient id="acc" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="{accent}"/>
      <stop offset="100%" stop-color="{accent2}"/>
    </linearGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="8" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>

  <!-- Background -->
  <rect width="1200" height="630" fill="url(#bg)"/>

  <!-- Grid overlay -->
  <g opacity="0.06" stroke="{accent}" stroke-width="0.5">
    {''.join(f'<line x1="{x}" y1="0" x2="{x}" y2="630"/>' for x in range(0, 1201, 40))}
    {''.join(f'<line x1="0" y1="{y}" x2="1200" y2="{y}"/>' for y in range(0, 631, 40))}
  </g>

  <!-- Glow orbs -->
  <circle cx="100" cy="100" r="200" fill="{accent}" opacity="0.06"/>
  <circle cx="1100" cy="530" r="160" fill="{accent2}" opacity="0.07"/>

  <!-- Top accent bar -->
  <rect x="0" y="0" width="1200" height="6" fill="url(#acc)"/>

  <!-- Brand bar -->
  <rect x="0" y="0" width="1200" height="70" fill="#000000" opacity="0.45"/>
  <text x="60" y="46" font-family="Arial,sans-serif" font-size="15" font-weight="700" fill="{accent}" letter-spacing="3">CYBERDUDEBIVASH®</text>
  <text x="280" y="46" font-family="Arial,sans-serif" font-size="15" fill="#64748b" letter-spacing="1">SENTINEL APEX  ·  THREAT INTELLIGENCE</text>

  {cvss_badge}

  <!-- Shield icon -->
  <g transform="translate(60,200)" filter="url(#glow)">
    <path d="M30 0 L60 12 L60 40 C60 56 46 68 30 74 C14 68 0 56 0 40 L0 12 Z" fill="none" stroke="{accent}" stroke-width="2.5" opacity="0.9"/>
    <path d="M30 18 L44 24 L44 40 C44 50 38 57 30 61 C22 57 16 50 16 40 L16 24 Z" fill="{accent}" opacity="0.2"/>
    <text x="30" y="45" text-anchor="middle" font-family="Arial,sans-serif" font-size="22" font-weight="900" fill="{accent}">✦</text>
  </g>

  <!-- Category badge -->
  <rect x="60" y="295" width="{len(category_short) * 11 + 24}" height="30" rx="4" fill="{label_bg}" opacity="0.9"/>
  <text x="72" y="315" font-family="Arial,sans-serif" font-size="13" font-weight="700" fill="{accent}" letter-spacing="1">{category_short}</text>

  <!-- Post title -->
  {title_svgs}

  <!-- Bottom bar -->
  <rect x="0" y="600" width="1200" height="30" fill="#000000" opacity="0.5"/>
  <rect x="0" y="600" width="1200" height="3" fill="url(#acc)"/>
  <text x="60" y="622" font-family="Arial,sans-serif" font-size="12" fill="#475569">blog.cyberdudebivash.in  ·  AI-Powered Cybersecurity Intelligence</text>
  <text x="1140" y="622" text-anchor="end" font-family="Arial,sans-serif" font-size="12" fill="#475569">{datetime.now(timezone.utc).strftime("%Y")}</text>
</svg>'''

    encoded = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f'data:image/svg+xml;base64,{encoded}'


# ---------------------------------------------------------------------------
# LLM Prompt — 18-section enterprise intelligence report
# ---------------------------------------------------------------------------

def _build_analyst_prompt(article: DiscoveredArticle) -> str:
    return f"""You are the CYBERDUDEBIVASH® SENTINEL APEX AI Security Analyst — a senior CTI analyst with expertise in threat intelligence, vulnerability research, detection engineering, and enterprise security operations.

Transform the following cybersecurity article into a premium enterprise threat intelligence report. Write at analyst level — no marketing fluff, no generic advice.

ARTICLE TITLE: {article.title}
ARTICLE URL: {article.url}
ARTICLE CONTENT:
{(article.full_content or article.summary)[:4000]}
LABELS/CATEGORY: {', '.join(article.labels)}

Generate a comprehensive threat intelligence report with EXACTLY these sections in HTML (use <h3>, <p>, <ul>, <li>, <table>, <code> tags — NO inline styles):

<h3>Executive Summary</h3>
[2-3 sentences for C-suite and board. Quantify risk. State business impact clearly.]

<h3>Threat Overview</h3>
[What is the threat? Who is affected? When was it discovered? Include CVE IDs if present.]

<h3>Threat Severity Assessment</h3>
[CRITICAL/HIGH/MEDIUM/LOW with justification. Reference CVSS score if available. Explain severity rationale.]

<h3>Business Impact</h3>
[Concrete business risks: financial, operational, reputational, regulatory. Quantify where supported by article data.]

<h3>Technical Analysis</h3>
[Deep technical breakdown for SOC analysts. Attack vector, affected components, exploitation methodology, patch status.]

<h3>CVE Analysis</h3>
[Only if CVEs present. For each CVE: affected product, attack vector, CVSS base score, exploitation status, patch availability. Use a table if multiple CVEs.]

<h3>MITRE ATT&CK Mapping</h3>
<ul>[Map to specific MITRE ATT&CK tactics and techniques evidenced by the article. Format: Tactic: Technique (TXXXX). Only include confirmed techniques.]</ul>

<h3>IOC Intelligence</h3>
[List Indicators of Compromise from the article. If none explicitly provided, describe the indicator types defenders should hunt for. Categorize: file hashes, IPs/domains, registry keys, process names, network signatures.]

<h3>Detection Engineering Guidance</h3>
[Specific log sources, event IDs (Windows/Linux), network signatures, SIEM query logic. Be precise — name the event IDs and fields.]

<h3>Sigma Rules</h3>
[Write 1-2 Sigma rules in YAML format inside <code> blocks. Base them on the detection opportunities identified above. If no specific IOCs are available, write a behavioural detection rule aligned to the MITRE techniques.]

<h3>Threat Hunting Queries</h3>
<ul>[5 specific, actionable threat hunting hypotheses with search logic. Include the data source (SIEM, EDR, network) for each. Format: Hypothesis → Search Logic → Data Source]</ul>

<h3>SOC Analyst Actions</h3>
<ul>[Prioritised immediate actions for SOC L1/L2/L3 analysts. Be specific: which alerts to create, which logs to review, which patches to apply.]</ul>

<h3>Executive Recommendations</h3>
<ul>[Strategic 90-day remediation roadmap: Day 1-7 (emergency), Day 8-30 (tactical), Day 31-90 (strategic). Each phase has specific deliverables.]</ul>

<h3>MSSP Opportunities</h3>
[How MSSPs can deliver value here: managed detection, threat hunting, IR retainer, advisory services. Positions CYBERDUDEBIVASH® SENTINEL APEX as the delivery vehicle.]

<h3>Sentinel APEX Intelligence Correlation</h3>
[How SENTINEL APEX intelligence feeds, detection packs, and API would have detected this earlier or provides ongoing coverage.]

<h3>AI Security Impact</h3>
[Only include if the article relates to AI/LLM/ML/agentic systems. Reference OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF. Otherwise OMIT this section entirely.]

<h3>Long-Term Strategic Risk</h3>
[What does this threat indicate about the evolving threat landscape? What strategic decisions should CISOs make based on this intelligence?]

<h3>References</h3>
<ul>[Key references: NVD, CISA KEV, vendor advisories, MITRE ATT&CK. Link to primary source article.]</ul>

CRITICAL RULES:
- Do NOT fabricate CVE IDs, CVSS scores, threat actor names, IOCs, or technical details not evidenced in the source article
- Sigma rules MUST be syntactically valid YAML — use correct field names (EventID, CommandLine, Image, etc.)
- Write at analyst level — assume reader is a senior SOC analyst or CISO
- Every recommendation must be specific and actionable
- Total length: 1000-1800 words
- Return ONLY the HTML sections, no preamble or postamble
"""


# ---------------------------------------------------------------------------
# Template fallback — visual enterprise report when LLM is unavailable
# ---------------------------------------------------------------------------

def _severity_color(cvss: Optional[str]) -> tuple[str, str]:
    """Return (color_hex, severity_label) from CVSS string."""
    if cvss:
        try:
            score = float(cvss)
            if score >= 9.0:
                return "#ef4444", "CRITICAL"
            if score >= 7.0:
                return "#f97316", "HIGH"
            if score >= 4.0:
                return "#f59e0b", "MEDIUM"
            return "#22c55e", "LOW"
        except (ValueError, TypeError):
            pass
    return "#ef4444", "CRITICAL"


def _template_enhance(article: DiscoveredArticle, config: Config) -> str:
    """Template-based content enhancement when all LLM providers fail."""
    cves = _extract_cve_ids(article.title + " " + article.summary)
    cvss = _extract_cvss(article.title + " " + article.summary)
    category = primary_category(article.labels)

    cve_str = ", ".join(cves) if cves else "this vulnerability"
    sev_color, sev_label = _severity_color(cvss)
    cvss_display = f"CVSS {cvss}" if cvss else "Elevated"

    text = (article.title + " " + article.summary).lower()
    is_ransomware = "ransomware" in text
    is_ai = "ai " in text or "llm" in text or "prompt injection" in text or "artificial intelligence" in text
    is_apt = "apt" in text or "nation-state" in text or "nation state" in text
    is_patch = "patch" in text or "update" in text or "cisa" in text

    # MITRE mapping
    if is_ransomware:
        mitre_techniques = [
            ("Initial Access", "Phishing", "T1566"),
            ("Execution", "Command and Scripting Interpreter", "T1059"),
            ("Defense Evasion", "Obfuscated Files or Information", "T1027"),
            ("Impact", "Data Encrypted for Impact", "T1486"),
            ("Exfiltration", "Exfiltration Over C2 Channel", "T1041"),
        ]
        sigma_rule = textwrap.dedent("""\
            title: Ransomware Execution - Suspicious File Encryption Activity
            id: auto-generated-ransomware-01
            status: experimental
            description: Detects mass file renaming or encryption patterns consistent with ransomware execution
            logsource:
                category: file_event
                product: windows
            detection:
                selection:
                    TargetFilename|endswith:
                        - '.encrypted'
                        - '.locked'
                        - '.ransom'
                        - '.crypted'
                condition: selection | count(TargetFilename) by Image > 100
            falsepositives:
                - Legitimate backup or archiving tools
            level: high
            tags:
                - attack.impact
                - attack.t1486""")
        hunt_queries = [
            "Hunt: Rapid file extension changes → Search EDR telemetry for >50 file renames in 60s → EDR/XDR",
            "Hunt: VSS deletion → Windows Event 4688 with vssadmin/wbadmin commands → Windows Security Logs",
            "Hunt: Lateral movement pre-encryption → Abnormal SMB connections to file shares → Network Flow",
            "Hunt: Credential harvesting precursor → LSASS memory access events → EDR/Sysmon Event 10",
            "Hunt: C2 beaconing → Regular interval outbound connections to unknown IPs → Proxy/Firewall Logs",
        ]
    elif is_apt:
        mitre_techniques = [
            ("Reconnaissance", "Active Scanning", "T1595"),
            ("Initial Access", "Exploit Public-Facing Application", "T1190"),
            ("Persistence", "Create or Modify System Process", "T1543"),
            ("Collection", "Data from Local System", "T1005"),
            ("Exfiltration", "Exfiltration Over Alternative Protocol", "T1048"),
        ]
        sigma_rule = textwrap.dedent("""\
            title: APT Activity - Suspicious Outbound Data Transfer
            id: auto-generated-apt-01
            status: experimental
            description: Detects large or unusual outbound data transfers indicative of APT exfiltration
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    Initiated: 'true'
                    DestinationPort:
                        - 443
                        - 8443
                        - 8080
                filter_common:
                    DestinationIp|startswith:
                        - '10.'
                        - '192.168.'
                condition: selection and not filter_common
            falsepositives:
                - Legitimate cloud backups
                - Software update services
            level: medium
            tags:
                - attack.exfiltration
                - attack.t1048""")
        hunt_queries = [
            "Hunt: Persistence mechanisms → Registry Run keys and scheduled tasks created after business hours → Sysmon Event 13/12",
            "Hunt: Living-off-the-land binaries → Execution of certutil, bitsadmin, mshta with network connections → EDR",
            "Hunt: DNS-based exfiltration → Unusually long DNS query strings or high query volume → DNS Logs",
            "Hunt: Lateral movement → Pass-the-hash/ticket events — Event 4624 logon type 3 with NTLM → Security Logs",
            "Hunt: Dormant implants → Process execution from temp/appdata directories at regular intervals → EDR",
        ]
    elif cves:
        mitre_techniques = [
            ("Initial Access", "Exploit Public-Facing Application", "T1190"),
            ("Privilege Escalation", "Exploitation for Privilege Escalation", "T1068"),
            ("Lateral Movement", "Exploitation of Remote Services", "T1210"),
            ("Execution", "Command and Scripting Interpreter", "T1059"),
        ]
        sigma_rule = textwrap.dedent(f"""\
            title: Exploitation Attempt - {cves[0] if cves else 'CVE Unknown'}
            id: auto-generated-cve-01
            status: experimental
            description: Detects exploitation attempts related to {cves[0] if cves else 'identified CVE'}
            logsource:
                category: webserver
            detection:
                selection:
                    cs-uri-query|contains:
                        - '../'
                        - '%2e%2e'
                        - 'cmd.exe'
                        - 'powershell'
                        - '/etc/passwd'
                condition: selection
            falsepositives:
                - Penetration testing
                - Security scanners
            level: high
            tags:
                - attack.initial_access
                - attack.t1190""")
        hunt_queries = [
            f"Hunt: Active exploitation → Search web/application logs for {cve_str} exploit patterns → WAF/Web Logs",
            "Hunt: Post-exploitation → Unexpected child processes spawned by web server process → EDR",
            "Hunt: Privilege escalation → Token impersonation events (Event 4672) after web request → Security Logs",
            "Hunt: Persistence post-exploit → New services or scheduled tasks created by web server user context → Sysmon",
            "Hunt: Data access post-compromise → Bulk database queries or file access from web server process → SIEM",
        ]
    else:
        mitre_techniques = [
            ("Initial Access", "Phishing", "T1566"),
            ("Execution", "User Execution", "T1204"),
            ("Defense Evasion", "Masquerading", "T1036"),
        ]
        sigma_rule = textwrap.dedent("""\
            title: Suspicious Process Execution from User Downloads
            id: auto-generated-generic-01
            status: experimental
            description: Detects execution of binaries from user download directories
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image|contains:
                        - '\\Downloads\\'
                        - '\\AppData\\Local\\Temp\\'
                    Image|endswith:
                        - '.exe'
                        - '.dll'
                        - '.ps1'
                condition: selection
            falsepositives:
                - Software installations from downloads
            level: medium
            tags:
                - attack.execution
                - attack.t1204""")
        hunt_queries = [
            "Hunt: Malicious email attachments → Execution of office child processes (winword.exe → cmd.exe) → EDR",
            "Hunt: Macro execution → Suspicious Office VBA macro execution events → Office/EDR Logs",
            "Hunt: LOLBin abuse → Execution of certutil/regsvr32/msiexec for payload delivery → Sysmon Event 1",
            "Hunt: New persistence → Registry run keys added in last 24h → Sysmon Event 13",
            "Hunt: Outbound C2 → New outbound connections from recently executed processes → Network/EDR",
        ]

    mitre_html = "\n".join(
        f'<li><strong>{tac}:</strong> {tech} (<code>{tid}</code>)</li>'
        for tac, tech, tid in mitre_techniques
    )

    soc_actions = []
    if cves:
        soc_actions.append(f"<strong>IMMEDIATE:</strong> Apply vendor patches for {cve_str} within your SLA window")
        soc_actions.append("Search SIEM/EDR for exploitation IOCs — prioritise internet-facing systems")
    if is_ransomware:
        soc_actions += [
            "Verify immutable backup integrity and test restoration procedure NOW",
            "Audit privileged accounts — enforce MFA on all admin and service accounts",
            "Enable network segmentation to contain potential ransomware lateral movement",
        ]
    if is_apt:
        soc_actions += [
            "Conduct targeted threat hunt across endpoints for persistence artefacts",
            "Review egress traffic for C2 communication patterns (beaconing, DNS tunnelling)",
            "Audit IAM logs for suspicious authentication and privilege escalation",
        ]
    soc_actions += [
        "Update threat intelligence platform with associated IOC types from this advisory",
        "Brief IR team — establish escalation criteria and on-call rotation if severity is HIGH/CRITICAL",
    ]
    soc_html = "\n".join(f"<li>{a}</li>" for a in soc_actions[:6])

    enterprise_recs = [
        "<strong>Day 1-7 (Emergency):</strong> Patch all affected systems, block known exploitation vectors, verify backup integrity",
        "<strong>Day 8-30 (Tactical):</strong> Deploy detection rules for identified MITRE techniques, conduct targeted threat hunt, review exposure surface",
        "<strong>Day 31-90 (Strategic):</strong> Conduct tabletop exercise, evaluate detection coverage gaps, integrate intelligence feeds",
        "Evaluate CYBERDUDEBIVASH® SENTINEL APEX API for continuous intelligence coverage on this threat class",
        "Assess third-party and supply chain vendor exposure to this threat vector",
    ]
    if is_ai:
        enterprise_recs.insert(0, "<strong>AI Risk:</strong> Conduct OWASP LLM Top 10 assessment on all deployed AI/LLM systems")
    ent_html = "\n".join(f"<li>{r}</li>" for r in enterprise_recs[:5])

    ai_section = ""
    if is_ai:
        ai_section = """
<h3>AI Security Impact</h3>
<p>This threat carries direct implications for enterprise AI deployments. Organizations running LLMs, AI agents, RAG (Retrieval-Augmented Generation) pipelines, or ML inference infrastructure must evaluate exposure to prompt injection, training data poisoning, model inversion, and AI supply chain attacks.</p>
<p>Reference frameworks: <strong>OWASP LLM Top 10</strong>, <strong>MITRE ATLAS</strong>, <strong>NIST AI RMF</strong>. CYBERDUDEBIVASH® AI Security Hub delivers dedicated AI security assessments and continuous monitoring aligned to these frameworks.</p>
"""

    ioc_section = f"""
<h3>IOC Intelligence</h3>
<p>The following IOC categories are relevant to this threat. Defenders should hunt for these indicator types across their environment:</p>
<ul>
<li><strong>Network:</strong> Unusual outbound connections on non-standard ports; DNS queries to newly registered domains; beaconing traffic patterns</li>
<li><strong>Endpoint:</strong> Execution from temp/download directories; suspicious child process relationships; unsigned binary execution</li>
{'<li><strong>CVE-Specific:</strong> Exploitation artefacts for ' + cve_str + ' — review vendor advisories for specific IOC lists</li>' if cves else ''}
<li><strong>Behaviour:</strong> Privilege escalation sequences; mass file access patterns; scheduled task creation outside business hours</li>
</ul>
<p><em>Subscribe to CYBERDUDEBIVASH® SENTINEL APEX for real-time structured IOC feeds (STIX 2.1 format) for this threat class.</em></p>
"""

    return f"""
<h3>Executive Summary</h3>
<p>{article.summary[:450].rstrip('.')}. This represents a <strong>{sev_label} ({cvss_display})</strong> risk requiring immediate attention from enterprise security teams. CYBERDUDEBIVASH® SENTINEL APEX has classified this as priority-tier intelligence requiring coordinated response across SOC, vulnerability management, and executive stakeholders.</p>

<h3>Threat Overview</h3>
<p>{article.summary[:600]}</p>
<p>Category: <strong>{category}</strong> · Severity: <strong>{sev_label}</strong> · CVEs: <strong>{"None disclosed" if not cves else ", ".join(cves)}</strong></p>

<h3>Threat Severity Assessment</h3>
<p>Severity Rating: <strong style="color:{sev_color}">{sev_label}</strong>{' — CVSS Base Score: ' + cvss if cvss else ''}. Enterprise environments with unpatched systems or inadequate detection coverage are at elevated risk of exploitation. Immediate escalation to the CISO and vulnerability management team is recommended.</p>

<h3>Business Impact</h3>
<p>Organizations with exposure face: financial loss from operational disruption, regulatory penalties under GDPR/NIS2/DORA for data breaches, reputational damage from customer data exposure, and legal liability from third-party impacts. The threat vector identified represents a significant risk to enterprise infrastructure, particularly for organizations operating {category.lower()}-affected systems.</p>

<h3>Technical Analysis</h3>
<p>{article.summary[:800]}</p>
<p>Security teams must treat this as an active threat requiring immediate defensive posture adjustment. Attack surface enumeration across all potentially affected assets is required before remediation can be prioritised.</p>

<h3>MITRE ATT&CK Mapping</h3>
<ul>
{mitre_html}
</ul>

{ioc_section}

<h3>Detection Engineering Guidance</h3>
<p>Configure detections across these data sources: <strong>Windows Event Logs</strong> (Security 4624/4625/4688/4698/4702), <strong>Sysmon</strong> (Event 1/3/7/10/11/13), <strong>EDR/XDR telemetry</strong>, <strong>Web/Application logs</strong>, <strong>Network flow data</strong>, and <strong>Authentication logs</strong>.</p>
<p>Tune SIEM rules to cover the MITRE techniques mapped above. CYBERDUDEBIVASH® SENTINEL APEX provides 2,400+ production-ready Sigma and YARA detection rules for immediate SIEM deployment.</p>

<h3>Sigma Rules</h3>
<p>Production-ready detection rule for immediate deployment:</p>
<pre><code>{sigma_rule}</code></pre>

<h3>Threat Hunting Queries</h3>
<ul>
{''.join(f'<li>{q}</li>' for q in hunt_queries)}
</ul>

<h3>SOC Analyst Actions</h3>
<ul>
{soc_html}
</ul>

<h3>CYBERDUDEBIVASH® Analyst Commentary</h3>
<p>This intelligence item reflects a continuing pattern in the current threat landscape. Threat actors are systematically targeting {category.lower()} attack surfaces to gain initial access into enterprise environments. Organizations that maintain real-time intelligence integration — such as through SENTINEL APEX — gain significantly earlier warning than those relying on periodic advisories alone. Transitioning from reactive to intelligence-driven defensive operations is no longer optional for enterprise security teams.</p>

{ai_section}

<h3>Executive Recommendations</h3>
<ul>
{ent_html}
</ul>

<h3>MSSP Opportunities</h3>
<p>MSSPs can deliver immediate value to clients by: deploying managed detection rules for identified techniques, conducting proactive threat hunts across client environments, activating IR retainer services for at-risk accounts, and providing advisory on remediation prioritisation. CYBERDUDEBIVASH® SENTINEL APEX white-label intelligence packages enable MSSPs to deliver this capability at scale.</p>

<h3>Sentinel APEX Intelligence Correlation</h3>
<p>CYBERDUDEBIVASH® SENTINEL APEX subscribers receive real-time intelligence feeds covering this exact threat class, including: structured IOC feeds (STIX 2.1), SIEM-ready Sigma rules, MITRE ATT&CK heatmaps, and API access for direct integration with your security stack. Early detection is the difference between containment and breach.</p>

<h3>Long-Term Strategic Risk</h3>
<p>This threat indicates a maturation of {category.lower()} attack tooling. CISOs should reassess detection stack coverage against current MITRE ATT&CK techniques, accelerate vulnerability management SLA enforcement, invest in threat intelligence feeds providing early warning of emerging CVEs, and evaluate AI-augmented SOC capabilities to maintain defensive parity as threat velocity increases.</p>

<h3>Key Takeaways</h3>
<ul>
<li>This threat requires immediate evaluation against your organization's specific attack surface and asset inventory</li>
<li>Patch and mitigate all identified vulnerable systems within your SLA window — prioritise internet-facing assets</li>
<li>Validate detection coverage against every MITRE ATT&CK technique listed above</li>
<li>Deploy the Sigma rules provided above into your SIEM for immediate coverage</li>
<li>Brief CISO and executive stakeholders on business impact and remediation timeline</li>
</ul>
""".strip()


# ---------------------------------------------------------------------------
# Main AuthorityTransformer class
# ---------------------------------------------------------------------------

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

        llm_result = call_llm(self.config, _build_analyst_prompt(article))
        if llm_result:
            body_content, content_source = llm_result
        else:
            body_content = _template_enhance(article, self.config)
            content_source = "template"

        seo_data = self.seo.generate(
            title=article.title,
            summary=article.summary,
            url=article.url,
            labels=article.labels,
            published_at=article.published_at,
        )

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

        # Generate branded SVG thumbnail — this is what Blogger uses for data:post.firstImageUrl
        thumbnail_uri = generate_svg_thumbnail(article.title, category, article.labels, cvss)

        # Build metadata bar
        meta_items = [f"📅 {pub_date}", f"📂 {category}", "🛡 CYBERDUDEBIVASH®"]
        if cves:
            meta_items.insert(0, f"🔍 {', '.join(cves[:2])}")
        if cvss:
            meta_items.insert(1 if cves else 0, f"⚠ CVSS {cvss}")
        meta_bar = " &nbsp;|&nbsp; ".join(meta_items)

        sev_color, sev_label = _severity_color(cvss)

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
<!-- CYBERDUDEBIVASH® SENTINEL APEX — Intelligence Report v2.0 -->
<!-- Source: {article.url} -->
<!-- Generated: {datetime.now(timezone.utc).isoformat()} -->

<!-- THUMBNAIL: Blogger firstImageUrl target -->
<img src="{thumbnail_uri}" alt="{article.title}" width="1200" height="630" style="width:100%;height:auto;border-radius:8px;display:block;margin-bottom:16px" loading="eager"/>

<!-- Severity banner -->
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0 0 16px;padding:12px 20px;background:{sev_color}18;border-left:4px solid {sev_color};border-radius:0 6px 6px 0;display:flex;align-items:center;gap:14px">
  <span style="font-size:22px;font-weight:900;color:{sev_color}">{sev_label}</span>
  <span style="font-size:13px;color:#94a3b8">Threat Severity Assessment · CYBERDUDEBIVASH® SENTINEL APEX</span>
  {f'<span style="margin-left:auto;font-size:14px;font-weight:700;color:{sev_color}">CVSS {cvss}</span>' if cvss else ''}
</div>

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
  Intelligence syndicated from <a href="{article.url}" target="_blank" rel="noopener" style="color:#334155">{article.url}</a> by CYBERDUDEBIVASH® SENTINEL APEX Syndication Engine v2.0
</div>
"""
        return html
