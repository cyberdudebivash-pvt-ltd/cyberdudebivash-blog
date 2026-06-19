"""
CYBERDUDEBIVASH® SENTINEL APEX — Category Mapping Module
Maps content signals to Blogger labels and article categories.
"""

from typing import Optional


# Primary category signals → canonical label
CATEGORY_RULES: list[tuple[list[str], str]] = [
    (["cve-20", "cvss", "vulnerability", "patch", "update now", "rce", "lpe", "authentication bypass"], "Vulnerabilities"),
    (["zero-day", "zero day", "0-day", "unpatched", "poc exploit", "proof of concept"], "Zero-Day"),
    (["ransomware", "lockbit", "qilin", "akira", "cl0p", "blackcat", "conti", "ryuk"], "Ransomware"),
    (["malware", "trojan", "backdoor", "botnet", "loader", "stealer", "infostealer", "rat "], "Malware Research"),
    (["apt", "nation-state", "lazarus", "volt typhoon", "apt28", "apt29", "cozy bear", "fancy bear", "sandworm", "unc"], "APT"),
    (["phishing", "spear phishing", "vishing", "smishing", "social engineering", "bec ", "business email compromise"], "Phishing"),
    (["ai security", "llm", "prompt injection", "owasp llm", "generative ai", "chatgpt", "gpt-4", "claude", "gemini", "agentic"], "AI Security"),
    (["mitre att&ck", "sigma rule", "yara rule", "detection engineering", "siem", "detection rule", "splunk", "elastic siem", "sentinel siem"], "Detection Engineering"),
    (["soc ", "security operations", "threat hunting", "threat hunt", "incident response", "playbook", "triage"], "SOC Operations"),
    (["cloud security", "aws", "azure", "gcp", "kubernetes", "s3 bucket", "iam ", "cloud misconfiguration"], "Cloud Security"),
    (["devsecops", "ci/cd", "pipeline security", "secrets scanning", "sast", "dast", "shift left"], "DevSecOps"),
    (["supply chain", "dependency confusion", "npm package", "pypi", "malicious package", "software supply chain"], "Supply Chain"),
    (["cisa kev", "known exploited", "cisa adds", "federal deadline"], "CISA KEV"),
    (["patch tuesday", "microsoft patch", "adobe patch", "monthly update"], "Patch Tuesday"),
    (["data breach", "breach", "data leak", "exposed records", "credentials leaked"], "Data Breach"),
    (["iot security", "iot device", "embedded device", "firmware", "scada", "ics ", "ot security"], "IoT Security"),
    (["ai awareness", "human firewall", "security awareness", "phishing awareness", "cyber hygiene"], "Security Awareness"),
    (["sentinel apex", "cyberdudebivash platform", "product update", "new feature", "api update"], "Product Updates"),
    (["consulting", "mssp", "managed security", "soc service", "cyber consulting"], "Services"),
]

DEFAULT_LABELS = ["CYBERDUDEBIVASH", "Threat Intelligence", "Sentinel APEX"]


def map_to_labels(title: str, summary: str) -> list[str]:
    """Return Blogger labels for an article based on content signals."""
    text = (title + " " + summary).lower()
    labels = list(DEFAULT_LABELS)

    for signals, label in CATEGORY_RULES:
        if any(s in text for s in signals):
            if label not in labels:
                labels.append(label)

    return labels


def primary_category(labels: list[str]) -> str:
    """Return the single most specific category from a label set."""
    priority = [
        "Zero-Day", "CISA KEV", "Ransomware", "APT", "Vulnerabilities",
        "AI Security", "Malware Research", "Detection Engineering",
        "Supply Chain", "Phishing", "Cloud Security", "DevSecOps",
        "SOC Operations", "Patch Tuesday", "Data Breach", "IoT Security",
        "Security Awareness", "Product Updates", "Services", "Threat Intelligence",
    ]
    for cat in priority:
        if cat in labels:
            return cat
    return "Threat Intelligence"


def blogger_label_for_category(category: str) -> Optional[str]:
    """Map a category to a Blogger-compatible label string."""
    return category if category else "Threat Intelligence"
