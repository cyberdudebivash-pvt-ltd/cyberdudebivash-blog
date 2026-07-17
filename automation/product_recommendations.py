"""
CYBERDUDEBIVASH® SENTINEL APEX — Product Recommendation Engine
Data-driven mapping from report category/labels to the real CYBERDUDEBIVASH®
service catalog (the same 8 services already listed in
monetization_injector.py's inject_services_block — reused here, not
reinvented). Rules live in one table; nothing is hardcoded per-template.
"""

from typing import Optional

# Canonical service catalog — must match monetization_injector.py's
# inject_services_block() names exactly (single source of truth for what
# CYBERDUDEBIVASH® actually sells).
SERVICES = {
    "threat_intelligence": {
        "name": "Threat Intelligence",
        "description": "CTI Advisory & Premium Intel Briefs",
    },
    "ai_security_assessment": {
        "name": "AI Security Assessment",
        "description": "LLM · Prompt Injection · Agent Security",
    },
    "vulnerability_assessment": {
        "name": "Vulnerability Assessment",
        "description": "API · SaaS · Cloud · Web Security",
    },
    "soc_mssp": {
        "name": "SOC & MSSP Services",
        "description": "Co-Managed SOC · Threat Hunting",
    },
    "ai_governance": {
        "name": "AI Governance Consulting",
        "description": "NIST AI RMF · ISO 42001 · OWASP LLM",
    },
    "devsecops": {
        "name": "DevSecOps Optimization",
        "description": "CI/CD Security · Pipeline Hardening",
    },
    "incident_response": {
        "name": "Incident Response",
        "description": "Digital Forensics · IR Retainer",
    },
    "detection_engineering": {
        "name": "Detection Engineering",
        "description": "2,400+ Sigma · YARA · SIEM Rules",
    },
}

# Ordered by priority — first matching rule(s) win. Each rule maps a
# real, already-produced label (see content_discovery._infer_labels) to
# 1-2 services from the catalog above. Multiple rules can match; callers
# choose how many to surface.
RECOMMENDATION_RULES = [
    {"label": "Ransomware", "services": ["incident_response", "detection_engineering"]},
    {"label": "CISA KEV", "services": ["vulnerability_assessment", "detection_engineering"]},
    {"label": "Zero-Day", "services": ["vulnerability_assessment", "incident_response"]},
    {"label": "Vulnerabilities", "services": ["vulnerability_assessment"]},
    {"label": "APT", "services": ["soc_mssp", "detection_engineering"]},
    {"label": "AI Security", "services": ["ai_security_assessment", "ai_governance"]},
    {"label": "Malware Research", "services": ["incident_response", "detection_engineering"]},
    {"label": "Cloud Security", "services": ["devsecops"]},
    {"label": "Supply Chain", "services": ["devsecops"]},
    {"label": "Detection Engineering", "services": ["detection_engineering"]},
    {"label": "SOC Operations", "services": ["soc_mssp"]},
    {"label": "Data Breach", "services": ["incident_response"]},
    {"label": "Incident Response", "services": ["incident_response"]},
    {"label": "Phishing", "services": ["soc_mssp"]},
    {"label": "IoT Security", "services": ["vulnerability_assessment"]},
]

_DEFAULT_SERVICE = "threat_intelligence"


def recommend_services(labels: list[str], max_results: int = 3) -> list[dict]:
    """
    Return up to max_results services relevant to this report's labels,
    ordered by rule priority, each service appearing at most once.
    Falls back to the flagship Threat Intelligence service if nothing
    in the labels matches a specific rule.
    """
    label_set = set(labels)
    seen: set = set()
    result: list[dict] = []

    for rule in RECOMMENDATION_RULES:
        if rule["label"] not in label_set:
            continue
        for service_key in rule["services"]:
            if service_key in seen:
                continue
            seen.add(service_key)
            result.append(SERVICES[service_key])
            if len(result) >= max_results:
                return result

    if not result:
        result.append(SERVICES[_DEFAULT_SERVICE])

    return result


def top_recommendation(labels: list[str]) -> Optional[dict]:
    """Return the single highest-priority matching service, or None if
    labels are empty (callers typically fall back to a generic CTA)."""
    if not labels:
        return None
    matches = recommend_services(labels, max_results=1)
    return matches[0] if matches else None
