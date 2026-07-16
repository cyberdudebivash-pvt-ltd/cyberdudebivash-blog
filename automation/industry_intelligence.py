"""
CYBERDUDEBIVASH® SENTINEL APEX — Industry Intelligence Layer
Static, analyst-grade per-industry reference profiles (risk profile, common
targets, typical attack paths, compliance mapping, priority actions,
relevant services) — only the industries genuinely detected in an article's
title/summary are rendered. Never pads with irrelevant sectors.
"""

# Compliance frameworks named below are real, widely-documented regulatory
# regimes (not fabricated) — same evidentiary standard already used
# elsewhere in this pipeline (e.g. the Business Impact section's GDPR/HIPAA
# notification-window references).
INDUSTRY_PROFILES = {
    "healthcare": {
        "name": "Healthcare",
        "risk_profile": "High-value target due to protected health information (PHI), life-safety system dependencies, and historically under-resourced security budgets relative to data sensitivity.",
        "common_targets": "Electronic health record (EHR) systems, medical IoT devices, patient portals, insurance/billing platforms, hospital network infrastructure.",
        "attack_paths": "Phishing against clinical staff, unpatched legacy medical devices, third-party vendor/supply-chain compromise, exposed RDP/VPN into clinical networks.",
        "compliance_mapping": "HIPAA Security Rule, HITECH Act breach notification (60-day window), state-level health data laws.",
        "priority_actions": "Segment clinical/IoT networks from IT, enforce MFA on remote clinical access, maintain offline/immutable backups of EHR systems, validate BAA security requirements with vendors.",
        "services": ["vulnerability_assessment", "incident_response"],
    },
    "finance": {
        "name": "Financial Services",
        "risk_profile": "Direct monetization target for financially-motivated actors; heavily regulated with severe penalty exposure for both breaches and control failures.",
        "common_targets": "Payment processing systems, core banking platforms, customer authentication flows, trading infrastructure, API gateways to financial data.",
        "attack_paths": "Credential stuffing against customer accounts, business email compromise targeting wire transfers, API abuse, insider threat, third-party fintech integrations.",
        "compliance_mapping": "PCI-DSS, GLBA Safeguards Rule, SOX (public issuers), FFIEC guidance, SEC cybersecurity disclosure rules.",
        "priority_actions": "Enforce transaction anomaly detection, MFA on all privileged and customer-facing auth, PCI-DSS scope reduction, wire transfer verification callback procedures.",
        "services": ["detection_engineering", "incident_response"],
    },
    "government": {
        "name": "Government / Public Sector",
        "risk_profile": "Nation-state and hacktivist target for espionage, disruption, and data theft; often runs legacy systems with long patch cycles.",
        "common_targets": "Citizen data systems, election infrastructure, internal case-management systems, public-facing web portals, inter-agency data exchanges.",
        "attack_paths": "Spearphishing against personnel, exploitation of internet-facing legacy applications, supply-chain compromise via IT contractors, credential reuse across agency systems.",
        "compliance_mapping": "FISMA, FedRAMP (cloud services), NIST 800-53 controls, CISA Binding Operational Directives (federal civilian agencies).",
        "priority_actions": "Prioritize CISA KEV remediation against federal deadlines, enforce phishing-resistant MFA (FIDO2/PIV), inventory and decommission end-of-life systems.",
        "services": ["vulnerability_assessment", "detection_engineering"],
    },
    "retail": {
        "name": "Retail / E-Commerce",
        "risk_profile": "High-volume payment card processing and seasonal traffic spikes create both a large attack surface and low tolerance for security-driven downtime.",
        "common_targets": "Point-of-sale (POS) systems, e-commerce checkout flows, customer loyalty/account systems, third-party payment integrations.",
        "attack_paths": "POS malware, e-skimming (Magecart-style checkout injection), credential stuffing against customer accounts, API abuse on inventory/pricing endpoints.",
        "compliance_mapping": "PCI-DSS, state consumer data breach notification laws, CCPA/CPRA (California consumers).",
        "priority_actions": "Subresource integrity on checkout pages, POS network segmentation, rate-limit and bot-detection on login/checkout APIs, PCI-DSS quarterly scanning.",
        "services": ["vulnerability_assessment", "detection_engineering"],
    },
    "manufacturing": {
        "name": "Manufacturing",
        "risk_profile": "Convergence of IT and OT networks creates disproportionate operational-disruption risk — ransomware halting production is often more costly than data loss.",
        "common_targets": "SCADA/PLC controllers, manufacturing execution systems (MES), engineering workstations, IT-OT boundary infrastructure.",
        "attack_paths": "Ransomware pivoting from IT to OT networks, compromised remote-access tools for third-party equipment vendors, unpatched industrial protocols exposed internally.",
        "compliance_mapping": "IEC 62443 (industrial control systems), NIST 800-82 (ICS security guidance), sector-specific state regulations.",
        "priority_actions": "Enforce IT/OT network segmentation, inventory all remote-access paths to OT, verify offline backups for MES/SCADA configuration, incident response plan covering production-line shutdown procedures.",
        "services": ["incident_response", "vulnerability_assessment"],
    },
    "critical_infrastructure": {
        "name": "Critical Infrastructure",
        "risk_profile": "Nation-state and criminal targeting with potential for cascading physical/societal impact; subject to the highest regulatory scrutiny.",
        "common_targets": "Industrial control systems, SCADA historians, utility billing/customer systems, grid/network management platforms.",
        "attack_paths": "Living-off-the-land techniques post-IT compromise, exploitation of internet-exposed ICS/SCADA interfaces, supply-chain compromise of OT vendors.",
        "compliance_mapping": "NERC CIP (electric sector), TSA security directives (pipelines), CISA sector-specific guidance.",
        "priority_actions": "Zero-trust segmentation at the IT/OT boundary, mandatory reporting readiness for CISA/sector-ISAC notification, tabletop exercises simulating OT-impacting incidents.",
        "services": ["incident_response", "detection_engineering"],
    },
    "energy": {
        "name": "Energy",
        "risk_profile": "High-value nation-state target given geopolitical significance; operational technology failures carry direct public-safety consequences.",
        "common_targets": "SCADA/DCS control systems, grid management software, pipeline monitoring systems, corporate IT networks bridging to OT.",
        "attack_paths": "OT-targeted malware, spearphishing against control-room and engineering staff, exploitation of remote monitoring/telemetry systems.",
        "compliance_mapping": "NERC CIP, TSA Security Directive Pipeline-2021-02 series, DOE cybersecurity guidance.",
        "priority_actions": "Validate NERC CIP control implementation, isolate control-system networks from corporate IT, monitor for anomalous OT protocol traffic.",
        "services": ["incident_response", "vulnerability_assessment"],
    },
    "technology": {
        "name": "Technology",
        "risk_profile": "Frequent target for supply-chain attacks given downstream customer reach; source code and credential exposure carries outsized blast radius.",
        "common_targets": "CI/CD pipelines, source code repositories, cloud infrastructure credentials, customer-facing SaaS platforms, developer endpoints.",
        "attack_paths": "Malicious package/dependency injection, exposed cloud credentials in code or CI logs, compromised developer accounts, API key leakage.",
        "compliance_mapping": "SOC 2, ISO 27001, customer-driven contractual security requirements, applicable state/international privacy law for SaaS data processors.",
        "priority_actions": "Software composition analysis in CI/CD, secrets scanning on every commit, least-privilege cloud IAM, dependency pinning and provenance verification.",
        "services": ["devsecops", "vulnerability_assessment"],
    },
    "education": {
        "name": "Education",
        "risk_profile": "Large, diverse user population with limited security staffing; student/research data and campus operational systems both at risk.",
        "common_targets": "Student information systems, learning management platforms, campus network infrastructure, research computing environments.",
        "attack_paths": "Ransomware against under-resourced IT departments, phishing against staff/students, exposed legacy campus systems, compromised student/faculty credentials reused across services.",
        "compliance_mapping": "FERPA (student records), state breach notification laws, GLBA (institutions handling financial aid data).",
        "priority_actions": "Enforce MFA for staff and privileged student-system access, network segmentation between research/administrative/student networks, offline backups for student information systems.",
        "services": ["incident_response", "vulnerability_assessment"],
    },
}

_DETECTION_KEYWORDS = {
    "healthcare": ["healthcare", "hospital", "patient", "clinical", "medical", "ehr", "health system"],
    "finance": ["bank", "financial services", "fintech", "payment processor", "trading platform", "credit union", "insurance"],
    "government": ["government", "federal agency", "municipal", "public sector", "election", "state agency"],
    "retail": ["retail", "e-commerce", "point-of-sale", "pos system", "checkout", "online store"],
    "manufacturing": ["manufacturing", "factory", "production line", "industrial plant", "assembly line"],
    "critical_infrastructure": ["critical infrastructure", "water treatment", "utility", "power grid", "scada", "ics "],
    "energy": ["energy sector", "oil and gas", "pipeline", "power plant", "electric utility"],
    "technology": ["saas", "software company", "tech company", "cloud provider", "developer platform"],
    "education": ["university", "school district", "college", "campus", "student information system", "higher education"],
}


def detect_industries(title: str, summary: str, max_results: int = 2) -> list[str]:
    """Return up to max_results industry keys genuinely referenced in the
    text — never guesses, never returns all industries as filler."""
    text = (title + " " + summary).lower()
    matched = []
    for industry_key, keywords in _DETECTION_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            matched.append(industry_key)
        if len(matched) >= max_results:
            break
    return matched


def get_industry_profile(industry_key: str) -> dict:
    return INDUSTRY_PROFILES.get(industry_key, {})
