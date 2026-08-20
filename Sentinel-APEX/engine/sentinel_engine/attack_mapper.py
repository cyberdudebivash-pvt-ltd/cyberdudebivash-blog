"""Evidence-driven MITRE ATT&CK technique mapping.

A technique is only mapped when a concrete phrase in the source text supports
it, and the triggering phrase is stored on the mapping so every ATT&CK claim
in a published report is traceable back to evidence. This is the direct
replacement for template-stamped technique blocks.
"""

from __future__ import annotations

import re

from .models import Confidence, TechniqueMapping

# Curated subset of ATT&CK Enterprise used for validation of technique IDs.
# id -> (name, tactic)
KNOWN_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1003": ("OS Credential Dumping", "credential-access"),
    "T1012": ("Query Registry", "discovery"),
    "T1016": ("System Network Configuration Discovery", "discovery"),
    "T1033": ("System Owner/User Discovery", "discovery"),
    "T1036": ("Masquerading", "defense-evasion"),
    "T1036.005": ("Match Legitimate Name or Location", "defense-evasion"),
    "T1049": ("System Network Connections Discovery", "discovery"),
    # RX-P1I: found live -- two real, gold-standard canary exports
    # (dragonforce/T1219, medusalocker/T1053) cite these genuine, standalone
    # MITRE technique IDs, but only their sub-technique siblings (T1053.005)
    # or no sibling at all (T1219) were previously curated here. Consistent
    # with this dict's own existing pattern of listing both a parent and its
    # sub-technique when both are in real use (e.g. T1003/T1003.001,
    # T1059/T1059.001, T1070/T1070.004, T1021/T1021.001).
    "T1053": ("Scheduled Task/Job", "persistence"),
    "T1219": ("Remote Access Tools", "command-and-control"),
    "T1057": ("Process Discovery", "discovery"),
    "T1070": ("Indicator Removal", "defense-evasion"),
    "T1070.004": ("File Deletion", "defense-evasion"),
    "T1072": ("Software Deployment Tools", "execution"),
    "T1074": ("Data Staged", "collection"),
    "T1083": ("File and Directory Discovery", "discovery"),
    "T1087": ("Account Discovery", "discovery"),
    "T1135": ("Network Share Discovery", "discovery"),
    "T1482": ("Domain Trust Discovery", "discovery"),
    "T1518": ("Software Discovery", "discovery"),
    "T1546": ("Event Triggered Execution", "persistence"),
    "T1555": ("Credentials from Password Stores", "credential-access"),
    "T1567.002": ("Exfiltration to Cloud Storage", "exfiltration"),
    "T1003.001": ("LSASS Memory", "credential-access"),
    "T1005": ("Data from Local System", "collection"),
    "T1021": ("Remote Services", "lateral-movement"),
    "T1021.001": ("Remote Desktop Protocol", "lateral-movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "lateral-movement"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1046": ("Network Service Discovery", "discovery"),
    "T1047": ("Windows Management Instrumentation", "execution"),
    "T1053.005": ("Scheduled Task", "persistence"),
    "T1055": ("Process Injection", "defense-evasion"),
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1059.001": ("PowerShell", "execution"),
    "T1059.003": ("Windows Command Shell", "execution"),
    "T1059.004": ("Unix Shell", "execution"),
    "T1068": ("Exploitation for Privilege Escalation", "privilege-escalation"),
    "T1071": ("Application Layer Protocol", "command-and-control"),
    "T1071.001": ("Web Protocols", "command-and-control"),
    "T1071.004": ("DNS", "command-and-control"),
    "T1078": ("Valid Accounts", "initial-access"),
    "T1082": ("System Information Discovery", "discovery"),
    "T1090": ("Proxy", "command-and-control"),
    "T1098": ("Account Manipulation", "persistence"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1110": ("Brute Force", "credential-access"),
    "T1112": ("Modify Registry", "defense-evasion"),
    "T1133": ("External Remote Services", "initial-access"),
    "T1140": ("Deobfuscate/Decode Files or Information", "defense-evasion"),
    "T1189": ("Drive-by Compromise", "initial-access"),
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1195": ("Supply Chain Compromise", "initial-access"),
    "T1195.002": ("Compromise Software Supply Chain", "initial-access"),
    "T1203": ("Exploitation for Client Execution", "execution"),
    "T1204": ("User Execution", "execution"),
    "T1204.001": ("Malicious Link", "execution"),
    "T1204.002": ("Malicious File", "execution"),
    "T1218": ("System Binary Proxy Execution", "defense-evasion"),
    "T1218.005": ("Mshta", "defense-evasion"),
    "T1218.007": ("Msiexec", "defense-evasion"),
    "T1486": ("Data Encrypted for Impact", "impact"),
    "T1489": ("Service Stop", "impact"),
    "T1490": ("Inhibit System Recovery", "impact"),
    "T1496": ("Resource Hijacking", "impact"),
    "T1498": ("Network Denial of Service", "impact"),
    "T1505.003": ("Web Shell", "persistence"),
    "T1518.001": ("Security Software Discovery", "discovery"),
    "T1543": ("Create or Modify System Process", "persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1548": ("Abuse Elevation Control Mechanism", "privilege-escalation"),
    "T1552": ("Unsecured Credentials", "credential-access"),
    "T1557": ("Adversary-in-the-Middle", "credential-access"),
    "T1560": ("Archive Collected Data", "collection"),
    "T1562.001": ("Disable or Modify Tools", "defense-evasion"),
    "T1566": ("Phishing", "initial-access"),
    "T1566.001": ("Spearphishing Attachment", "initial-access"),
    "T1566.002": ("Spearphishing Link", "initial-access"),
    "T1567": ("Exfiltration Over Web Service", "exfiltration"),
    "T1573": ("Encrypted Channel", "command-and-control"),
    "T1574.002": ("DLL Side-Loading", "persistence"),
    "T1583": ("Acquire Infrastructure", "resource-development"),
    "T1587.001": ("Develop Capabilities: Malware", "resource-development"),
    "T1588.006": ("Obtain Capabilities: Vulnerabilities", "resource-development"),
    "T1595": ("Active Scanning", "reconnaissance"),
    "T1598": ("Phishing for Information", "reconnaissance"),
}

# phrase-pattern -> technique id. Patterns are matched with word boundaries,
# case-insensitively. Order matters: more specific patterns first, and a
# technique is only added once.
_LEXICON: list[tuple[str, str, Confidence]] = [
    (r"spear[- ]?phishing (?:e-?mails? with )?attachments?", "T1566.001", Confidence.HIGH),
    (r"spear[- ]?phishing links?", "T1566.002", Confidence.HIGH),
    (r"phishing", "T1566", Confidence.MEDIUM),
    (r"smishing|vishing", "T1566", Confidence.MEDIUM),
    (r"zero[- ]click", "T1203", Confidence.HIGH),
    (r"drive[- ]by", "T1189", Confidence.HIGH),
    (r"exploit(?:ed|ing|s)? (?:a |an )?(?:public[- ]facing|internet[- ]facing|exposed)", "T1190", Confidence.HIGH),
    (r"supply[- ]chain (?:attack|compromise)", "T1195", Confidence.HIGH),
    (r"malicious (?:npm|pypi|nuget|package|dependency)", "T1195.002", Confidence.HIGH),
    (r"powershell", "T1059.001", Confidence.HIGH),
    (r"cmd\.exe|command shell", "T1059.003", Confidence.MEDIUM),
    (r"bash script|shell script", "T1059.004", Confidence.MEDIUM),
    (r"\bwmi\b|windows management instrumentation", "T1047", Confidence.HIGH),
    (r"macro[- ]enabled|malicious (?:document|attachment|file)|weaponized document", "T1204.002", Confidence.MEDIUM),
    (r"process (?:injection|hollowing)", "T1055", Confidence.HIGH),
    (r"dll side[- ]?loading", "T1574.002", Confidence.HIGH),
    (r"web ?shell", "T1505.003", Confidence.HIGH),
    (r"scheduled tasks?", "T1053.005", Confidence.MEDIUM),
    (r"run keys?|startup folder", "T1547.001", Confidence.HIGH),
    (r"obfuscat|packed payload|packer", "T1027", Confidence.MEDIUM),
    (r"disabl(?:e[sd]?|ing) (?:edr|antivirus|defender|security tools?)", "T1562.001", Confidence.HIGH),
    (r"mshta", "T1218.005", Confidence.HIGH),
    (r"msiexec", "T1218.007", Confidence.HIGH),
    (r"lsass|credential dump|mimikatz", "T1003.001", Confidence.HIGH),
    (r"brute[- ]forc|password spray|credential stuffing", "T1110", Confidence.HIGH),
    (r"stolen credentials|compromised (?:credentials|accounts?)|valid accounts?", "T1078", Confidence.MEDIUM),
    (r"adversary[- ]in[- ]the[- ]middle|\baitm\b|man[- ]in[- ]the[- ]middle", "T1557", Confidence.HIGH),
    (r"\brdp\b|remote desktop", "T1021.001", Confidence.MEDIUM),
    (r"\bsmb\b|admin(?:istrative)? shares?|psexec", "T1021.002", Confidence.MEDIUM),
    (r"\bvpn\b (?:appliance|gateway|access)|external remote services", "T1133", Confidence.MEDIUM),
    (r"lateral movement", "T1021", Confidence.MEDIUM),
    (r"privilege escalation", "T1068", Confidence.MEDIUM),
    (r"c2|command[- ]and[- ]control|beacon(?:ing)?", "T1071", Confidence.MEDIUM),
    (r"dns tunnel", "T1071.004", Confidence.HIGH),
    (r"download(?:s|ed|er)? (?:a |the )?(?:second[- ]stage|payload|additional tools?)", "T1105", Confidence.MEDIUM),
    (r"exfiltrat", "T1041", Confidence.MEDIUM),
    (r"data theft|st(?:eal|ole)(?:s|n)? (?:sensitive )?data", "T1005", Confidence.MEDIUM),
    (r"ransomware|encrypt(?:s|ed|ing)? (?:files|data|systems)", "T1486", Confidence.HIGH),
    (r"delet(?:e[sd]?|ing) (?:volume )?shadow cop(?:y|ies)|vssadmin", "T1490", Confidence.HIGH),
    (r"cryptomin|coin ?miner|cryptojack", "T1496", Confidence.HIGH),
    (r"\bddos\b|denial[- ]of[- ]service", "T1498", Confidence.HIGH),
    (r"port scan|mass[- ]scan|active scanning", "T1595", Confidence.MEDIUM),
    (r"registry modification|modif(?:y|ies|ied) (?:the )?registry", "T1112", Confidence.MEDIUM),
]

_RE_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Keyword-proximity matching has no grasp of grammar: "no confirmed ransomware
# impact", "has not been observed deploying ransomware", and "T1486 ... was
# considered and rejected" all contain the same bare keywords as a genuine
# positive finding. _is_negated() scopes a negation search to the sentence
# enclosing the match, so a negation elsewhere in the document doesn't
# suppress an unrelated, genuinely positive statement.
#
# A markdown table row is also its own clause boundary, not just `.!?` and
# blank lines: a multi-row table (e.g. a MITRE ATT&CK Mapping table) has no
# terminal punctuation between rows, so without this a hedge word in ANY
# row's Evidence cell ("not explicitly confirmed") silently suppressed every
# OTHER technique ID cited elsewhere in the same table, including ones with
# a fully clean, unhedged citation of their own — found running a real
# published report (SA-2026-0001) through the knowledge graph for the first
# time (GIKEP v1). GFM table rows reliably end in a trailing ` |`.
#
# COMMERCIAL-QUALITY-2026-08-18: rendered HTML report text ends sentences
# like "...observed child-process execution.</div>" -- punctuation
# immediately followed by a closing tag, never by whitespace. The original
# `[.!?](?:\s|$)` alternative requires whitespace or end-of-string right
# after the punctuation, so it never fired there; the boundary scan then
# ran straight through the tag change into the NEXT, structurally separate
# paragraph -- the standard "Mappings are conditional analytical aids, not
# claims that the technique occurred" disclaimer -- and _is_negated()
# matched its "not" against a citation the disclaimer wasn't talking
# about, negating a clean, unhedged technique citation. Found running a
# real composed CVE report through map_techniques() for the first time.
_RE_SENTENCE_BOUNDARY = re.compile(r"[.!?](?:\s|$|(?=<))|\n\s*\n|\|[ \t]*\n")
_RE_NEGATION_CUE = re.compile(
    r"\b(?:no|not|none|never|without|lacks?|absent|ruled out|rejected)\b|n't\b",
    re.IGNORECASE,
)


def _clause_span(text: str, pos: int) -> tuple[int, int]:
    """Start/end offsets of the sentence in `text` that contains `pos`."""
    start = 0
    for b in _RE_SENTENCE_BOUNDARY.finditer(text, 0, pos):
        start = b.end()
    end_match = _RE_SENTENCE_BOUNDARY.search(text, pos)
    end = end_match.start() if end_match else len(text)
    return start, end


def _is_negated(text: str, match: re.Match) -> bool:
    start, end = _clause_span(text, match.start())
    return bool(_RE_NEGATION_CUE.search(text[start:end]))


def is_valid_technique_id(technique_id: str) -> bool:
    """Format-valid AND present in the curated Enterprise subset."""
    return technique_id in KNOWN_TECHNIQUES


def extract_technique_ids(text: str) -> list[str]:
    """Pull explicit Txxxx(.yyy) references out of text."""
    return sorted({m.group(0) for m in _RE_TECHNIQUE_ID.finditer(text)})


def map_techniques(text: str) -> list[TechniqueMapping]:
    """Map source text to ATT&CK techniques with per-mapping evidence."""
    mappings: dict[str, TechniqueMapping] = {}

    for pattern, tid, confidence in _LEXICON:
        if tid in mappings:
            continue
        match = None
        for m in re.finditer(pattern, text, re.IGNORECASE):
            if not _is_negated(text, m):
                match = m
                break
        if match is None:
            continue
        name, tactic = KNOWN_TECHNIQUES[tid]
        start = max(0, match.start() - 50)
        evidence = " ".join(text[start : match.end() + 50].split())
        mappings[tid] = TechniqueMapping(
            technique_id=tid,
            name=name,
            tactic=tactic,
            evidence=evidence,
            confidence=confidence,
        )

    # Explicit technique IDs cited in the source are high-confidence evidence
    # — unless EVERY citation of that ID is negated ("T1486 ... was ...
    # rejected"). RX-P1I fix: this used to check only the first occurrence
    # of a given ID (`next(...)`) -- an early negated mention ("T1486 was
    # considered and rejected") silently suppressed a genuinely supported,
    # non-negated citation of the same ID appearing later in the same
    # document, exactly the false-negative risk commercial_readiness.py's
    # new detection_evidence_discipline hard gate (RX-P1I) can't afford: a
    # real citation wrongly reported as "no evidence" would incorrectly
    # block a legitimately well-evidenced report. Mirrors the phrase-lexicon
    # loop above, which already got this right.
    for tid in extract_technique_ids(text):
        if tid in mappings or tid not in KNOWN_TECHNIQUES:
            continue
        occurrences = [m for m in _RE_TECHNIQUE_ID.finditer(text) if m.group(0) == tid]
        if occurrences and all(_is_negated(text, m) for m in occurrences):
            continue
        name, tactic = KNOWN_TECHNIQUES[tid]
        mappings[tid] = TechniqueMapping(
            technique_id=tid,
            name=name,
            tactic=tactic,
            evidence=f"technique ID {tid} cited explicitly in source",
            confidence=Confidence.HIGH,
        )

    return sorted(mappings.values(), key=lambda t: t.technique_id)
