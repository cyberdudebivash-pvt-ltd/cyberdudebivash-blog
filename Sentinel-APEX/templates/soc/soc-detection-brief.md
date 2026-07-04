---
title: "<SOC Detection Brief — subject>"
report_id: "SA-<YYYY>-<NNNN>"
date: "<YYYY-MM-DD>"
tlp: "TLP:CLEAR"
audience: "soc"
attack_ids: []
detection_confidence: "<VERY LOW|LOW|MEDIUM|HIGH|VERY HIGH>"
---

# SOC Detection Brief

## SOC Action Box
> **Detect:** <what to look for now>
> **Telemetry required:** <Sysmon EIDs, EDR events, proxy/DNS, cloud audit>
> **Priority:** <P1|P2|P3>

## Threat Summary
<3–5 sentences: actor/malware/CVE, behavior, why it is detectable.>

## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Detection surface |
|---|---|---|---|
| | | | |

## IOC Intelligence

### Confirmed IOCs
| Type | Value (defanged) | Role | First seen |
|---|---|---|---|

### Behavioral IOCs
- <process/registry/network behaviors>

## Detection Content

### Sigma
```yaml
# → Sentinel-APEX/sigma/<name>.yml
```

### Microsoft Sentinel / Defender KQL
```kql
// → Sentinel-APEX/kql/<name>.kql
```

### Splunk SPL
```spl
```

### Suricata
```
# → Sentinel-APEX/suricata/<name>.rules
```

## Expected False Positives
- <per rule>

## SOC Investigation Workflow
1. <triage step>
2. <scoping step>
3. <escalation criteria>

## Escalation Criteria
<When this becomes an IR incident.>

---
*CyberDudeBivash® Sentinel APEX — SOC Operations*
