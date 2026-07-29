---
title: "<SOC Detection Brief — subject>"
report_id: "SA-<YYYY>-<NNNN>"
date: "<YYYY-MM-DD>"
tlp: "TLP:CLEAR"
audience: "soc"
attack_ids: []
overall_confidence: "<VERY LOW|LOW|MEDIUM|HIGH|VERY HIGH>"
detection_confidence: "<VERY LOW|LOW|MEDIUM|HIGH|VERY HIGH>"
---

# SOC Detection Brief

**`overall_confidence` added (GCIEP v1)** for consistency with every other
template's front matter — `detection_confidence` stays as this template's
own, narrower confidence-in-the-detection-content-specifically field; the
two are not redundant (a report can have high overall confidence in the
underlying finding while its detection rule is still experimental, or vice
versa) but every template must carry `overall_confidence` at minimum. See
`Sentinel-APEX/eios/sentinel-intelligence-standard.md`.

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
