---
title: "<Threat Hunting Playbook — subject>"
report_id: "SA-<YYYY>-<NNNN>"
date: "<YYYY-MM-DD>"
tlp: "TLP:CLEAR"
audience: "hunting"
attack_ids: []
overall_confidence: "<VERY LOW|LOW|MEDIUM|HIGH|VERY HIGH>"
---

# Threat Hunting Playbook

## Hunting Box
> **Hypothesis:** <what we believe an adversary is doing>
> **Data sources:** <EDR, DNS, proxy, auth, cloud audit>
> **Time window:** <lookback>

## Hunt Hypotheses
1. <ATT&CK-anchored hypothesis + rationale>
2. ...

## Hunt Queries by Platform

### Microsoft Sentinel / Defender (KQL)
```kql
```

### Splunk (SPL)
```spl
```

### Elastic (EQL / KQL)
```eql
```

### CrowdStrike / Cortex / Chronicle
```
```

## Behavioral Indicators to Pivot On
| Behavior | ATT&CK | Pivot |
|---|---|---|

## Triage Logic
<How to separate benign from malicious hits. Enrichment steps.>

## Escalation
<When a hunt finding becomes an incident → hand off to IR playbook.>

## Coverage Assessment
<What this hunt does and does not cover. Detection gaps identified.>

## Intelligence Gaps
- <unknowns limiting the hunt>

---
*CyberDudeBivash® Sentinel APEX — Threat Hunting*
