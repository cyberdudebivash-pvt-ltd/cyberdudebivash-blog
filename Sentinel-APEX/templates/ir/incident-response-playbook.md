---
title: "<IR Playbook — subject>"
report_id: "SA-<YYYY>-<NNNN>"
date: "<YYYY-MM-DD>"
tlp: "TLP:CLEAR"
audience: "dfir"
overall_confidence: "<VERY LOW|LOW|MEDIUM|HIGH|VERY HIGH>"
---

# Incident Response Playbook

## IR Checklist (at-a-glance)
- [ ] Confirm infection / exploitation
- [ ] Scope affected assets and accounts
- [ ] Preserve evidence (memory, disk, logs)
- [ ] Contain
- [ ] Eradicate all persistence
- [ ] Rotate impacted credentials
- [ ] Recover and validate
- [ ] Post-incident review

## 1. Detection & Confirmation
<How to confirm from telemetry. Distinguish true positive from FP.>

## 2. Scoping
<Lateral movement indicators, blast-radius queries, account/asset enumeration.>

## 3. Evidence Preservation
| Artifact | Source | Priority |
|---|---|---|
| Volatile memory | | |
| Disk image | | |
| EDR timeline | | |
| Auth/cloud logs | | |

## 4. Containment Strategy
<Isolation order. Does the threat react to containment? Network vs host.>

## 5. Eradication Strategy
<Every persistence location. Payload removal. Backdoor account cleanup.>

## 6. Recovery Guidance
<Rebuild vs clean. Credential rotation scope. Validation before return to service.>

## 7. Ransomware-Specific (if applicable)
- Decryptor availability (source-verified only)
- Backup integrity validation
- Extortion / data-theft handling
- Recovery sequencing

## 8. Regulatory & Notification
<Breach-notification triggers, timelines, regulators, applicable law.>

## 9. Post-Incident
<Lessons learned, detection gaps to close, hardening actions.>

## Intelligence Gaps
- <unknowns affecting response>

---
*CyberDudeBivash® Sentinel APEX — DFIR*
