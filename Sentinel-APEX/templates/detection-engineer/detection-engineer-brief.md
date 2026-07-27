---
title: "<Detection Engineering Brief — subject>"
report_id: "SA-<YYYY>-<NNNN>"
date: "<YYYY-MM-DD>"
tlp: "TLP:CLEAR"
audience: "detection-engineer"
attack_ids: []
---

# Detection Engineering Brief

> Different job from the SOC Detection Brief (`templates/soc/soc-detection-brief.md`):
> that one tells an analyst what to do when a rule fires. This one tells a
> detection engineer what to build, why, and how confident to be in it
> before it goes into a production ruleset.

## Coverage Objective
<What ATT&CK techniques/sub-techniques this detection content is meant to
cover, and what evidence justifies each one — see `master-prompt.md` §
TechniqueMapping: every technique carries its triggering evidence.>

## Detection Artifacts

| Format | Artifact | Maturity | Required telemetry |
|---|---|---|---|
| Sigma | | Reference \| Reviewed \| Tested \| Production Validated | |
| YARA | | | |
| KQL | | | |
| SPL | | | |
| EQL / ES\|QL | | | |
| Suricata | | | |

Maturity levels are defined in EIOS Layer 6
(`Sentinel-APEX/eios/layer-06-detection-engineering-standards.md`). Do not
mark anything "Production Validated" without a documented test against real
or synthetic telemetry — see that layer for what evidence each level requires.

## Known False-Positive Conditions
<Per artifact. If untested, say "untested" — don't guess a false-positive
rate.>

## Required Telemetry / Logging Gaps
<What logging must be enabled for this content to fire at all — e.g. Sysmon
Event ID 1 process creation, cloud audit logs, EDR process-tree events.>

## Tuning Notes
<Environment-specific exclusions expected. What's likely to need tuning
per-deployment and why.>

## Retirement / Supersession
<When should this rule be revisited or retired — e.g., tied to a technique
the actor is known to rotate away from. See EIOS Layer 11.>

---
*CyberDudeBivash® Sentinel APEX — Detection Engineering*
