# EIOS LAYER 5 — MULTI-AUDIENCE OUTPUT

Every audience view is derived from one underlying intelligence package —
never written independently. This is already implemented as
`Sentinel-APEX/templates/`, driven by the `audience_priority` field in
`prompts/report-prompt.md`'s input contract.

## Implemented

| Audience | Template | Distinguishing content |
|---|---|---|
| Executive Leadership / CISO | `templates/executive/executive-brief.md` | Bottom line up front, risk snapshot table, decision matrix, financial/regulatory exposure |
| SOC Analyst / Technical Analyst | `templates/soc/soc-detection-brief.md` | SOC action box, ATT&CK coverage table, detection content by platform, investigation workflow |
| Threat Hunter | `templates/hunting/threat-hunting-playbook.md` | Hunt hypotheses, hunt queries by platform, triage logic, coverage assessment |
| Incident Responder | `templates/ir/incident-response-playbook.md` | Containment/eradication/recovery sequencing |

## Added by this EIOS revision

Two audiences from the v2 specification had no distinct template — both were
previously folded into an adjacent one (Board into Executive, Detection
Engineer into SOC), which loses real distinctions in tone and content:

| Audience | Template | Why it's distinct from its nearest existing template |
|---|---|---|
| Board Summary | `templates/board/board-summary.md` | One page, no jargon, materiality/disclosure framing — the Executive Brief still assumes a security-literate reader who will act; the board reads to govern, not to act |
| Detection Engineer | `templates/detection-engineer/detection-engineer-brief.md` | Answers "what should I build and how sure am I in it" (coverage objective, maturity per Layer 6, false-positive conditions, retirement triggers) — the SOC brief answers "what do I do when this fires," a different question for a different job |

## Not duplicated

"Technical Analyst" from the v2 list is intentionally not a ninth template —
it is the audience the SOC Detection Brief already serves (the front matter
even carries `detection_confidence`, a technical-analyst-facing field). Two
templates for the same reader would violate Single Source of Truth; the SOC
brief's own front matter documents this.

## Rule

All eight views are generated **from** the full report (the 60-section
master structure) — a template file is a rendering lens, not an independent
authoring surface. An analyst-authored fact in an Executive Brief that
doesn't trace back to the full report's Verified Facts is a process
violation, not a shortcut.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 5*
