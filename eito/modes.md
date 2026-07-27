# EITO — SPECIALIZED OPERATING MODES

Six modes, one governance model (`lifecycle.md` applies to all of them
identically). A mode is a focus lens, not a different rulebook — it changes
which questions get emphasized in Stages 1, 3, 6, and 8; it never relaxes
Stage 7's engineering validation or the no-fabrication rule.

Pick a mode from the task's actual deliverable (Stage 1), not from which
directory happens to be open. A task can span modes — say so rather than
forcing a single label.

| Mode | Focus | Where its concrete mechanism lives |
|---|---|---|
| **CTI Mode** | Threat actors, malware, campaigns, vulnerabilities, incidents, intelligence reports | `Sentinel-APEX/prompts/`, `Sentinel-APEX/eios/` (all 14 layers apply) |
| **Detection Engineering Mode** | Sigma, YARA, SIEM queries, detection logic, hunting hypotheses | EIOS Layer 6 (maturity model), Layer 4 (`quality.py` validators), `Sentinel-APEX/{sigma,yara,kql,suricata,osquery}/` |
| **DFIR Mode** | Incident analysis, forensics, root cause, containment, recovery | `Sentinel-APEX/templates/ir/incident-response-playbook.md`, `malware-prompt.md` §§33–36 IR Guidance |
| **Executive Intelligence Mode** | Risk, business impact, strategic recommendations, board communication | `Sentinel-APEX/templates/executive/`, `templates/board/` (EIOS Layer 5), EIOS Layer 10 (commercial scoring) |
| **Platform Architecture Mode** | Repository design, APIs, object models, validation engines, automation | `CLAUDE.md` Architecture Preservation Rule, EIOS Layer 3 (object model), Layer 12 (API schema) |
| **Product Strategy Mode** | Product roadmap, commercial positioning, packaging, licensing, customer experience | `CLAUDE.md` Commercial-Value layers, EIOS Layer 10 (tiering), `BUSINESS-TRANSFORMATION-ROADMAP-2026.md` |

## Mode selection is not exclusive

A task like "add a new detection format to the CVE report pipeline" is
simultaneously CTI Mode (it's a CVE report) and Detection Engineering Mode
(it's a new artifact format) and, if it touches `quality.py`, Platform
Architecture Mode (it's a validation-engine change). Run Stage 3's Impact
Analysis across every mode the task actually touches — naming only one mode
when two apply is how a commercial or architectural consideration gets
silently dropped.

## Platform Architecture Mode and Product Strategy Mode are not CTI-specific

These two modes are why EITO lives at the repository root
(`eito/README.md` § Placement) rather than under `Sentinel-APEX/`: they
apply to the blog itself — pricing pages, the billing API, the Next.js/static
build, the newsletter funnel — exactly as much as to the Sentinel-APEX
engine. A request to redesign `pricing.html` is Product Strategy Mode with
zero CTI content in scope.

---
*CyberDudeBivash® Sentinel APEX — EITO Operating Modes*
