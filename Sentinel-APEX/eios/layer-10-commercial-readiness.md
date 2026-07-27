# EIOS LAYER 10 — COMMERCIAL READINESS

The final publication gate. This is the layer most at risk of being
reinvented as a prose checklist when a working, tested, deterministic
scoring engine already exists —
`engine/sentinel_engine/scoring.py`. Read this layer before writing a new
commercial-readiness mechanism.

## What already exists

`scoring.py::score()` computes nine weighted dimensions from artifacts the
pipeline already produced — no new claims, no model call, fully
reproducible (`test_scoring.py::test_scoring_is_deterministic`):

| Dimension | Weight | What it measures |
|---|---|---|
| Evidence Quality | 0.22 | Source attribution, CVE count, IOC count, successful enrichments, entities, techniques |
| Original Analysis | 0.18 | Technique correlation, historical/prior-context correlation (Layer 9), derived detection engineering, multi-entity correlation |
| Detection Value | 0.15 | Number of detection formats emitted, Suricata rule count |
| SOC Value | 0.10 | Half of detection value, plus network IOCs and hunt-hypothesis-bearing techniques |
| DFIR Value | 0.06 | Forensic-tactic techniques (credential access, persistence, defense evasion, lateral movement, etc.), host-based IOCs |
| Executive Value | 0.10 | CISA KEV status, max CVSS, presence of named actors/malware |
| Commercial Value | 0.08 | Which product lines this report justifies (detection pack, intel API/IOC feed, APT consulting, vuln advisory) |
| Analyst Confidence | 0.06 | See Layer 7, mechanism 2 |
| SEO Value | 0.05 | Title length, CVE presence, vendor/product entities, technique/entity density, source attribution |

`overall = Σ(dimension × weight)`, clamped 0–100. **Publication eligibility**
is `overall >= threshold (default 60) AND quality_gate.passed` — a report
cannot buy its way past a correctness failure with a high score; see Layer 4
for why these are separate gates.

## Commercial tiering

The overall score and detection value jointly decide the commercial tier
(`scoring.py::_tier()`):

| Tier | Condition |
|---|---|
| `ENTERPRISE` | overall ≥ 82 **and** detection_value ≥ 60 |
| `PRO` | overall ≥ 70 |
| `FREE` | eligible but below PRO threshold |
| `BLOCKED` | ineligible (below score threshold or gate failed) |

This is not aspirational — `pipeline.py::render_draft()` already prints the
score table and PUBLISH/HOLD decision directly into the generated draft
under "## Intelligence Score." Every report produced through `cli.py run` or
`cli.py score` carries this today.

## What this layer adds

The v2 specification's checklist (technical accuracy, evidence completeness,
editorial quality, consistent terminology, actionable recommendations,
executive clarity, detection completeness) splits into what the score
already measures and what still requires human judgment:

| Checklist item | Covered by `scoring.py`? | If not, where |
|---|---|---|
| Evidence completeness | Yes — `evidence_quality` | |
| Detection completeness | Yes — `detection_value`, `soc_value` | |
| Actionable recommendations | Partially — `executive_value`, `commercial_value` proxy this | Human review: is the recommendation *specific* (Layer 4's SLA-not-"patch promptly" rule)? |
| Technical accuracy | No — score measures *presence* of analysis, not its correctness | `quality/quality-gate.md` §1–3 (Evidence Integrity, Analytical Discipline, Framework Accuracy) + human review |
| Editorial quality | No | `quality/quality-gate.md` §8 + Layer 13 (Editorial Style Guide) |
| Consistent terminology | No | Layer 13, tied to `entities.py`'s canonical-name lexicon |
| Executive clarity | Partially — `executive_value` measures content, not clarity of prose | Human review |

**The score is necessary, not sufficient.** A report can score `ENTERPRISE`
tier and still fail human editorial review for clarity or terminology — run
both gates, always.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 10*
