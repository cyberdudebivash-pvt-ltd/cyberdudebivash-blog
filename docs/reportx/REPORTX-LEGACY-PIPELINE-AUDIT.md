# Legacy High-Volume Pipeline — Quality Audit

Audits the 11 sample reports supplied for this task (8 CVE advisories, 3
ransomware victim-claim posts, 1 CISA KEV catalog update — all published
2026-08-17/18) against the MISSION standard (analyst-grade, evidence-
traceable, non-repetitive commercial CTI). Every finding below is backed by
a direct code read or a direct grep of `logs/run-*.json`, not an inference
from the 11 samples alone — the samples are corroborating evidence, not the
sole evidence.

**Read alongside**: `CANONICAL-WRITER-TRACE.md` (the five-system map this
audit extends with one correction — see below), `REPORTX-CANARY-CERTIFICATION.md`
and `REPORTX-RELEASE-CERTIFICATION.md` (the evidence-first engine this
audit recommends connecting to this pipeline).

---

## Correction to the prior system trace

`CANONICAL-WRITER-TRACE.md` attributes the motivating boilerplate strings
("Executive Decision Matrix", "Campaign continuation (HIGH CONFIDENCE)") to
`automation/authority_transformer.py` and leaves `automation/report_renderer.py`
/ `automation/report_integrity.py` untraced. Both files exist at this SHA
and are directly relevant:

- `automation/authority_transformer.py` **imports and calls**
  `report_renderer.render_evidence_report()` internally (`_template_enhance()`,
  line 1759) — it is not an independent, unrelated writer; it is a superset
  that wraps `report_renderer.py`'s evidence-gated core in additional
  sections.
- A code comment the pipeline's own authors left in place
  (`authority_transformer.py:1747-1758`) documents the actual history:
  between commit `0a4b2df` and a change labeled `RX-PR0`, the clean,
  evidence-only renderer (`report_renderer.py` → `render_evidence_report()`)
  **was** the sole production path. `RX-PR0` restored the older, thicker
  `_legacy_template_enhance()` template specifically "so every report gets
  full commercial depth" — trading a thinner-but-honest report for a
  longer-but-generic one. The comment explicitly flags
  `render_evidence_report()` as "a candidate input for the RX-PR2 canonical
  contract" that nothing in production currently calls. This audit is,
  functionally, the overdue RX-PR2 follow-through.

---

## Finding 1 — 97.6% of all historically generated reports never used the LLM path

`automation/authority_transformer.py`'s `transform()` tries `call_llm()`
(Groq → DeepSeek → OpenRouter → Anthropic, `automation/config.py`'s
priority order) first; only on failure does it fall back to
`_legacy_template_enhance()`, a fully deterministic, hardcoded HTML
template. Both paths are logged per-article as `content_source` in every
`logs/run-*.json` run report. Counted directly across all 4,253 run-report
files in this repository:

| `content_source` | Count | Share |
|---|---:|---:|
| `template` (deterministic fallback) | 33,470 | **97.6%** |
| `groq` (LLM succeeded) | 704 | 2.0% |
| `openrouter` (LLM succeeded, fallback provider) | 138 | 0.4% |
| `evidence_safe_template` | 43 | 0.1% |

All 11 of the samples supplied for this task independently confirm this —
every one carries the fallback template's exact fingerprint phrases
("Based on historical patterns for vulnerabilities in this class...",
"Ransomware encryption of production systems carries average recovery
costs exceeding $1.85M (Sophos State of Ransomware 2024)"), verified by
direct grep against all 11 files. **This is not a sampling artifact — it
is the overwhelming statistical norm for this pipeline's entire operating
history**, and it means the "LLM-authored, commercially rich" path this
pipeline was designed around effectively does not run in production. A
pipeline redesign that only tries to raise the LLM path's success rate
would still leave ~98% of report-days exposed to the same defect; the
deterministic path itself has to stop being generic.

## Finding 2 — the deterministic fallback repeats identical analytical prose across unrelated incidents

Confirmed both by direct code read (`_legacy_template_enhance()`,
`authority_transformer.py:723-1740`) and by diffing the 11 samples against
each other. Concrete instances:

- **Predictive Intelligence**: "Active exploitation escalation (HIGH
  CONFIDENCE): Based on historical patterns for vulnerabilities in this
  class, `{CVE_ID}` will be incorporated into exploit kits and automated
  scanning tools within 72 hours of PoC publication..." — appears
  byte-identical (CVE ID substituted) in CVE-2026-74899, CVE-2025-62593,
  and CVE-2026-75094, three vulnerabilities in unrelated products (a
  Python sandbox library, a distributed-compute framework, a router CGI
  interface) with no shared exploitation history to support a shared
  forecast.
- **Business Impact**: the same "$1.85M (Sophos State of Ransomware
  2024)" figure and the same GDPR/NIS2 sentence appear verbatim across
  `play`/Bridgeport Capital, `qilin`/EmpireWorks, and `incransom`/Third
  Coast Bancshares — three different actors, three different sectors
  (financial services, unspecified, financial services), zero
  victim-specific quantification.
- **MSSP Partner Advisory**: identical paragraph, down to the exact Sigma
  technique IDs cited (T1486/T1490/T1021.002), across all three
  ransomware samples regardless of which techniques the specific actor is
  actually associated with.
- **Executive Decision Matrix**: identical four-row P0-P2 table (same
  owners, same timelines, same wording) across every CVE sample
  regardless of exploit maturity, patch availability, or actual technical
  differences between the vulnerabilities.

This is precisely "generic AI-generated text" / "repetitive language" the
MISSION prohibits — except it is not AI-generated at all; it is static
Python string literals with a single variable substituted.

## Finding 3 — no source-reliability grading

Neither `report_renderer.py` nor `authority_transformer.py` computes or
renders an Admiralty Code (A-F reliability / 1-6 credibility) or any
equivalent per-source grading. `DiscoveredArticle` (`content_discovery.py`)
carries a `source` field (`nvd`, `cisa_kev`, `ransomware_intel`,
`cisa_advisory`) used only for routing, never surfaced to the reader as a
reliability signal.

## Finding 4 — MITRE ATT&CK coverage is real but shallow, and the fallback path duplicates it worse

`report_renderer.py`'s `_detection_package()` maps a genuine, evidence-
conditioned ATT&CK technique per vulnerability class (T1190 for SQLi/path
traversal/SSRF, T1059 for command injection, T1499 for DoS, T1068 for
privilege escalation, T1078 for auth bypass) with an explicit
non-promotion caveat ("conditional analytical aid, not a claim the
technique occurred"). This is genuinely good, ReportX-adjacent discipline.
But: (a) it is single-technique per report, never a kill-chain or Diamond
Model view; (b) `_legacy_template_enhance()`'s own "MITRE Correlation"
block is a **static marketing tile** ("Automated technique mapping with
detection gap analysis vs. your SIEM coverage...") that asserts a
capability rather than rendering one; (c) no D3FEND, CWE↔CAPEC, Pyramid of
Pain, or Cyber Kill Chain mapping exists anywhere in either path.

## Finding 5 — no role-differentiated executive guidance

Every sample has exactly one generic "Executive Decision Matrix" (four
rows, owners named only by title — "CISO/IT Operations", "CEO/CFO/CISO")
and one "MSSP Partner Advisory" paragraph. The MISSION's role list (CEO,
Board, CISO, CIO, SOC Manager, IR Manager, Threat Hunter, Vulnerability
Manager, Cloud Team, OT Team, Legal, Compliance, Privacy, Business
Continuity, Supply Chain, MSSP) is not represented as distinct sections
anywhere in the pipeline.

## Finding 6 — no threat-hunting hypothesis structure

Neither renderer emits hypotheses, required telemetry, pivot
opportunities, negative indicators, false-positive considerations, or
validation/success criteria. `report_renderer.py`'s `DetectionPackage.telemetry`
tuple is the closest analog (a short "what to collect" list) but stops
well short of a hunting hypothesis.

## Finding 7 — Predictive Intelligence has no timeframe ladder and static confidence

The fallback template emits exactly 2-3 forecasts per report with
hand-assigned confidence labels baked into the template string itself
(not derived from any evidence property of the specific report). The
MISSION's 24h/72h/7d/30d/90d ladder does not exist in either renderer.

## Finding 8 — no sector-differentiated impact analysis

"Healthcare, financial services, technology, and government sectors" is
named identically across every CVE sample as a flat list, not a
per-sector exposure/regulatory-obligation breakdown (the MISSION's
Healthcare/Finance/Government/Manufacturing/Retail/Energy/CI/Tech/
Cloud/Education/Telecom differentiation).

## Finding 9 — marketing content is interleaved inside the analytical body

`_build_risk_command_center()` (`authority_transformer.py:544`) and
similar functions insert "Request Vulnerability Scan →", "Get Ransomware
Assessment →", and "🎯 Recommended For This Threat" cross-sell blocks
directly between the risk-command-center header and the Executive Summary
— before the reader reaches any actual analysis. This directly violates
the MISSION's "avoid marketing language inside analytical sections."

## Finding 10 — self-referential provenance language substitutes for real sourcing

"TYPE ... — derived from article classification and content analysis",
"CVE ... — extracted from article content" describe the PIPELINE's own
extraction mechanism, not the underlying evidentiary basis for the fact.
This is meta-commentary, not source attribution — contrast with
ReportX's `SourceRecord` (publisher, URL, retrieval timestamp, content
hash, reliability tier) as the actual target shape.

---

## What is already correct and must be preserved (Reuse Before Build)

The audit is not "rebuild everything." Real, working discipline already
exists and should be extended, not replaced:

- **`automation/report_integrity.py`'s `validate_publication()`** is a
  genuine fail-closed gate: blocks missing provenance, sub-3000-char
  bodies, placeholder text, unsupported commercial-scale claims,
  KEV/exploitation contradictions, ransomware/AI schema contamination, and
  **fabricated human-analyst attribution** ("blocks if 'Bivash Kumar Nayak
  — Chief Security Architect' appears without a review event" —
  line 308-309). All 11 samples pass this gate today; the gate itself is
  sound and should remain the floor, not be replaced.
- **`automation/legacy_quality_auditor.py`** already does retroactive
  quarantine of historically-published posts that fail these same
  integrity checks, with a transparent, source-preserving withdrawal
  notice (never silent deletion) — this is exactly the Deprecation
  Instead of Deletion discipline this repository's own CLAUDE.md requires
  elsewhere.
- **Every sample's own footer already self-certifies honestly**: "Review
  status: Automated intelligence synthesis — not human reviewed" /
  "Certification: Public reference draft — not a certified customer
  deliverable." This is, functionally, `human_review.CertificationState.PUBLIC_REFERENCE_DRAFT`
  already — the pipeline does not lie about its own certification tier.
- **`report_renderer.py`'s vulnerability-class-conditional analysis and
  detection package** (Finding 4) is real, evidence-gated content, not
  boilerplate — it should be the connective tissue between raw source data
  and a richer downstream engine, not discarded.
- **Every source is already SHA-256 hashed** (`report_integrity.py`'s
  `_record_hash()`) and every report ID is deterministically derived from
  that hash — real provenance infrastructure exists; it is only the
  reliability *grading* on top of it (Finding 3) that is missing.

## Root cause, stated plainly

This is not a prompt-engineering problem and not a template-polish
problem. It is an **architecture gap**: no claim/evidence model connects
the deterministic fallback's variables to per-report-specific analytical
text. The fallback was written as static prose with slots for a CVE ID or
victim name, not as a real generator over structured evidence — so the
prose is exactly as generic as a template with three inputs (severity,
family, entity name) can be. `sentinel_engine.reportx` (ReportX/System 3),
matured substantially this repository's own history (four real 23/23
premium canaries, now a release/automated-certification layer), is the
one system in this repository that already has the claim/evidence/
confidence structure needed to generate genuinely per-report analysis at
this volume — but it has never been connected to this pipeline. See
`REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md` for the proposed
connection.
