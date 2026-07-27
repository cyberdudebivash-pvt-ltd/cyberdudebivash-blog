# EIOS LAYER 2 — INTELLIGENCE GOVERNANCE

Governs two things: the lifecycle every report moves through, and how every
claim inside a report is classified. Both are additive refinements of
existing, working process — not replacements.

---

## Part A — Intelligence Lifecycle

Every report passes through 10 conceptual stages. No stage is skipped.
These are a finer-grained breakdown of the 8 operational stages already
defined in `pipeline/WORKFLOW.md` — not a competing pipeline. Stages 4–7
below are sub-activities inside WORKFLOW's single "Draft" stage, made
explicit because they require different expertise (technical vs. strategic
vs. detection vs. executive framing) even when one analyst does all four.

| # | EIOS stage | Maps to `WORKFLOW.md` stage | Physical location |
|---|---|---|---|
| 1 | Collection | Stage 1 — Collect | sources recorded in draft front matter |
| 2 | Validation | Stage 2 — Normalize & Extract | `reports/drafts/` |
| 3 | Correlation | Stage 3 — Enrich (+ Layer 9 knowledge graph `prior_context`) | `reports/drafts/` |
| 4 | Technical Analysis | Stage 4 — Draft (attack chain, malware, detection) | `reports/drafts/` |
| 5 | Intelligence Analysis | Stage 4 — Draft (strategic assessment, landscape) | `reports/drafts/` |
| 6 | Detection Engineering | Stage 4 — Draft (Sigma/YARA/KQL/etc. emission) | `sigma/`, `yara/`, `kql/`, `suricata/`, `osquery/` |
| 7 | Executive Assessment | Stage 4 — Draft (exec summary, risk, board/CISO recs) | `reports/drafts/` |
| 8 | Quality Assurance | Stage 5 — Quality Gates | `cli.py gate`, then `reports/final/` |
| 9 | Publication | Stages 6–8 — Variants, SEO, Publish | `reports/published/` + blog |
| 10 | Continuous Updates | *(new — see Layer 11)* | `archive/` on supersession |

No report reaches `reports/final/` having skipped stage 8, and no report
reaches `reports/published/` having skipped stage 9. This is enforced today
by the physical directory convention in `docs/CONVENTIONS.md`; EIOS does not
change that enforcement mechanism, it names the stages more precisely.

## Part B — Evidence Classification

Every report already labels non-verified claims with an epistemic-status
word (`VERIFIED FACT`, `ANALYST ASSESSMENT`, `HYPOTHESIS`, `ESTIMATED`,
`LIKELY`, `POSSIBLE`, `UNCONFIRMED`, `UNKNOWN` — defined in
`prompts/master-prompt.md`). That vocabulary is load-bearing: the executable
gate (`engine/sentinel_engine/quality.py::_gate_confidence`) scans report
text for exactly these hedge words and requires a `(LOW|MEDIUM|HIGH
CONFIDENCE)` tag wherever they appear. **Do not remove or rename these
words** — doing so would silently defeat the gate (it would stop finding
assessments to check, producing false-negative passes on unlabeled claims).

EIOS v2 adds a second, independent dimension: **provenance** — what kind of
source produced the claim. Every significant statement carries both tags:

```
[<Provenance>] <claim>. [<Epistemic status>[, <CONFIDENCE LEVEL>]]
```

### Provenance categories

| Provenance | Meaning |
|---|---|
| Verified Evidence | Directly confirmed against primary source material (advisory, sample, log) |
| Observed Behavior | Directly observed in a sandbox, honeypot, or live telemetry |
| Vendor Statement | Asserted by the affected vendor, not independently verified |
| Open Source Intelligence | Public reporting, forums, social media — treated as a lead until corroborated |
| Telemetry Observation | Seen in the analyst's or a partner's own monitored environment |
| Reverse Engineering Finding | Derived from static/dynamic analysis of a sample |
| Analyst Assessment | Sentinel APEX interpretation beyond what any single source states |
| Working Hypothesis | A plausible explanation not yet corroborated |
| Unknown | Explicitly not known — stated, not omitted |

### Worked examples

> The loader injects into `explorer.exe` via process hollowing.
> **[Reverse Engineering Finding — VERIFIED FACT]**

> The operators are likely affiliated with a known ransomware-as-a-service
> program, based on TTP overlap with three prior campaigns.
> **[Analyst Assessment — LIKELY, MEDIUM CONFIDENCE]**

> A community forum post claims a second, unrelated group is exploiting the
> same flaw.
> **[Open Source Intelligence — UNCONFIRMED]**

### Why this is additive, not a replacement

Provenance answers "where did this come from." Epistemic status answers "how
sure are we." A vendor statement can be VERIFIED FACT (the vendor confirmed
it and nothing contradicts it) or UNCONFIRMED (the vendor asserted it and no
one has corroborated it independently) — provenance alone does not determine
confidence. Collapsing the two into one taxonomy, as a naive reading of "one
of the following" would do, would lose that distinction and break the
existing gate. Use both tags on every significant claim.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 2*
