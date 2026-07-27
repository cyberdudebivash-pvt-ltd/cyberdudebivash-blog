> ⚠ **Superseded** — see `prompts/README.md` and
> `Sentinel-APEX/eios/layer-04-quality-gates.md` /
> `Sentinel-APEX/eios/layer-10-commercial-readiness.md`. This file's
> "Automated failure detectors" (hype language, unsupported numeric claims)
> were genuinely new and have been implemented as an executable gate in
> `Sentinel-APEX/engine/sentinel_engine/quality.py` — the rest of this
> checklist is covered by `Sentinel-APEX/quality/quality-gate.md`.

# SENTINEL APEX™ — EDITORIAL QA & PUBLICATION GATE

**Version:** 1.0
**Status:** Active · Layer 5 of 5 · Runs on every draft before publication
**Purpose:** Independent quality control — factual consistency, unsupported-claim
detection, evidence verification, style, SEO, and a numeric publication score.

> Run this as a *separate pass* from writing. The QA reviewer is adversarial: its
> job is to find reasons **not** to publish.

---

## Publication checklist (all must pass)

- [ ] **Evidence complete** — every material claim traces to a source or is
      labeled Hypothesis / Unknown / Intelligence Gap.
- [ ] **Claims supported** — no assertion exceeds its evidence; no severity
      inflation; no fear language.
- [ ] **Evidence classes not mixed** — each statement is cleanly one class.
- [ ] **Confidence assigned** — all six dimensions present, each with a rationale.
- [ ] **References validated** — every CVE/KEV/advisory link resolves to the
      claimed record; no invented references.
- [ ] **No fabrication** — CVEs, IOCs, actors, campaigns, MITRE mappings, and
      detection logic are all real and verifiable.
- [ ] **Executive summary accurate** — matches the body; leads with significance
      and the decision, not the description.
- [ ] **Technical guidance actionable** — a SOC analyst can act on it today.
- [ ] **Detection content useful & justified** — rules are sound; detection
      confidence labeled.
- [ ] **Business impact realistic** — proportionate, sector-aware, not generic.
- [ ] **SEO clean** — enterprise search intent served; no keyword stuffing;
      structured metadata and internal links present.
- [ ] **Editorial quality** — clear, precise, professional; audience layers
      distinct.

**If any check fails → return to draft. Never publish unfinished intelligence.**

---

## Automated failure detectors (flag on match)

- Absolute exploitation claims ("actively exploited", "in the wild") **without**
  a KEV listing or a cited credible source.
- Superlatives and hype ("catastrophic", "the worst ever", "unprecedented")
  without evidence.
- Any CVE/CWE/CVSS value not matching its primary record.
- Detection rules with no logsource, no condition, or untunable breadth.
- Marketing claims embedded in analytical prose.
- Templated content presented as observed per-incident activity.
- Numbers (victim counts, dollar figures, subscriber counts) stated as fact
  without a source.

## Publication score (0–100)

| Dimension | Weight |
|---|---|
| Evidence integrity (sourcing, no fabrication, correct primary values) | 30 |
| Decision value (prioritization, actionable guidance, executive clarity) | 25 |
| Analytical quality (correlation, significance, confidence rigor) | 20 |
| Detection & technical usefulness | 10 |
| SEO & structure | 10 |
| Editorial quality | 5 |

**Threshold: publish only at ≥ 85.** Evidence-integrity failures are
disqualifying regardless of total score — a report that fabricates or mis-states
a primary value cannot publish even if everything else is perfect.

## Output of the QA pass

Return: pass/fail, the numeric score with per-dimension breakdown, and a list of
specific fixes for any failed item. On fail, the draft returns to Stage 9 (WRITE)
of the Production Workflow.

---

### Changelog
- **v1.0** — Initial QA gate: checklist, automated failure detectors, weighted
  publication score (threshold 85; evidence-integrity failures disqualifying).
