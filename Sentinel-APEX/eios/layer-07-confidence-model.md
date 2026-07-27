# EIOS LAYER 7 — INTELLIGENCE CONFIDENCE MODEL

Two distinct confidence mechanisms exist in this platform. Neither replaces
the other; conflating them is the most common way this layer gets
misapplied.

## Mechanism 1 — Analyst-declared, per-claim (prose)

Every significant claim in a report carries a confidence rating the analyst
assigns by judgment, alongside the evidence classification from Layer 2.
This EIOS revision supersedes v1's 8-dimension list
(`prompts/master-prompt.md` § Confidence Framework: Source / Collection /
Attribution / Detection / IOC / Exploit / Business Impact / Overall) with a
7-dimension model:

| Dimension | Question it answers |
|---|---|
| Source Confidence | How reliable is the originating source? |
| Evidence Confidence | How strong is the evidence itself, independent of source reliability? |
| Technical Confidence | How certain is the technical analysis (attack chain, malware behavior)? |
| Attribution Confidence | How certain is the actor/campaign attribution? |
| Detection Confidence | How certain is the detection engineer that the shipped content actually catches the behavior? |
| Operational Confidence | How certain is the recommended response (containment/eradication/patch guidance)? |
| Business Impact Confidence | How certain is the assessed business/financial/regulatory impact? |

Each dimension is rated `VERY LOW` / `LOW` / `MEDIUM` / `HIGH` / `VERY HIGH`
with a stated rationale — the rating word alone, without the "why," is not
compliant.

**Migration note:** v1's dimension list (Collection, IOC, Exploit
Confidence) is deprecated, not deleted. Reports already published under the
v1 model are not retroactively relabeled — the seven-dimension model applies
to reports produced from this revision forward. There is no executable-gate
dependency on the specific dimension names (the gate,
`quality.py::_gate_confidence`, only checks that *some* `(LOW|MEDIUM|HIGH
CONFIDENCE)` tag accompanies hedge language — see Layer 2 for why the hedge
vocabulary itself must not change), so this supersession is safe.

## Mechanism 2 — Machine-derived, per-report (code)

`engine/sentinel_engine/scoring.py::_analyst_confidence()` computes a single
deterministic 0–100 score from structured evidence already in the pipeline:
the average confidence of extracted `TechniqueMapping`s, whether CVE
enrichment succeeded, and whether the source is both URL- and
name-attributed (strong corroboration) or URL-only (weak). This is not a
replacement for the analyst's per-claim judgment above — it is a
reproducible cross-check computed from what the evidence layer actually
contains, with no LLM call and no new claims. See `test_scoring.py::
test_scoring_is_deterministic` for the guarantee: same input, same score,
always.

**Use both.** The prose dimensions are what a human reader sees and
evaluates per-claim. The machine score is what an automated pipeline can
recompute on every run to catch drift between what an analyst *says* their
confidence is and what the underlying evidence structurally supports (e.g.,
a report asserting `HIGH CONFIDENCE` attribution built from a single
unenriched, unattributed source would score low on `analyst_confidence`
despite the prose label — a legitimate discrepancy worth a second look, not
an automatic contradiction).

## Where this fits in the pipeline

`scoring.py::score()` combines `analyst_confidence` with eight other
dimensions into the overall publication score — see Layer 10 for that
composite and the commercial tiering it drives.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 7*
