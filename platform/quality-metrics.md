# EIPS — PLATFORM QUALITY METRICS

Genuinely different in kind from EIOS Layer 4: that layer gates one report
at a time, pass/fail, before publication. This layer tracks the platform
*as a whole*, continuously, as a number that goes up or down over time. A
report can pass every gate and the platform can still be trending worse on
review-completion rate.

## The baseline, updated honestly (n=3 — the first real trend signal)

The "zero reports" baseline this file originally recorded is no longer
current: `Sentinel-APEX/reports/published/` now contains three real reports
(SA-2026-0001, SA-2026-0002, SA-2026-0003), each independently taken through
the actual gate/certify/knowledge-graph machinery this file was built to
eventually measure. Three data points is still thin, but it is the first
point at which a metric that moves (Certification outcome, below) is a
signal worth reading rather than a single anecdote.

| Metric | Formula / source | Current value |
|---|---|---|
| Report completeness | % of the 60 master-prompt.md sections actually populated (not omitted) per published report, averaged | Not computed — no cross-reference exists yet between a published report's sections and master-prompt.md's full 60-section taxonomy; stating a percentage without that cross-check would be exactly the estimate-presented-as-measured this file's own Rule prohibits |
| Evidence coverage | % of non-trivial claims carrying an evidence/confidence label (EIOS Layer 2) | Not computed for the same reason — "non-trivial claims" has no defined denominator yet. Qualitatively: all three published reports use the `[Verified Fact]`/`[Analyst Assessment]`/`[Intelligence Gap]`/`[Unresolved Reference]` tag convention throughout (formalized in EIOS Layer 13 by GIAAP v1) |
| Detection coverage | % of reports with ≥1 detection artifact passing `quality.py` | **33% (1/3)** — only SA-2026-0001 carries a Sigma rule; SA-2026-0002 and SA-2026-0003 both explicitly omit one (undocumented log-schema fields), stated as a gap rather than filled with unverified guesses. This dropped from the previously-reported 100% (1/1) — not a regression, a truer denominator now that n>1 |
| Review completion | % of reports at `review_status: published` (EIOS Layer 8) vs. stuck earlier in the pipeline | **100% (3/3)** |
| Reference completeness | % of front-matter `sources:` entries surfaced in the rendered References section (GIAAP v1's `_gate_reference_completeness`) | **100% (3/3)** |
| Knowledge graph ingestion | % of published reports present in `Sentinel-APEX/knowledge-graph.json` | **100% (3/3)** |
| Certification outcome | `cli.py certify` decision per published report (EICF v1) | SA-2026-0001: CERTIFIED WITH CONDITIONS. SA-2026-0002: CERTIFIED WITH CONDITIONS. SA-2026-0003: **CERTIFIED** (no conditions) — the first unconditional certification, following two small additive fixes to `attack_mapper.py`/`entities.py` made during that report's own production (see `open-issues.md` Issue 9's GIEP v1 update). Three points, trending toward fewer conditions as curated coverage grows — not yet enough to call a trend line, but the first metric in this file with more than one data point |
| Documentation freshness | Days since each governance file's last substantive edit (`git log -1 --format=%ad -- <file>`) | Everything touched this session — establish a real decay baseline starting from today, not from this number |
| API reliability | Error rate / latency on `api/v1/*` | Not observable from this repository — needs the hosting provider's real monitoring, not a repo-computed guess |
| Customer satisfaction | Support tickets, churn, NPS | Not observable from this repository |
| Platform uptime | Vercel deployment health | Not observable from this repository — see `vercel-ignore-build.sh`'s documented 2026-07-05 quota-exhaustion incident for the one uptime event this repo's own files record |

## Rule

A metric with no data source is listed as N/A, not omitted and not
estimated. An estimated number presented as measured is the exact defect
EIOS Layer 2 prohibits in intelligence content, applied to the platform's
own health reporting.

---
*CyberDudeBivash® Sentinel APEX — Platform Quality Metrics*
