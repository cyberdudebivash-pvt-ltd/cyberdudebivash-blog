# EIPS — PLATFORM QUALITY METRICS

Genuinely different in kind from EIOS Layer 4: that layer gates one report
at a time, pass/fail, before publication. This layer tracks the platform
*as a whole*, continuously, as a number that goes up or down over time. A
report can pass every gate and the platform can still be trending worse on
review-completion rate.

## The baseline, updated honestly (still n=1, not a trend)

The "zero reports" baseline this file originally recorded is no longer
current: `Sentinel-APEX/reports/published/` now contains one real report,
SA-2026-0001, that has gone through the actual gate/certify/knowledge-graph
machinery this file was built to eventually measure. The metrics below are
now genuinely computed, not estimated — but n=1 means they describe one
report, not a trend, and should not be read as a rate until a second and
third report exist.

| Metric | Formula / source | Current value |
|---|---|---|
| Report completeness | % of the 60 master-prompt.md sections actually populated (not omitted) per published report, averaged | Not computed — no cross-reference exists yet between SA-2026-0001's ~24 sections and master-prompt.md's full 60-section taxonomy; stating a percentage without that cross-check would be exactly the estimate-presented-as-measured this file's own Rule prohibits |
| Evidence coverage | % of non-trivial claims carrying an evidence/confidence label (EIOS Layer 2) | Not computed for the same reason — "non-trivial claims" has no defined denominator yet. Qualitatively: SA-2026-0001 uses the `[Verified Fact]`/`[Analyst Assessment]`/`[Intelligence Gap]` tag convention throughout (formalized in EIOS Layer 13 by GIAAP v1) |
| Detection coverage | % of reports with ≥1 detection artifact passing `quality.py` | **100% (1/1)** — SA-2026-0001's Sigma rule passes `_gate_sigma`, confirmed via `scripts/assure.sh` |
| Review completion | % of reports at `review_status: published` (EIOS Layer 8) vs. stuck earlier in the pipeline | **100% (1/1)** — SA-2026-0001's front matter: `review_status: "published"` |
| Reference completeness | % of front-matter `sources:` entries surfaced in the rendered References section (GIAAP v1's `_gate_reference_completeness`) | **100% (1/1)**, after v1.1 — v1.0 had one gap, found and fixed the same session the gate was built |
| Knowledge graph ingestion | % of published reports present in `Sentinel-APEX/knowledge-graph.json` | **100% (1/1)** — GIKEP v1 closed the gap where this was 0% (the graph existed in code but nothing fed it a published report) |
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
