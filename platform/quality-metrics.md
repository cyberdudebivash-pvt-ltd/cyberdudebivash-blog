# EIPS — PLATFORM QUALITY METRICS

Genuinely different in kind from EIOS Layer 4: that layer gates one report
at a time, pass/fail, before publication. This layer tracks the platform
*as a whole*, continuously, as a number that goes up or down over time. A
report can pass every gate and the platform can still be trending worse on
review-completion rate.

## The uncomfortable baseline, stated honestly

`Sentinel-APEX/reports/{drafts,final,published}/` contain only `.gitkeep`
placeholders — verified repeatedly this session, not stale information.
**Zero reports have been produced through this pipeline.** Four rounds of
governance, quality-gate, and scoring infrastructure now exist
(`Sentinel-APEX/prompts/`, `eios/`, `eito/`, this directory) and none of it
has processed a real report yet. That is not a criticism to bury — it is the
single most important number on this page, and every metric below currently
reads N/A because of it. This file exists so that the day the first report
ships, there is already a defined way to measure whether the machinery was
worth building.

| Metric | Formula / source | Current value |
|---|---|---|
| Report completeness | % of the 60 master-prompt.md sections actually populated (not omitted) per published report, averaged | N/A — no published reports |
| Evidence coverage | % of non-trivial claims carrying an evidence/confidence label (EIOS Layer 2) | N/A — no published reports |
| Detection coverage | % of reports with ≥1 detection artifact passing `quality.py` | N/A — no published reports |
| Review completion | % of reports at `review_status: published` (EIOS Layer 8) vs. stuck earlier in the pipeline | N/A — no reports in any status |
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
