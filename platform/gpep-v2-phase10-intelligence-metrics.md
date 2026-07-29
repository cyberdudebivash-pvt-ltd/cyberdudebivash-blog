# GPEP v2 Phase 10 — Intelligence Metrics

Every number below was measured directly while producing this document
(commands shown), not estimated. Where no instrumentation exists to
measure something real metrics require, that is stated as "not
instrumented" rather than filled with a plausible-looking placeholder —
per this phase's own explicit instruction not to invent metric values.

## Report Quality

| Metric | Value | How measured |
|---|---|---|
| Reports published, certified | 3 (SA-2026-0001/2/3) | `cli.py certify` run directly against all 3 during this session |
| Certification decisions | 2× CERTIFIED WITH CONDITIONS, 1× CERTIFIED (unconditional) | Same, live runs, not recalled |
| Commercial quality scores | 43, 37, 48 (of 100) | Same `cli.py certify` output, Commercial Assessment section |
| Commercial tier eligibility | 0 of 3 eligible (threshold 60) | Same |
| Certification domains covered | 6 (Intelligence, Evidence, Editorial, Detection, Rendering, Publication) | `certification.py`'s `ALL_DOMAINS`, verified via `test_certification.py` |

## Publication Consistency

| Metric | Value | How measured |
|---|---|---|
| Reports live in production | 3 of 3 | Direct `WebFetch` of `blog.cyberdudebivash.in/intelligence/` this session — confirmed all 3 titles/CVE IDs present |
| Manual publication steps per report | 1 (`publish-report.js`, CLI, human-run) | `capabilities.md` row 1 |
| Reports that sat certified-but-unpublished (historical) | 2 of 3, for multiple weeks | `capabilities.md` row 1, prior audit |

## Detection Quality

| Metric | Value | How measured |
|---|---|---|
| Reports shipping an embedded Sigma rule | 0 of 3 | Read all 3 reports' "Detection guidance" sections directly — both SA-2026-0002 and SA-2026-0003 explicitly decline; SA-2026-0001 embeds one by hand |
| Detection formats the automated pipeline can generate | Sigma, KQL, Splunk, OSQuery (generated); Suricata (derived from network IOCs); YARA (validated only, not generated) | `capabilities.md` row 5, corrected during GTIEP v1 |

## Knowledge Graph Growth (this session's own before/after)

| Metric | Before | After | Change |
|---|---|---|---|
| Total nodes | 9,678 | 9,681 | +3 |
| ThreatActor nodes | 8 | 9 | +1 (actor:apt29) |
| Malware nodes | 0 | 2 | +2 (malware:bianlian, malware:jasmin) |
| Edges | 3,515 | 3,514 | −1 (removed 3 mis-sourced edges, added 5: 1 actor + 2 campaign + 2 malware) |
| CVE nodes | 2,702 | 2,702 | unchanged |
| Campaign nodes | 1,007 | 1,007 | unchanged |
| IOC nodes | 862 | 862 | unchanged |

Measured via `computeStats()` (the graph's own exported function), called
before and after the Phase 3 fix, not estimated from memory.

## Analyst Productivity

**Not instrumented in any customer/business sense** (there is no analyst
time-tracking anywhere in this platform). The only real, measurable proxy
available is engineering throughput within this program, stated as a
count, not a rate: this GPEP v2 pass alone produced 1 new report-graph
correction (3 mis-sourced edges removed, 1 correctly-sourced actor added),
1 new node-type population (Malware, 2 entries), 8 new regression tests,
and 6 new platform documents, verified against 451 total passing tests
across 4 suites (176 Python + 64 renderer + 106 engine-node + 105 root JS)
run both before and after the graph changes.

## Editorial Quality

| Metric | Value | How measured |
|---|---|---|
| Editorial Quality certification domain pass rate | 3 of 3 reports | `cli.py certify`, Editorial Findings section, all 3 |
| SIS audience-enum conformance | 4 of 4 tests pass | `test_sis_conformance.py`, run directly this session |
| Templates conforming to the single-value audience contract | 7 of 7 | Same test, `_template_files()` glob |

## Customer Engagement

**Not instrumented — no metric available to this audit.** No analytics
dashboard, traffic count, or engagement number is accessible from within
this codebase or session. `capabilities.md`'s Observability row confirms
raw Redis counters exist for registration/auth/payment events but states
plainly "no dashboard or alerting layer on top of any of these raw counters"
exists yet — so even the counters that do exist aren't currently
summarized into a reportable metric. Recorded as a genuine platform gap
(Phase 1 subsystem 11), not filled with an invented number here.

## Operational Reliability

| Metric | Value | How measured |
|---|---|---|
| `scripts/assure.sh --all` stages passing | 5 of 5 | Run twice this session (before and after the graph fix), both green |
| GitHub Actions checks on the PR #47 merge commit | 5 of 5 (Intelligence Engine CI, Report Renderer CI, Continuous Assurance, Production Smoke Test, GitGuardian) | Checked directly via `mcp__github__actions_get`, all `conclusion: success` |
| Total automated tests across all 4 suites | 451 | Direct run counts, this session (176+64+106+105) |

---
*CyberDudeBivash® Sentinel APEX — GPEP v2 Phase 10 Intelligence Metrics*
