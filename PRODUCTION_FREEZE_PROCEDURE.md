# Production Content Freeze Procedure — Stage 6

Defines exactly what gets paused, why, how, and how it resumes, to obtain a
stable `PRODUCTION_FREEZE_SHA` immediately before the production cutover
deploy. **This document is a plan only — nothing in it has been executed.**
Per the task's explicit instruction, no workflow has been paused remotely;
execution requires separate, explicit operator authorization at the moment
of actual cutover.

---

## 1. Why a freeze is needed

This repository receives automated content commits continuously — observed
this session at roughly one push every 15–30 minutes (`git log` shows
commits from the `sentinel-apex`, `blogger-syndication`, and
`ai-security-intel` pipelines interleaved throughout the session). A
production deploy built from a Git SHA that content keeps changing under is
not a stable target: by the time the deploy finishes and is verified, `main`
may have already advanced, and the deployed artifact would under-represent
current content from the moment it goes live.

The freeze exists solely to get a short, stable window in which:
`fetch latest main → build → test → deploy → verify → cut over` all
reference the exact same, unmoving Git SHA.

## 2. Every process capable of committing deployable content to `main`

Identified by reading every `.github/workflows/*.yml`'s trigger and
commit/push steps directly (not inferred from names):

| Workflow file | Trigger | Commits to `main`? | Role |
|---|---|---|---|
| `sentinel-apex.yml` | `schedule: "0,30 * * * *"` (every 30 min) + `workflow_dispatch` | **Yes** | Primary — generates CVE/product/report content, the main "SENTINEL APEX v5.0" commits |
| `blogger-syndication.yml` | `schedule` (interleaved at :15/:45) + `workflow_dispatch` | **Yes** | Primary — auto-publishes posts ("syndication: auto-published" commits) |
| `ai-security-intel.yml` | `schedule: "0 */2 * * *"` (even UTC hours) + `workflow_dispatch` | **Yes** | Primary — AI-security intel feed content |
| `cve-pages.yml` | `push` (paths: `api/intel/cve/**`, `generate-cve-pages.js`) + `schedule: "0 */6 * * *"` + `workflow_dispatch` | **Yes** | Secondary — cascades off the 3 primaries' pushes; also has its own 6-hourly independent schedule |
| `generate-rss.yml` | `push` (paths: `posts/**`, `generate-rss.js`) + `schedule: "0 */6 * * *"` + `workflow_dispatch` | **Yes** | Secondary — same cascade + independent 6-hourly schedule |
| `intelligence-hub.yml` | `push` (paths: `api/intel/products/**`, `api/intel/cve/**`, etc.) + `schedule` + `workflow_dispatch` | **Yes** | Secondary — same cascade pattern |

All other workflows (`backup-customer-data.yml`, `blogger-integrity-ci.yml`,
`continuous-assurance.yml`, `detection-engine-node-ci.yml`,
`freshness-check.yml`, `intelligence-engine-ci.yml`,
`pipeline-health-certification.yml`, `pricing-integrity.yml`,
`report-renderer-ci.yml`, `security-audit.yml`, `smoke-test.yml`, `test.yml`)
were checked and confirmed to contain **no** `git commit`/`git push` step —
they are CI/test/security/backup workflows that read the repository but
never write to it. **None of these are freeze targets, and none should be
touched** — Section 3's "do not disable security/emergency workflows
unnecessarily" applies directly to `security-audit.yml`,
`continuous-assurance.yml`, and `backup-customer-data.yml` in particular.

## 3. Minimum set to pause

**All 6 content-committing workflows listed above**, not just the 3
"primary" schedule-triggered ones. Pausing only the primaries is
insufficient: `cve-pages.yml`, `generate-rss.yml`, and `intelligence-hub.yml`
each carry their own independent 6-hourly `schedule` trigger in addition to
their push-cascade trigger, so any of the three could still fire and commit
on its own schedule during the freeze window even with all 3 primaries
paused.

## 4. Exact pause mechanism

**Recommended: GitHub web UI, one workflow at a time — zero commits, instant,
trivially reversible.** For each of the 6 workflow files above:

1. Navigate to `https://github.com/cyberdudebivash-pvt-ltd/cyberdudebivash-blog/actions/workflows/<filename>`
2. Click the **"..."** menu (top right of the workflow's run list) → **"Disable workflow"**
3. Confirm the workflow now shows a **"This workflow is disabled"** banner

This is a GitHub-side toggle, not a repository change — it does not create a
commit, does not touch `main`, and does not require a PR or review. It can
be reversed in the same number of clicks (**"Enable workflow"**).

This session's GitHub integration has tools to list/get/trigger/cancel
workflow runs but **no tool to disable/enable a workflow** — that action is
not available to this session and must be performed by the operator via the
dashboard (or `gh workflow disable <filename>` from an authenticated local
`gh` CLI, if the operator prefers a command-line path over the UI).

**Do not** achieve the pause by editing/committing changes to the workflow
YAML files (e.g., commenting out the `schedule:` block) — that would itself
be a `main`-mutating commit competing with the very automation being paused,
and would need its own follow-up revert commit to resume, adding avoidable
commits to the freeze/resume history for no benefit over the zero-commit
dashboard toggle.

## 5. Freeze timeline

| Step | Action |
|---|---|
| **Freeze start** | Operator disables all 6 workflows via the dashboard (Section 4). Record the UTC timestamp. |
| **Drain window** | Wait for any already-in-flight run of the 6 workflows to finish (check `https://github.com/cyberdudebivash-pvt-ltd/cyberdudebivash-blog/actions` for `in_progress`/`queued` runs of these 6 specifically) — do not proceed while one is still running, since it could still push after being "disabled" if already mid-run. |
| **Final sync** | `git fetch origin main` and `git rev-parse origin/main` — this SHA is `PRODUCTION_FREEZE_SHA`. Record it plus the UTC timestamp as `PRODUCTION_FREEZE_UTC`. |
| **Validation** | Confirm no new commit lands on `main` for at least 2 minutes after recording the freeze SHA (a final safety check that the drain window worked) — re-run `git fetch origin main && git rev-parse origin/main` and confirm it still matches. |
| **Build → deploy → verify → cut over** | Proceed through `PRODUCTION-CUTOVER-RUNBOOK.md` using exactly this SHA. |

## 6. Resume procedure

Immediately after cutover is confirmed stable (see the runbook's
observation-window step — **not** immediately after the DNS change itself):

1. Re-enable all 6 workflows via the same dashboard menu → **"Enable workflow"**
2. Verify at least one of the 3 primary schedule-triggered workflows
   (`sentinel-apex.yml`, `blogger-syndication.yml`, `ai-security-intel.yml`)
   fires on its next natural schedule tick and produces a normal commit
   (check `git log origin/main` for a new automation commit within the
   expected interval — 30 min for `sentinel-apex.yml`, its own interleaved
   schedule for `blogger-syndication.yml`, next even UTC hour for
   `ai-security-intel.yml`)
3. Confirm no duplicate/overlapping run fired for any of the 6 (GitHub does
   not queue missed schedule ticks while a workflow is disabled — re-enabling
   resumes the normal schedule going forward, it does not "catch up" missed
   runs, so no duplicate-publish risk exists from the pause itself)
4. Confirm feed freshness: `rss.xml`, `sitemap.xml`, and the intel JSON
   endpoints reflect new content within the next expected pipeline cycle

## 7. Rollback (if the freeze itself needs to be aborted before cutover)

If cutover is aborted for any reason after the freeze but before DNS is
touched: simply re-enable the 6 workflows (Section 6) — there is nothing
else to roll back. No commit was made to pause them, so there is no commit
to revert. Content generation resumes exactly where it left off on its next
scheduled tick.

## 8. Expected freeze duration

Target: **under 15 minutes** from freeze start to cutover completion,
consistent with the task's "the freeze must be as short as possible"
requirement. The build/test/deploy/verify sequence in
`PRODUCTION-CUTOVER-RUNBOOK.md` has already been rehearsed against the
Stage 6 branch this session (full regression suite completes in under a
minute locally; the operator's own build+deploy in Stage 5/6 took under 4
minutes end-to-end) — the freeze window should not need to extend
meaningfully beyond that rehearsed timing.
