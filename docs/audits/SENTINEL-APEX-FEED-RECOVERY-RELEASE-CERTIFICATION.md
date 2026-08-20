# SENTINEL APEX — Feed Recovery Release Certification

**Scope:** PR #109 (sentinel_apex quality-gate `source_url`/`blog_url` field mapping) and PR #110 (freshness-check `lastReportGeneratedAt` signal), certified together as one production-health story — #110 exists because certifying #109 honestly required actually running it in production, which surfaced a second, distinct defect.
**Certified by:** Claude (this session), via real triggered production runs, not simulation.
**Governing standard applied throughout:** MERGED ≠ VERIFIED. CI GREEN ≠ PRODUCTION HEALTHY. IMPLEMENTED ≠ RELEASE CERTIFIED.
**Status as of this update:** both PRs merged. §9 records the final live confirmation that closes the one item §6 originally left open — `freshness-check.yml` now genuinely reports HEALTHY in production, not merely in simulation.

---

## 1. Root cause — two distinct defects, found in sequence

### 1a. The original defect (#109, merged)

`fetch-live-intel.js`'s quality gate rejected every candidate from the `sentinel_apex` source because the live API's actual reference-URL field (`source_url`, or `blog_url` on the 9/500 records lacking it) was never in the list of field names the gate checked (`references`/`refs`/`links`/`sources`/`external_references`/`url`/`link`/`report_url`). Full detail in PR #109's description and commit message.

### 1b. The defect this certification round discovered (#110, open)

Proving #109 in real production (Section 2 below) required actually watching `live-intel.json` for a freshness signal. It didn't move. Root-caused to `writeLiveIntel()`: the 150-item rolling window is sorted by `priority` (desc) then `pubDate` (desc) and trimmed to size — **not sorted by recency**. A genuinely new, freshly-generated report can be trimmed out of the window if its priority score is lower than what's already resident there. This is why `freshness-check.yml`, which reads that window's item `_addedAt` values, would have kept reporting CRITICAL even after #109's fix started working — the newly published reports were real MEDIUM-severity items (score 45-51) sitting behind a wall of higher-priority CISA KEV / actively-exploited entries.

This is **not** a #109 regression and **not** a bug in the priority-first window design, which is very likely intentional (the live site should show the most severe current threats, not just the newest). #110 does not touch that ranking — it gives `freshness-check.yml` a different, recency-accurate signal instead (`intel-state.json.lastReportGeneratedAt`, set only when a report is actually written).

---

## 2. Real production workflow evidence — the decisive proof

Triggered `sentinel-apex.yml` manually via `workflow_dispatch` immediately after confirming #109's merge commit (`c6c96591f`) was the tip of `main`, specifically to get first-eligible-run evidence rather than wait for the next 30-minute schedule slot.

| Field | Value |
|---|---|
| Workflow run ID | [32332548766](https://github.com/cyberdudebivash-pvt-ltd/cyberdudebivash-blog/actions/runs/32332548766) |
| Job ID | 96315829478 |
| Commit run against | `c6c96591f7728ac518000be194a1e553fd41e2ea` (#109's merge commit — the first commit on `main` carrying the fix) |
| Trigger | `workflow_dispatch` (manual, for immediate verification) |
| Start / End | 2026-08-20T04:37:22Z → 2026-08-20T04:38:20Z |
| Conclusion | success |
| Source records fetched (full corpus) | 247 items from 3/28 sources active this cycle |
| `sentinel_apex` source specifically | fetched=244 (3/5 endpoints ok, 478 raw → 244 unique), new=71 |
| Candidates entering quality gate | 71 new-after-dedup → 77 enriched → `toPublish` capped at `CFG.maxNewPostsPerRun` |
| **Quality gate** | **`15 passed, 0 rejected`** |
| **Reports generated** | **`✅ Reports generated: 15`** |
| Reports committed | 15 new `posts/cve-2026-*.html` files + 15 new `api/intel/products/cve-2026-*.json` files, confirmed present in commit `37b267b45` via `git show --stat` |
| Publication status | Real — not dry-run. `git push origin main` succeeded (`c6c9659..37b267b main -> main`), confirmed via a second, independent `git fetch` |
| Errors | Only pre-existing, unrelated source-fetch issues on OTHER sources (PacketStorm TLS cert mismatch, NVD 404 on two query params, Talos/Rapid7 dead feed URLs returning 404, Reddit 429 rate-limit, URLhaus/ThreatFox 401 auth) — none touch `sentinel_apex` or the fixed code path. One informational, non-blocking warning (`FRESHNESS ALERT: No intel with pubDate >= yesterday`) from a separate, pre-existing pubDate-based check that is informational only and does not gate the run |
| Auto-recovery | Not invoked this run (only fires from `freshness-check.yml`'s own failure path) |

**Before/after, on the exact same real API data:** extracted the actual `sapexPick`/`sapexPickArray`/`extractHttpUrls` functions from `fetch-live-intel.js` (pre- and post-fix versions) and ran both against a fresh 500-record pull from `https://intel.cyberdudebivash.com/api/v1/intel/latest.json`: **0/500 pass pre-fix, 500/500 pass post-fix.** In production terms: every run for hours before the merge logged `Quality gate: 0 passed, N rejected`; the first run after the merge logged `Quality gate: 15 passed, 0 rejected`.

---

## 3. Root cause closure — adversarial field-mapping matrix (mandate §2)

Ran the real, extracted `refs`-computation logic against 18 synthetic cases:

| Case | Result |
|---|---|
| `source_url` only (dominant real-world case, 491/500 sampled) | ACCEPT |
| `blog_url` only (fallback case, 9/500 sampled) | ACCEPT |
| Legacy `url` field | ACCEPT (unchanged) |
| Legacy `link` field | ACCEPT (unchanged) |
| Legacy `report_url` field | ACCEPT (unchanged) |
| `references[]` array of strings | ACCEPT (unchanged) |
| `refs[]` array of objects with `.url` | ACCEPT (unchanged) |
| `external_references[]` (STIX-style) | ACCEPT (unchanged) |
| `nvd_url` present | ACCEPT |
| Missing all source fields | REJECT (correct — no fabricated reference) |
| Malformed `source_url` (not a URL) | REJECT |
| Empty string `source_url` | REJECT |
| `null` `source_url` | REJECT |
| `javascript:` scheme | REJECT (unsafe scheme never matched by the `https?://` extraction regex, and independently blocked by the `new URL().protocol` guard) |
| `file:` scheme | REJECT |
| `data:` scheme | REJECT |
| `source_url` embedded in surrounding text | ACCEPT (extracts just the URL substring — unchanged existing behavior) |
| `source_url` + `blog_url` both present | ACCEPT, `source_url` wins (correct priority order) |

Every previously-accepted field name still passes (zero regression). No malformed, empty, null, or unsafe-scheme value is accepted (source integrity preserved, not weakened — mandate's explicit requirement).

---

## 4. Feed freshness recovery (mandate §4)

| Check | Result |
|---|---|
| `live-intel.json` modified timestamp advances | Yes — `metadata.generated`/`lastPipelineRun` advanced to `2026-08-20T04:38:12.386Z` |
| Latest **report** timestamp advances | Yes, in the sense that matters — 15 real reports were generated and committed at `2026-08-20T04:38:14Z`. Item-level `_addedAt` **inside the 150-item live-intel.json window** did **not** advance, because of the window-trimming defect described in §1b — this is the exact finding that produced PR #110 |
| New report IDs appear | Yes — 15 distinct new CVE IDs, verified as real new `posts/*.html` + `api/intel/products/*.json` files in the commit, not counter artifacts |
| `source_url`/`blog_url` provenance preserved | Yes — spot-checked several window items' `refs` fields; real URLs preserved, not stripped or replaced |
| No duplicate reports introduced | Confirmed — none of the 15 new CVE IDs appear more than once in `intel-state.json`'s `published` list (1958 entries total; 4 duplicate IDs and 51 duplicate slugs exist in that list, but all pre-existing and unrelated to this change — not introduced by #109 or #110) |
| `freshness-check.yml` returns healthy | **Yes, confirmed live as of §9** — `freshness-check.yml` run [32335285875](https://github.com/cyberdudebivash-pvt-ltd/cyberdudebivash-blog/actions/runs/32335285875) reported `Status level: HEALTHY`, `Age (minutes): 0`, `Freshness ref: intel-state.json lastReportGeneratedAt`. (As of #109 alone, before #110, this was confirmed NOT yet true: max `_addedAt` in the window was still `2026-08-18T06:32:44.039Z`, 2768+ minutes old — exactly the defect #110 fixes.) |
| Auto-recovery does not falsely report failure | The `run.data.id` bug from #109's own bundled fix is confirmed not to recur — this run's log path wasn't exercised (auto-recovery only triggers from a freshness-check failure), but the fix itself was already adversarially verified in #109's own certification |

---

## 5. #110 verification (freshness-signal fix)

Simulated the exact new `freshness-check.yml` Node logic against real `live-intel.json` data in three scenarios:

| Scenario | `lastReportGeneratedAt` | Result | Correct? |
|---|---|---|---|
| Post-fix, next real run (simulated: field freshly set) | present, fresh | **HEALTHY**, 0 min old | Yes — this is the target state |
| Pre-fix / old state file (backward compatibility) | absent | Falls back to `_addedAt` → **CRITICAL**, 2770 min | Yes — matches real current production state exactly, proving no silent regression |
| `intel-state.json` missing entirely | n/a | Falls back to `_addedAt` → **CRITICAL**, 2770 min | Yes — graceful degradation |

`node --test tests-js/*.test.js`: 123/123 pass in both #109 and #110's states, no regressions. `node --check` and YAML parse clean on all four touched files across both PRs.

---

## 6. Remaining risks

- ~~#110 is not yet merged or live-verified~~ — **closed, see §9.** #110 merged and the full live cycle (real `sentinel-apex.yml` run → real `intel-state.json.lastReportGeneratedAt` → real `freshness-check.yml` run reading it) is now confirmed.
- **No unit test exists yet for `sapexPick`'s field-mapping logic** (the #109 fix) or for `writeLiveIntel()`'s window-trimming interaction with `lastReportGeneratedAt` (the #110 fix). Both were verified against real production data instead, which is stronger evidence but not a permanent regression guard. Worth adding as a follow-up, not blocking this certification.
- **The pre-existing 4 duplicate IDs / 51 duplicate slugs** in `intel-state.json`'s historical `published` list are a real, separate, pre-existing data-quality issue, unrelated to and not introduced by either PR. Not in scope here.
- **`writeLiveIntel()`'s priority-first window design** means `live-intel.json`'s item list will continue to under-represent genuinely new but lower-severity content. This is treated here as intentional product behavior, not a defect — but it's worth an explicit product decision at some point on whether the public-facing feed should also expose a recency-sorted view.

## 7. Rollback

Both PRs are single-purpose, additive-only changes with no schema removal:
- #109: revert restores the pre-fix field list (immediately reintroduces the 0%-pass-rate defect — not recommended, but mechanically safe).
- #110: revert removes `lastReportGeneratedAt` from `intel-state.json` writes and freshness-check's use of it; freshness-check falls back to its pre-#110 `_addedAt`-only logic automatically (the field is optional/additive, no migration needed either direction).

## 9. Final live confirmation (#110, post-merge)

After #110 merged, triggered the full real cycle end to end rather than trusting the merge alone:

1. `sentinel-apex.yml` triggered via `workflow_dispatch` against #110's merge commit (`1aedeec5e`). Result: commit [`ceb4b7867`](https://github.com/cyberdudebivash-pvt-ltd/cyberdudebivash-blog/commit/ceb4b7867088072d4e16a47774e9da8bf0b52c40), `+15 reports, +15 API files` — report generation continues working. `intel-state.json.lastReportGeneratedAt` genuinely set for the first time: `2026-08-20T05:20:48.754Z`.
2. `freshness-check.yml` triggered via `workflow_dispatch` immediately after, against that same commit. Run [32335285875](https://github.com/cyberdudebivash-pvt-ltd/cyberdudebivash-blog/actions/runs/32335285875), job 96323563512, conclusion `success`. Log output, verbatim:
   ```
   Freshness ref  : intel-state.json lastReportGeneratedAt
   Timestamp      : 2026-08-20T05:20:48.754Z
   Age (minutes)  : 0
   ✅ Pipeline healthy — latest items 0 minutes old
   Status level: HEALTHY
   ```
   `Auto-recovery trigger` and `Alert on failure` steps both show `conclusion: skipped` — confirming the check did not fail, not merely that a downstream step didn't run.

This is the exact real-world sequence #106-111's cumulative work was meant to restore: pipeline runs → real reports generate → the monitor watching it correctly says so. No simulation, no synthetic timestamp — genuine production state, read back independently after the fact.

## 8. Certification verdict

**PR #109: RELEASE_CERTIFIED.** Its stated scope — the quality-gate field-mapping defect — is fully fixed, adversarially tested, and proven with real production evidence (0/500 → 500/500 pass rate; a real run producing 15 reports with 0 rejections).

**PR #110: RELEASE_CERTIFIED.** Its stated scope — the freshness-monitoring signal defect — is fully fixed and confirmed by a genuine live production cycle (§9), not simulation alone.

**Overall feed-recovery story (109 + 110): RELEASE_CERTIFIED.** No open items remain. The underlying pipeline defect (reports not generating) and the monitoring-accuracy defect it exposed are both conclusively fixed and independently proven live, end to end.
