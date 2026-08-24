# Blogger Syndication Engine — Run #8459 Incident Review

**Date:** 2026-08-20
**Trigger:** User-reported red-X failure on "CYBERDUDEBIVASH® — Blogger Syndication Engine #8459" (GitHub Actions), requesting root-cause review and a production-stable fix.
**Run investigated:** internal run ID `32335514019`, `workflow_run` trigger against commit `590c5c862` (PR #111's merge), job `📡 Syndicate to Blogger` (`job_id` `96324218316`).

## Verdict: not a defect. No code change made.

The workflow failed because the publication integrity gate (`report_integrity.py::validate_publication()`) correctly blocked one LLM-fabricated, unverifiable claim before it reached Blogger. This is the gate doing its job — the same governance this repository's CLAUDE.md makes non-negotiable ("NEVER generate fake cybersecurity intelligence," "avoid unverifiable claims"). The other 4/5 articles in the run published successfully, including full graceful degradation through a total LLM-provider outage. Nothing in this run indicates a pipeline defect.

## Real run evidence

```
"Pipeline complete" — discovered: 5, published: 4, failed: 1, skipped: 0, integrity_blocked: 1
Errors: ['Publication blocked: unsupported commercial claim matched /\\b2,400\\+/']
```

| # | Article | Outcome | Evidence |
|---|---|---|---|
| 1 | `krybit Ransomware Claims New Victim: sipresitalia.it \| Manufacturing Sector` | **Blocked by integrity gate** | LLM (Groq `openai/gpt-oss-120b`) call succeeded (`chars: 9396`), then `validate_publication()` raised `PublicationIntegrityError`: `unsupported commercial claim matched /\b2,400\+/` |
| 2 | `qilin Ransomware Claims New Victim: InVentry \| Technology Sector` | Published | Groq 429 → DeepSeek 402 → OpenRouter 402 → deterministic composer fallback (`"No LLM provider available — using template fallback"`) → published to Blogger (`post_id 3026527763800646055`) |
| 3 | `T-Mobile Physically Cuts Network Cable to Evict Chinese Salt Typhoon Hackers` | Published | Groq rate-limited twice, succeeded on 3rd attempt, published (`post_id 1763716309172616157`) |
| 4, 5 | (remaining discovered articles) | Published | No integrity or provider issues in the log |

Exit code 1 (the red-X) came from `automation/main.py::_pipeline_exit_code()`: `return 1 if int(report.get("failed", 0)) > 0 else 0`, and the integrity-block handler increments both `report["integrity_blocked"]` and `report["failed"]` (`main.py` lines 289–290).

## Root cause: real LLM hallucination, not a gate miscalibration

Traced the article's source data end to end to confirm the number had no basis in reality:

1. **`automation/threat_feeds.py::RansomwareIntelSource.discover()`** (lines 157–217) builds this article's entire input from the ransomware.live API using only `victim`, `group`, `activity`/`sector`, `country`, and a leak-site URL. The `summary`/`full_content` fields are fixed template sentences (`"{group} has listed {victim_name} as a new victim on its leak site."` + optional sector/country clauses) — **none of these fields are numeric**. Confirmed by reading the function directly; there is no code path that could carry a real "2,400" from the source into the LLM prompt for this article.
2. The job log shows the Groq call for this exact article **succeeded** immediately before the block (`"LLM call succeeded", "provider": "groq", "chars": 9396`) — the blocked content was LLM-authored prose, not template output.
3. Since the only real facts available were `krybit` / `sipresitalia.it` / Manufacturing / a leak-site URL, and none of those are numeric, the LLM invented the "2,400+" figure while writing free-form report prose. That is a fabricated, unverifiable quantitative claim by definition.
4. This is the same failure class the gate was built for. `_UNSUPPORTED_COMMERCIAL_PATTERNS` (`report_integrity.py:290-295`) was introduced in commit `0a4b2df3b` ("fix: enforce evidence-safe CTI publication," 2026-08-12) as a set of exact-literal guards — `2,400+`, `10,000+`, `40+ TI sources`, plus the generalized `trusted by \d[\d,]*\+` — which only make sense as hardcoded responses to specific unverified self-promotional/scale claims the LLM had actually produced in real output at the time. Today's block is the same pattern firing again, on a fresh instance of the same underlying LLM behavior.

**Conclusion:** true positive. No false-positive risk exists in this instance — the source data genuinely contains no numeric claim of any kind, so there is no legitimate "2,400+" this gate could have wrongly suppressed.

## Resilience mechanisms confirmed working correctly

- **LLM provider fallback chain** (`llm_client.py::call_llm()`): Groq → DeepSeek → OpenRouter, then deterministic composer fallback when all three fail — verified twice in this same run (a full outage: Groq 429, DeepSeek 402, OpenRouter 402) and both times the article still published via the composer path. No user-visible impact from the provider outage.
- **Retry queue** (`content_discovery.py::add_to_retry_queue()` / `get_retry_queue()`): the blocked article was automatically re-queued, capped at 3 attempts, then silently dropped — bounded, self-limiting behavior. Since LLM generation is non-deterministic, the most likely outcome is it publishes cleanly on a later attempt; if it keeps hallucinating, the gate keeps blocking it, and after 3 attempts it stops consuming further runs. No manual intervention is required.

## What was checked and found not to need fixing

- `_UNSUPPORTED_COMMERCIAL_PATTERNS` and its check loop in `validate_publication()` — correctly calibrated, correctly fired. Not touched.
- `threat_feeds.py`'s ransomware source-data mapping — confirmed clean (no numeric fields silently mishandled).
- The LLM fallback chain and retry queue — both already handled this exact scenario correctly with no changes needed.

## Open design question — not decided here, needs owner input

`automation/main.py` treats an integrity block as a subset of `failed` (both counters increment together), so **any single correctly-blocked article turns the entire workflow run red**, even when every other article in the same run published successfully — as it did here (4/5). This is why the same, working-as-intended gate keeps producing a visible GitHub Actions failure the owner has to triage each time it fires.

This is a CI-signal/alerting design choice, not a content-safety one — changing it would not touch what gets published, only how a "gate correctly blocked one article" run is surfaced in the Actions UI. Per this repository's governance (no unilateral changes to gates, and prior owner-authorization precedent set earlier in this same round for similarly CI/production-facing decisions), this is being raised rather than decided:

- **Option A — leave as-is.** Every integrity block stays a hard workflow failure. Keeps maximum visibility on every hallucination instance, at the cost of a red-X for what is often correct behavior.
- **Option B — separate the signal.** Keep `validate_publication()` exactly as strict (still blocks 100% of matches, still never publishes fabricated content), but stop counting an integrity-only block (no auth/quota/unexpected errors alongside it) toward the workflow's hard exit code — e.g., exit 0 with a clearly flagged warning annotation when `failed == integrity_blocked` and no other error class occurred, reserving red-X for real pipeline failures (auth, quota, unexpected exceptions, or a run where publishing itself is broken).

**Decision (owner, 2026-08-20): Option A — leave as-is.** No code change made or planned for this question. A future integrity-only block will continue to show as a red-X workflow failure by design; that is expected, correct behavior, not a regression to re-investigate.

## Files touched by this review

None (production code). This document only.

---

## Addendum — 2026-08-24: Decision reversed under the Intel Factory Publication Reliability mandate

**This section does not alter the analysis or conclusions above.** The root
cause finding (real LLM hallucination, gate correctly fired, true positive)
and the resilience findings (provider fallback, retry queue) still stand
unchanged. Only the **CI-signal policy decision** immediately above —
"Decision (owner, 2026-08-20): Option A — leave as-is" — has been
superseded.

**What changed:** the P0 "Intel Factory Publication Reliability, Blogger
Syndication Recovery & Customer Delivery Assurance v1" mandate
(2026-08-24), triggered by continued syndication workflow failures,
independently re-derived this exact same root cause from fresh evidence
(runs spanning 2026-08-22 through 2026-08-24, ~24 of the last 30 scheduled
runs showing `conclusion: failure`) and explicitly specified a 3-state
run-verdict model (`SUCCESS` / `DEGRADED` / `FAILED`) in place of the
binary pass/fail this document's Option A kept. That mandate frames the
distinction as: *"Never turn INTEGRITY_BLOCKED into PUBLISHED to make CI
green... A healthy production system may legitimately block a bad report.
Workflow success and report publication count are different metrics"* —
i.e. the gate staying strict was never in question; only whether a
correctly-functioning gate should keep reddening an otherwise-healthy run.

**Why this reads as a reversal, not a contradiction:** Option A was chosen
on 2026-08-20 to preserve maximum visibility on every hallucination
instance. Four days and roughly two dozen majority-failure-rate runs later,
that same choice was producing chronic, low-signal red-X noise that
obscured genuine outages (a broken credential, an unexpected exception)
behind routine, healthy integrity blocks — the opposite of the visibility
Option A was meant to protect. The new mandate reflects the owner
revisiting that tradeoff with more data, not a different agent overriding
the recorded decision unilaterally.

**What actually changed in code:** `automation/main.py` gained
`_pipeline_run_status()`, classifying a completed run as `FAILED` only for
a broken credential (`auth_error`) or an exception outside the pipeline's
own error taxonomy (`error`); an integrity block, a self-healing rate
limit, or a queued-for-retry publish error now classify as `DEGRADED` —
exit code 0, but distinctly flagged (a `::warning::` annotation and a `Run
status:` line in the GitHub Actions summary) rather than silently folded
into a plain success. The evidence gate itself
(`report_integrity.py::validate_publication()`, the artifact-hash binding
check in `main.py`) was **not** touched, loosened, or bypassed in any way —
every report this document analyzed as correctly blocked would still be
blocked today.

Full reasoning, evidence, and certification:
`docs/audits/SENTINEL-APEX-INTEL-FACTORY-PUBLICATION-RELIABILITY-V1-CERTIFICATION.md`.
