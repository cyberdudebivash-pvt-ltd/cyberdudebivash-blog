## Production Certification

**CYBERDUDEBIVASH® SENTINEL APEX — Intel Factory Publication Reliability, Blogger Syndication Recovery & Customer Delivery Assurance v1**

Branch: `claude/p0-intel-factory-publication-reliability-v1`
Date: 2026-08-24

---

## 1. Executive Verdict

**GO — CONDITIONAL.** The Blogger syndication pipeline was never losing
intelligence. The red workflow runs were a **CI-signal-calibration defect**,
not a publication-continuity incident: articles that failed a healthy,
correctly-firing evidence-integrity gate (or hit a self-healing Blogger rate
limit) were counted the same as a broken credential or an unhandled
exception, so a partially-successful run and a genuinely broken run were
indistinguishable in the GitHub Actions UI. Real production evidence across
three independently-sampled failed runs shows every one of them still
published the majority of its discovered articles correctly.

This certification fixes the root cause (a 3-state `SUCCESS` / `DEGRADED` /
`FAILED` run-verdict model), closes one latent related defect found during
the same investigation (a missing-Blogger-credentials run previously exited
0/green), and hardens the publication-state file against a real, previously
unmitigated corruption risk. It does **not** weaken, bypass, or relax any
evidence-integrity or fabrication check — every report this pipeline
correctly blocked before this change is still blocked today.

**CONDITIONAL** because this reverses an explicit, documented owner decision
from four days earlier (`docs/audits/blogger-syndication-run-8459-incident-review-2026-08-20.md`,
"Option A — leave as-is"). The current mandate re-raises that exact
question and specifies the opposite resolution; see §10. The operator should
consciously confirm this reversal before merging — it is the single most
important thing to review in this PR.

---

## 2. Production Incident — What Was Reported vs. What The Evidence Shows

**Reported:** "A recent scheduled Blogger Syndication workflow… was observed
failing," framed as a potential production-intelligence-publication
continuity risk.

**Found:** Real GitHub Actions history (`blogger-syndication.yml`, `main`)
shows this was understated in the other direction — roughly 24 of the last
30 scheduled runs (spanning at least 2026-08-22 through 2026-08-24) report
`conclusion: failure`. This is a chronic majority-failure-rate condition,
not a one-off. But "failure" here is a CI-signal artifact, not evidence of
lost intelligence — see §4 for the run-by-run evidence.

**Not an incident in the data-loss sense.** No article that was ever
eligible for publication failed to publish and stay unpublished. No
duplicate posts were created. No customer-facing content was ever
fabricated or served incorrectly. The defect is entirely in how a healthy
partial-success run was *reported*, not in what it *did*.

---

## 3. Customer Impact

**Direct customer impact: none identified.** `cti.cyberdudebivash.in` kept
receiving new intelligence on schedule throughout the sampled failure
window (verified live, §21). The only real impact was operator-facing:
chronic red-X noise that (a) obscured genuine failure modes behind routine,
expected integrity-gate blocks, and (b) is the reason the 2026-08-20
decision needed revisiting — see §10.

---

## 4. Real Run Evidence

Three independently-sampled failed runs, forensically inspected via GitHub
Actions job logs (`mcp__github__get_job_logs`), all show the same pattern:

| Run | Job / Commit | Result |
|---|---|---|
| `32753522822` (2026-08-24T16:54:54–16:57:25Z) | job `97515721845` | discovered 5, **published 4**, integrity_blocked 1 (CVE-2026-76071, "unverified exploitation assertion"), failed 1 → workflow marked FAILED |
| `32335514019` (2026-08-20, PR #111 merge) | job `96324218316` | discovered 5, **published 4**, integrity_blocked 1 (fabricated "2,400+" claim, true-positive hallucination — see the 2026-08-20 incident review), failed 1 → workflow marked FAILED |
| (additional sampled runs across 2026-08-22–24) | — | same pattern: 3–4 of 5 discovered articles published live, exactly one correctly gated, workflow marked FAILED |

In every sampled case: the workflow's own "Commit Publication State" step
(`if: always()`) committed the real, correct `data/published_posts.json`
update a few minutes later — which is why a "failed" run was still visibly
followed by a `syndication: auto-published […]` commit. That was never a
bug; it is what exposed that publications were succeeding despite the red
status.

---

## 5. Failure Classification

Per the required taxonomy (AUTHENTICATION / BLOGGER API / QUOTA / SOURCE
FAILURE / INTELLIGENCE QUALITY FAILURE / PIPELINE DEFECT / INFRASTRUCTURE /
CONFIGURATION / TRANSIENT):

**PIPELINE DEFECT — CI-signal miscalibration**, in
`automation/main.py::_pipeline_exit_code()`. Not classified as any of the
others:
- Not AUTHENTICATION or QUOTA — `blogger_publisher.py`'s auth/rate-limit
  handling is correct (§15); no sampled run hit a genuine credential or
  quota failure.
- Not SOURCE FAILURE — ~30 dead RSS feeds per run are already handled as
  non-fatal warnings; they never touch `report["failed"]`.
- Not INTELLIGENCE QUALITY FAILURE — the integrity gate blocking one
  article per run is *correct* behavior, not a quality defect.
- Not TRANSIENT — this is a deterministic, reproducible code path with an
  identified line-level cause, not a flaky or unexplained condition.

---

## 6. Root Cause

`automation/main.py` (pre-fix):

```python
def _pipeline_exit_code(report: dict) -> int:
    """Return non-zero for every partial or complete pipeline failure."""
    return 1 if int(report.get("failed", 0)) > 0 else 0
```

`report["failed"]` is a single umbrella counter incremented identically by
five different exception types in the publish loop:
`PublicationIntegrityError` (a healthy, correct evidence-gate block),
`BloggerAuthError` (a broken credential — systemic and terminal),
`BloggerRateLimitError` (a self-healing quota condition — the run
correctly stops early and requeues), `BloggerPublishError` (a single
article rejected by Blogger, already queued for retry), and a bare
`Exception` (anything outside the pipeline's own designed error taxonomy).
`_pipeline_exit_code()` could not distinguish "the gate did its job" from
"the pipeline is broken" — both produced exit code 1.

This is a deliberate prior design choice, not an accident: the surrounding
comment in `main()` read *"Any blocked or failed article must surface as a
workflow failure even when other articles published successfully."* The
2026-08-20 incident review independently reached the identical diagnosis
and explicitly asked the repository owner to decide between leaving it
as-is or separating the signal — see §10.

---

## 7. Architecture (unchanged)

No architectural change. The three-layer separation this repository's
governance requires stays intact:

- **GitHub Actions** — scheduled Intel Factory orchestrator (this pipeline).
- **Cloudflare Workers** — canonical customer-facing API runtime (untouched
  this round).
- **Blogger** — CTI publishing destination, reached via
  `automation/blogger_publisher.py`.

All changes in this round are confined to `automation/main.py`,
`automation/content_discovery.py`, `.github/workflows/blogger-syndication.yml`,
and their tests. No new service, no new dependency, no new architecture.

---

## 8. Publication State Reconciliation

`data/published_posts.json` (via `PublicationState` in
`content_discovery.py`) was read in full and confirmed correct in its
existing design: `mark_published()` persists immediately after every single
successful publish (not batched), matching the per-article incremental
`total_published` checkpoints observed in real logs
(5157→5158→5159→5160→5161 across one sampled run). `is_published()` /
`is_source_url_published()` / `is_cve_published()` are simple, correct
lookups.

**One real, latent gap found:** `PublicationState.save()` wrote directly to
the state file with `json.dump()` — no write-temp-then-rename. A process
kill mid-write (the workflow's own 10-minute job timeout, in the worst
case) could truncate the file; `_load()` already treats a corrupt file as
"start fresh," which would silently forget every prior publication and
risk duplicate Blogger posts on the next run. This had not yet been
observed in production but is a real, structurally possible risk directly
relevant to "duplicate publication safety" — fixed in §9.

---

## 9. The Fix

### 9.1 Three-state run classification (`automation/main.py`)

```python
_TERMINAL_POST_STATUSES = {"auth_error", "error"}

def _pipeline_run_status(report: dict) -> str:
    if any(post.get("status") in _TERMINAL_POST_STATUSES for post in report.get("posts", [])):
        return "FAILED"
    if int(report.get("failed", 0)) > 0:
        return "DEGRADED"
    return "SUCCESS"

def _pipeline_exit_code(report: dict) -> int:
    return 1 if report.get("run_status") == "FAILED" else 0
```

**Classification policy** (Phase 65's "define and test" — the actual policy
decision this round makes explicit):

| Post status | Classification | Why |
|---|---|---|
| `integrity_blocked` | DEGRADED | The evidence gate correctly kept an unverified/fabricated report out of publication. Healthy behavior by design. |
| `rate_limited` | DEGRADED | Self-healing — Blogger's quota resets on its own; the article is already queued for retry next scheduled run. |
| `publish_error` | DEGRADED | Already placed in the retry queue by the pipeline's own design; a single Blogger-side rejection, not evidence of systemic breakage. |
| `auth_error` | **FAILED** | Not self-healing. Every future run fails identically until `BLOGGER_REFRESH_TOKEN` is rotated by an operator (see the credential hint in `blogger_publisher.py`). |
| `error` (bare `Exception`) | **FAILED** | By construction, everything with a designed failure path already has its own specific `except` clause above this one. This bucket is, by definition, something the pipeline was not built to expect. |

A run with *both* a healthy block and a terminal status is still FAILED —
the terminal condition can never be masked by also containing a benign one
(tested explicitly, §19).

`report["run_status"]` is now persisted in every `logs/run-*.json` and set
at all three `run_pipeline()` exit points (normal completion, "no new
articles," and the config-validation early return).

### 9.2 Second, related fix: missing-credentials silent green

Found while implementing 9.1: the config-validation early return in
`run_pipeline()` returned before ever touching `report["failed"]`:

```python
missing = config.validate()
if missing and not dry_run:
    ...
    report["run_end"] = ...
    return report   # report["failed"] still 0 here
```

Under the *old* exit-code logic (`failed > 0` ⇒ exit 1), a run with zero
Blogger credentials configured would exit **0 (green)** — nothing was
validated or published, but the workflow would report success. Fixed by
explicitly setting `report["run_status"] = "FAILED"` on this path. This is
a different, independently-discovered defect in the same function, fixed
in the same change because it shares the exact evidence trail and the
exact "never silently lose intelligence visibility" concern this mandate
exists to protect.

### 9.3 Atomic state-file write (`automation/content_discovery.py`)

```python
def save(self) -> None:
    self.state_file.parent.mkdir(parents=True, exist_ok=True)
    self._state["last_updated"] = datetime.now(timezone.utc).isoformat()
    tmp_path = self.state_file.with_name(self.state_file.name + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(self._state, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, self.state_file)
    logger.info(...)
```

`os.replace()` is atomic within the same directory/filesystem — a reader
only ever sees the fully-old or fully-new file, never a partial write.
Regression-tested by simulating a crash mid-write (§20).

### 9.4 Workflow observability (`.github/workflows/blogger-syndication.yml`)

- "Run Syndication Pipeline" step now reads `run_status` from the just-written
  run report and emits `::warning::` when DEGRADED (exit is still 0 — the
  step was already succeeding — but the condition is now visible instead of
  silent).
- "Pipeline Summary" step now prints a `Run status: …` line alongside the
  existing Discovered/Published/Failed/Integrity-blocked lines.
- "Flag Pipeline Failure" (`if: failure()`) needed no change — it already
  keys off the step's own exit code, so it now naturally fires only for
  genuinely FAILED runs.

---

## 10. Prior Decision Supersession — Read This Before Merging

`docs/audits/blogger-syndication-run-8459-incident-review-2026-08-20.md`
recorded an explicit owner decision four days before this round:
*"Decision (owner, 2026-08-20): Option A — leave as-is… A future
integrity-only block will continue to show as a red-X workflow failure by
design; that is expected, correct behavior, not a regression to
re-investigate."*

This round's fix does the opposite for the integrity-block case (DEGRADED,
not FAILED). This is a deliberate reversal, not an oversight or a
contradiction discovered late:

- The current 70-phase mandate independently re-raised this exact question
  and explicitly specified a 3-state `SUCCESS`/`DEGRADED`/`FAILED` model
  with a worked example — see the mandate's Phase 18 and Phase 65.
- Four days and roughly two dozen majority-failure-rate runs after Option A
  was chosen for maximum visibility, that same choice was producing chronic
  red-X noise that obscured genuine outages behind routine, healthy
  integrity blocks — the opposite of the visibility it was meant to
  protect.
- A short, explicitly-dated addendum was appended to the original
  2026-08-20 document (not a rewrite of its conclusions — its root-cause
  and resilience findings are untouched) recording this supersession and
  linking back to this certification.
- **The evidence gate itself was not touched, loosened, or made less
  strict in any way.** Every report the 2026-08-20 review found correctly
  blocked would still be blocked today; only how a correctly-blocked run is
  *reported* changed.

**This is flagged as the one item in this PR that most needs the
operator's conscious sign-off**, per this repository's standing "no
unilateral changes to gates / CI-facing decisions without owner
authorization" precedent.

---

## 11. Idempotency / Duplicate-Publication Safety

- **Dedup on publish:** `is_published(content_hash)` and
  `is_source_url_published(url)` are both checked before an article is
  considered new (in `_merge_retry_and_fresh()` and content discovery).
- **Retry-queue dedup:** `add_to_retry_queue()` removes any existing entry
  for the same `content_hash` before re-appending, so an article can never
  appear twice in the queue; attempts are capped at 3
  (`get_retry_queue()` filters `attempts <= 3`); queue capped at the last 20
  items.
- **Fresh-vs-retry precedence:** `_merge_retry_and_fresh()` prefers current
  discovery data over a stale retry entry for the same source URL, with an
  explicit rationale (editorial normalization can change a content hash
  while the canonical source URL stays stable) — prevents publishing both
  an old placeholder and a corrected version of the same article.
- **Post-publish state write:** now atomic (§9.3) — closes the one real gap
  found, where a truncated state file could have caused the next run to
  treat already-published articles as new.

No duplicate-publication defect was found in the sampled evidence; this
section documents what was audited and the one gap that was fixed
pre-emptively.

---

## 12. Retry / Recovery

- `_requeue_unattempted()` (pre-existing, from an earlier round): on a
  fatal `break` (auth or rate-limit error), every not-yet-attempted article
  in the batch — not just the one that triggered the error — is queued for
  retry. Historical log analysis (documented in the function's own
  docstring) found this closed a real gap affecting roughly 1 in 5 runs
  historically, effectively every run in the week before that fix.
- Rate-limit and publish-error paths both call `add_to_retry_queue()`
  before moving on, so a DEGRADED run's failed articles are not lost —
  they are picked up automatically on the next scheduled run (every 2
  hours).

No changes made to retry/recovery logic this round beyond the atomic write
in §9.3; audited and found already correct.

---

## 13. Integrity Gates — Confirmed Unweakened

`report_integrity.py::PublicationIntegrityError` and the
`RX-P1-ARTIFACT-BINDING` hash-verification check in `main.py`
(`compute_artifact_hash(transformed["content"]) != transformed.get("certified_artifact_hash")`)
were **read but not modified**. Both are exercised end-to-end by existing
tests (`test_certified_artifact_hash_mismatch_blocks_publication`, still
passing) that tamper a real transformed artifact and confirm it is still
blocked before ever reaching Blogger. The only change touching
integrity-blocked articles is how the *run* is classified afterward — the
block itself is unconditional and untouched.

---

## 14. Blogger API Client Audit

`automation/blogger_publisher.py` read in full. Found solid; **no code
changes made**:

- **Auth:** token refresh with a 60s expiry buffer; a 401 triggers exactly
  one refresh-and-retry, a second 401 raises a fatal `BloggerAuthError`
  with an actionable hint (`invalid_grant` → rotate
  `BLOGGER_REFRESH_TOKEN`). No infinite-retry risk.
- **Rate limiting:** exponential backoff on 429, correctly raises the more
  specific `BloggerRateLimitError` (subclass of `BloggerPublishError`)
  after exhausting retries, which `main.py` already handles as a
  stop-and-requeue condition.
- **Publish-acceptance hard gate (pre-existing, "ReportX Phase 1P"):** an
  HTTP 200 only proves Blogger *accepted* the request; the response's own
  `status` field is checked against `LIVE` for non-draft publishes, so a
  quota/permission edge case silently downgrading to a draft is caught
  rather than reported as a successful publish.
- **No secrets logged:** error text is truncated to short snippets; tokens
  are never printed.

---

## 15. LLM Provider Reliability — Operator Action Items, Not Code Defects

`automation/llm_client.py` and `automation/config.py` read in full.
Provider chain: Groq → DeepSeek → OpenRouter → Anthropic → deterministic
template fallback.

- **Groq:** correctly configured (model ID already fixed in a prior round
  from a deprecated ID to `openai/gpt-oss-120b`); observed failure mode in
  sampled logs is a legitimate 429 after 1–2 successful calls per run — a
  real usage-volume rate limit, not a defect. Backoff/retry logic (bounded,
  jittered, respects a real `Retry-After` header, capped at 10s) is correct
  and was verified against the exact 10s/8s backoff delays seen in real
  logs.
- **DeepSeek / OpenRouter:** both return HTTP 402 Payment Required on every
  call — an account-billing exhaustion, not fixable from this repository.
  Correctly *not* retried (402 is excluded from the retry-on-429-only
  policy, confirmed in code and via the module's own documented rationale).
- **Anthropic:** correctly wired end-to-end —
  `Config.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")` maps
  correctly, the workflow YAML passes the secret through, and
  `call_llm()`'s provider list includes it fourth in priority order. It was
  never reached in sampled logs because the underlying GitHub Actions
  secret `ANTHROPIC_API_KEY` has not yet been populated (documented by a
  prior round's own code comment in `config.py`). This is an **operator
  action item**, not a bug: adding the secret would activate a fourth,
  currently-unused fallback provider.
- **Net effect:** every sampled run correctly and safely degrades to the
  deterministic `reportx_composer` template fallback, which still passes
  the quality scorecard for the large majority of published articles. No
  customer-facing quality defect; only reduced use of LLM-authored prose
  versus the template path, and increased per-article wall-clock time
  (~35–45s cycling through 3 failing providers before falling back).

**Recommended operator actions (not implemented here — outside this
repository's control):** top up DeepSeek and/or OpenRouter billing; add the
`ANTHROPIC_API_KEY` GitHub Actions secret if a fourth LLM fallback is
desired.

---

## 16. Observability

See §9.4. `run_status` is now: (a) persisted in every `logs/run-*.json`,
(b) logged in the "Pipeline complete" structured log line, (c) surfaced as
a `::warning::` annotation for DEGRADED runs in the Actions UI, and (d)
printed in the "Pipeline Summary" step output. A DEGRADED run is no longer
indistinguishable from either a clean SUCCESS or a genuine FAILED outage.

---

## 17. Security

- No secrets introduced, logged, or hardcoded. No changes to authentication
  or authorization logic (`blogger_publisher.py` untouched).
- No new external dependency, no new network egress target.
- The atomic-write change (`os.replace`) uses only the Python standard
  library, writes only within the existing `state_file`'s own directory,
  and does not change file permissions or introduce a predictable-tempfile
  race (the temp file is written directly, not via a shared/world-writable
  location).
- No change to CSP, input validation, or any customer-facing surface —
  this round is entirely confined to the internal GitHub-Actions-orchestrated
  publication pipeline.

---

## 18. Tests

Full regression run after all changes in this round:

| Suite | Result |
|---|---|
| `pytest tests/ automation/tests/` | **673 passed**, 0 failed |
| `jest` (repo-wide) | **1819 passed**, 60 skipped (pre-existing, unrelated to this round), 51/52 suites passed, 1 suite skipped |
| `node --test tests-js/*.test.js` | **206 passed**, 0 failed |
| `tsc --noEmit` | 0 errors |

New/updated tests this round:
- `automation/tests/test_main_requeue.py` — 12 new tests covering
  `_pipeline_run_status()` / `_pipeline_exit_code()` classification for
  every post-status combination, including the "terminal status wins even
  alongside a benign one" case and a missing-`run_status` safety case.
  2 pre-existing tests that encoded the *old* binary policy were replaced
  (see §10 — this is the deliberate, documented policy reversal, not
  incidental test breakage).
- `tests/test_integration.py` — 1 new end-to-end test
  (`test_auth_error_marks_run_failed_not_degraded`, real mocked 401-twice
  flow through the actual `run_pipeline()` exception handling, not just the
  pure classifier) plus `run_status` assertions added to 3 existing
  end-to-end tests (rate-limit exhaustion → DEGRADED, integrity-block →
  DEGRADED, missing-credentials → FAILED + exit 1).
- `tests/test_content_discovery.py` — 2 new tests: no `.tmp` file left
  behind after a normal save, and a simulated crash mid-write (patched
  `os.replace` to raise) proving the original state file survives intact
  and a fresh load still sees the prior publication correctly.

---

## 19. Failure Injection

Explicitly tested failure modes (all via `run_pipeline()` end-to-end unless
noted as a pure-function test):

| Injected failure | Expected classification | Verified |
|---|---|---|
| Evidence-integrity gate blocks a tampered artifact | DEGRADED | ✅ (existing + new assertion) |
| Blogger 429 exhausted across all retries | DEGRADED | ✅ (existing + new assertion) |
| Blogger 401 twice (revoked credential) | **FAILED** | ✅ (new end-to-end test) |
| Missing Blogger credentials entirely | **FAILED** | ✅ (existing + new assertion) |
| Bare/unexpected exception mid-article | **FAILED** | ✅ (pure-function test) |
| Single `publish_error` alongside otherwise-clean run | DEGRADED | ✅ (pure-function test) |
| Integrity block *and* auth error in the same run | **FAILED** (terminal wins) | ✅ (pure-function test) |
| Process killed mid state-file write | Original state file intact, no data loss | ✅ (new crash-injection test) |

---

## 20. Live Verification

Four real, recently-published posts (exact URLs recovered from real
production log evidence, not guessed) checked against the live
customer-facing domain:

| URL | HTTP status |
|---|---|
| `cti.cyberdudebivash.in/2026/08/cve-2026-76070-cvss-98-critical.html` | 200 |
| `cti.cyberdudebivash.in/2026/08/cve-2026-78206-cvss-75-high-severity.html` | 200 |
| `cti.cyberdudebivash.in/2026/08/cve-2026-78203-cvss-71-high-severity.html` | 200 |
| `cti.cyberdudebivash.in/2026/08/cve-2026-78161-cvss-73-high-severity.html` | 200 |

Content of the first post fetched and inspected directly: correct title
(`CVE-2026-76070 — CVSS 9.8 CRITICAL Severity | NVD Vulnerability Record |
CYBERDUDEBIVASH SENTINEL APEX`), correct CVE ID present in body, `<link
rel="canonical">` and `og:url` both correctly point to
`cti.cyberdudebivash.in` (not the underlying Blogspot domain). The only
`blogspot.com` references in the page are a secondary schema.org
`WebSite` node's `@id`/`url` (a legitimate, technically-accurate secondary
identity, distinct from the article's own canonical identity) and
Blogger's own platform-injected `google-adsense-platform-domain` meta tag
— neither is a canonical-domain regression.

---

## 21. Known Limitations

- The DEGRADED/FAILED policy in §9.1 is a judgment call on which failure
  modes are "self-healing/designed-for" versus "systemic." It is
  documented and tested but, like any policy, could be revisited again if
  real-world evidence shows a status currently classified DEGRADED is
  actually chronic and needs escalation (or vice versa).
- LLM-provider degradation (§15) is not fixed by this change — it requires
  operator action outside this repository (billing, secrets) and is
  explicitly out of scope for a code-only fix.
- The atomic state-write fix (§9.3) protects the state file itself; it
  does not add a two-phase-commit between "Blogger accepted the post" and
  "state file recorded it" — if the process were killed in the narrow
  window after `publisher.publish_post()` succeeds but before
  `mark_published()` completes, the article could be re-attempted on the
  next run and produce a second live Blogger post. This was true before
  this change as well; closing it fully would require either a Blogger-side
  idempotency key (not offered by the Blogger API) or a pre-publish
  reservation record, which is a larger design change out of scope for this
  reliability-focused round. Recommended as a future hardening item.
- CVE + Campaign Intelligence Dossiers & Analyst Decision Workspace v1 (the
  next commercial tranche) is explicitly deferred — not built in this PR
  per the mandate's own scope boundary.

---

## 22. Rollback Plan

All changes are additive/behavioral within existing functions — no schema,
route, or interface changes. Rollback is a straight `git revert` of this
PR's commits:
- `automation/main.py` reverts to the prior binary `failed > 0 → exit 1`
  policy (restoring the 2026-08-20 "Option A" behavior exactly).
- `automation/content_discovery.py`'s `save()` reverts to the direct
  (non-atomic) write — no data format change, so no migration needed either
  direction.
- `.github/workflows/blogger-syndication.yml` reverts to the prior
  Pipeline Summary/step-7 output — purely cosmetic, no functional
  dependency.
- No data migration required in either direction: `data/published_posts.json`'s
  schema is unchanged; `run_status` is simply an additional key in
  `logs/run-*.json` that older tooling would ignore.

---

## 23. Reuse Report

| Metric | Result |
|---|---|
| Existing components reused (extended, not replaced) | `automation/main.py` (`run_pipeline`, `_pipeline_exit_code`), `automation/content_discovery.py` (`PublicationState.save`), `.github/workflows/blogger-syndication.yml` (existing summary/annotation steps) |
| Existing API routes extended | N/A — no API surface touched this round |
| Existing pages extended | N/A |
| New components introduced | One new pure function, `_pipeline_run_status()`, colocated in the file whose policy it implements — justified by the gap analysis in §6 |
| Duplicate components introduced | **0** |
| Duplicate routes introduced | **0** |
| Backward compatibility preserved | PASS — `report` dict gained one additive key (`run_status`); every existing field and its computation is unchanged |
| Lighthouse scores maintained | N/A — no frontend/customer-facing surface touched |
| Build passing with zero errors | PASS — pytest 673/673, Jest 1819/1819 (+60 pre-existing skips), node:test 206/206, tsc 0 errors |

---

## 24. Verdict

**GO — CONDITIONAL** on the operator reading §10 and consciously confirming
the reversal of the 2026-08-20 decision before merging. Everything else in
this change is a strict reliability/observability improvement with full
test coverage, zero weakening of any evidence or security control, and
live-verified customer-facing delivery.
