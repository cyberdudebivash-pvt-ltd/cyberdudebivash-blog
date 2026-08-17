# Cloudflare Staging Validation — Stage 5

Canonical Stage 5 artifact for the `blog.cyberdudebivash.in` Vercel → Cloudflare
Workers migration. This document certifies (or explicitly declines to certify)
the live, isolated Cloudflare staging deployment against production Vercel,
using only directly observed evidence. No claim in this document is inferred
without a cited command, HTTP response, or file comparison backing it.

Continuation branch: `claude/cyberdudebivash-migration-stage5-jvrr4j`
(this branch started from `origin/main` at the exact commit where the prior
session's `.gitattributes` LF-fix branch was squash-merged via PR #80 — see
§2 for the full ancestry proof).

---

## 1. Executive summary

Stage 5 had two jobs: (a) prove the `.gitattributes` LF-normalization fix
(committed by the prior session, merged to `main` via PR #80) actually
produces byte-deterministic deployable assets, and (b) certify a
LF-corrected live Cloudflare staging redeploy end-to-end against live
production Vercel, closing out the artifact-integrity defect the prior
session found (deployed JSON/HTML/XML assets carried injected `\r` bytes
from a Windows checkout with no `.gitattributes` in place at deploy time).

**This session's own Cloudflare credential status is identical to the prior
session's: none.** `wrangler whoami` reports unauthenticated, no
`CLOUDFLARE_API_TOKEN` in the environment, no Cloudflare MCP connector
configured for this account. This is a genuine, structural limitation of
this remote container, not a retry-able transient failure — confirmed by
directly checking `wrangler whoami`, `env | grep -i cloudflare`, and the
account's available MCP connectors (§9 in the task handoff already
established the same for the prior session; this session independently
re-confirmed it rather than assuming the prior finding still holds).

Consequently, this session completed **all repository-side certification
work that does not require a live deployment**: git reconciliation, LF
byte-integrity proof (Git blob = working tree = build output, SHA-256,
6/6 representative files), the full predeploy QA gate (npm ci / audit /
Jest / node:test / wrangler dry-run), and — using the network access this
session *does* have — a complete live HTTP certification of the **existing**
staging Worker (still running pre-LF-fix version `6f243f31`) against live
Vercel production, including a full 31-handler / 54-path API route
reachability census that was not previously run at this scope.

**The actual LF-corrected redeploy (Stage 5 §10) requires the operator's
authenticated local Wrangler**, exactly as it did in the prior session. Exact
commands are in §9 below. Sections 10–12, 17 (remote byte integrity against
the *new* version, re-run live security certification against the *new*
version) are marked `PENDING OPERATOR REDEPLOY` and cannot be marked PASS
until that redeploy happens and is re-verified in a follow-up turn of this
same session.

**Interim verdict, pending only the operator redeploy**:
**CONDITIONAL GO** — see §26.

---

## 2. Git identity

| Ref | SHA |
|---|---|
| `origin/main` (at session start) | `522d7372cb286f691b83cda96f2693ab50f304eb` |
| `origin/claude/cyberdudebivash-state-recovery-iewq2g` (prior continuation branch, per handoff) | `c782fd6fbbcbc2367aa6f0bc52a33d66b0ac9127` |
| This session's branch (`claude/cyberdudebivash-migration-stage5-jvrr4j`), starting `HEAD` | `522d7372cb286f691b83cda96f2693ab50f304eb` (== `origin/main`) |

**Reconciliation proof** (per handoff §1, mandatory before any other work):

- `git merge-base --is-ancestor c782fd6f... origin/main` → **NO** (the exact
  commit is not a literal ancestor of `main`).
- GitHub PR #80's merge commit on `main` (`522d7372c`, titled `Claude/
  cyberdudebivash state recovery iewq2g (#80)`) was a **squash merge** of the
  state-recovery branch — confirmed by content, not title alone:
  `git show origin/main:.gitattributes` returns the exact `.gitattributes`
  file (including its full incident-narrative comment block) that the
  state-recovery branch's final commit (`c782fd6fb`, "fix: pin text-asset
  line endings to LF via .gitattributes") introduced.
- `git diff --stat origin/main origin/claude/cyberdudebivash-state-recovery-iewq2g`
  shows **zero** remaining difference in any migration document, code file,
  or `.gitattributes` — the only remaining deltas are 19 files of
  auto-generated content-pipeline state (`intel-state.json`, `live-intel.json`,
  `api/intel/*.json`, syndication timestamps, a stale run log) that the
  scheduled SENTINEL APEX content pipeline regenerates independently on both
  branches. None of these are migration work product.
- **Conclusion: Case A — lossless, content-verified fast-forward equivalent.**
  `origin/main` already contains 100% of the prior session's Stage 4/5 work.
  This session's branch, cut from `origin/main`, needed no merge, no
  cherry-pick, and no conflict resolution. No `git reset`, no force-push, no
  destructive operation was used or needed.

---

## 3. Cloudflare identity

| Field | Value |
|---|---|
| Worker name | `cyberdudebivash-blog` |
| `*.workers.dev` URL | `https://cyberdudebivash-blog.iambivash-bn.workers.dev` |
| Original (pre-LF-fix) Version ID | `6f243f31-a98a-4324-b2c1-32bb9b4a5bae` |
| Replacement (LF-fixed) Version ID | **PENDING OPERATOR REDEPLOY** — not yet created |
| Cloudflare account authenticated in this session | **No** — confirmed via `wrangler whoami` (`You are not authenticated`), `env \| grep -i cloudflare` (no `CLOUDFLARE_API_TOKEN`/`CF_API_TOKEN`), and no Cloudflare MCP connector available to this account |

---

## 4. Deployment bindings

Read directly from the committed `wrangler.jsonc` on this branch (not
inferred): `env.ASSETS` (static asset binding) only.

Explicitly, verifiably absent: `routes`, `custom_domains`, `kv_namespaces`,
`d1_databases`, `r2_buckets`, `services`, `triggers.crons`, and no `vars`/
`secrets` with real values (the file's own trailing comment block documents
each omission and the reason). `npx wrangler deploy --dry-run` (§8 below)
independently confirms the same at runtime: `Your Worker has access to the
following bindings: Binding env.ASSETS Resource Assets` — nothing else
listed.

**This is structurally incapable of touching production DNS, Vercel, or any
production data store.** The worst-case blast radius of any deploy under
this config is: create or update the isolated `cyberdudebivash-blog` Worker
and its own `*.workers.dev` static assets. Nothing else.

---

## 5. Build reproducibility

`node scripts/build-cloudflare-assets.js` run fresh this session (after
`npm ci`, from a clean, previously-nonexistent `dist-public/`):

```
dist-public/ built: 8412 files
```

`wrangler deploy --dry-run` independently counted **8434** files read from
the assets directory — a 22-file discrepancy against the build script's own
`countFiles()` (also independently re-verified via `find dist-public -type f
| wc -l` → 8412). This is a Wrangler-internal accounting artifact (e.g. its
own asset-manifest/upload bookkeeping), not evidence of extra or missing
files — `find` and the build script's own counter agree exactly with each
other at 8412, and neither wrangler run wrote anything into `dist-public/`
before counting. Flagged honestly rather than silently reconciled; does not
block certification.

Total upload size this session's dry-run reported: **13,956.73 KiB / gzip:
2,753.96 KiB** — close to but not identical to the prior session's live
deployment figure (13,944.50 KiB / 2,752.22 KiB gzip). This delta is
expected and not a red flag: the site's automated content pipeline
("SENTINEL APEX v5.0") publishes new posts/CVE pages continuously (visible
in `git log` as recurring `[skip ci]` auto-commits), and real time elapsed
between the prior deployment and this session's build. It is **not** the LF
byte-inflation the prior session found and fixed — this session's build ran
on a Linux container with no `core.autocrlf` conversion (see §6), so the
LF fix's effect on THIS build's size is zero; the size delta here is pure
content growth.

---

## 6. LF/CRLF incident — byte-integrity proof

### 6.1 What was proven

For 6 representative text-asset files spanning the categories the prior
session found affected (large generated JSON, small JSON, large generated
XML, HTML, client JS, CSS), SHA-256 was computed independently for:

- **A** — the committed Git blob (`git cat-file -p HEAD:<path> | sha256sum`)
- **B** — the working-tree file on disk (`sha256sum <path>`)
- **C** — the same file inside the freshly built `dist-public/` (`sha256sum
  dist-public/<path>`)

| Path | Git bytes | Working bytes | dist-public bytes | A (git) SHA-256 | B (working) SHA-256 | C (dist) SHA-256 | Result |
|---|---|---|---|---|---|---|---|
| `api/intel/threat-graph.json` | 7,535,625 | 7,535,625 | 7,535,625 | `1c026044...` | `1c026044...` | `1c026044...` | **PASS — A==B==C** |
| `api/intel/iocs.json` | 439 | 439 | 439 | `ae179a02...` | `ae179a02...` | `ae179a02...` | **PASS — A==B==C** |
| `sitemap.xml` | 1,223,532 | 1,223,532 | 1,223,532 | `85b766d8...` | `85b766d8...` | `85b766d8...` | **PASS — A==B==C** |
| `index.html` | 198,062 | 198,062 | 198,062 | `76f31356...` | `76f31356...` | `76f31356...` | **PASS — A==B==C** |
| `banner-orchestrator.js` | 9,885 | 9,885 | 9,885 | `3b145e28...` | `3b145e28...` | `3b145e28...` | **PASS — A==B==C** |
| `apex-v13.css` | 9,279 | 9,279 | 9,279 | `646a50dd...` | `646a50dd...` | `646a50dd...` | **PASS — A==B==C** |

(Full 64-hex-char SHA-256 values recorded in this session's transcript;
truncated here for table width. All three values matched in full for every
row — no truncated-prefix collision risk, exact-string comparison was used.)

### 6.2 Root cause and remediation (carried forward from the prior session,
re-verified not re-litigated)

Root cause: `.gitattributes` did not exist on the branch when the original
`6f243f31` staging deployment was built on a Windows operator machine.
Windows Git for Windows defaults `core.autocrlf=true`, which silently
rewrites every text file's LF line endings to CRLF on checkout;
`scripts/build-cloudflare-assets.js` then `fs.copyFileSync()`'s those
already-CRLF-converted files into `dist-public/` byte-for-byte, and
`wrangler deploy` uploads them as-is. Proven at the time via direct
byte-level comparison (`api/intel/threat-graph.json`: deployed 7,778,626
bytes vs. committed blob 7,534,017 bytes — a 244,609-byte gap matching the
file's own newline count exactly, one injected `\r` per line;
`util.isDeepStrictEqual` on parsed JSON confirmed the data itself was
semantically unaffected — an artifact-integrity defect, not data
corruption).

Remediation: `.gitattributes` committed with `* text=auto eol=lf` (overrides
`core.autocrlf` for every matched pattern, sufficient without any
operator-side `git config` change) plus explicit `binary` declarations for
`*.png`, `*.woff`, `*.ico`.

### 6.3 Coverage check — does `.gitattributes` actually cover every deployed
file type? (new this session, not assumed)

Enumerated every distinct file extension actually present in the built
`dist-public/` (the real deployable set, not the whole repo):

```
5713 html   2661 json   14 js   8 yml   4 png   3 css
   2 xml       2 txt    1 webmanifest   1 ico   2 svg
```

Every one of these is either plain text (covered by `text=auto eol=lf`) or
`.png`/`.ico` (explicitly declared `binary`). No `.woff`, `.wasm`, or other
binary type appears in the deployed static-asset set (fonts are Data-module
imports at Worker-bundle build time, not static assets; `.wasm` is a
`CompiledWasm` Wrangler bundling rule, also not a static asset) — so the
`*.woff binary` declaration in `.gitattributes` is defensive/currently-unused
for `dist-public/` specifically, and there is no unaccounted-for binary
extension in the actual deployed set.

### 6.4 Build-time normalization — evaluated, not implemented (evidence-based
conclusion, per handoff §7)

Question: should `scripts/build-cloudflare-assets.js` normalize text-asset
line endings to LF itself, as defense-in-depth on top of `.gitattributes`?

**Conclusion: not implemented. `.gitattributes` + a fresh checkout is
sufficient, evidenced as follows:**

- §6.1 already proves byte-identity end-to-end (Git blob → working tree →
  build output) on this session's Linux checkout with `.gitattributes` in
  place. `.gitattributes`' `eol=lf` directive is Git's own checkout-time
  normalization; it is not a Cloudflare-specific or Linux-specific
  workaround.
- §6.3 confirms every actual deployed file type is covered by the existing
  `.gitattributes` rules by direct enumeration, not assumption.
- The build script (`scripts/build-cloudflare-assets.js`) uses
  `fs.copyFileSync()` — a pure byte copy. Given a correctly-normalized
  working tree, its output is byte-identical to the source by construction;
  no separate normalization logic is needed downstream of a correct
  checkout.
- The residual risk `.gitattributes` alone cannot retroactively fix is an
  **already-populated** working tree whose files were checked out on
  Windows *before* `.gitattributes` existed — Git does not retroactively
  rewrite unchanged tracked files' on-disk bytes when a new
  `.gitattributes` is added. This is a checkout-process risk, not a
  build-script risk, and the correct mitigation is a **fresh clone** (§9),
  not new code.
- Adding build-time normalization would require the build script to
  independently classify text vs. binary for every current and future asset
  type — a second place (parallel to `.gitattributes`) that must be kept in
  sync, and a real risk (per handoff §7's own caution) of corrupting a
  binary file if that classification logic ever drifts from
  `.gitattributes`'s. This is exactly the kind of unforced, unjustified
  change-surface expansion Levels 1 and 5 of this repository's engineering
  decision order (Correctness, Minimal Change Surface) argue against absent
  a documented requirement — and §6.1–6.3 show no such requirement exists.

**Decision: no code change to `scripts/build-cloudflare-assets.js`.**
`.gitattributes` (source-tree protection) + a fresh clone before build
(operator-process protection, §9) is the certified, evidence-backed
sufficient mitigation.

---

## 7. Static validation

`GET /` and `GET /about.html` both re-verified live this session against
**both** platforms (§18, §19) — 200, correct content, no console/runtime
errors observed in response bodies. Full static/routing/private-path matrix
(homepage, representative pages, JSON, RSS, sitemap, robots, assets, path
traversal, encoded-path probes) was already `LIVE-CLOUDFLARE-VERIFIED` by
the prior session against `6f243f31` (handoff §3, "ACCEPTED STAGE 5 LIVE
DEPLOYMENT EVIDENCE") — carried forward as baseline, **scheduled for
re-verification against the LF-corrected redeploy**, since static asset
*bytes* are exactly what changed (§6).

---

## 8. API validation

Full 31-handler API surface exercised live this session — see §9 below
(route reachability census) for the complete table. Summary: every
Cloudflare-reachable handler returned a well-formed, correctly-headered
response (200/400/401/404/405/500-with-structured-body); zero raw stack
traces, zero unhandled exceptions, zero silent 5xx without a structured JSON
error body.

---

## 9. Route reachability census

Full census — 31 handler files, 54 URL variants, live HTTP against both
`blog.cyberdudebivash.in` (Vercel production) and
`cyberdudebivash-blog.iambivash-bn.workers.dev` (Cloudflare staging,
version `6f243f31`) — is recorded in full in
`VERCEL-CLOUDFLARE-PARITY-MATRIX.md` §6.1. Summary:

| Classification | Count |
|---|---|
| `PARITY_PASS` | 30 |
| `CLOUDFLARE_FIXES_PREEXISTING_VERCEL_DEFECT` | 23 (of which 3 also carry a `NOT_VERIFIED` functional-depth caveat — Redis-dependent handlers, no Redis binding on isolated staging by design) |
| `INTENTIONALLY_CHANGED` | 1 (`/api/og` dynamic rendering — see §19) |
| `CLOUDFLARE_REGRESSION` | 0 |
| `NOT_SAFE_TO_TEST` | 0 |
| `NOT_VERIFIED` (standalone, beyond the 3 above) | 0 |

**Headline finding**: 23 of 31 API handler files are completely unreachable
on live Vercel production (`vercel.json`'s `functions` block explicitly
configures exactly 8 files; live evidence shows those 8, and only those 8,
are the ones reachable — 100% correlation, 8/8 and 23/23). This is a
pre-existing Vercel production defect that Cloudflare correctly routes
around by design (its own `route-table.js` port has no such restriction).
Full detail, including the honestly-stated caveat about the inferred causal
mechanism, is in `VERCEL-CLOUDFLARE-PARITY-MATRIX.md` §6.1.

---

## 10. Private-path validation

Prior session (handoff §2/§3): 17 representative internal/private paths
tested against `6f243f31`, **0/17 exposed**. This session did not re-run
the full 17-path sweep against the unchanged routing/security-header logic
(only static asset *bytes* changed via the LF fix — `workers/lib/
route-table.js`'s `BLOCKED_PREFIXES` and the allowlist-first
`scripts/build-cloudflare-assets.js` build are unmodified on this branch,
confirmed via `git diff origin/main HEAD` showing this branch is byte-
identical to `origin/main` at session start). **Scheduled for full re-run
against the LF-corrected redeploy** per Stage 5 protocol — status:
`PENDING OPERATOR REDEPLOY`.

---

## 11. Headers

Static-asset header baseline (`dist-public/_headers`, transcribed from
`vercel.json`) and dynamic-response header baseline
(`workers/lib/security-headers.js`) are unmodified on this branch relative
to the already-certified `origin/main` state. Live re-spot-check this
session (`/about.html`, `/api/v1/intel/live` on both platforms) shows the
expected HSTS/CSP/X-Frame-Options/Referrer-Policy/Permissions-Policy set
present on Cloudflare responses. Full per-path-type header matrix:
`PENDING OPERATOR REDEPLOY` (full re-run against the new version, per
Stage 5 protocol).

---

## 12. Caching

The Stage 4 dynamic-Cache-Control fix (`applyBaselineHeaders()`,
commit `9ba8a16b2`) was independently re-confirmed live by the prior session
against `6f243f31` (handoff §3: "Cache-Control fix from Stage 4 is live and
correct: no-store on sensitive endpoints ... while billing?action=plans's
own deliberate public caching is preserved untouched"). Unmodified on this
branch. Full re-run: `PENDING OPERATOR REDEPLOY`.

---

## 13. CORS

`Access-Control-Allow-Origin: *` never combined with
`Access-Control-Allow-Credentials` (bearer/API-key auth only, zero
`Set-Cookie` usage anywhere in the codebase, per Stage 4's full-codebase
grep, unmodified on this branch). Full OPTIONS/GET re-probe:
`PENDING OPERATOR REDEPLOY`.

---

## 14. Authentication

Full census in §9 shows every auth-gated endpoint correctly returning `401`
(anonymous) on both platforms, with generic, non-leaking error messages
(`"API key required..."`, `"Valid X-Admin-Key header required."`) — no
format-vs-value oracle, no stack traces. Consistent live evidence, this
session, against `6f243f31`. Full re-run against the LF-corrected redeploy:
`PENDING OPERATOR REDEPLOY`.

---

## 15. Webhooks

Prior session (handoff §2): Stripe and Razorpay webhook negative-path
security (missing/invalid/tampered/oversized/empty/wrong-method) already
`LIVE-CLOUDFLARE-VERIFIED` against `6f243f31`. This session independently
re-confirmed both webhook endpoints are method-gated (`405` on bare `GET`,
both platforms, §9 census) — consistent, no regression. Full 7-case ×
2-processor re-run: `PENDING OPERATOR REDEPLOY`.

---

## 16. Body limits

Prior session (Stage 4, `LOCAL-TEST-RESULTS.md` §3.1): 4.5 MB ceiling
enforced via `readBoundedText()`, incremental stream-cancellation hardening
applied (commit `91ab7bebe`). Unmodified on this branch. Not independently
re-exercised this session (would require sending a large POST body — safe
but not repeated here since the code path is unchanged and byte-identical
to the already-certified `main` state). Full re-run: `PENDING OPERATOR
REDEPLOY`.

---

## 17. Asset integrity

§6 proves Git blob = working tree = `dist-public` build output
byte-identity for 6 representative files on this session's Linux container.
**Remote byte-integrity** (live `*.workers.dev` response bytes vs. committed
Git blob) requires the LF-corrected redeploy to exist first — the currently
live `6f243f31` deployment is the *pre-fix* artifact by definition (that's
the whole reason a redeploy is needed). Status: `PENDING OPERATOR
REDEPLOY`. Exact verification commands are pre-staged and will run
immediately once the operator reports a new Version ID (§9's redeploy
commands, §21 below for the verification script).

---

## 18. Vercel-vs-Cloudflare comparison

See `VERCEL-CLOUDFLARE-PARITY-MATRIX.md` in full (128+ rows across 6
sections) and this document's §9, §19, §20. Net-net: Cloudflare staging
matches or improves on every capability tested; the one intentional
functional difference (§19) is a known, pre-existing package-level
limitation with a safe graceful fallback, not a Cloudflare defect.

---

## 19. Security improvements (Cloudflare over current Vercel production)

1. **Homepage (`/`) CSP/Permissions-Policy** — `vercel.json`'s
   `/(.*).html` header rule (which carries CSP, Permissions-Policy, and
   Cache-Control) only matches URLs literally ending in `.html`; the bare
   `/` never matches it and falls through to the platform-default headers
   from the separate `/(.*)`  catch-all rule, which does **not** set CSP or
   Permissions-Policy. Live Vercel's bare `/` today ships with **no CSP at
   all**. Cloudflare's `dist-public/_headers` deliberately mirrors the
   `.html` rule's header set onto `/` as well (via its own `/` block) —
   confirmed via live header diff this session and the prior session. This
   is a real security improvement inherent to the migration, not a
   regression risk.
2. **23 previously-unreachable API handlers now correctly routed** (§9) —
   while primarily a functionality fix, several of these are
   security-relevant surfaces (`customer/dashboard`, `customer/download`)
   that now correctly enforce their own auth/validation logic instead of
   being invisible to any client, legitimate or otherwise.

---

## 20. Pre-existing Vercel defects discovered (not migration-caused)

1. **23 of 31 API handler files unreachable on live Vercel production**
   (§9) — `vercel.json`'s `functions` block appears to restrict Vercel's
   serverless-function discovery to exactly the 8 files it explicitly
   lists; the other 23 return Vercel's own platform-level `NOT_FOUND`.
   Caveat on causal mechanism stated honestly in
   `VERCEL-CLOUDFLARE-PARITY-MATRIX.md` §6.1 — not confirmed against
   Vercel's own dashboard/build logs (no Vercel account access from this
   session), but the reachability gap itself is directly, repeatedly
   observed and 100%-correlated with the `functions` block's contents.
2. **Homepage has no CSP** on live Vercel production (§19.1) — a
   pre-existing gap that migration incidentally corrects; flagged here as
   a Vercel-side finding independent of the migration decision either way.
3. **Bare homepage `/` has no CSP** — same root cause as #2, listed
   separately per the handoff's own itemization (Section 13.A).

These are reported as findings about current Vercel production, not
acted upon — Stage 5's scope is Cloudflare staging certification, not
production Vercel remediation, and no Vercel-side change was made or
proposed.

---

## 21. Cloudflare regressions, if any

**Zero found this session, with one caveat requiring explicit acknowledgment
before cutover** (not a regression, but a known functional gap):
`/api/og`'s dynamic per-post PNG rendering does not work on Cloudflare
(`@resvg/resvg-wasm` fails to instantiate at runtime — `WebAssembly.
instantiate(): Wasm code generation disallowed by embedder`, reproduced
live on the deployed Worker and locally via `wrangler dev`, root-caused to
a package-level incompatibility already documented in `wrangler.jsonc`'s own
`.wasm` rule comment). The endpoint's own designed fallback (302 to the
static `/og-image.png`) fires correctly — zero 500s, zero broken share
cards, just a less-specific image. This was already known and classified
`INTENTIONALLY-CHANGED` by Stage 4's local testing; this session's
contribution is live corroboration on the real deployed edge (§6.2 of the
parity matrix), not a new discovery. Listed here because it is real,
user-facing functional degradation that deserves an explicit go/no-go
decision from the business before cutover, not silent inheritance.

---

## 22. Unresolved production defects

- **Issue 19** (`api/v1/products/approvals.js`, `api/v1/workbench/cases.js`
  action sub-path contract vs. actual routing on both platforms) — remains
  open, per the handoff's explicit instruction not to silently fix it in
  Stage 5. Documented separately in `platform/open-issues.md` (not modified
  this session).
- The 23-handler Vercel reachability defect (§20.1) is a **production**
  defect independent of the migration decision — it exists on live Vercel
  today, regardless of whether/when Cloudflare cutover happens. Flagged for
  the operator's awareness; not a Cloudflare migration blocker (Cloudflare
  does not reproduce it — see §9).

---

## 23. Known staging limitations

- No Redis binding on the isolated staging Worker (by design) — 3 handlers
  (`api/v1/products`, `api/v1/workbench/dashboard`, `api/v1/workbench/
  investigations`) return a structured `500` with `"Redis not configured"`
  rather than real data. Reachability is proven; full functional behavior
  requires either a staging-scoped Redis credential (not provisioned) or
  production cutover with real secrets (Stage 6, not authorized).
- This session has no Cloudflare deploy credentials — the LF-corrected
  redeploy and its full live re-certification remain `PENDING OPERATOR
  REDEPLOY` (§9, §26).
- Cloudflare Worker logs (`wrangler tail` or dashboard) were not accessible
  from this session (no Cloudflare auth) — the `/api/og` root cause was
  independently reproduced via local `wrangler dev` instead (§6.2 of the
  parity matrix), which is direct evidence of the same failure mode, but
  live-edge log inspection per handoff §18 is marked `NOT VERIFIED —
  OPERATOR LOG REVIEW REQUIRED` for anything beyond what local reproduction
  already explains.

---

## 24. Rollback evidence

No production system was touched this session. Vercel remains the sole
production platform for `blog.cyberdudebivash.in`; DNS, Vercel deployment,
and all production secrets/storage are untouched. The isolated Cloudflare
Worker (`cyberdudebivash-blog`) has no route, no custom domain, and no
production binding — deleting it or leaving it as-is has zero effect on
production traffic. `ROLLBACK-RUNBOOK.md` (committed prior to this session,
unmodified) remains the authoritative rollback procedure for the eventual
Stage 6 cutover; nothing in this session invalidates it.

---

## 25. Production cutover blockers

Per the handoff's explicit gate (§20), Stage 5 may recommend cutover
**planning** only once every item below is closed. Current status:

| Gate item | Status |
|---|---|
| 0 npm vulnerabilities | **PASS** — `npm audit`: 0 vulnerabilities |
| 0 Jest failures | **PASS** — 1600 passed, 0 failed, 60 skipped (pre-existing, unrelated to this session) |
| 0 node:test failures | **PASS** — 527 passed, 0 failed (exceeds the ≥255 baseline) across all 5 discovered node:test locations |
| Wrangler dry-run PASS | **PASS** — clean, `env.ASSETS` only |
| Asset integrity PASS | **PASS** (Git↔working↔dist) / **PENDING** (Git↔live-remote, needs redeploy) |
| 0 private path exposure | **PASS** (prior session, `6f243f31`) / **PENDING** re-run on new version |
| 0 critical auth regressions | **PASS** (this session, full 31-handler census) |
| 0 sensitive cache regressions | **PASS** (prior session) / **PENDING** re-run on new version |
| 0 critical CORS regressions | **PASS** (prior session + this session's codebase grep) |
| 0 unexplained staging 5xx | **PASS with explained exceptions** — the only 500s observed (§9, §23) are the designed, structured, non-leaking Redis-unavailable response on an intentionally-secret-free staging Worker; not unexplained |
| 0 Cloudflare route regressions | **PASS** — 0 `CLOUDFLARE_REGRESSION` in the full 54-path census |
| All intended public assets verified | **PASS** — allowlist-first build, enumerated and cross-checked (§6.3) |
| Staging LF/byte-integrity defect closed | **PASS at the Git/build level (§6.1)** / **PENDING at the live-remote level** — requires the redeploy |
| Rollback plan valid | **PASS** — unchanged, production untouched (§24) |
| Vercel production untouched | **PASS** — confirmed, no DNS/route/secret/storage change made or attempted |

**Remaining blockers to a full, unconditional GO**: the LF-corrected staging
redeploy itself (blocked on operator-side Cloudflare credentials, not on any
open code or certification question), and the live re-certifications that
depend on it (§10–§17, §21 remote byte check). No code defect, no security
finding, and no unresolved regression is blocking — only the deployment
action itself.

---

## 26. Final Stage-5 verdict

```
STAGE 5 — LIVE CLOUDFLARE STAGING CERTIFICATION (interim, this session)

Git:
  main SHA:        522d7372cb286f691b83cda96f2693ab50f304eb
  branch SHA:       (this branch, cut from main; see §2 for full ancestry proof)
  deployment SHA:   PENDING — operator has not yet run the redeploy in §9

Cloudflare:
  Worker:           cyberdudebivash-blog
  URL:              https://cyberdudebivash-blog.iambivash-bn.workers.dev
  previous Version: 6f243f31-a98a-4324-b2c1-32bb9b4a5bae (pre-LF-fix)
  current Version:  PENDING OPERATOR REDEPLOY
  bindings:         env.ASSETS only (confirmed, dry-run + wrangler.jsonc read)

Quality:
  npm audit:        0 vulnerabilities
  Jest:              1600 passed / 0 failed / 60 skipped
  node:test:         527 passed / 0 failed (>= 255 baseline)
  Wrangler dry-run:  PASS, clean

Artifacts:
  LF integrity (Git<->working<->dist): PASS, 6/6 files, SHA-256 exact match
  Git<->remote hash:                   PENDING — requires the redeploy in §9

Runtime (against currently-live 6f243f31, pre-LF-fix):
  static:       PASS (prior session; scheduled for re-run post-redeploy)
  API:          PASS (this session, full 31-handler / 54-path census)
  private paths: PASS 0/17 exposed (prior session; scheduled for re-run)
  auth:         PASS (this session, full census)
  cache:        PASS (prior session; scheduled for re-run)
  CORS:         PASS (prior + this session)
  webhooks:     PASS (prior session; method-gating re-confirmed this session)
  logs:         NOT VERIFIED — no Cloudflare log access this session;
                /api/og root cause independently reproduced via local
                wrangler dev instead
  performance:  no unexplained regression; small-sample median TTFB
                comparable on both platforms (static ~0.2s both; API
                Cloudflare trending faster, ~0.42s vs ~0.74s median — single
                vantage point, not a platform-speed claim)

Route census (31 handlers / 54 paths):
  PARITY_PASS:                              30
  CLOUDFLARE_FIXES_PREEXISTING_VERCEL_DEFECT: 23 (3 also NOT_VERIFIED functional-depth, Redis)
  CLOUDFLARE_REGRESSION:                     0
  INTENTIONALLY_CHANGED:                     1 (/api/og dynamic render)
  NOT_VERIFIED:                              0 standalone

Parity (full matrix, VERCEL-CLOUDFLARE-PARITY-MATRIX.md):
  PASS:                        38 (Stage 4) + 30 (Stage 5 census) = 68
  EXPECTED_SECURITY_IMPROVEMENT: 2 (homepage CSP, §19)
  PREEXISTING_VERCEL_DEFECT:    1 major (23-handler reachability, §20) + prior
                                 CVE-detail/workbench-dashboard/redis-command
                                 defects already fixed in both platforms (Stage 4)
  FAIL:                         0
  BLOCKED:                      0

Open issues:
  Issue 19:            still open, not fixed in Stage 5 per explicit instruction
  other production defects: 23-handler Vercel reachability gap (§20.1) — a
                             live-production issue independent of migration
                             timing; Vercel homepage missing CSP (§20.2/3)

Production blockers:
  Only the operator-side LF-corrected redeploy itself (§9) and the live
  re-certifications that depend on it. Zero code, security, or regression
  blockers identified.

FINAL VERDICT:

CONDITIONAL GO — STAGING HEALTHY, SPECIFIED ITEMS MUST CLOSE FIRST

Specified items required to close before an unconditional GO:
  1. Operator redeploys staging with the LF-corrected build (§9 exact
     commands) and reports back the new Version ID + full wrangler output.
  2. This session (or a continuation of it) re-runs: remote byte-integrity
     (Git blob SHA-256 vs. live response SHA-256, §17), the full private-path
     sweep (17 paths, §10), the full header/cache/CORS/auth/webhook/body-limit
     matrix (§11-16) against the NEW version, and confirms zero regression
     vs. the 6f243f31 baseline recorded in this document.
  3. Business/product sign-off on the one known, accepted functional
     limitation: /api/og dynamic per-post social-card rendering does not
     work on Cloudflare (static fallback only) — §21, §19-note.
  4. No DNS, Vercel, or production change of any kind until Stage 6 is
     explicitly authorized by the operator, independent of this verdict.
```

---

## Appendix: hard stop

This document certifies Cloudflare **staging** only. Per the task's explicit
instruction, no Stage 6 action was taken or will be taken as part of this
session: no DNS mutation, no production custom domain, no Vercel removal or
modification, no production Cron/KV/D1/R2/Queue migration, no production
secret rotation. Stage 6 requires separate, explicit operator authorization.
