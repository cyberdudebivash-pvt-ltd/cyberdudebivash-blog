# Production Cutover Runbook — Stage 6

`blog.cyberdudebivash.in`: Vercel → Cloudflare Workers

**Status of this document: prechecks and pre-deploy steps are certified
and ready to execute. The DNS-mutation section (Section 6) is fully
written and ready, but MUST NOT be executed without a separate, explicit
"proceed with DNS cutover" authorization from the operator, given after
reviewing the GO/NO-GO checkpoint. Nothing past Section 5 has been run.**

All commands are Windows `cmd.exe`, matching Stages 5 and 6's established
operator environment (Wrangler is authenticated locally there; this
session has no Cloudflare credentials).

---

## 0. Before you start — what this changes and what it doesn't

**This runbook changes exactly one thing**: which backend serves HTTP
requests for `blog.cyberdudebivash.in`. It does not touch KV, D1, R2, Cron,
payment provider configuration, or remove Vercel. Per Stage 6 Section 15,
those are explicitly out of scope for this cutover.

**Domain model**: Cloudflare **Custom Domain** (not a Worker Route),
verified against Cloudflare's current documentation this session. Custom
Domains are Cloudflare's recommended model when a Worker owns 100% of a
hostname's traffic (as opposed to Routes, meant for a Worker handling only
part of a zone's traffic alongside another origin). The zone
`cyberdudebivash.in` is already on Cloudflare nameservers
(`lewis.ns.cloudflare.com`, `venus.ns.cloudflare.com` — confirmed via live
DNS query this session), so no zone transfer is needed.

**Critical constraint, confirmed against Cloudflare's own documentation**:
*"You cannot create a Custom Domain on a hostname with an existing CNAME DNS
record."* `blog.cyberdudebivash.in` currently has exactly that — a DNS-only
CNAME to `4eefaa5cc0d21fce.vercel-dns-017.com` (TTL 600s). **The existing
record must be deleted before the Custom Domain can be created.** This means
the cutover is not a single atomic step — there is a brief window between
deleting the old record and the new one becoming active. Section 6 below
sequences this to minimize that window and gives an immediate verification
step to confirm it closed correctly.

---

## 1. Precheck — confirm starting state

Run every command in this section before touching anything. If any output
doesn't match what's shown, **stop and investigate before continuing.**

```cmd
cd C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-PLATFORMS
npx wrangler whoami
```
Expected: shows an authenticated Cloudflare account (not "You are not
authenticated").

```cmd
npx wrangler deployments list --name cyberdudebivash-blog
```
Expected: most recent version is `09d20b10-ade1-486c-a8eb-e54ce42fb12c`
(Stage 5) or `042a8e08-31d0-47f9-884d-ac61e78d5a53` (Stage 6 pre-freeze
deploy) — confirms you're looking at the right Worker before doing anything
to it.

Check current DNS (does not require any tool beyond a browser or `curl`; if
using `curl` from `cmd.exe`, it's available by default on modern Windows):
```cmd
curl -s -o nul -w "%%{http_code}\n" https://blog.cyberdudebivash.in/
```
Expected: `200` (site currently live via Vercel).

**Record the pre-cutover rollback baseline** (you will need this in Section
7 if a rollback is ever required):

| Field | Value |
|---|---|
| Record type | CNAME |
| Name | `blog` (i.e. `blog.cyberdudebivash.in`) |
| Target | `4eefaa5cc0d21fce.vercel-dns-017.com` |
| TTL | 600 seconds |
| Proxy status | DNS only (grey cloud, not proxied) |

(This was captured via live DNS query during Stage 6 prep. **Re-verify it
is still accurate immediately before cutover** — do not trust a value that
may be stale by the time you actually execute this runbook.)

---

## 2. Content freeze

Follow `PRODUCTION_FREEZE_PROCEDURE.md` in full. Summary:

1. Disable these 6 workflows via
   `https://github.com/cyberdudebivash-pvt-ltd/cyberdudebivash-blog/actions/workflows/<file>`
   → **"..."** → **"Disable workflow"**:
   `sentinel-apex.yml`, `blogger-syndication.yml`, `ai-security-intel.yml`,
   `cve-pages.yml`, `generate-rss.yml`, `intelligence-hub.yml`
2. Record the UTC timestamp.
3. Wait for any in-flight run of those 6 to finish (check the Actions tab).
4. Wait an additional 2 minutes, then confirm no further commits land.

---

## 3. Capture the freeze SHA

```cmd
cd C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-PLATFORMS
git clone https://github.com/cyberdudebivash-pvt-ltd/cyberdudebivash-blog.git cyberdudebivash-blog-cutover
cd cyberdudebivash-blog-cutover
git checkout claude/cyberdudebivash-cloudflare-stage6-cutover
git fetch origin main
git rev-parse origin/main
```

Record this SHA as `PRODUCTION_FREEZE_SHA`. If the operator wants the
absolute latest content (recommended — the whole point of the freeze is to
capture current content, not this branch's slightly older snapshot), merge
it in now:

```cmd
git merge origin/main -m "Stage 6: merge final pre-freeze main content"
```

This should merge cleanly — Stage 6 prep confirmed zero code/config
conflicts between this branch and `main`'s recent history (only generated
content differs, which merges without conflict). If it does **not** merge
cleanly, **stop** — do not resolve conflicts blindly in a production cutover
window; investigate what changed.

```cmd
git rev-parse HEAD
```
This is your final `PRODUCTION_FREEZE_SHA` — record it.

---

## 4. Build and test the freeze SHA

```cmd
npm ci
npm audit
node scripts/build-cloudflare-assets.js
```

Expected: `0 vulnerabilities`; build prints a file count close to 8422–8430
(a handful more than Stage 6 prep's 8422, depending on how much content
landed in the final sync).

```cmd
npx jest --ci
```
Expected: `Tests: 0 failed` (baseline: 1603 passed, 60 skipped — skips are
pre-existing and unrelated).

```cmd
cd Sentinel-APEX\engine-node && node --test && cd ..\..
cd Sentinel-APEX\renderer && node --test && cd ..\..
cd scripts && node --test && cd ..
cd workers\lib && node --test && cd ..\..
node --test tests-js\*.test.js
```
Expected: `0 failed` in every one of the 5 runs (baseline total: 527
passed).

```cmd
npx wrangler deploy --dry-run
```
Expected: bindings show **`env.ASSETS` only** — nothing else. No
"Duplicate key" warnings (fixed this session — if this warning reappears,
new code introduced it after Stage 6; investigate before continuing, do
not ignore). Note the reported file count and upload size for the final
report.

**Stop condition**: any non-zero vulnerability count, any test failure, any
binding other than `env.ASSETS`, or any duplicate-key warning halts the
runbook here. Do not proceed to deployment.

---

## 5. Deploy the freeze SHA and live-certify (still no domain attached)

```cmd
npx wrangler deploy
```

Record the new Version ID. This updates the **same isolated Worker** —
still only reachable at `https://cyberdudebivash-blog.iambivash-bn.workers.dev`,
no production traffic yet.

Run the live certification matrix against that URL (all read-only/negative-
path, safe to run from any machine with internet access — does not need to
be run from the Windows deploy machine):

- Static: `/`, a representative post, a representative CVE page, `/rss.xml`,
  `/sitemap.xml`, `/robots.txt` — all expect `200`
- Private paths: the 17-path sweep from `CLOUDFLARE-STAGING-VALIDATION.md`
  §10 — expect `0/17` exposed
- API: spot-check `/api/v1/intel/live` (401), `/api/v1/admin/payments/pending`
  (401), `/api/v1/customer/dashboard` (400 — reachable, correctly rejects
  missing param), `/api/v1/detections/rules` (200)
- Security: headers on `/` (CSP/HSTS/Permissions-Policy present), CORS
  preflight on `/api/v1/intel/live` (204, no credentials+wildcard combo),
  webhook negative-path (`POST /api/v1/billing/webhook` with no signature
  → `400`), oversized body (5MB POST → `413`)

**Required: 0 unexpected 5xx, 0 private-path exposure, 0 regression from
the Stage 5/6 baselines already recorded in `CLOUDFLARE-STAGING-VALIDATION.md`.**

**This is the GO/NO-GO checkpoint.** If everything above passes, the Worker
now represents the exact artifact that Section 6 will put into production.
Do not proceed past this point without explicit operator authorization to
continue with the DNS mutation.

---

## 6. DNS cutover — REQUIRES SEPARATE EXPLICIT AUTHORIZATION

**Do not run anything in this section until the operator has explicitly
said to proceed, after reviewing Section 5's results.**

### 6.1 Remove the conflicting CNAME

Via the Cloudflare dashboard (`dash.cloudflare.com` → select the
`cyberdudebivash.in` zone → **DNS** → **Records**):

1. Find the CNAME record for `blog` → `4eefaa5cc0d21fce.vercel-dns-017.com`
2. **Before deleting**, re-confirm it still matches Section 1's recorded
   baseline (target and TTL) — if it has changed, stop and re-capture the
   baseline before proceeding, since your rollback data would otherwise be
   stale.
3. Delete the record.

This is the moment `blog.cyberdudebivash.in` stops resolving to Vercel.
There will be a brief gap (seconds to low minutes, depending on resolver
caching against the 600s TTL) until Section 6.2 completes and the new
record propagates. This gap is expected and unavoidable given Cloudflare's
documented Custom Domain prerequisite — it is not a sign of something
going wrong.

### 6.2 Add the Custom Domain

**Config-file approach** (recommended — keeps the domain binding in version
control, consistent with how `wrangler.jsonc` already documents every other
deliberate inclusion/omission):

Edit `wrangler.jsonc` in the cutover checkout, adding one block (verified
against Cloudflare's current Wrangler configuration reference this
session — this is the exact, current syntax, not remembered/assumed):

```jsonc
"routes": [
  {
    "pattern": "blog.cyberdudebivash.in",
    "custom_domain": true
  }
],
```

Add this as a new top-level key, placed after the `"assets"` block and
before the trailing comment block documenting deliberately-absent keys
(update that comment block too — `routes` is no longer absent).

```cmd
npx wrangler deploy
```

Cloudflare will create the necessary DNS record and provision a TLS
certificate automatically (per its own documentation: *"Cloudflare will
create DNS records and issue necessary certificates on your behalf"*) — no
manual DNS record creation needed for this step.

**Alternative (dashboard-only, if you prefer not to edit the config file
mid-cutover)**: Cloudflare Dashboard → **Workers & Pages** → select
`cyberdudebivash-blog` → **Settings** → **Domains & Routes** → **Add** →
**Custom Domain** → enter `blog.cyberdudebivash.in` → confirm. Functionally
equivalent to the config-file approach; either is acceptable, but only do
one (not both, to avoid a duplicate/conflicting route definition).

Record the UTC timestamp the moment this step completes — this is your
official cutover time.

---

## 7. Immediate post-cutover certification

Run within minutes of Section 6.2 completing, against
`https://blog.cyberdudebivash.in` directly (now the production Worker):

```cmd
curl -s -o nul -w "%%{http_code}\n" https://blog.cyberdudebivash.in/
```
Expected: `200`. If `522`/`523`/timeout, DNS/TLS provisioning is still
propagating — wait up to 2 minutes and retry before treating as an
incident (per Cloudflare's own certificate-issuance timing).

Re-run the full Section 5 certification matrix against
`https://blog.cyberdudebivash.in` instead of the `workers.dev` URL. Then
additionally:

- **Compare against the certified `workers.dev` output** (§20 of the
  original Stage 6 task): status codes, headers, and response bytes for
  the same paths on both URLs should match exactly (modulo the `Host`
  header and any host-specific CSP `connect-src` entries already present
  in `dist-public/_headers`, which reference `blog.cyberdudebivash.in`
  explicitly and were always correct — nothing to change there). **Any
  unexplained difference between the two is a cutover incident** — stop
  and investigate before declaring success.
- OG fallback: confirm `/api/og` still 302s to `/og-image.png` cleanly (no
  500) — known, accepted limitation, not a regression if consistent with
  Section 5's pre-cutover check.

**Required: 0 unexpected 5xx, 0 private exposure, 0 missing critical
content**, matching Stage 6 Section 19's gate exactly.

---

## 8. Observation window

Do **not** decommission Vercel. Keep it fully intact and reachable at its
own Vercel-assigned URL (unaffected by the DNS change — only the custom
domain moved).

Monitor for at least the observation window the operator sets (recommend a
minimum of 2–4 hours covering at least one full automated-content-pipeline
cycle once resumed, so publication flows are also exercised under
production traffic):

- Cloudflare dashboard → **Workers & Pages** → `cyberdudebivash-blog` →
  **Metrics**: error rate, request volume, CPU time
- Manually re-check the critical paths from Section 7 periodically
- Watch for Redis/webhook/external-dependency issues flagged as
  `CUTOVER WATCH ITEM`s during Stage 6 prep (real Upstash connectivity,
  real Stripe/Razorpay webhook delivery, real download-token validation,
  real Apex-bridge outbound calls — none of these were safely testable
  pre-cutover without live credentials/traffic; this is where they get
  their first real exercise)

## 9. Resume automation

Once the observation window is complete and stable: follow
`PRODUCTION_FREEZE_PROCEDURE.md` §6 (re-enable the 6 workflows, verify the
next scheduled tick produces a normal commit, confirm feed freshness).

---

## 10. Rollback

**Trigger immediately** (per Stage 6 Section 22) for: homepage outage,
critical route outage, private-data exposure, auth bypass, customer-endpoint
failure, billing/webhook critical failure, persistent unexplained 5xx, major
asset loss, or major DNS/routing failure. Do not troubleshoot indefinitely
on live production when rollback is safer.

```
Cloudflare Dashboard → cyberdudebivash.in zone → DNS → Records
→ delete the auto-created Custom Domain record
→ Workers & Pages → cyberdudebivash-blog → Settings → Domains & Routes
  → remove the blog.cyberdudebivash.in Custom Domain
→ (if the config-file approach was used) revert the wrangler.jsonc
  "routes" addition and redeploy, OR simply leave it — an un-attached
  custom_domain route with no matching DNS record is inert, matching the
  Worker's pre-cutover state
→ Add DNS record: type CNAME, name "blog",
  target "4eefaa5cc0d21fce.vercel-dns-017.com", TTL 600, DNS only (not proxied)
  — using the Section 1 baseline, re-confirmed at cutover time
```

Verify after rollback:
```cmd
curl -s -o nul -w "%%{http_code}\n" https://blog.cyberdudebivash.in/
curl -sI https://blog.cyberdudebivash.in/ | findstr /i "server"
```
Expected: `200`, `server: Vercel` — production restored to its pre-cutover
state.

Record incident evidence (what triggered rollback, timestamps, error
samples) before and after. **Do not delete the Cloudflare staging Worker or
its version history** — it remains available for post-incident analysis and
a future retry.

Per Cloudflare's documented Custom Domain behavior, the Advanced
Certificate created for the domain is **not** automatically deleted when
the Custom Domain is removed — if doing a full clean rollback (not just an
emergency traffic revert), manually remove it via **SSL/TLS** → **Edge
Certificates** in the dashboard to avoid an orphaned certificate resource.
This is not required for traffic to roll back correctly; it is cleanup.

---

## 11. Explicitly out of scope for this cutover

Per Stage 6 Section 15/25 — do not do any of the following as part of this
runbook, regardless of how smoothly the cutover goes:

- KV/D1/R2 migration (none currently bound; not needed for hosting)
- Cron trigger migration (GitHub Actions remains authoritative — see
  `VERCEL-CLOUDFLARE-PARITY-MATRIX.md` §3's Cron row)
- Payment provider (Stripe/Razorpay) reconfiguration — webhook endpoint
  URLs stay identical (`/api/v1/billing/webhook`,
  `/api/v1/billing/razorpay-webhook`), so no provider-side change is needed
- Vercel account/project deletion — separate, later, explicitly authorized
  decommission step only, after a full stability gate
- Any secret rotation beyond what's already documented as recommended
  (optional) in the environment/secret cutover matrix
