# Blog DNS Baseline

Current DNS state for `blog.cyberdudebivash.in`, to the extent this session
can establish it, plus an explicit statement of what remains unverified.
Required by Stage 4 Section 19 as one of the 11 canonical migration
documents.

## Current known state

**`blog.cyberdudebivash.in` currently resolves to Vercel.** This is
CLAUDE-VERIFIED indirectly but solidly: `.github/workflows/smoke-test.yml`
runs on every qualifying push to `main` and performs real `curl` requests
against `https://blog.cyberdudebivash.in/*` (homepage, intel hub, pricing,
products, enterprise, contact, archive, live-intel API, RSS, sitemap),
expecting 200s and specific content — and this workflow has been passing
continuously, including immediately after this session's own merge of PR
#79 into `main` (workflow run triggered at commit `768ae37dc`, completed
successfully). A DNS record pointing anywhere other than the live,
correctly-serving Vercel deployment would make that smoke test fail
outright. This is PRODUCTION-BEHAVIOR-VERIFIED, not a direct DNS record
lookup.

## What this session cannot verify directly

- **The actual DNS record type/value** (A/AAAA/CNAME, TTL, proxy status).
  No DNS-capable tool was available in this session — the Cloudflare
  Developer Platform MCP connector used for `CLOUDFLARE-ACCOUNT-INVENTORY.md`
  explicitly does not expose zone/DNS-record tools (see that document's
  §6), and no direct `dig`/`whois`/registrar access was used in this
  session. **NOT VERIFIED** by this document.
- **Whether `cyberdudebivash.in` (the parent zone) is already onboarded to
  Cloudflare at all**, independent of whether any *record* points to
  Cloudflare. Given `CLOUDFLARE-ACCOUNT-INVENTORY.md` confirms at least
  four other CYBERDUDEBIVASH platforms are already live on Cloudflare
  Workers (`sentinel-apex-*`, `academy-api-*`, `titan-platform-*`,
  `trustx-*`), it is plausible the zone is already Cloudflare-managed for
  other subdomains even while `blog.` itself still points elsewhere — but
  this is INFERRED, not confirmed.
- **Whether any existing Cloudflare Worker Route already claims a pattern
  that would collide with a future `blog.cyberdudebivash.in` route.**
  Carried forward from `WORKER-COLLISION-MATRIX.md`'s own stated gap —
  the MCP connector's Workers tools don't expose bound routes.

## What this document does NOT authorize

Per Section 28/29 of this migration's governance: **no DNS change of any
kind is made, planned-and-executed, or prepared-as-a-pending-action by
this document.** The first isolated staging deployment
(`STAGING-DEPLOYMENT-PLAN.md`) explicitly targets `workers.dev` only —
zero DNS interaction. This document exists solely to record the current
baseline honestly (including its gaps) so that a *future*, separately
authorized production-cutover stage has an accurate starting point rather
than an assumed one.

## Recommended pre-cutover verification (future stage, not this one)

Before any future stage attempts a custom-domain binding for
`blog.cyberdudebivash.in`, that stage should independently:
1. Confirm current DNS record type/value/TTL via a registrar/DNS lookup
   tool with actual zone visibility.
2. Confirm whether `cyberdudebivash.in` is Cloudflare-managed (nameservers)
   or externally-hosted DNS pointing at Vercel.
3. Confirm no existing Worker Route on the target account already claims
   `blog.cyberdudebivash.in/*` or an overlapping pattern.

None of this blocks Section 26's staging-readiness verdict — the first
staging deployment does not touch DNS at all.
