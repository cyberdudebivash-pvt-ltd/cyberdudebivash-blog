# Worker Name Collision Matrix

Focused extraction from `CLOUDFLARE-ACCOUNT-INVENTORY.md` §1 — narrowed to
the single question Stage 4 Section 19 asks for on its own: does the
planned Worker name collide with anything already on the target Cloudflare
account. `CLOUDFLARE-ACCOUNT-INVENTORY.md` remains the source investigation
log (how the data was gathered, via the Cloudflare Developer Platform MCP
connector's `workers_list`); this document is the canonical answer.

**Planned Worker name**: `cyberdudebivash-blog`

## Existing Workers on the target account (13 total, `workers_list`, 2026-08-16)

| Name | Created | Last modified | Collision? |
|---|---|---|---|
| `trustx-api` | 2026-08-15 | 2026-08-15 | No |
| `trustx-web` | 2026-08-15 | 2026-08-15 | No |
| `sentinel-intel-retention` | 2026-08-10 | 2026-08-10 | No |
| `academy-api-production` | 2026-08-04 | 2026-08-04 | No |
| `academy-api-preview` | 2026-08-03 | 2026-08-04 | No |
| `titan-platform-production` | 2026-07-23 | 2026-07-30 | No |
| `sentinel-revenue-engine` | 2026-04-18 | 2026-08-10 | No |
| `sentinel-apex-gateway` | 2026-04-16 | 2026-08-13 | No |
| `sentinel-apex-intel-gateway-prod` | 2026-04-15 | 2026-04-15 | No |
| `sentinel-apex-intel-gateway` | 2026-04-15 | 2026-04-15 | No |
| `red-lab-44fa` | 2026-04-07 | 2026-04-07 | No |
| `cyberdudebivash-security-hub` | 2026-04-03 | 2026-08-15 | No |
| `quiet-lake-801cads-txt-handler` | 2026-03-31 | 2026-03-31 | No |

**Result: `cyberdudebivash-blog` does not collide with any existing Worker
name on this account.** SOURCE: `CLOUDFLARE-ACCOUNT-INVENTORY.md` §1
(CLAUDE-MCP-VERIFIED, live tool-call result, not an estimate).

## Naming convention observed on this account

kebab-case, with `-production`/`-preview` or `-prod` suffixes distinguishing
environments of the same logical service (e.g. `academy-api-production` /
`academy-api-preview`). A staging variant of this Worker
(e.g. `cyberdudebivash-blog-preview` or `cyberdudebivash-blog-staging`)
would fit this convention without modification — recorded here as a
naming recommendation for the eventual first isolated staging deploy
(see `STAGING-DEPLOYMENT-PLAN.md`), not a decision made in this document.

## What this matrix cannot confirm (carried forward from `CLOUDFLARE-ACCOUNT-INVENTORY.md` §6)

- **Worker Routes / custom domain bindings.** `workers_get_worker` (the MCP
  connector's own tool) returns only `name` and `id`, not bound routes or
  custom domains. This matrix proves no *Worker name* collides — it does
  **not** prove no existing route/hostname on this account would collide
  with a chosen staging subdomain. That remains open until a DNS-capable
  check is available (see `BLOG-DNS-BASELINE.md`).
- **Cloudflare Pages projects.** No `pages_list`-equivalent tool existed in
  the connector session that produced this data. Whether any sibling
  platform on this account uses Pages rather than Workers is NOT VERIFIED,
  and therefore cannot collide-check against Pages project names either.

## Verdict

**No blocking collision found.** Safe to proceed with the name
`cyberdudebivash-blog` for the first isolated `workers.dev` staging
deployment, subject to the DNS/route caveats above being resolved before
any *custom domain* (not `workers.dev`) binding is ever attempted — which
is explicitly out of scope for the first staging deploy regardless
(see `STAGING-DEPLOYMENT-PLAN.md`).
