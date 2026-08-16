# Cloudflare Account Inventory

Phase 0 deliverable (account-side half). Produced 2026-08-16 via the
**Cloudflare Developer Platform MCP connector** attached to this session —
not via `wrangler` CLI (still unauthenticated in this shell, see §5) and
not via a raw API token in this shell's environment. Every figure below is
a live tool-call result, not an estimate.

**Note on how access arrived**: the user added `CLOUDFLARE_API_TOKEN` /
`CLOUDFLARE_ACCOUNT_ID` as GitHub Actions repository secrets. Those are
scoped to GitHub Actions workflow runs and do not reach this interactive
session's shell — `wrangler whoami` still reports unauthenticated and
`env | grep -i cloudflare` is still empty here (re-checked at the time of
writing). The real access this document is built from is a separately
attached MCP connector, authenticated server-side outside this shell. This
is the same two-store distinction `ENVIRONMENT_VARIABLE_MATRIX.md` already
documents for Vercel vs. GitHub Actions — worth keeping straight here too.

---

## 1. Workers (13 total, `workers_list`)

| Name | Created | Last modified |
|---|---|---|
| `trustx-api` | 2026-08-15 | 2026-08-15 |
| `trustx-web` | 2026-08-15 | 2026-08-15 |
| `sentinel-intel-retention` | 2026-08-10 | 2026-08-10 |
| `academy-api-production` | 2026-08-04 | 2026-08-04 |
| `academy-api-preview` | 2026-08-03 | 2026-08-04 |
| `titan-platform-production` | 2026-07-23 | 2026-07-30 |
| `sentinel-revenue-engine` | 2026-04-18 | 2026-08-10 |
| `sentinel-apex-gateway` | 2026-04-16 | 2026-08-13 |
| `sentinel-apex-intel-gateway-prod` | 2026-04-15 | 2026-04-15 |
| `sentinel-apex-intel-gateway` | 2026-04-15 | 2026-04-15 |
| `red-lab-44fa` | 2026-04-07 | 2026-04-07 |
| `cyberdudebivash-security-hub` | 2026-04-03 | 2026-08-15 |
| `quiet-lake-801cads-txt-handler` | 2026-03-31 | 2026-03-31 |

**No name collision with `cyberdudebivash-blog`** — confirmed directly
against this list, not inferred.

**Corroborating finding**: `sentinel-apex-gateway`,
`sentinel-apex-intel-gateway-prod`, and `sentinel-apex-intel-gateway`
strongly indicate the Sentinel APEX CTI platform
(`intel.cyberdudebivash.com`, per `CLAUDE.md`'s ecosystem-separation
section) is **already running on Cloudflare Workers**, actively modified
as recently as 2026-08-13. This corroborates the user's "we have all our
platforms hosted there" statement with direct evidence — unlike the
earlier Vercel-account-loss claim, which contradicted this session's first
checks, this claim checks out. `academy-api-*`, `titan-platform-*`,
`trustx-*`, `sentinel-revenue-engine`, and `cyberdudebivash-security-hub`
indicate at least four more distinct platforms live on the same account.

**Naming convention observed**: kebab-case, `-production`/`-preview` or
`-prod` suffixes distinguish environments on the same logical service
(`academy-api-production` / `academy-api-preview`;
`sentinel-apex-intel-gateway` / `sentinel-apex-intel-gateway-prod`). The
planned `cyberdudebivash-blog` (staging variant, e.g.
`cyberdudebivash-blog-preview`) fits this convention without modification.

`quiet-lake-801cads-txt-handler` matches Cloudflare's own
auto-generated-name pattern (`quiet-lake-xxxx`) for a Worker created
without an explicit name — `NOT VERIFIED` what it does beyond what its
suffix implies (an `ads.txt` handler for one of the domains on this
account).

## 2. KV namespaces (8 total, `kv_namespaces_list`)

`REVENUE_CRM_KV`, `ACADEMY_KV_PRODUCTION`, `THREAT_INTEL_KV`,
`RATE_LIMIT_KV`, `EMAIL_QUEUE_KV`, `SECURITY_HUB_KV`, `ANALYTICS_KV`,
`API_KEYS_KV`. None named for the blog. This tool does not report which
Worker binds which namespace, so cross-Worker binding relationships are
`NOT VERIFIED` from this listing alone. Not a blocker: the blog's only
datastore today is Upstash Redis (REST API, works unchanged from a
Worker) — this migration does not require a new KV namespace unless scope
changes later.

## 3. R2 buckets (3 total, `r2_buckets_list`)

`cyberdudebivash-scan-results`, `sentinel-apex-data`,
`sentinel-apex-reports`. **`cyberdudebivash-products` — the bucket name
`.env.example`/`PRODUCTS_BUCKET` documents for the (currently dead-code,
per `platform/open-issues.md`) digital-download R2 path — does not exist
in this account.** This is a concrete, pre-existing gap independent of the
Cloudflare migration: that download path was already non-functional on
Vercel (missing `aws-sdk` dependency) and would still need this bucket
created even if the R2 code path is fixed. Not a migration blocker, since
that feature isn't functional today either way — noted so it isn't
mistaken for something the migration itself broke.

## 4. D1 databases (5 total, `d1_databases_list`)

`academy-db-production`, `epimap-registry`, `titan-platform-production-db`,
`sentinel-crm`, `cyberdudebivash-security-hub`. None belong to the blog,
and none are needed — the blog has no relational-database dependency
today (Upstash Redis + static JSON under `api/intel/**`).

## 5. Hyperdrive (0 configured)

Empty. Not relevant — the blog never connects to an external SQL database
from a Worker, so no Hyperdrive config is needed.

## 6. What this inventory still cannot answer

The Developer Platform MCP connector exposes Workers (read-only — see
below), KV, R2, D1, and Hyperdrive. It does **not** expose:

- **DNS zones or records** — no tool lists zones, records, or proves what
  `blog.cyberdudebivash.in` or any candidate staging hostname currently
  resolves to or is claimed by.
- **Cloudflare Pages projects** — no `pages_list`-equivalent tool exists
  in this connector, only a Workers-focused one
  (`migrate_pages_to_workers_guide` — a doc/guide tool, not an inventory
  one). Whether any existing platform uses Pages rather than Workers is
  `NOT VERIFIED`.
- **Worker Routes / custom domain bindings** — `workers_get_worker`
  returns only `name` and `id`, not bound routes or custom domains. So
  while §1 proves no *Worker name* collides with `cyberdudebivash-blog`,
  it does **not** prove no existing route/hostname would collide with a
  chosen staging subdomain — that remains open until a DNS-capable check
  is available.
- **Account plan tier and limits** — no account-settings tool in this
  connector. Whether Workers CPU-time limits comfortably fit the OG-image
  route's current Vercel budget (`memory: 512, maxDuration: 15`, flagged
  as the one workload worth explicit load-testing in
  `PRE-MIGRATION-FORENSICS.md` §8) remains unconfirmed.
- **Worker deploy/write access.** The Workers tools available here are
  read-only (`workers_list`, `workers_get_worker`,
  `workers_get_worker_code`) — there is no create/deploy tool. D1/KV/R2
  do have create/delete tools in this connector, but Workers do not.
  Actually deploying the new isolated staging Worker will need either an
  authenticated `wrangler` session in this shell, or direct Workers API
  access — neither is available yet (see §5 above on why the GitHub
  Actions secret doesn't reach here).

## 7. Practical consequence for sequencing

Nothing above blocks continuing repo-side work right now: the
compatibility-shim and Worker-routing-logic build (mirroring
`vercel.json`'s rewrite/header table, per `PRE-MIGRATION-FORENSICS.md`
§3/§6) needs no Cloudflare access at all. The gaps in §6 only become
blocking at the point of actually deploying a staging Worker and binding
it to a route — that is where DNS visibility and deploy-capable
credentials become required, not before.
