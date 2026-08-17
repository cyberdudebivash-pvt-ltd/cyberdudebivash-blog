# Complete Cloudflare Inventory

Canonical, structured formalization of `CLOUDFLARE-ACCOUNT-INVENTORY.md`'s
investigation. That document remains the full narrative log (how each
figure was obtained, what tools were used, what disconnected mid-session,
what was later corroborated via a local `wrangler whoami`) — this document
is the canonical reference table Stage 4 Section 19 requires under this
exact filename. Reconciled, not duplicated: nothing below contradicts
`CLOUDFLARE-ACCOUNT-INVENTORY.md`; this is that document's findings
organized as the formal inventory record.

**Evidence basis**: Cloudflare Developer Platform MCP connector
(CLAUDE-MCP-VERIFIED, 2026-08-16) for §1–5, corroborated by a locally
authenticated `wrangler whoami` transcript the user provided later the
same day (§6) — that connector has since disconnected and could not be
re-run for this document; all figures below are carried forward from
`CLOUDFLARE-ACCOUNT-INVENTORY.md` verbatim, not re-queried.

## 1. Workers — 13 total

See `WORKER-COLLISION-MATRIX.md` for the full list and the specific
name-collision analysis. Summary: no collision with `cyberdudebivash-blog`;
strong evidence (via naming pattern) that the separate Sentinel APEX CTI
platform and at least four other CYBERDUDEBIVASH platforms
(`academy-api-*`, `titan-platform-*`, `trustx-*`,
`sentinel-revenue-engine`, `cyberdudebivash-security-hub`) are already
live on this same Cloudflare account.

## 2. KV namespaces — 8 total

`REVENUE_CRM_KV`, `ACADEMY_KV_PRODUCTION`, `THREAT_INTEL_KV`,
`RATE_LIMIT_KV`, `EMAIL_QUEUE_KV`, `SECURITY_HUB_KV`, `ANALYTICS_KV`,
`API_KEYS_KV`. **None are named for, or verified-owned-by, the blog.**
Cross-Worker binding relationships (which Worker binds which namespace)
are NOT VERIFIED — the connector's `kv_namespaces_list` does not expose
that relationship. See Stage 4 Section 10's storage-binding decision
(this session): all three candidates relevant to the blog
(`THREAT_INTEL_KV`, `API_KEYS_KV`, `RATE_LIMIT_KV`) are classified
**DEFER** — the blog's current datastore (Upstash Redis) has no forcing
Worker-compatibility reason to change, and per this migration's own
"hosting migration first, data-platform migration later" principle, no
decision is made now.

## 3. R2 buckets — 3 total

`cyberdudebivash-scan-results`, `sentinel-apex-data`,
`sentinel-apex-reports`. **`cyberdudebivash-products`** — the bucket name
`.env.example`/`PRODUCTS_BUCKET` documents for the digital-download path —
**does not exist in this account.** That download code path
(`api/v1/customer/download.js`'s `getS3Client()`) is confirmed dead code
independent of this migration: it `require()`s `aws-sdk`, which is not a
declared dependency and is absent from `node_modules` — this branch always
fails on Vercel today regardless of R2/S3 credentials or bucket existence.
Storage decision (Section 10, this session): `sentinel-apex-data` and
`sentinel-apex-reports` are classified **DO_NOT_REUSE** — their naming is
direct, unambiguous evidence of ownership by the separate Sentinel APEX
CTI platform, and `CLAUDE.md`'s own ecosystem-separation policy explicitly
prohibits the blog from coupling to that platform's infrastructure.

## 4. D1 databases — 5 total

`academy-db-production`, `epimap-registry`,
`titan-platform-production-db`, `sentinel-crm`,
`cyberdudebivash-security-hub`. None belong to the blog, and none are
needed — the blog has no relational-database dependency today (Upstash
Redis REST API + static JSON under `api/intel/**`, both confirmed
throughout this migration's testing).

## 5. Hyperdrive — 0 configured

Not relevant. The blog never connects to an external SQL database from a
Worker.

## 6. Account identity (local `wrangler whoami`, later corroboration)

- Account: `Iambivash.bn@gmail.com's Account`
- Account ID: `055c68d5d664747ff6c9e1093cd9673f`
- Confirmed token scopes include `workers (write)`, `workers_scripts
  (write)`, `workers_routes (write)`, `workers_kv (write)`, `d1 (write)`,
  `pages (write)` — real deploy capability.
- **`zone (read)` only — no zone/DNS write scope.** This token structurally
  cannot mutate DNS even by accident, independent of any procedural
  safeguard in this migration's governance.
- This account ID has **not** been independently cross-confirmed against
  §1–5's data (both came from the same underlying account per the user's
  statement, but no shared identifier exists across the two evidence
  sources to prove it directly in this session). NOT VERIFIED, flagged
  as such in `CLOUDFLARE-ACCOUNT-INVENTORY.md` §8 originally and carried
  forward here unchanged.

## 7. What remains unknown (carried forward, not re-litigated)

- DNS zones/records — see `BLOG-DNS-BASELINE.md`.
- Cloudflare Pages projects — no inventory tool exposed this.
- Worker Routes / custom domain bindings — see `WORKER-COLLISION-MATRIX.md`.
- Account plan tier and limits (e.g. whether Workers CPU-time limits
  comfortably cover the OG-image route's Vercel budget of
  `memory: 512, maxDuration: 15`) — no account-settings tool was available.
  Moot for the current architecture regardless, since OG dynamic rendering
  is classified INTENTIONALLY-CHANGED (static fallback) per
  `VERCEL-CLOUDFLARE-PARITY-MATRIX.md`.

## 8. Practical consequence

None of the above blocks local repo-side work, real `wrangler dev`
certification, or a `wrangler deploy --dry-run`. The gaps become relevant
only at the point of an actual remote deployment and route/domain binding
— which this task explicitly does not authorize (see Section 28 of the
governing task spec). `STAGING-DEPLOYMENT-PLAN.md` documents the *plan*
for the one narrow remote action a future, separately-authorized stage may
take.
