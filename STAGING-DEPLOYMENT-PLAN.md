# Staging Deployment Plan

**PLAN ONLY. NOT EXECUTED BY THIS DOCUMENT OR THIS TASK.**

Per Section 28 of this migration's governing task spec, this session is
not authorized to run a remote Cloudflare deployment under any
circumstance, regardless of readiness verdict. This document exists so a
future, separately-authorized session can execute a known, pre-reviewed
plan rather than improvise one.

## Scope — what the first staging deployment IS

| Property | Value |
|---|---|
| Worker name | `cyberdudebivash-blog` |
| Static assets | `dist-public/` (rebuilt fresh immediately before deploy) |
| Endpoint | `*.workers.dev` only (Cloudflare-assigned subdomain) |
| Bindings | `env.ASSETS` only |
| Secrets/vars | None (see `ENVIRONMENT-MIGRATION-MATRIX.md` — not required for this scope) |
| Custom domain | **None** |
| DNS | **Zero changes** |
| Cron trigger | **None** |
| Production storage (KV/D1/R2) | **None** |

## Exact command

```bash
rm -rf dist-public && node scripts/build-cloudflare-assets.js
npx wrangler deploy
```

(No `--dry-run` flag — this is the one deliberate remote-mutating step
this plan authorizes for a *future* execution. `wrangler.jsonc` as
currently committed has no `routes`, `custom_domains`, storage bindings,
or cron triggers — see the Wrangler Config Safety Audit in
`ROLLBACK-RUNBOOK.md`'s companion final readiness report — so this
command cannot mutate anything beyond creating/updating the named Worker
and its static asset bundle.)

## Expected outcomes

**Remote mutations this command WILL make:**
- Creates (first run) or updates (subsequent runs) the Worker script
  named `cyberdudebivash-blog` on the target Cloudflare account.
- Uploads `dist-public/`'s ~8,412 files (~197 MB uncompressed) as the
  Worker's static assets.
- Assigns/confirms a `*.workers.dev` subdomain for the Worker
  (Cloudflare's default behavior for a Worker with no explicit route).

**Remote mutations this command will NOT make** (verified against the
committed `wrangler.jsonc` — see the safety audit):
- No DNS record of any kind, for `blog.cyberdudebivash.in` or any other
  hostname.
- No custom domain binding.
- No production route claiming any hostname/path pattern.
- No KV namespace, D1 database, R2 bucket, or Queue binding — none are
  declared in `wrangler.jsonc`.
- No Cron Trigger — none declared.
- No secret value transmitted (`wrangler.jsonc` declares no `vars`/
  `secrets` section; none are set by this command).
- No change to the Vercel project, its configuration, or
  `blog.cyberdudebivash.in`'s current DNS/serving state — this command
  never touches Vercel at all.

**Expected local build artifacts** (from the certified, current build —
see `STATIC-ASSET-MANIFEST.md`):
- 8,412 files, ≈197.4 MiB total, largest single file
  `api/intel/threat-graph.json` (≈7.2 MiB).
- Worker bundle: previously measured at ≈5.16 MB / ≈1.82 MB gzip at an
  earlier Stage 3 checkpoint — **should be re-measured immediately before
  the actual future deploy**, since Stage 4's additional code
  (security-headers.js, the Redis client's 6 new methods, etc.) has
  grown the bundle somewhat since that figure was taken. A fresh
  `wrangler deploy --dry-run` immediately before the real deploy will
  report the current, accurate size.

## Post-deploy validation (future session's responsibility)

1. Confirm the assigned `*.workers.dev` hostname resolves and serves the
   homepage (200, correct `<title>`).
2. Re-run a subset of this session's real-HTTP certification suite
   (private-path blocking, security headers, a representative
   auth-gated 401, CORS preflight) against the **live** `workers.dev`
   endpoint — everything in `VERCEL-CLOUDFLARE-PARITY-MATRIX.md` was
   proven under local `wrangler dev`/Workerd, which is a faithful but not
   byte-identical simulation of the real edge (see, for example, the
   `CF-Connecting-IP` caveat in that matrix's Security Posture section —
   local Workerd cannot simulate Cloudflare's own edge-level header
   sanitization).
3. Confirm `blog.cyberdudebivash.in` is completely unaffected (still
   serving from Vercel, unchanged) — this is a structural guarantee from
   this plan never touching DNS, but worth a live spot-check anyway.

## What this plan explicitly does NOT cover

Provisioning real secrets, binding real storage, configuring a custom
domain, or any DNS change — all deliberately out of scope for a *first*
staging deployment whose purpose is proving the hosting/compatibility
layer, not exercising live payment or intelligence-data flows. A
follow-on plan, written after this first deployment is validated, would
scope that separately.

## Authorization gate

This plan may be executed only after:
1. This document, `ROLLBACK-RUNBOOK.md`, and the final readiness report's
   verdict have been reviewed by the operator.
2. Explicit, separate authorization is given for the remote action itself
   — completion of this Stage 4 certification is **not** that
   authorization on its own, per Section 34 (Hard Stop) of the governing
   task spec.
