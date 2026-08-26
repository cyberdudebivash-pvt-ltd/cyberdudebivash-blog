# SENTINEL APEX — Production Runtime Policy

**Effective:** 2026-08-26
**Authority:** Operator directive, issued immediately after PR #137 (Cloudflare-Native Alert Orchestration v1) merged.
**Status:** Active policy. Supersedes any prior "scheduling authority is undecided" framing in this repository's own comments (e.g. `wrangler.jsonc`'s original header, `workers/lib/router.js#handleScheduled`'s original docstring) for the alert-delivery subsystem specifically — see the Migration Status table below for what has and has not yet been brought into compliance.

---

## 1. The policy, stated once

> **Cloudflare Workers is the only production runtime going forward.**
>
> - No Vercel production runtime for new capability.
> - No Upstash Redis production dependency for new capability.
> - No GitHub Actions as a production scheduler for new capability.
>
> **GitHub Actions remains permitted** for CI, automated tests, CodeQL, build verification, and deployment assurance — it is a development-and-verification tool, not a production execution environment, going forward.

This is a **forward-looking policy for new capability**, not a retroactive claim that every existing production dependency has already been migrated. §3 states precisely what is and is not yet in compliance, and why retroactive migration is sequenced deliberately rather than attempted all at once.

---

## 2. Rationale

- **Consolidation**: this platform already runs its primary HTTP surface on Cloudflare Workers (`workers/entry.js` → `workers/lib/router.js`, dual-runtime alongside Vercel via the same handler code). Extending Cloudflare to own scheduling and durable state removes a second, independently-operated runtime (GitHub Actions' scheduler) and a second, independently-operated data store (Upstash) from the critical path of any NEW capability, reducing operational surface area over time.
- **Cost and control**: Cloudflare Workers + D1 + Cron Triggers are the platform this operator has chosen to invest in operationally; GitHub Actions' scheduler was always a stopgap (documented as such from its own introduction — see `.github/workflows/alert-delivery.yml`'s header: "GitHub's native scheduler is UNRELIABLE below roughly 30 minutes," never framed as a permanent home).
- **Correctness discipline this policy imposes**: any new scheduled/durable-state capability must be designed against the assumption that its trigger mechanism does NOT provide exactly-once execution (Cloudflare Cron Triggers, like GitHub Actions schedules, are at-least-once at best) — see §5's non-negotiables, carried forward unchanged from the Alert Orchestration v1 mandate that first established this discipline.

---

## 3. Migration status — the honest inventory, not an aspiration

| Subsystem | Runtime / Store | Status | Reference |
|---|---|---|---|
| **Alert-delivery control plane** (preferences, delivery jobs, delivery log, dead letters, audit log) | Cloudflare D1 (scheduler: GitHub Actions bridge active; Cloudflare Cron Trigger code-complete, not yet live-deployed) | **Migrated this round** | `SENTINEL-APEX-CLOUDFLARE-ONLY-ALERT-RUNTIME-V1-CERTIFICATION.md` |
| Watchlists / change detection | Redis (Upstash) | **Not migrated** — explicitly out of scope for the above tranche; a future, separately-scoped tranche required | `SENTINEL-APEX-CLOUDFLARE-RUNTIME-DEPENDENCY-INVENTORY.md` §0 |
| Customer identity / auth / billing | Redis (Upstash) | **Not migrated** — 4+ files, unrelated mandate lineage | same, §2 |
| ReportX / Intelligence Factory (quality scoring, product composition, publication policy, etc.) | Redis (Upstash) | **Not migrated** — ~16 files, unrelated product surface | same, §2 |
| Content-generation pipeline (Intel Factory, Blogger syndication, RSS/CVE/intelligence-hub page generation) | GitHub Actions (scheduled, with real filesystem + `git commit`/push access) | **Not migrated, and not straightforwardly migratable** — Cloudflare Workers has no persistent filesystem and cannot `git commit`; this pipeline's actual mechanism is structurally incompatible with the Workers execution model as currently designed | same, §3 |
| Weekly security scan, pipeline-health CI check | GitHub Actions | **Compliant as-is** — this is exactly the CI/build/security-assurance use this policy explicitly permits, not a production scheduler | same, §3 |
| Primary HTTP surface (`api/v1/*`, static asset serving) | Dual-runtime: Vercel (live production today) + Cloudflare Workers (parity-verified, not yet the sole live production target) | **Partially migrated** (pre-dates this policy) — see `docs/architecture/VERCEL-CLOUDFLARE-PARITY-MATRIX.md` if present, or the PRE-MIGRATION-FORENSICS.md lineage this repo's `wrangler.jsonc` header references | `wrangler.jsonc` |

**Net position**: this policy is declared and one subsystem (alert delivery) has been brought into compliance with real evidence. The platform as a whole is NOT yet Cloudflare-only. Any future task or mandate that assumes otherwise should be corrected against this table, not against the policy's own aspirational framing.

---

## 4. What "brought into compliance" requires — the evidence bar

A subsystem is not considered migrated merely because Cloudflare-native code exists for it. Per the precedent set by the alert-delivery migration, compliance requires:

1. **A real, evidence-based dependency inventory** written before migration code, classifying every touched file (see the Dependency Inventory doc's own classification legend: `CLOUDFLARE_ACTIVE` / `MIGRATION_REQUIRED` / `CI_ONLY` / `LEGACY` / `DEAD` / `UNKNOWN`).
2. **Verification of the target Cloudflare primitive's actual behavior**, against current documentation AND, wherever feasible from the available sandbox, local emulation (`wrangler ... --local`) — never assumed from training data or the target primitive's name alone.
3. **A trigger-independence guarantee**: the migrated capability must continue to function correctly if its Cloudflare-native trigger is not yet live-deployed (i.e., a working bridge or fallback during the transition window) — never a "flag day" cutover that depends on unverifiable production access this session may not have.
4. **A certification document** disclosing exactly what was and was not proven, with the credential/access gaps stated plainly (see `SENTINEL-APEX-CLOUDFLARE-ONLY-ALERT-RUNTIME-V1-CERTIFICATION.md` §2/§13 for the template this establishes).
5. **Full regression evidence** (existing test suites unbroken, new tests for the new mechanism, run and reported with exact pass/fail counts — never "should work").

---

## 5. Non-negotiables for any future scheduled/durable-state migration under this policy

Carried forward unchanged from the Alert Orchestration v1 mandate, since they are runtime-agnostic correctness properties, not specific to Redis or D1:

- Never assume the trigger mechanism (Cloudflare Cron, GitHub Actions, or any other scheduler) provides exactly-once execution. Design for at-least-once, with idempotency as the actual safety mechanism.
- Never weaken atomic claim, lease expiration, idempotency, retry bounds, terminal-failure handling, delivery/job identity, customer isolation, or any existing security control "because of migration complexity." If the target Cloudflare primitive cannot match an existing property, STOP, document why, and choose a stronger primitive — do not ship a weaker system.
- Never destroy the source system's data before reconciliation is complete and verified.
- Never leave a period with zero working scheduler — a bridge/dual-write period is required until the new trigger is proven live.
- PR/task titles and certification claims must scope accurately to what was actually migrated — never claim platform-wide completion for a subsystem-scoped change.

---

## 6. Amending this policy

This document reflects an explicit operator directive. Loosening or reversing it (e.g., re-introducing a new GitHub-Actions-as-scheduler dependency, or a new Redis production dependency for a NEW capability) requires the same standard as any other architectural change under this repository's governance constitution: current-architecture/proposed-architecture/reason/expected-benefits/compatibility/migration-plan/rollback-plan, documented explicitly, not inferred from a single task's convenience.

---

*CYBERDUDEBIVASH® SENTINEL APEX — Production Runtime Policy*
*Established by the Cloudflare-Only Alert Runtime v1 tranche, 2026-08-26.*
