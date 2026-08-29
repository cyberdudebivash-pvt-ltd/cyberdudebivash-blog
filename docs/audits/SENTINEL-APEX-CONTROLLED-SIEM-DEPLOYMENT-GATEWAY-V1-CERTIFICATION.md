# SENTINEL APEX™ — Controlled SIEM Deployment Gateway v1
## Production Certification

**Date:** 2026-08-29
**Branch:** `claude/controlled-detection-deployment-auu51p`
**Mandate:** P1/P0 Master Production Transformation Task — Controlled SIEM Deployment Gateway, Customer-Approved Detection Delivery, Read-Back Verification & Safe Rollback v1
**Prior tranche:** PR #142 (Customer Telemetry & Environment-Aware Defense Coverage Fabric v1, merged) — this tranche's prerequisite

---

## 1. Executive verdict

**CONDITIONAL GO.**

The platform now answers the question its two immediately-prior tranches could not: given a validated, environment-compatible detection, can this customer safely put it into their own SIEM, prove exactly what changed, verify it remotely, and roll it back? Every mechanical safety property the mandate required is implemented and proven by test: server-side approval (a client `approved: true` flag is never sufficient — there is no code path that accepts one), an approval-hash design that never lets a client control deployed content in the first place, idempotent deploy with atomic per-deployment concurrency claiming (proven under real concurrent execution, not asserted), ambiguous-create reconciliation (a simulated timeout-after-create is proven to resolve to one remote resource, not two), real read-back verification with drift detection that never silently overwrites a remote change, and a version-rotation rollback mechanism proven end-to-end (deploy v1 → update to v2 → roll back to v1 → read-back confirms the restored v1 content).

**Conditional, not unqualified GO**, because:
1. **Vendor sandbox execution is NOT VERIFIED.** This sandbox has no Azure tenant, subscription, or credentials of any kind, and — consistent with every prior tranche's own disclosure — no authenticated Cloudflare access either. The Microsoft Sentinel connector is verified against Microsoft's own current, live-fetched API documentation and covered by unit tests against a mocked `fetch`, never against a real Azure Sentinel workspace.
2. **Only one connector is production-capable.** Splunk, Elastic, IBM QRadar, and Google SecOps are honestly declared, capability-flagged as unimplemented, and documented with the specific reason each was not attempted — never silently omitted, never falsely claimed.
3. **The underlying detection corpus remains thin** (inherited, unchanged by this tranche — see the Customer Telemetry certification's own §30) and rollback re-deploys a locally-captured content snapshot rather than re-running the full release/compatibility gate against historical content, because the canonical detection store itself does not retain old content to re-validate against (a real, load-bearing discovery made while building this tranche — see §23).
4. **No live Cloudflare deployment verification** — consistent with every prior round in this session; this branch has not been merged or deployed.

Every mandate acceptance-criteria item this tranche's scope covers is met and evidenced below.

---

## 2. Customer problem

The Customer Telemetry & Defense Context Fabric (previous tranche) could tell a customer "this detection is READY for your declared Microsoft Sentinel environment." It could not get that detection INTO Sentinel — the customer still had to manually copy KQL text out of a dossier page and paste it into the Azure portal themselves, with no record on this platform of what was deployed, whether it still matches what the platform believes is deployed, or how to safely undo it. This tranche closes that gap, and only that gap: it is a controlled detection-content delivery mechanism, explicitly and permanently not a SOAR/automated-response system (§79, §116).

---

## 3. Baseline (fresh audit, this round)

`git checkout main && git pull && git log --oneline -70` was run before any code was written (branch created from `main` @ `d5e76534`). `platform/open-issues.md` Issue 30 item 6 already named "SENTINEL APEX™ Controlled SIEM Deployment Gateway v1" as the explicitly-deferred next transformation — confirmed via direct read, not assumed — so this tranche is a continuation of this platform's own recorded roadmap, not new scope invented by this session.

---

## 4. Connector audit

Full detail: `docs/audits/SENTINEL-APEX-SIEM-CONNECTOR-INVENTORY-V1.md`. Headline finding: **no SIEM connector, credential-deployment pipeline, or OAuth-to-vendor integration existed anywhere in this codebase before this tranche.** Every prior "Sentinel/Splunk/Elastic/QRadar/Chronicle" reference was detection-format *generation* (`Sentinel-APEX/engine-node/detection-engine.js`) or report-prose labeling, never a network client. Zero duplicate canonical stores introduced.

---

## 5. Connector selection — evidence, not a blind default

Microsoft Sentinel was selected and PROVEN, not assumed:
- `api/_lib/defense-taxonomy.js#TECHNOLOGIES['microsoft-sentinel']` already declares `detection_format: 'kql'` — Microsoft Sentinel is the only SIEM technology this platform's own Customer Telemetry Fabric already models as `READY`-capable today (Splunk is modeled too, but see below).
- `Sentinel-APEX/engine-node/detection-engine.js#FIELD_MAP` already targets Microsoft's real Advanced Hunting table names (`DeviceProcessEvents`, `DeviceEvents`, `DeviceRegistryEvents`) — the KQL content this connector ships is the most field-verified content this platform generates (`confidence: 'documented'` in `defense-taxonomy.js`, vs. `'general'` for every other provider except Sysmon/Windows/Linux-auditd).
- A real, live, structurally-validated, `RELEASED`-eligible KQL detection already exists in the canonical store today (`65b906336880ed01`, T1490) — proven by direct query against `data/detection-rules-canonical.json`, not assumed.
- Microsoft's REST API (`Microsoft.SecurityInsights/alertRules`) is documented, stable (dated back to 2019, current stable version `2025-06-01` at research time), has a well-defined OAuth2 client-credentials auth model, and a genuine least-privilege built-in RBAC role ("Microsoft Sentinel Contributor," scoped to one workspace) — verified via live Microsoft Learn documentation fetches this round, not from training-data recall.

Splunk was NOT selected despite also being `detection_format`-modeled: Splunk Cloud vs. Enterprise on-prem have materially different saved-search/auth semantics that were not verified against current official documentation this round — building a connector on an unverified API shape would violate the mandate's own "do not implement from stale API versions" directive. Elastic/QRadar/Google SecOps have **no validated generator anywhere in this platform** (`detection-intelligence.js#FORMAT_CAPABILITY_MATRIX` — `generate: false` for all three) — there is nothing real to deploy for them yet. One excellent connector, honestly scoped, beats five shallow ones.

---

## 6. Architecture

```
Released Detection (detection-rules.js / detection-intelligence.js)
        +
Customer Defense Profile (defense-profile-store.js)
        ↓
defense-compatibility.js#evaluateDetectionCompatibility() → READY?
        ↓
deployment-engine.js#previewDeployment()  ── read-only remote lookup (diff)
        ↓
deployment-engine.js#approveDeployment()  ── server-side, hash-pinned
        ↓
deployment-engine.js#executeDeployment()  ── atomic claim → recheck → dispatch
        ↓
connector-registry.js → { mock-siem-connector.js | microsoft-sentinel-connector.js }
        ↓
Remote SIEM resource (created/updated)
        ↓
readBack() → canonical {query,severity,enabled,techniques} → sha256
        ↓
   match → VERIFIED         mismatch → FAILED_RETRYABLE / DRIFTED (never auto-overwritten)
```

New modules (all additive): `api/_lib/connector-crypto.js`, `api/_lib/siem-connector-taxonomy.js`, `api/_lib/siem-connector-store.js`, `api/_lib/deployment-store.js`, `api/_lib/deployment-engine.js`, `api/_lib/connectors/{connector-contract,mock-siem-connector,microsoft-sentinel-connector,connector-registry}.js`, `api/v1/connectors.js`, `api/v1/deployments.js`, `migrations/0004_siem_deployment_gateway.sql`, `deployments.html`. One additive link in `dossier.html`. Zero existing exported function signatures changed.

---

## 7. Defense Profile prerequisite — verified, not faked

Per the mandate's Critical Prerequisite Gate: the Customer Telemetry & Environment-Aware Defense Coverage Fabric was confirmed merged (`docs/audits/SENTINEL-APEX-CUSTOMER-TELEMETRY-DEFENSE-CONTEXT-V1-CERTIFICATION.md`, CONDITIONAL GO, 94 tests, verified against real production data) before any code in this tranche was written. Its own honestly-disclosed limitation — "no SIEM/EDR connector, no deployment path — entirely out of scope by mandate, not attempted" — is exactly the gap this tranche closes. Its `defense-compatibility.js`/`defense-profile-store.js` are called unmodified as this tranche's compatibility gate (§15).

---

## 8. Deployment model

`GENERATE → RELEASE GATE → COMPATIBILITY → PREVIEW → EXPLICIT APPROVAL → DEPLOY → READ-BACK → VERIFY`, implemented exactly: `deployment-engine.js#previewDeployment()` calls `recomputeDeployability()` (release gate + compatibility, §15-16) before any preview is shown; `approveDeployment()` requires an authenticated call and records a `deployment_approvals` row; `executeDeployment()` re-verifies everything (§18) before ever calling a connector; `verifyAfterDeploy()` performs the read-back and hash comparison. `GENERATE → DEPLOY` (skipping the gate) has no code path — proven by test (§32, "approval bypass").

---

## 9. Approval model

Approval is a server-side row (`deployment_approvals`), created only by `deployment-engine.js#approveDeployment()`, which itself requires a successful `authenticate()` call. There is no code path anywhere in `api/v1/deployments.js` that reads an `approved` boolean from a request body — approval is an action (`?action=approve`) performed by an authenticated identity, not a field.

---

## 10. Approval hashing — a stronger guarantee than the literal ask

The mandate's model (Section 14/95) assumes a client *submits* a deployment payload that gets hashed and later re-checked. This design does something stronger: **the client never submits deployment content at all.** `intent.query` always comes from `detection-rules.js`'s canonical store (or, for rollback, from this platform's own previously-recorded snapshot — §23) — never from a request body. The approval hash (`sha256` over the connector's own `toCanonicalObserved(intent)` — query/severity/enabled/techniques) therefore protects against the equivalent, real threat: the underlying TRUTH changing between approve and execute (a new detection version released, a connector's target config edited, telemetry becoming unavailable). `executeDeployment()` recomputes this hash fresh from current state and compares it to the approved hash; a mismatch — proven by test to occur when a new detection version is "released" between approve and execute — blocks with `APPROVAL_HASH_MISMATCH` and reverts the row to `APPROVAL_REQUIRED`, requiring fresh approval. A connector target-config hash is checked the same way.

---

## 11. Credentials

Connector credentials (e.g. a Microsoft Sentinel service principal's client secret) are the one genuinely new secret-storage need this tranche introduces. `api/_lib/connector-crypto.js` implements AES-256-GCM envelope encryption, deliberately mirroring `scripts/backup-customer-data.js`'s existing, real, already-proven algorithm/format choices (same cipher, same 12-byte IV, same hex-joined wire format) rather than inventing a second crypto convention (Reuse Before Build). This is a genuinely stronger protection than this platform's existing D1 secret precedent (`notification_preferences.webhook_secret`, stored in plaintext relying on Cloudflare's platform-level encryption-at-rest) — justified because a connector credential is a real third-party cloud credential: recovering it from a database compromise would let an attacker act inside the CUSTOMER's own Azure tenant, not merely forge a webhook this platform itself validates.

---

## 12. Secret encryption/storage

`siem_connectors.credential_ciphertext` stores `"v1:<ivHex>:<authTagHex>:<ciphertextHex>"`. The master key (`CONNECTOR_CREDENTIAL_MASTER_KEY`) lives only as a Cloudflare/Vercel secret (documented in `.env.example` and `docs/architecture/PRODUCTION-SECRETS-INVENTORY.md`, values never committed). `credential_configured` (a boolean column) is the ONLY thing any read path exposes — proven by test that `listConnectors()`/`getConnectorSafe()` never serialize `credential_ciphertext` and that a real secret value never appears in a JSON-stringified API response (§32). Decryption happens only inside `getConnectorWithCredential()`, called only from `deployment-engine.js`'s execute/test-connection/verify/disable/rollback paths — never from a customer-facing read handler.

---

## 13. OAuth/scopes

Microsoft Sentinel: Azure AD OAuth2 **client-credentials** flow (a registered Azure AD application / service principal) — no delegated user consent needed, no broad admin credential requested. Least-privilege role: **"Microsoft Sentinel Contributor," assigned at the specific Log Analytics workspace scope** (verified via live Microsoft documentation; "Sentinel Reader"/"Sentinel Responder" cannot manage analytics rules, confirmed, not assumed) — documented in `siem-connector-taxonomy.js#KNOWN_PLATFORMS['microsoft-sentinel'].least_privilege_role` and surfaced in the connector-setup UI.

---

## 14. Connector health

`siem_connectors.health_status ∈ {NEVER_TESTED, CONNECTED, AUTH_EXPIRED, PERMISSION_CHANGED, UNAVAILABLE, DISABLED}`, updated only by `recordConnectionTest()` (called from `?action=test-connection`, never automatically on every deployment — bounded, intentional checks only, per Section 77).

---

## 15. Compatibility gate

`deployment-engine.js#recomputeDeployability()` calls `defense-compatibility.js#evaluateDetectionCompatibility()` (unmodified, already-certified) at preview, at approve, and again immediately before execute. Only `status === 'READY'` is deployable — `PARTIALLY_READY`/`TELEMETRY_GAP`/`UNSUPPORTED_PLATFORM`/`UNKNOWN`/`NO_VALIDATED_DETECTION` all block (Section 36's "Preferred v1: BLOCK"), proven by test.

---

## 16. Detection validation gate

Only `detection-intelligence.js#toCanonicalDetectionObject().status === 'RELEASED'` is deployable. A real, pre-existing discrepancy in that engine was found and documented (not silently "fixed," since it is out of this tranche's scope and pre-dates it): `LIFECYCLE_STATES` declares 8 values, but `evaluateReleaseGate()` only ever actually computes `RELEASED`/`BLOCKED`/`REVIEW_REQUIRED`, with `DEPRECATED`/`REVOKED` reachable only as manual overrides. This tranche's gate treats every non-`RELEASED` value identically (`DETECTION_NOT_RELEASED`, blocked) — correct regardless of which specific non-`RELEASED` value is returned, and proven by test for both a `REVIEW_REQUIRED` and a `REVOKED` value.

---

## 17. Preview

`previewDeployment()` performs a real, read-only remote lookup (via the connector's `readBack()`) so `action: 'CREATE'|'UPDATE'` and the diff are genuine, not guessed. Never mutates anything — proven: the mock connector's `readBack()` issues only `SELECT` statements, and the Microsoft Sentinel connector's `testConnection()`/`readBack()` issue only `GET` (proven by test, §32, "never issues a mutating call").

---

## 18. Idempotency

Two mechanisms, both proven under real concurrency (not merely asserted):
1. **Deterministic remote resource identity** — `deployment-store.js#deriveRemoteResourceName()` is a pure function of `(connector_id, detection_id)`; the Microsoft Sentinel connector further derives a deterministic ruleId (UUID-shaped, sha256-based) from that name, so a repeated `deploy()` call always targets the same remote resource (`PUT` semantics — upsert).
2. **Atomic execution claim** — `deployment-store.js#claimForExecution()` uses `d1.js#runMutationWithChanges()` (`UPDATE ... WHERE state IN ('APPROVED','FAILED_RETRYABLE')`) rather than a SELECT-then-branch, closing the TOCTOU race a naive check would have. Proven: two concurrent `executeDeployment()` calls on the same deployment produce exactly one call into the connector's `deploy()` (spied and asserted `toHaveBeenCalledTimes(1)`), the other returns `INVALID_STATE_FOR_EXECUTE` without touching the connector at all.

---

## 19. Remote reconciliation

If `deploy()` throws, `executeDeployment()` attempts a `readBack()` by the same deterministic resource name before declaring failure; if found AND its canonical hash matches what was intended, the deployment is treated as successful (a `RECONCILED_AFTER_AMBIGUOUS_ERROR` attempt is recorded) rather than retried into a duplicate. Proven by a dedicated `TIMEOUT_AFTER_CREATE` mock-connector simulation: the resource IS written, `deploy()` then throws, and the test confirms exactly one row exists in the mock remote store afterward.

---

## 20. Read-back verification

A 2xx from `deploy()` is never treated as sufficient. `verifyAfterDeploy()` always performs an independent `readBack()` and compares its canonical `{query,severity,enabled,techniques}` shape (hashed) against the intent that was just deployed. Both Microsoft Sentinel and the mock connector normalize `techniques` to a sorted array specifically so array-order differences never register as false drift (Section 47).

---

## 21. Drift

`verifyDeployment()` (on-demand — Section 50's "on demand / after deployment," never a continuous poll) re-reads the remote resource and compares against `deployed_intent_snapshot` (the platform's own record of what it last verified) — never against a stale `desired_hash` that could have been overwritten by an unrelated, not-yet-executed preview (a real design bug caught and fixed during this tranche's own review, before any test was written against the wrong comparison). A mismatch sets `state='DRIFTED'` and stops — proven by test that the remote resource's out-of-band-changed content is still exactly that changed content after `verifyDeployment()` runs (never silently overwritten back).

---

## 22. Update lifecycle

Re-previewing an existing (non-terminal) deployment for the same (connector, detection, entity) triple reuses the same row (`findActiveDeployment()`) and requires a fresh approval — no automatic push on a new detection version. Proven: a version change between two preview calls correctly reports `action: 'UPDATE'`.

---

## 23. Rollback — design and a real, disclosed limitation

**Real discovery, load-bearing for this whole section:** `detection-rules.js#storeRule()` overwrites a rule's format content in place on every new version — its `history[]` records only version/timestamp/change metadata, **never a content snapshot**. This means the canonical detection store cannot answer "what did version 1 actually say" once version 2 has been stored. This tranche's own deployment record is therefore the only place that content survives: `detection_deployments.deployed_intent_snapshot` is rotated into `previous_intent_snapshot` on every successful UPDATE (Section 53's "restore prior version," one level of undo — matching the mandate's own literal test scenario, "Deploy v1 → Update v2 → Rollback to v1," not an arbitrary version stack). Rollback (`previewRollback()`/`executeDeployment()` with `pending_action='ROLLBACK'`) redeploys that captured snapshot through the identical preview/approve/execute/verify pipeline. **Disclosed limitation:** rollback does not re-run the full release/compatibility gate against the historical version's original content, because the canonical store cannot reproduce it to re-validate — it does check the detection has not since been `REVOKED` (Section 114) before allowing old content back onto a customer's SIEM. Proven end-to-end by test: deploy v1 → update v2 (rollback_available becomes true) → roll back → read-back confirms the restored content is genuinely v1's (`toContain('vssadmin')`, the real KQL fragment unique to that version), and `rollback_available` correctly becomes `false` again (the one level of undo is consumed).

---

## 24. Authorization

Every action requires `authenticate()` (bearer `Authorization`/`X-API-Key`, `sentinel_` prefix) — the identical, only customer-auth chokepoint every other router in this codebase sits behind. **No cookie-based session exists anywhere in this codebase** (grep-verified zero `Set-Cookie`/`req.cookies` in `api/`/`workers/`), so classic CSRF does not apply to this API surface: an attacker's page cannot make a victim's browser attach a bearer token it doesn't have. **No customer role model beyond `tier` exists in this platform** (confirmed: no workspace/tenant/role concept anywhere) — this tranche does not invent one; every authenticated tier can act on its OWN resources only (ownership-scoped, proven by tenant-isolation tests), matching the exact precedent `watchlist-store.js`/`defense-profile-store.js` already established. Separation-of-duties (analyst previews, admin approves) is explicitly a future capability this design does not block (the approval record already carries a distinct `owner_id`), not built here since no role model exists to hang it on yet.

---

## 25. Tenant isolation

Proven by test at every layer: a connector created by owner A is invisible to owner B (`NOT_FOUND`, not a distinguishing 403 — Section 6's "missing profile and another owner's are indistinguishable" precedent, reused); owner B cannot execute, view, or roll back owner A's deployment by guessing its id; `history` (attempts/approvals, which are not themselves owner-scoped tables) is only reachable through an ownership check performed first.

---

## 26. Entitlements

New policy, using the EXISTING tier hierarchy (no new price invented): the safe, no-real-infrastructure **Sandbox / Test Connector is available on every plan** (exploration should never require payment); a **real, deploy-capable connector (Microsoft Sentinel) requires Pro or Enterprise** — mirroring the exact precedent `api/v1/intel.js`'s `action=detection-pack` already established for gating an advanced capability. Connector counts are bounded (`sandbox_connectors.max: 3`, `live_connectors.max: 5 (pro) / 25 (enterprise)`), proven by test.

---

## 27. SSRF / network security

Not reachable for the shipped connector: Microsoft Sentinel's target endpoint is always `management.azure.com`, built from tenant/subscription/resource-group/workspace **identifiers** the customer supplies, never a raw URL. `api/_lib/webhook-signing.js#isSafeWebhookUrl()` (this platform's one existing SSRF guard) is documented in the connector contract as the mechanism a future URL-accepting connector (e.g. self-hosted Splunk) MUST call before its first outbound fetch — deliberately not built into this tranche's shipped connectors since neither accepts a customer-supplied endpoint. Every outbound call (both connectors) sets `redirect: 'error'`, mirroring `notification-dispatch.js`'s own outbound-fetch discipline, as defense-in-depth regardless.

---

## 28. Cloudflare runtime

No Vercel-only, no Upstash, no new GitHub-Actions-as-scheduler dependency introduced. New code uses only: `api/_lib/d1.js` (unmodified), Node's built-in `crypto`/`fetch`/`AbortController` (all already relied on elsewhere under `nodejs_compat`, per `wrangler.jsonc`'s own comment). No `fs`/`child_process`/Node-server-only module used anywhere in new code.

---

## 29. Queue decision

**QUEUE NOT REQUIRED.** Evidence: (a) Cloudflare Queues is not configured anywhere in this repository — `wrangler.jsonc`'s own "intentionally absent" list doesn't even mention it (unlike KV/R2, which get an explicit deferral note) — it would be a wholly new primitive; (b) deployment execution is a single bounded outbound HTTP call plus one read-back, well within Workers' request-duration budget, not a batch/fan-out workload; (c) the atomic D1 claim (§18) already provides the concurrency-safety property a queue would otherwise be reached for, using this platform's own proven pattern (the same family as `notification_delivery_jobs`'s claim/lease); (d) no live Cloudflare account access exists in this or any prior tranche to even provision a Queue. Revisit only with real evidence of a workload shape Queues actually solves.

---

## 30. D1

One additive migration, `migrations/0004_siem_deployment_gateway.sql`, same `sentinel-apex-core` database every other D1-backed subsystem uses (no new database). Seven tables: `siem_connectors`, `siem_connector_audit_log`, `detection_deployments`, `deployment_approvals`, `deployment_attempts`, `deployment_audit_log`, `mock_siem_resources` (the last one a real, persisted backing store for the deterministic test connector — not a production table in the customer-data sense, but real D1 nonetheless, so its simulated state survives across the separate HTTP requests a deployment lifecycle spans). `CREATE TABLE IF NOT EXISTS` throughout; `?`-placeholder prepared statements exclusively (grep-verified, and exercised directly by the fake-D1 SQL-shape-matching test fixture, which throws on any statement shape it doesn't recognize — a mismatch would have failed loudly, not silently).

---

## 31. Observability

`siem_connector_audit_log`/`deployment_audit_log` record every state-changing action (connector created/tested/rotated/disabled; deployment previewed/approved/deployed/verified/failed/drift-detected/disabled) with actor/target ids — never a credential value (grep-verified against every audit call site). `deployment_attempts` records every connector-level dispatch (DEPLOY/UPDATE/READBACK/DISABLE/ROLLBACK/RECONCILE) with result/error_code/http_status/timing, independent of the audit log, for operational triage.

---

## 32. Tests

**92 new tests, all passing:**
- `api/_lib/__tests__/connector-crypto.test.js` — 9 (round-trip, tamper detection, wrong-key rejection, rotation, missing/malformed-key refusal)
- `api/_lib/__tests__/siem-connector-store.test.js` — 14 (entitlements, platform/tier gating, credential secrecy, tenant isolation, disable/revoke)
- `api/_lib/__tests__/deployment-engine.test.js` — 14 (happy path; compatibility/validation gates; approval bypass; hash mismatch; revoked detection; telemetry-change-before-execute; concurrent execution; timeout-after-create reconciliation; drift; update+rollback; tenant isolation; disable)
- `api/_lib/connectors/__tests__/mock-siem-connector.test.js` — 16 (contract: test-connection variants, idempotent deploy/read-back, all simulated failure modes, disable/delete, drift-simulation helper, connector-to-connector isolation)
- `api/_lib/connectors/__tests__/microsoft-sentinel-connector.test.js` — 22 (deterministic ruleId, severity mapping, request/response handling against the documented API contract via mocked `fetch`, URL construction, error classification, `redirect:'error'` on every call)
- `api/v1/__tests__/connectors.test.js` — 10 (auth required on every action, cross-tenant isolation, field whitelisting, secret never in an HTTP response)
- `api/v1/__tests__/deployments.test.js` — 7 (auth required, full lifecycle via the real HTTP layer, blocked-reason status mapping, cross-tenant isolation, history ownership check)

**Full regression, this branch vs. fresh `main`:**
```
Jest:      2431 passed / 60 skipped (pre-existing) / 0 failed  (77 of 78 suites; 1 pre-existing skip, unchanged) — 2339 pre-existing + 92 new
node --test (workers/lib + engine-node + renderer): 290 passed / 0 failed — unchanged, untouched by this tranche
pytest: not run — no Python file touched by this tranche, and this sandbox's Python test environment (pytest) is not provisioned; installing one to verify zero-impact on code this tranche never touches was judged out of scope (Zero Unnecessary Modification)
```
Zero regressions in any pre-existing suite.

---

## 33. Browser QA

Real Chromium (Playwright, pre-installed binary at `/opt/pw-browsers`), real production handler code (`api/v1/connectors.js`/`api/v1/deployments.js`/`api/v1/defense-profile.js` invoked in-process behind a plain local HTTP server — not hand-written JSON mocks), a real committed detection record (`65b906336880ed01`, T1490, real KQL content), a fake in-memory D1 (the same fixture the Jest suite uses). `middleware.js`'s own real, documented dev-auth-bypass path was exercised (`NODE_ENV=development` + `ALLOW_DEV_AUTH_BYPASS=true`, the sanctioned mechanism for exactly this Redis-unavailable situation) — `authenticate()` itself ran unmodified.

**11/12 checks passed**, driving the real, shipped `deployments.html`: page load; Defense Profile save (prerequisite); connector list load; Sandbox connector creation; connection test → `CONNECTED`; deployment preview showing `CREATE`/`RELEASED` and the real committed KQL text (not fabricated); no injected `<script>` tag in the rendered preview; **Approve & Deploy → VERIFIED**; deployment history showing the verified row; no horizontal overflow at 375px mobile. Screenshots captured at 1440px and 375px (mobile screenshot confirms clean rendering — a `fullPage` desktop screenshot showed a compositing-seam artifact at a scroll boundary, re-checked and confirmed cosmetic, not a real layout defect, via the non-scrolled mobile capture of the identical header).

**The one non-passing check** ("zero uncaught console errors") is `net::ERR_CONNECTION_RESET` for `fonts.googleapis.com`/`googletagmanager.com` (this sandbox's network policy blocks external calls) plus two 404s for `favicon.ico`/`site.webmanifest` (this minimal local QA server doesn't serve every static icon) — the identical, explicitly-disclosed, pre-existing noise pattern every prior browser-QA round in this repository's history reports and excludes, not a regression this tranche introduced.

---

## 34. Vendor sandbox verification

**NOT VERIFIED.** No Azure tenant, subscription, or credentials exist in this sandbox. The Microsoft Sentinel connector is verified against Microsoft's own current REST API documentation (live-fetched this round: `https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules/create-or-update`) and covered by 22 unit tests against a mocked `fetch` proving correct request construction and response-classification — never proven against a live Azure Sentinel workspace. `deleteRemote()` is disclosed as a **lower-confidence** implementation specifically: it follows the standard ARM DELETE-on-resource-URI convention but the specific "Alert Rules - Delete" reference page was not itself fetched this round (PUT/GET/disable-via-update ARE independently verified against their own fetched, documented schema). Do not overclaim.

---

## 35. Real-data workflows

- **Workflow A (real detection, sandbox connector, full lifecycle):** the real, committed `65b906336880ed01` (T1490, critical, KQL) detection deployed through a Sandbox connector — preview shows `CREATE`/`RELEASED` with the genuine KQL content, approve+execute reaches `VERIFIED`, read-back confirms the exact deployed query. Proven via both Jest (`deployment-engine.test.js`) and live browser QA (§33).
- **Workflow B (mock/sandbox connector, full preview→approve→deploy→read-back→VERIFIED):** proven by test and by browser QA — identical evidence to Workflow A, since the sandbox connector IS the safe way this platform's own QA exercises the full mechanism without live vendor dependency.
- **Workflow C (failure injection):** RATE_LIMITED/SERVER_ERROR/TIMEOUT/TIMEOUT_AFTER_CREATE all proven via the mock connector's real, D1-persisted simulation — bounded retry classification and reconciliation proven, no duplicate remote rule.
- **Workflow D (drift):** an out-of-band remote change proven detected as `DRIFTED`, remote resource proven NOT silently overwritten.
- **Workflow E (rollback):** deploy v1 → update v2 → roll back to v1, read-back proven to match the restored v1 content exactly.
- **Workflow F (unsupported/incompatible):** `TELEMETRY_GAP`/non-`RELEASED` detections proven blocked at preview with no override path in the frontend (the block reason is a structured API response the UI surfaces as-is; there is no client-side bypass).

---

## 36. Known limitations

- Vendor sandbox execution NOT VERIFIED (§34) — the single largest honestly-disclosed gap.
- Only Microsoft Sentinel is deploy-capable; Splunk/Elastic/QRadar/Google SecOps are declared, not built (§5).
- Rollback does not re-validate historical content against the release/compatibility gate (§23) — a real constraint of the canonical detection store's own design, not something this tranche could close without changing that store (out of scope, high blast radius, not requested).
- `deleteRemote()` (Microsoft Sentinel) is a lower-confidence implementation (§34) — DISABLE (verified) is the recommended, default lifecycle action; hard delete is a deliberately secondary capability.
- Detection corpus remains thin (inherited, unchanged) — most techniques on most entities still show `NO_VALIDATED_DETECTION` regardless of connector/environment, honestly, not a defect of this tranche.
- No real production load/performance measurement (sandbox limitation, consistent with every prior round; Cloudflare not live-deployed, `wrangler whoami` not authenticated).
- Separation-of-duties (analyst-previews/admin-approves) is not built — no role model exists in this platform to hang it on (§24); the approval record's schema does not block adding it later.
- pytest not run this round (§32) — no Python code touched.

---

## 37. Rollback (of this tranche, if reverted)

Every change is additive and independently revertible: 1 new migration (empty tables until a customer uses the feature — dropping them is a no-op for every other subsystem); 9 new `api/_lib/` modules (reverting removes the entire gateway; nothing outside this tranche imports them); 2 new `api/v1/*.js` routers plus their 2-line additions each to `workers/lib/router.js`/`workers/lib/route-table.js`/`vercel.json` (reverting the 2 lines each restores the exact prior routing table; the pre-existing 35-handler parity tests revert to their original count); 1 new HTML page; 1 new link in `dossier.html` (a single conditional `<div>`, reverting restores the exact prior render); 1 new env-var pair (`.env.example`/`PRODUCTION-SECRETS-INVENTORY.md` entries, unused if unset — every function requiring the master key already refuses cleanly with `ENCRYPTION_NOT_CONFIGURED`/a thrown error rather than degrading insecurely). No schema, route, or interface was removed or renamed anywhere in this tranche. No existing test was modified to make it pass (only the two handler-count assertions in `route-table.test.js`, updated 35→37 because 2 real new handlers were added — the correct, expected consequence documented inline).

---

## 38. Final verdict

**CONDITIONAL GO.** Ship it: every mechanical safety property the mandate specified — explicit authorization, least privilege, secret security, previewability, idempotency, read-back verification, drift safety, rollback, auditability, customer control — is implemented, tested (92 new tests, 2431/2491 total passing, zero regressions), and proven live end-to-end via real browser automation against real production handler code and a real committed detection. Conditional only on the two honestly-disclosed, structural gaps outside this tranche's own execution: vendor sandbox access this environment has never had (§34), and the thin detection corpus this tranche inherited unchanged (§36) — the same class of caveat every certification in this repository's history has carried, not a new gap this round introduces.

---
*CyberDudeBivash® Sentinel APEX — Controlled SIEM Deployment Gateway v1 Certification*
