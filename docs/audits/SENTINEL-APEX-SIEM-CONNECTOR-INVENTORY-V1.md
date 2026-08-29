# SENTINEL APEX™ — SIEM Connector & Deployment Foundations Inventory v1

**Date:** 2026-08-29
**Branch:** `claude/controlled-detection-deployment-auu51p`
**Purpose:** Reuse-before-build audit, performed before any connector/deployment code was written, per this mandate's Section 8 and this repository's Principle 4 ("Reuse Before Build"). Answers: does any SIEM connector, credential-deployment, or OAuth-integration system already exist in this codebase that a Controlled SIEM Deployment Gateway would duplicate?

**Method:** Direct `grep`/`Read` against the live tree (fresh `main` @ `d5e76534`), not assumed from prior certification summaries. Keywords swept: `sentinel|splunk|elastic|qradar|chronicle|secops|siem|connector|integration|oauth|credential|secret|deployment|rule deployment|analytics rule|saved search|detection rule|api token|service principal`.

---

## 1. Headline finding

**No SIEM connector, no credential-deployment pipeline, no OAuth-to-third-party-vendor integration exists anywhere in this codebase.** Every "Sentinel/Splunk/Elastic/QRadar/Chronicle" hit is one of three unrelated things, none of which is a connector:

1. **Detection-format generation** (`Sentinel-APEX/engine-node/detection-engine.js`, `data/detection-rules-canonical.json`) — the canonical engine *generates* KQL/Splunk-SPL/OSQuery/Sigma/Suricata *text content* for a detection rule. It has no network client, no auth, no concept of a remote workspace, and never calls out to a vendor API. This is the content the new deployment gateway will *ship*, not a competing deployment mechanism.
2. **Report-prose labeling** (`automation/authority_transformer.py`'s `SIEM_PLATFORM_LABELS`) — a hardcoded display-name lexicon (`"Splunk SPL"`, `"Microsoft Sentinel KQL"`, `"IBM QRadar AQL"`, `"Google Chronicle YARA-L"`) used only to caption which query language a *published report's* code block is written in. Confirmed via `platform/gtiep-v1-audit.md` §"Detection format capability" — this is prose metadata, not executable integration.
3. **The word "deploy" in operational docs** (`STAGING-DEPLOYMENT-PLAN.md`, `PRODUCTION-CUTOVER-RUNBOOK.md`, CI workflow names, etc.) — this platform's own release process, unrelated to shipping a *detection rule* into a *customer's* SIEM.

**Zero duplicate canonical stores would be introduced.** This tranche is genuinely new capability, not a sixth parallel implementation of something that already exists — confirmed, not assumed.

---

## 2. Table

| Integration | Existing code | Auth | Deploy | Read-back | Rollback | Production maturity |
|---|---|---|---|---|---|---|
| Microsoft Sentinel (or any SIEM) rule push | **None** | **None** | **None** | **None** | **None** | **Not implemented** — this tranche is greenfield |
| Splunk saved-search/detection push | **None** | **None** | **None** | **None** | **None** | Not implemented |
| Elastic Detection Engine rule push | **None** | **None** | **None** | **None** | **None** | Not implemented |
| QRadar / Google SecOps rule push | **None** | **None** | **None** | **None** | **None** | Not implemented — and, per §7 (Detection Coverage row of the source-of-truth matrix), QRadar has `detection_format: null` in this platform's own taxonomy: no validated generator output exists for it at all, so a connector would have nothing real to deploy yet |
| Customer OAuth / delegated auth to any external SIEM/EDR vendor | **None** | **None** | N/A | N/A | N/A | Not implemented |
| `lib/detection/*.ts` (43-file, ~12,500-line frozen TS stack, per `docs/audits/SENTINEL-APEX-THREAT-TO-DEFENSE-FABRIC-V1-CERTIFICATION.md` §4) | Exists, **unwired to any live route** (confirmed by that tranche's own direct verification) | N/A | N/A | N/A | N/A | Experimental/unwired — not a connector, not reused, not modified |

---

## 3. Adjacent, genuinely reusable infrastructure (not connectors themselves, but the load-bearing pieces this tranche builds on)

| Capability needed by a deployment gateway | Reused from | Why it qualifies |
|---|---|---|
| Customer identity / ownership derivation | `api/_lib/middleware.js#authenticate()` (bearer/`X-API-Key`, `sentinel_` prefix, hashed lookup) | The exact, only customer-auth chokepoint every other customer-facing router (`watchlists.js`, `defense-profile.js`, `intel.js`) already sits behind. No cookies are used anywhere in this auth path — session CSRF does not apply to this API surface (an attacker's page cannot make the victim's browser attach a bearer token or `X-API-Key` header it doesn't have); see the certification doc §Authorization for the full reasoning. |
| Detection eligibility (only deploy a real, released rule) | `api/_lib/detection-rules.js` + `api/_lib/detection-intelligence.js` (`RELEASED`/`REVIEW_REQUIRED`/`DEPRECATED`/`REVOKED` lifecycle, `evaluateReleaseGate()`) | Canonical, already-certified (Threat-to-Defense Fabric v1). Not re-derived. |
| Customer environment compatibility (only deploy what the customer's declared telemetry can use) | `api/_lib/defense-compatibility.js#evaluateDetectionCompatibility()` / `computeCustomerCoverage()` | Canonical, already-certified (Customer Telemetry & Defense Context v1). `READY` is the only status this tranche treats as deployable. |
| D1 access | `api/_lib/d1.js` (`query`/`run`/`runMutationWithChanges`, dual native-binding/REST transport) | The only D1 client in this codebase; every D1-backed store (`watchlist-store.js`, `defense-profile-store.js`, `notification-store.js`) already uses it unchanged. |
| Customer-owned D1 CRUD router shape | `api/v1/defense-profile.js` (`guardRequest` → `globalIpRateLimit` → `authenticate()` per action → `action=` dispatch → `assertFieldWhitelist` → `successResponse`/`apiError`) | Followed exactly for the two new routers (§API in the certification doc), not reinvented. |
| Outbound HTTPS SSRF guard | `api/_lib/webhook-signing.js#isSafeWebhookUrl()` (blocks loopback/RFC1918/link-local/metadata/CGNAT, requires HTTPS, resolves DNS before trusting a hostname) | The only existing "we are about to `fetch()` a destination partially outside this platform's control" guard in this codebase. Reused for any future connector that accepts a customer-supplied endpoint URL (e.g. a self-hosted Splunk/Elastic target). The first connector shipped this round (Microsoft Sentinel) calls a **fixed** Microsoft-owned endpoint (`management.azure.com`) built from tenant/subscription/resource-group/workspace **identifiers**, never a customer-supplied URL — so SSRF is structurally not reachable for it, but the guard is wired into the connector *interface* layer now so a URL-accepting connector added later cannot forget it. |
| Envelope-encryption algorithm/format for a secret this platform must decrypt later | `scripts/backup-customer-data.js#encryptSnapshot()`/`decryptSnapshot()` — **AES-256-GCM via Node's `crypto.createCipheriv`/`createDecipheriv`, 12-byte random IV, `iv:authTag:ciphertext` hex-joined storage, key supplied only via an environment secret never committed** | The only existing precedent for "encrypt a customer-sensitive blob this platform must later decrypt" (as opposed to `webhook-signing.js`'s one-way HMAC, or `middleware.js#hashKey()`'s one-way SHA-256). Mirrored exactly (same algorithm, same IV size, same wire format) for connector-credential storage — see the certification doc §Credential Security — rather than introducing a second, divergent crypto convention. `createCipheriv('aes-256-gcm', ...)` is exercised today only under Node (this script is a CLI tool, never Workers-loaded); this tranche's use of the identical API from Workers-reachable code is a genuinely new claim, disclosed as such (relies on `nodejs_compat`, matching `webhook-signing.js`'s own already-Workers-reached `crypto.createHmac`/`timingSafeEqual` calls, but not itself previously proven live on deployed Workers — no tranche in this repository's history has had authenticated Cloudflare access to prove that; see Known Limitations). |
| Detection/coverage taxonomy pattern to mirror for connector capability declarations | `api/_lib/defense-taxonomy.js` (`CUSTOM_UNMAPPED` escape hatch, `detection_format: null` for platforms with no real generator, never a fabricated capability) | Mirrored for `siem-connector-taxonomy.js`'s `KNOWN_PLATFORMS` registry — a platform this tranche cannot deploy to is declared `deploy_supported: false`, never silently omitted or falsely claimed. |
| D1 migration conventions | `migrations/0001-0003` (`CREATE TABLE IF NOT EXISTS`, prefixed random-hex TEXT PKs, capped audit-log tables, one shared `sentinel-apex-core` database) | Followed exactly by `migrations/0004_siem_deployment_gateway.sql`. |

---

## 4. Conclusion

No existing connector of any kind is duplicated. The reusable pieces above (auth, detection lifecycle, customer compatibility, D1 client, router shape, SSRF guard, encryption algorithm, taxonomy pattern) are extended, not reimplemented, matching this repository's Principle 4 priority order (call unchanged → extend → compose → delegate → build from scratch only where nothing exists). Connector selection (§ below and in the certification doc) proceeds on this basis.
