# Publication Engine

Cryptographic publication-authorization gate: a case cannot become a public
artifact unless a human/system holding a trusted Ed25519 key has signed a
record binding the exact decision, the exact artifact bytes, and an
expiry — and every sink independently re-verifies all of that before
admitting anything.

This module is **new** (built 2026-08-16). No prior version of it exists
anywhere reachable from this repository or its GitHub remote — see "Origin"
below before assuming any history predates this file.

## The invariant

```
NO VALID AUTHORIZED RELEASE OBJECT  =  NO EXTERNAL PUBLICATION
```

No renderer, workflow, API endpoint, RSS generator, Blogger publisher,
bundle generator, or legacy script may infer publication permission on its
own. Every sink calls `verifyAuthorization()` itself; none of them trust a
boolean, a hash, or a disposition string handed to them by a caller.

## The DAG

```
case (JSON)
  |  validateCase()                         case_schema.js
  v
decide()                                    publication_engine.js
  -> { disposition, reasonCode, reasons, evaluatedAt, policyVersion, caseId }
  |  disposition in {PUBLISH-READY, RESTRICTED-CONDITIONAL, HOLD, DENY}
  v
buildManifest()                             release_manifest.js
  -> content-addressed manifest, manifestHash = sha256(canonical(decision))
  v
authorize()                                 authorization.js  (+ signing.js)
  -> refuses HOLD/DENY unconditionally
  -> Ed25519-signs {manifestHash, artifactHash, signerIdentity,
     authorizationDecision, issuedAt, expiresAt, policyVersion, keyId, nonce}
  v
sink.publish(authRecord, context)           publication_sinks.js
  -> verifyAuthorization() independently re-derives every fact              authorization.js
  -> re-checks disposition eligibility for THIS sink type
  -> recordAuditEvent()                                                     audit.js
  -> ALLOW or DENY, always with a reason code
```

`index.js` re-exports every module's public API as one barrel.

## Files

| File | Responsibility |
|---|---|
| `canonical_json.js` | Deterministic, key-sorted JSON serialization. Throws on anything not unambiguously representable (`undefined`, `NaN`, `Date`, functions). Everything hashed or signed in this module goes through it first. |
| `case_schema.js` | Structural validation of a case object. Fails closed — `qa` and `contradictions` are *required* fields (even empty), not optional, because their absence is not the same claim as "nothing was found." |
| `publication_engine.js` | `decide()` — the single authoritative place a disposition is computed. Never reads a caller-supplied `disposition`/`requestedDisposition` field. Owns `POLICY_VERSION`, the one source of truth every other module imports. |
| `release_manifest.js` | `buildManifest()` freezes `decide()`'s output into a hash. `MANIFEST_HASHED_FIELDS` lists exactly what's covered — extend it deliberately if `decide()`'s shape grows. |
| `signing.js` | Injectable Ed25519 signer/verifier over `node:crypto` only (no new dependency). `generateEphemeralKeypair()` is test/dev-only. |
| `authorization.js` | `authorize()` binds manifest + artifact + signer + expiry + nonce and signs it; refuses HOLD/DENY unconditionally. `verifyAuthorization()` independently re-verifies every fact (never trusts a precomputed hash or flag) and fails closed on any exception. |
| `nonce_store.js` | In-memory single-use nonce guard. **Process-local only** — see Verification Boundaries. |
| `publication_sinks.js` | Mock RSS / Blogger / API / downloadable-bundle / restricted-enterprise adapters. Local stubs proving the pattern — not real integrations (see "Real publishing DAG" below). |
| `audit.js` | `recordAuditEvent()` — one structured, SIEM-ready event per publish attempt, ALLOW or DENY. |
| `test/fixtures.js` | Shared synthetic case builders. Everything in it is labeled `SYNTHETIC TEST FIXTURE — NOT REAL INTELLIGENCE` per the Zero-Hallucination addendum §30 and must never be copied into a real report. |

## Reason code vocabulary

Decision-layer (`decide()`'s own `reasonCode`, distinct namespace from the audit codes below):
`DENY_MALFORMED_CASE`, `DENY_CASE_POLICY_VERSION_MISMATCH`, `HOLD_EVIDENCE_POLICY_GATE`,
`RESTRICTED_CONDITIONAL_CLEARED`, `PUBLISH_READY_CLEARED`.

Authorization/audit-layer (what `verifyAuthorization()` and every sink emit — SIEM-ingestible):

```
ALLOW_AUTHORIZED_PUBLIC_RELEASE       ALLOW_AUTHORIZED_RESTRICTED_RELEASE
DENY_HOLD                             DENY_RESTRICTED_PUBLICATION
DENY_MISSING_SIGNATURE                DENY_INVALID_SIGNATURE
DENY_UNKNOWN_KEY                      DENY_REVOKED_AUTHORIZATION
DENY_MANIFEST_HASH_MISMATCH           DENY_MALFORMED_MANIFEST
DENY_ARTIFACT_HASH_MISMATCH           DENY_AUTHORIZATION_DECISION_MISMATCH
DENY_MALFORMED_AUTHORIZATION          DENY_MISSING_VERIFIER
DENY_EXPIRED_AUTHORIZATION            DENY_NOT_YET_VALID
DENY_POLICY_VERSION                   DENY_REPLAY
DENY_INTERNAL_VERIFICATION_ERROR
```

## Running the tests

```bash
node --test scripts/publication-engine/*.test.js
```

Zero new npm dependencies — everything runs on `node:test`, `node:assert`,
and `node:crypto`, deliberately decoupled from this repo's Jest
config (`jest.config.js` `roots` doesn't include `scripts/`, so this suite
never touches Jest's coverage thresholds or `npm test`). 143 tests / 30
suites, all passing as of this writing; rerun before trusting that number.

## Verification boundaries — read before claiming this is "done"

**`PRODUCTION KEY MANAGEMENT: NOT VERIFIED`.** `signing.js` defines the
signer/verifier *interface* a real KMS-backed implementation must satisfy.
It does not provide one. `generateEphemeralKeypair()` exists only so tests
don't need real keys; nothing generated by it, and no private key material
of any kind, is committed to this repository. Wiring a real signer means
injecting a `{ keyId, sign(payload) }` backed by an actual secret
manager/KMS — that integration doesn't exist here.

**`REPLAY STATE ENFORCEMENT: NOT VERIFIED`** for any deployment with more
than one process, or with restarts, in scope. `nonce_store.js` is an
in-memory `Set` — it proves the *pattern* (a nonce can't be consumed
twice) but provides no protection across processes or restarts. Real
replay resistance needs persistent shared state (KV/D1/Redis), checked
and set atomically.

**`PRODUCTION CONTAINMENT: NOT VERIFIED`.** Nothing in this module is wired
into any live egress path. See below.

## Real publishing DAG in this repository

Discovered by inventory (grep for `wrangler|R2|KV|D1|blogger|rss|feed|
publish|upload|deploy|pages|syndicat` plus reading `.github/workflows/` and
`api/_lib/`), **not modified** by this work:

- **`.github/workflows/sentinel-apex.yml`** — cron (`:00`/`:30`), ingests
  28 sources, runs `fetch-live-intel.js`, commits generated content
  straight to `main`. Interleaved with `blogger-syndication.yml`
  (`:15`/`:45`) by design (see the workflow's own comment) so pushes land
  every ~15 min without deploy-starving each other. A push to `main` is a
  publish — there is no separate deploy-approval step visible in this
  workflow.
- **`.github/workflows/blogger-syndication.yml`, `generate-rss.yml`,
  `cve-pages.yml`** — additional scheduled egress (Blogger, RSS feed, CVE
  page generation).
- **`api/v1/intelligence/publish.js`** + **`api/_lib/publishing-pipeline.js`**
  + **`api/_lib/governance-engine.js`** — a *second*, independent,
  already-existing publication pipeline: a Redis-backed state machine
  (`draft -> review -> approved -> published`) with its own role/policy
  checks (`enforceGovernance`) and audit log
  (`governance.auditGovernanceAction`).

  **This pipeline's `publishToProduction()` authorizes purely on
  Redis-stored fields** (`obj.status === 'approved'`, `obj.approvedBy`,
  `obj.approvedAt`) **and a caller-supplied `actor` role string** — the
  `publish` API handler passes `body.actor || 'publisher'` straight from
  the request body into the governance check. There is no hash binding, no
  artifact-integrity check, and no cryptographic signature anywhere in
  `publishing-pipeline.js` or `governance-engine.js`: whoever can write
  those Redis fields (a bug, a compromised credential, an internal tool) or
  call this endpoint with `actor: 'publisher'` can move an object to
  `published` and trigger real distribution (webhooks, email queue,
  published feed). Whether a separate request-level auth layer (API
  key/session middleware) restricts who can reach this endpoint at all was
  **not checked** in this session — that would need its own investigation
  before drawing a conclusion either way.

  This is precisely the class of gap this module exists to close, and it is
  the most concrete, real integration point identified. **It has not been
  touched** — modifying a live, currently-running publication path used by
  real customer-facing distribution is a high-blast-radius production
  change (CLAUDE.md's own Blast Radius Assessment would flag it HIGH) and
  needs an explicit, separately-scoped decision, not a change folded into
  this task.

No R2/KV/D1 usage, no Wrangler/Cloudflare Pages config, was found in this
repository — deployment appears to be Vercel-style (`api/` directory
convention, `.vercelignore` present) rather than Cloudflare Workers.

**Recommended next step** (not executed here): inject `verifyAuthorization()`
into `PublishingPipeline.publishToProduction()` ahead of the existing
`governance.enforceGovernance()` check, with a real KMS-backed signer
issuing the authorization at `approveForPublication()` time. That is new,
separately-reviewable work against a live path — out of scope for this
session's "build it fresh" instruction, which was about this module.

## Final Quality Bar — self-challenge

Every question below is answered by a specific test in
`integration.test.js` or `authorization.test.js`, not by assertion:

| Question | Where answered |
|---|---|
| Can a caller fabricate `PUBLISH-READY`? | `integration.test.js` — hand-forged manifest self-signed by an untrusted key → `DENY_UNKNOWN_KEY` |
| Can a caller modify the artifact after approval? | `authorization.test.js` / `integration.test.js` — one-byte mutation → `DENY_ARTIFACT_HASH_MISMATCH` |
| Can authorization be replayed? | `authorization.test.js` / `integration.test.js` — nonce reuse across two sinks → `DENY_REPLAY` (process-local only, see above) |
| Can an expired approval publish? | `DENY_EXPIRED_AUTHORIZATION` |
| Can a revoked key publish? | `DENY_REVOKED_AUTHORIZATION` |
| Can restricted intelligence reach a public sink? | `DENY_RESTRICTED_PUBLICATION`, tested on all four public sink types |
| Can `HOLD` ever be authorized? | `authorize()` refuses unconditionally (throws `AuthorizationRefusedError`) *and* `verifyAuthorization()` independently blocks it (`DENY_HOLD`) if that refusal were ever bypassed |
| Can a missing verifier fail open? | `DENY_MISSING_VERIFIER` |
| Can a legacy publisher bypass the gate? | Not applicable to this module in isolation — the module cannot force adoption by a path that never calls it. See "Real publishing DAG" above. |
| Can the package accidentally contain signing secrets? | Grepped for `BEGIN PRIVATE KEY`/`BEGIN...KEY-----` across every file in this directory — none found; all keys in tests are ephemeral, generated in-memory, never written to disk |
| Can this claim production verification without production evidence? | It doesn't — see "Verification boundaries" above |
