# Puter User-Pays Fallback v17

## Purpose

Puter is integrated as an **optional final AI fallback** for the premium Blogger syndication factory. It is intentionally not classified as part of the v16 zero-cost provider mesh.

Browser applications using Puter.js normally meter usage to each signed-in end user. Backend/CI usage authenticates with a Puter auth token, so the token owner's Puter account is the metered user. For the pre-revenue platform this means Puter must remain explicit, bounded, and fail-closed.

## Effective provider order

1. Groq free pool
2. Gemini Free Tier
3. NVIDIA NIM hosted free endpoint
4. OpenRouter zero-priced model
5. Puter User-Pays fallback — **operator opt-in only**
6. Safe defer

Puter never bypasses the existing evidence, analytical-depth, provenance, prompt-leak, contradiction, ReportX, or Blogger fetch-back gates.

## Required GitHub configuration

### Secret

- `PUTER_AUTH_TOKEN` — Puter account auth token created from the Puter dashboard.

### Repository variables

- `PUTER_AUTOMATION_ENABLED` — must be exactly `true` to permit calls. Default/absent = disabled.
- `PUTER_MODEL` — optional. Default in code: `gpt-5.6-luna`.
- `PUTER_MAX_CALLS_PER_RUN` — optional integer `0..5`. Default: `1`.
- `PUTER_MIN_REMAINING_MICROCENTS` — optional remaining-allowance reserve. Default: `25000000` (Puter documents resource accounting in microcents; this is a $0.25-equivalent reserve).

The workflow hard-codes `PUTER_PUBLIC_DATA_ONLY=true` because this factory handles public CTI/OSINT only.

## Hard safety controls

- Disabled by default.
- No Puter request without `PUTER_AUTH_TOKEN`.
- Public-data-only policy required.
- Node 24 runtime required by the official Puter Node.js integration.
- `@heyputer/puter.js` pinned to `2.2.8` for deterministic CI behavior.
- Pre-call `puter.auth.getMonthlyUsage()` check is mandatory.
- Missing allowance telemetry = no request.
- Remaining allowance below reserve = no request.
- Maximum one Puter request per workflow run by default.
- Puter token is passed only to the Node subprocess; Groq/Gemini/NVIDIA/OpenRouter secrets are not forwarded.
- Token, prompt, response body, and exact allowance amounts are not written to public run telemetry.

## Zero-spend operating rule

Do not treat the phrase "free unlimited API" as an unlimited anonymous backend allowance. The User-Pays model means the authenticated Puter account owns the usage. Keep `PUTER_AUTOMATION_ENABLED=false` until the account has been reviewed and you intentionally accept use of its free allowance.

For a strict $0 operating posture, do not add paid balance/top-ups solely to support this automation. If the free allowance becomes insufficient, allow the v17 guard to skip Puter and preserve safe defer.

## Validation

A production acceptance run is successful only if all of the following are true:

1. Existing v16 provider mesh remains first in routing order.
2. Puter is not called after any v16 provider succeeds.
3. Puter is not called while opt-in is disabled.
4. Allowance telemetry is checked before every Puter AI request.
5. Puter content is labeled `content_source=puter` and still clears unchanged premium publication gates.
6. No secret or allowance amount appears in committed logs/telemetry.
7. Production workflow and repository security gates are green.
