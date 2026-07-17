# API Reference

_Auto-generated from the header comment block each `api/v1/*.js` router already maintains — regenerate with `node scripts/generate-docs.js` after changing a route. Do not hand-edit._

## SENTINEL APEX — Consolidated Admin Router

**File:** `api/v1/admin.js`

**Routing:** /api/v1/admin?action={action}

| Action | Method | Description |
|---|---|---|
| `pending` | GET | List payment submissions (filterable by status) |
| `approve` | POST | Approve payment → upgrade user tier in Redis |
| `reject` | POST | Reject payment with reason + audit trail |
| `audit` | GET | Full event audit log from Redis sorted set |

## SENTINEL APEX — Consolidated Auth Router

**File:** `api/v1/auth.js`

**Routing:** /api/v1/auth?action={action}

| Action | Method | Description |
|---|---|---|
| `register` | POST | Create account + generate API key |
| `me` | GET | Authenticated user profile + tier info |
| `usage` | GET | Per-key daily usage breakdown (last N days) |

## SENTINEL APEX — Consolidated Billing Router

**File:** `api/v1/billing.js`

**Routing:** /api/v1/billing?action={action}

| Action | Method | Description |
|---|---|---|
| `create-intent` | POST | Generate payment intent UUID, store in Redis 24h |
| `submit-payment` | POST | Accept UTR with fraud protection + duplicate guard |
| `status` | GET | User self-service payment status check |
| `subscribe` | POST | Create Stripe checkout session (when available) |
| `create-razorpay-order` | POST | Create a Razorpay Order for instant checkout |
| `verify-razorpay-payment` | POST | Verify checkout.js signature, instant tier upgrade |

## SENTINEL APEX — Consolidated Intel Router

**File:** `api/v1/intel.js`

**Routing:** GET /api/v1/intel?action={action}

| Action | Method | Description |
|---|---|---|
| `live` | GET | All live threat intelligence (tier-gated depth) |
| `top` | GET | Top-priority threats (priority_score >= 65) |
| `cve` | GET | CVE detail lookup  (?id=CVE-2024-xxxx) |
| `iocs` | GET | IOC feed — PRO+ only, STIX export for Enterprise |
| `ransomware` | GET | Ransomware campaign feed |
| `search` | GET | Full-text search across all intel (?q=query) |
| `stats` | GET | Platform stats — no auth required |
| `graph` | GET | Threat actor relationship graph (tier-gated) |
| `campaigns` | GET | Campaign clusters (?severity=&has_kev=) |
| `campaign` | GET | Single campaign detail (?id=campaign:...) |
| `top-actors` | GET | Most active threat actors ranked by activity |
| `entity` | GET | Unified content-graph lookup (?type=&id=) across |

## SENTINEL APEX — Newsletter Signup Endpoint

**File:** `api/v1/newsletter.js`

**Routing:** POST /api/v1/newsletter

## Content Graph Lookup

All five entity types exposed via `api/v1/intel.js?action=entity&type={type}&id={id}` are backed by `api/_lib/content-graph.js`, itself a facade over the intel-graph subsystem (threat-graph.js/campaign-engine.js) and the intelligence-hub subsystem (vendor/timeline/collections/detections). Valid types: `cve`, `vendor`, `actor`, `campaign`, `collection`.
