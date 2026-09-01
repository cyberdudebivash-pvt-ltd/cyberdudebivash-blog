# SENTINEL APEX™ Premium Intelligence Commerce Engine v1 — Certification

**Date:** 2026-09-01  
**Branch:** `claude/p0-premium-intelligence-commerce-v1`  
**Verdict before CI/live Cloudflare activation:** **CONDITIONAL GO — CODE CANDIDATE / PRODUCTION ACTIVATION BLOCKED**

## 1. Executive verdict

This tranche replaces the unsafe generic one-time product path with a dedicated commercial path for **certified cybersecurity intelligence reports**. It does not re-enable the legacy `create-product-checkout` / `verify-product-payment` actions; those remain fail-closed behind PR #148's safety gate.

The new commerce system is structurally capable of:

`ReportX exact-artifact human certification → protected R2 publication → D1 sellable catalog → authenticated Razorpay order → captured-payment verification → D1 entitlement → Customer Intelligence Library → authenticated artifact download`.

No current ReportX canary is automatically promoted to a real sellable product. Automated 23/23 controls without a real human review remain insufficient.

## 2. Primary product boundary

The sellable object is a **Premium Intelligence Report**, not a generic SKU. Initial report families are metadata-driven (`report_type`) so ransomware, malware analysis, incident/breach, campaign, vulnerability/zero-day and other CTI report families use one commercial truth model.

## 3. ReportX certification gate

`api/_lib/premium-report-certification.js` accepts an export only when:

- the bundle is premium tier;
- commercial readiness is `COMMERCIAL-READY`;
- rendered report text exists;
- a ReviewRecord exists;
- ReviewRecord decision is `APPROVE`;
- the review is not `is_test_only_fixture=true`;
- reviewer identity and timestamp exist;
- the review report ID matches;
- SHA-256 of the exact `bundle.rendered_text` equals the review's `artifact_sha256`.

Any post-review content edit invalidates commerce eligibility.

## 4. Artifact truth and R2

`api/_lib/premium-report-storage.js` uses only the Cloudflare `PREMIUM_REPORTS` R2 binding. No AWS SDK, S3 compatibility credential or public bucket URL is accepted.

Key format is content-addressed:

`premium-reports/<report-id>/<artifact-sha256>.md`

Object metadata carries report ID and SHA-256. Sellability and download both HEAD-check report identity, hash metadata and expected byte length.

## 5. Catalog

`premium_report_catalog` contains only `PREMIUM_CERTIFIED` rows and supports `SELLABLE`, `PAUSED`, `RETIRED`. Public catalog responses deliberately omit R2 keys, reviewer identity and other internal state.

## 6. Price/currency integrity

The previous generic checkout's USD-cent → INR-paise reinterpretation is not reused.

The new contract is explicit:

- `price_minor` = integer amount already expressed in the selected currency's smallest subunit;
- Razorpay receives that integer **unchanged**;
- currency is server catalog state, not client input;
- `PREMIUM_COMMERCE_CURRENCIES` is an operator allowlist (default `INR`);
- payment verification re-checks captured status, order ID, payment ID, exact amount and exact currency server-side.

## 7. Orders

D1 `premium_orders` snapshots the exact report title, artifact SHA/key/name/type/size, amount and currency at checkout. A later catalog update cannot silently change what an existing buyer purchased.

## 8. Payment idempotency

Payment claim is an atomic D1 mutation from `ORDER_CREATED` to `PAYMENT_VERIFIED`, requiring no existing payment ID. Same-payment retries can resume from `PAYMENT_VERIFIED` or `ENTITLED`; a different payment ID is rejected.

## 9. Browser-close recovery

The existing signed Razorpay webhook is extended for premium orders. `payment.captured` / `order.paid` can complete entitlement even when the browser callback never reaches the verify endpoint. Failure to create a known premium entitlement returns HTTP 500 so Razorpay can retry instead of losing paid fulfillment.

## 10. Refunds

`refund.processed` reconciles premium orders. Only a **processed full refund** revokes the entitlement and marks the order `REFUNDED`. Partial refunds do not revoke report access automatically.

## 11. Customer ownership

Checkout, verify, library and download derive ownership only from `authenticate()` API-key identity. Client payload cannot supply email, owner ID, price or currency.

## 12. Customer library

`customer-library.html` holds the API key only in tab memory, fetches the authenticated entitlement list, and downloads report bytes using an Authorization header. Credentials never enter query strings.

## 13. Download integrity

Download requires an active entitlement for the caller, verifies the **order-pinned** R2 artifact, verifies exact byte length, sets `private, no-store`, returns an attachment filename and `X-Content-SHA256`, and records a bounded audit row.

## 14. Legacy customer-dashboard security

The pre-existing `/api/v1/customer/dashboard?email=...` model was an IDOR/privacy defect and could expose customer state/API-key material by caller-supplied email. It is replaced with authenticated self-service identity and never returns API-key material.

## 15. Cloudflare architecture

New production state is Cloudflare-native:

- D1: catalog, orders, entitlements, download audit;
- R2: premium artifacts;
- Worker: commerce API and binary fulfillment;
- Razorpay: checkout/payment events.

No new Vercel runtime, Upstash storage, AWS SDK or GitHub-Actions production runtime is introduced.

## 16. Native Worker bindings

`workers/lib/router.js#handleFetch()` now registers `env.DB` and `env.PREMIUM_REPORTS` before HTTP dispatch. This also removes the unnecessary D1 REST hop for existing D1-backed HTTP routes when they execute inside Workers while preserving the repository's established `(req,res)` handler signatures.

## 17. Static customer surfaces

- `intelligence-store.html` — public certified catalog and Razorpay checkout.
- `customer-library.html` — authenticated entitlement/download library.

Both are added to the explicit Cloudflare static-asset allowlist.

## 18. Fail-closed states

No certified artifact → no catalog row.  
Missing R2 binding/object → no checkout.  
Invalid price/currency → no checkout.  
Uncaptured/mismatched payment → no entitlement.  
No entitlement → no download.  
Full processed refund → entitlement revoked.  
Automated-only ReportX approval → no sellable product.

## 19. Known limitations / operator activation gates

This session does not possess authenticated Cloudflare account mutation capability. Before production commerce can be called LIVE, an authorized operator must:

1. create/bind R2 bucket `sentinel-apex-premium-reports`;
2. apply D1 migration `0008_premium_intelligence_commerce.sql` to `sentinel-apex-core`;
3. confirm Cloudflare Worker has `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET`;
4. subscribe the existing Razorpay webhook URL to `payment.captured`, `order.paid`, and `refund.processed`;
5. deploy the Worker;
6. human-review one real ReportX artifact and publish it through `action=publish-certified` with a chosen server-governed `price_minor`/currency;
7. execute a Razorpay test-mode end-to-end purchase before live-mode acceptance;
8. perform a controlled live low-value purchase only after test-mode evidence is clean.

## 20. Non-claims

- No current report is claimed to be human-certified without its actual ReviewRecord.
- No real paid transaction has been executed by this branch.
- No Cloudflare R2 bucket or D1 production migration is claimed applied from repository code alone.
- Markdown `rendered_text` is the v1 certified downloadable artifact. PDF/STIX/ZIP derivatives require their own deterministic artifact/certification policy before being sold as the certified object.

## 21. Release gate

PR CI must pass Build Verification, full Jest/coverage, Worker route parity, governance, resilience, performance, end-to-end and CodeQL. Any real commerce/security failure blocks merge.

Final production verdict remains **CONDITIONAL GO** until the operator activation gates and a successful payment/fulfillment canary are proven.
