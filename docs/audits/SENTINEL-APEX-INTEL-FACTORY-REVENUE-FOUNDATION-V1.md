# SENTINEL APEX — Intel Factory Revenue Foundation v1

**Date:** 2026-09-01  
**Scope:** revenue-critical report/product integrity before premium CTI commercialization  
**Verdict:** **NO-GO for paid one-time report/product checkout until the gates below are closed**

## 1. Business north star

The primary product is cybersecurity intelligence: threat-intelligence reports, incident/breach reports, malware analysis, vulnerability/zero-day intelligence, campaign/actor intelligence, premium technical reports and machine-readable defensive intelligence. Secondary SOC/workbench capabilities support that product; they are not allowed to dilute report quality or commercial trust.

## 2. Reuse-before-build result

The repository already contains a substantial ReportX commercial-readiness system. System 3 is the canonical evidence/claim truth model, System 5 consumes its validated export through `api/_lib/reportx-adapter.js`, and four real canaries have passed the 23/23 automated control matrix. This foundation must be reused rather than replaced.

However, the rollout runbook records the four canaries as `PREMIUM_READY_PENDING_HUMAN`, with zero real operator `APPROVE` actions. The release therefore remains `NOT_CERTIFIED`; Phase 6 GO/NO-GO and Phase 7 live integration have not been authorized. No canary may be marketed as `PREMIUM_CERTIFIED` until a real operator performs the documented artifact-bound review.

## 3. P0 finding — report/product control-plane authorization

`api/v1/reports/index.js` and `api/v1/products/index.js` were routable while trusting caller-supplied identity fields for generation/review/approval/publication workflows. That is unacceptable for a commercial intelligence factory: a report approval must be attributable to a verified analyst, not a string supplied in the request body.

**Remediation in this tranche:**

- preserve the legacy engines byte-for-byte under `legacy-index.js` for compatibility/internal reuse;
- put an `X-Analyst-Key` authenticated gateway in front of both HTTP entry points;
- replace caller-supplied `analyst`, `reviewer`, `approver`, `publisher`, and `role` with the verified analyst identity;
- bound list/search inputs;
- preserve OPTIONS behavior and security headers.

Public CTI remains served through published report/intelligence surfaces, not these internal control-plane endpoints.

## 4. P0 finding — one-time product currency/unit mismatch

The one-time product catalog stores prices in **USD cents** (`19900` means `$199.00`). The legacy Razorpay product checkout instead multiplied that value by 100 and submitted it as **INR paise**, while returning `currency: INR` to the browser. A `$199` catalog item could therefore become a ₹19,900 order rather than a $199 order. That is a direct price/currency integrity failure.

## 5. P0 finding — paid fulfillment not operational

The existing product delivery manifest points at paths such as `products/q2-2026-threat-report.pdf`, but the repository has no `products/` artifact directory. The existing Cloudflare inventory also records that the expected `cyberdudebivash-products` bucket was not provisioned, while `api/v1/customer/download.js` depends on an `aws-sdk` runtime path that is not part of the declared Cloudflare-native product-delivery architecture.

A successful payment must never precede proof that the purchased artifact exists and is deliverable.

**Immediate remediation in this tranche:** legacy `create-product-checkout` and `verify-product-payment` are failed closed before the old payment code runs. Subscription/manual billing remains untouched.

## 6. Premium CTI commerce target

The replacement path must be Cloudflare-native and report-first:

```text
CERTIFIED REPORT ARTIFACT
        ↓
SELLABILITY GATE
        ↓
PUBLIC PREVIEW / PREMIUM DIFFERENTIATION
        ↓
SERVER-SIDE PRICE + CURRENCY
        ↓
RAZORPAY ORDER
        ↓
ATOMIC PAYMENT CLAIM
        ↓
PAID ORDER
        ↓
R2 ARTIFACT ENTITLEMENT
        ↓
SIGNED / AUTHORIZED DOWNLOAD
        ↓
PURCHASE HISTORY + AUDIT
```

Minimum sellability invariant:

```text
CERTIFICATION ELIGIBLE
AND ARTIFACT EXISTS
AND DELIVERY BACKEND HEALTHY
AND PRICE/CURRENCY VALID
AND PAYMENT IDEMPOTENCY READY
→ BUY ENABLED

anything else
→ BUY DISABLED
```

## 7. Product strategy

The current generic store emphasizes rule packs, playbooks and red-team bundles. The next commercial storefront must instead lead with the primary factory output:

1. Premium Threat Intelligence Reports
2. Cybersecurity Incident / Data Breach Intelligence
3. Malware & Ransomware Analysis
4. Vulnerability / CVE / Zero-Day Intelligence
5. Campaign / Threat Actor Intelligence
6. Executive / Sector Intelligence Briefings
7. Machine-readable IOC / detection / STIX add-ons where evidence exists

No unsupported quantity claim (for example thousands of rules/signatures) may be used without a canonical artifact count behind it.

## 8. Next implementation tranche

After this safety branch is green:

1. add a Cloudflare D1 commercial-report catalog/order model;
2. add an R2 `PREMIUM_REPORTS` binding and artifact-existence checks;
3. expose a read-only public premium-report catalog/preview API;
4. introduce a report sellability gate bound to ReportX certification state;
5. implement exact server-side amount/currency semantics for Razorpay;
6. implement atomic payment idempotency before entitlement/delivery;
7. deliver purchased report artifacts from R2 without query-string bearer secrets where avoidable;
8. rebuild `products.html` into an Intelligence Store centered on report sales and subscriptions;
9. add conversion telemetry based on real events only;
10. keep human/operator certification authority intact.

## 9. Explicit non-claims

This tranche does **not** claim:

- ReportX release certification is complete;
- any canary is human-approved;
- R2 premium-report delivery is live;
- one-time report checkout is live;
- a customer has purchased a ReportX report;
- unsupported product-count claims are verified.

Those statements become true only when their production evidence exists.
