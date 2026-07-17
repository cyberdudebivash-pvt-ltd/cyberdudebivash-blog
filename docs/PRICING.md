# Pricing — source of truth and incident record

## Canonical source

`api/_lib/payment-utils.js`'s `PLANS` object is the **only** authoritative
definition of what each tier costs. Every other value — display copy,
checkout UI, structured data — must either read from it at runtime or, for
static text that can't be dynamic, match it exactly and be covered by the
regression test below.

| Tier | Amount | Currency |
|---|---|---|
| Starter | 2,499 | INR |
| Pro ("SOC Pro") | 1,499 | INR (≈$18) |
| Enterprise | 4,999 | INR (≈$60) — self-serve API tier only; the separate white-label/SLA "Enterprise Platform" offering is custom-quoted, not a fixed price |

## Runtime consumers

`GET /api/v1/billing?action=plans` serves the `PLANS` object publicly
(cached 5 min). `pricing.html` and `payment-flow.js` fetch it on load and
use it for everything rendered in the checkout modal. Both keep a small
local fallback constant for the rare case that fetch fails before a user
clicks upgrade — the fallback must be kept in sync with `PLANS` manually and
is covered by `tests-js/pricing-consistency.test.js`.

For the manual UPI/bank-transfer flow specifically, the amount shown in the
"Amount" instruction row and encoded in the UPI QR code comes from the
**intent-creation response** (`intent.amount`, set server-side from
`PLANS`), not the client cache — this is the value a human reviewer checks
a submitted UTR against, so it has to be the real one regardless of what the
client's fallback says.

## What broke (2026-07-17) and why

SOC Pro was reduced from $49/₹4,099 to $18/₹1,499 at some point before this
incident was found. The rollout updated most of the site but missed four
independent hardcoded copies of the price: the actual billing backend
(`payment-utils.js` — the most consequential miss, since that's what
determined the real Razorpay/UPI charge), the Stripe checkout response in
`billing.js`'s `subscribe` handler, and roughly a dozen scattered
marketing/conversion-engine strings across `ai-monetization-engine.js`,
`ux-controller.js`, `revenue-cta-block.js`, `conversion-engine.js`,
`auto-intel-engine.js`, plus Schema.org structured data in `seo-engine.js`
and `api.html`. Two of those files also carried a "$X, was $Y" discount
anchor built on the stale number.

Direction was confirmed, not assumed: `OPERATIONS.md` and
`AUDIT-REPORT-2026-05-28.md` both already documented ₹1,499/$18 as
canonical; `api/_lib/stripe.js`'s own header comment independently
corroborated $49 as the *old* price; and "4099" appeared nowhere else in
the repository except the one line that was wrong.

## Preventing recurrence

- `tests-js/pricing-consistency.test.js` (run by
  `.github/workflows/pricing-integrity.yml` on every push/PR touching a
  pricing-relevant file) asserts the backend's `PLANS.pro.amount`,
  checks it against both client-side fallback constants, and greps the
  known marketing files for the stale price paired with "SOC Pro".
- `.github/workflows/smoke-test.yml` additionally checks the **live,
  deployed** site after every push to `main`: `live-intel.json` for the
  stale price (hard failure, previously only a non-blocking warning),
  `GET /api/v1/billing?action=plans` for `pro.amount === 1499`, and
  `pricing.html`'s served HTML for any trace of $49/₹4,099.
- Before changing `PLANS.pro.amount` again: update the two client fallback
  constants in the same change, and expect
  `tests-js/pricing-consistency.test.js`'s marketing-surface checks to
  need updating too if any copy quotes the old number by name.

## Known open item outside this codebase

If Stripe is ever activated (`STRIPE_SECRET_KEY` set), `STRIPE_PRICE_PRO`
must point at a Stripe Price object priced at $18/mo. That object lives in
the Stripe dashboard, not this repository, and cannot be verified or fixed
by a code change — confirm it directly before enabling Stripe checkout.
