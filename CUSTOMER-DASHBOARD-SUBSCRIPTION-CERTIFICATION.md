# Customer Dashboard — Subscription Self-Service Release Certification

**Date:** 2026-08-21
**Scope:** Fix a broken-access-control vulnerability in `billing.js`'s subscription-lifecycle actions, then build the customer-facing self-service UI on top of the now-secured backend: session persistence, a persistent identity bar, and a "My Subscription" management panel (view/pause/resume/cancel) in `api-dashboard.html`.
**Format:** Matches `SOC-WORKBENCH-RELEASE-CERTIFICATION.md`'s established structure.

## Background

Per the user's direction ("Customers asking to enhance/transform the UI/UX dashboard to SOC-2 & CTI style"), this round continued the platform-wide UI/UX transformation onto the customer-facing dashboard (`api-dashboard.html`), following the SOC Workbench (internal analysts, PR #123) and Phase 1K Section 16 (report pipeline, PR #124) rounds. A Reuse Before Build audit of `api/v1/billing.js` and `api/v1/auth.js` found three genuinely dormant, unwired customer-facing actions — `create-subscription`, `manage-subscription`, `list-subscriptions` — a real self-service subscription-management capability with zero frontend callers anywhere in the codebase.

That audit also surfaced a serious, live vulnerability: all three handlers trusted a bare, client-supplied `email` field with **zero authentication**. Anyone who knew or guessed a customer's email could list their subscription details or cancel their paid subscription outright — a broken-access-control/IDOR defect in production billing code. Per CLAUDE.md's always-active, non-negotiable Security First principle, fixing this was treated as a mandatory first step, ahead of and independent from the UI work it enabled.

## Changed components

**New:**
- `api/v1/__tests__/billing.test.js` — 10 route-handler tests covering the 3 fixed actions.

**Modified:**
- `api/v1/billing.js` — the 3 subscription-lifecycle handlers now require API-key authentication and derive identity from the authenticated caller, never the client:
  - `handleCreateSubscription` — `authenticate(req, res)` gate added; `email` now comes from `user.email`, not `body.email`. `FIELDS['create-subscription']` whitelist no longer accepts an `email` field at all (a client-supplied one is now rejected outright with `400 INVALID_FIELDS`, not silently ignored).
  - `handleManageSubscription` — same auth gate; additionally verifies the target subscription's stored owner matches the authenticated caller's email before allowing pause/resume/cancel (`subscription_id` itself is still client-supplied, so authentication alone isn't ownership). A subscription that doesn't exist and one that belongs to someone else return the **identical** `404 NOT_FOUND` response, so a valid ID can't be enumerated by comparing error responses.
  - `handleListSubscriptions` — same auth gate; `email` comes from `user.email`, not `req.query.email`.
- `api-dashboard.html`:
  - Session persistence via `sessionStorage` (`persistKey()`/`trySessionResume()`) — a returning visitor with a still-valid key resumes straight into the Dashboard tab instead of re-entering their key; an invalid/revoked stored key fails silently back to signed-out (no intrusive `alert()` on page load).
  - Persistent identity bar in the nav (`#who`, `#signout-link`) showing "Signed in as `{email}` · `{TIER}`", matching the pattern already proven in `workbench.html`.
  - New "My Subscription" panel: lists the caller's subscriptions (plan, status badge, amount, next billing date) with Pause/Resume/Cancel actions wired to the now-secured `list-subscriptions`/`manage-subscription` endpoints; hides itself entirely when the customer has none.
  - Fixed a pre-existing bug found along the way: the "Go to My Dashboard →" button after key generation called `loadDashboard()` directly instead of `switchTab('dashboard')`, so it loaded the dashboard's data but never actually navigated the user to see it.
  - Fixed a responsive-layout defect introduced by this round's own identity bar (see below).

## Defects discovered (this phase)

1. **Broken access control / IDOR in `billing.js` subscription actions (the mandatory security fix).** `create-subscription`, `manage-subscription`, and `list-subscriptions` all trusted a bare client-supplied `email` field with no verification. Any caller who knew or guessed a customer's email could view that customer's full subscription list (plan, amount, billing dates, subscription IDs) or cancel their paid subscription outright, with no authentication of any kind. Fixed by requiring `authenticate(req, res)` on all three and deriving identity exclusively from the authenticated caller.
2. **`manage-subscription` had a second, narrower gap even after adding authentication.** `subscription_id` is still client-supplied, so an authenticated caller could otherwise pause/resume/cancel a *different* customer's subscription simply by guessing or observing a valid ID. Fixed by fetching the subscription record and comparing its stored owner to the authenticated caller before permitting any action, with an identical `404` for "doesn't exist" and "belongs to someone else" to prevent ID enumeration via response-shape differences.
3. **Pre-existing UI bug: "Go to My Dashboard →" didn't navigate.** The button's `onclick` called `loadDashboard()` directly — which fetches and renders dashboard data into `#dash-content` — but never switched the active panel/tab to actually show it. A newly-registered customer clicking it saw no visible change. Fixed to call `switchTab('dashboard')`, which itself now triggers a silent `loadDashboard(true)`.
4. **Found during real-browser verification: horizontal overflow on mobile, introduced by this round's own identity bar.** The pre-existing mobile media query (`@media(max-width:600px)`) hides secondary nav links via `.nlinks a:not(.ncta){display:none}` — but that selector only matches `<a>` tags. The new `#who` identity `<span>` isn't an `<a>`, so it was never hidden, and its "Signed in as `{email}` · `{TIER}`" text overflowed the fixed nav on narrow viewports (confirmed: `document.documentElement.scrollWidth` = 424px against a 375px viewport). The same rule would also have silently swallowed the new `#signout-link` (it *is* an `<a>` without the `.ncta` class), making sign-out unreachable on mobile. Fixed by explicitly hiding `#who` in the same media query and excluding `#signout-link` from the hide rule — mobile now keeps only the "⚡ Upgrade" CTA and "Sign out" reachable, consistent with the existing design's mobile nav-reduction pattern, while eliminating the overflow.

## Defects fixed

All four above.

## Requirements proven

- **Authentication is real and enforced.** Route-handler tests prove unauthenticated requests to all three actions are rejected (`401`) before any subscription manager method is ever called — no lookup, no creation, no mutation occurs on an unauthenticated request.
- **Identity is never taken from the client.** Tests prove `list-subscriptions` returns the *authenticated* caller's subscriptions even when a different email is supplied as a query parameter, and `create-subscription` creates under the authenticated caller's email — with a dedicated adversarial test proving a client-supplied `email` body field is now rejected outright (`400 INVALID_FIELDS`) by the tightened field whitelist, not merely ignored.
- **Ownership is enforced, not just authentication.** The exact vulnerability this round fixes is directly reproduced and proven closed: an authenticated caller attempting to manage a subscription owned by a different email is rejected with `404`, `cancelSubscription`/`pauseSubscription`/`resumeSubscription` are never invoked, and a non-existent subscription ID produces the byte-identical response (no enumeration signal). A subscription genuinely owned by the caller can still be paused, resumed, and cancelled normally; ownership comparison is case-insensitive, matching `normalizeEmail`'s own normalization.
- **The UI is real and matches the backend's actual, now-secured contract**, proven in an actual Chromium browser (Playwright, the pre-installed `/opt/pw-browsers/chromium`) driving the real `api-dashboard.html` through a full session: fresh load → register → key generation → "Go to My Dashboard" navigation (the fixed bug) → identity bar and stats populate → My Subscription panel renders both an active and a paused subscription with correct plan/status/amount and contextually correct action buttons → Pause reaches the endpoint and the list refreshes → Cancel's confirmation dialog is proven both ways (dismiss sends no request, accept does) → hostile `plan_type`/`status` values from the mocked API are escaped, not rendered as live HTML (XSS defense) → the subscription card hides itself when empty → Sign Out clears session storage, the identity bar, and returns to Register → a real page reload with a stored key resumes straight into the Dashboard without re-login → a revoked stored key signs out silently, with no `alert()` dialog → mobile viewport (375×812) shows zero horizontal page overflow. 35/35 scripted assertions passing, zero uncaught JS exceptions. The API layer was mocked at the network level (no live Redis/Vercel deployment reachable from this sandbox) with response shapes copied field-for-field from the real handlers this session read (`auth.js`'s `handleMe`/`handleUsage`/`handleRegister`, `billing.js`'s `handleListSubscriptions`/`handleManageSubscription`) — this proves the frontend renders and wires correctly against the real, now-secured contract. This verification process is what surfaced defect #4 above — it was not reachable by reasoning about the code alone.
- **No regression**: full existing suite re-run clean after every change (`npx jest`: 1752/1752 passing, 46 of 47 suites, 1 pre-existing skipped suite and 60 pre-existing skipped tests, both unrelated to this work). `npx tsc --noEmit`: zero errors.

## Requirements NOT yet proven

- **Live Redis-backed persistence end-to-end.** No Upstash credentials and no deployed Vercel instance are reachable from this sandbox — the same accepted, out-of-scope local-environment limitation documented in the prior two certifications this session. Every fixed code path is proven correct in isolation (unit/route-handler tests against mocked `_lib/subscriptions` and `_lib/middleware`) and the full request pipeline is proven correct end-to-end against realistic mocked responses (browser tests); what is not proven here is Upstash Redis itself, or Razorpay's real pause/resume/cancel API, under real production load.
- **`create-subscription` has no new checkout UI.** The security fix applies to all three actions equally, but this round deliberately did not build a new "start a recurring subscription" checkout flow in the frontend. `create-subscription` (as implemented) only creates a Razorpay subscription record and returns a `subscription_id` — it does not itself collect payment, which would require a separate Razorpay recurring-checkout.js integration (a distinct `subscription_id`-based checkout, not the existing one-time-order flow `ApexPaymentFlow.startUpgrade()` already provides). Building that is a materially larger, separate initiative; wiring the existing "My Subscription" *management* UI (view/pause/resume/cancel for subscriptions that already exist) is the proportionate scope for a dashboard UI/UX round and is what shipped. This is a deliberate scope boundary, not an oversight — flagged explicitly under Next steps.

## Production evidence

- 10 new route-handler tests, all passing (`npx jest api/v1/__tests__/billing.test.js`).
- Full suite: `npx jest` → 46 of 47 suites passing (1 pre-existing skip, unrelated), 1752/1812 tests passing (60 pre-existing skips), 0 failures.
- `npx tsc --noEmit` → zero errors.
- Real-browser verification: Playwright + the environment's pre-installed Chromium, 35/35 scripted UI assertions passing across desktop and a 375px mobile viewport, 7 screenshots captured (register, post-registration dashboard, My Subscription panel close-up, session-resumed dashboard, revoked-key silent sign-out, mobile dashboard), zero uncaught page errors. The console noise observed (`net::ERR_CONNECTION_RESET` on the unreachable Google Analytics domain in this sandbox, and one intentional `401` from the revoked-key test fixture) is expected test/environment noise, not a defect.

## Known limitations

- **Live Redis / live Vercel / live Razorpay** — not reachable from this sandbox; see Requirements NOT yet proven.
- **No `create-subscription` checkout UI** — deliberate scope boundary this round; the action is secured but not yet reachable from any UI. Real, explicitly documented follow-up work, not silently left broken.
- **`handleSubscriptionCancelled`'s tier-downgrade TODO.** `api/_lib/subscriptions.js`'s webhook handler for a cancelled subscription has a pre-existing, pre-dating-this-round comment noting the automatic downgrade of a cancelled customer's API tier back to free is not yet implemented. Out of scope for this round (this round's `manage-subscription` fix is about *authorization*, not this separate, smaller pre-existing gap); flagged under Next steps.

## Unexecuted tests

- A live `workflow_dispatch`/production canary of the actual deployed Vercel routes and a real Razorpay pause/resume/cancel call — no equivalent trigger exists for this repo's Vercel deployment from within this session.

## Certification

**RELEASE_CERTIFIED_WITH_LIMITATIONS**

Every acceptance bar this session set for itself is met: the broken-access-control vulnerability is closed and tested from both the authentication and ownership angles, the dormant subscription-management capability is now real, wired, and reachable behind that secured backend, and the UI is built and verified in an actual browser — a process that itself found and fixed a real mobile-responsive defect no amount of code reading alone would have caught. Zero regressions across the full existing suite. The named limitations (no live Redis/Vercel/Razorpay to test against, no new recurring-checkout UI for `create-subscription`, a separate pre-existing tier-downgrade TODO) are real, bounded, and explicitly follow-up work — not defects in what shipped.

## Rollback

Every change here is corrective or additive, not architectural:
- `billing.js`'s three handlers are stricter versions of the same actions with the same success-path response shapes; no consumer that was calling them correctly (there were none — they were dormant) is affected. Reverting restores the prior (vulnerable) behavior.
- `api-dashboard.html`'s new functions (`esc`, `persistKey`, `signOut`, `trySessionResume`, `loadSubscriptions`, `renderSubscriptionRow`, `fmtDate`, `manageSubscription`) are additive; no existing function was renamed or had its signature changed except `loadDashboard`, which gained a new optional `silent` parameter (omitting it preserves the exact prior behavior).
- The mobile CSS fix narrows an existing selector and adds one new rule inside the existing media query block; reverting returns to the pre-existing (now-known-broken-for-this-round-only) mobile nav behavior.

## Next steps (per CLAUDE.md's continuous self-improvement cadence)

1. **Build the `create-subscription` recurring-checkout UI** — a Razorpay recurring-subscription checkout.js integration distinct from the existing one-time-order flow, so customers can start a subscription from the dashboard rather than only manage an existing one.
2. **Implement the tier-downgrade-on-cancellation TODO** in `handleSubscriptionCancelled` (`api/_lib/subscriptions.js`) — today a cancelled subscription's customer keeps their paid-tier API access until some other mechanism changes it.
3. **A real Vercel + Razorpay deployment smoke test** of the three fixed actions, to close the one requirement this sandbox genuinely cannot prove (see Requirements NOT yet proven).
