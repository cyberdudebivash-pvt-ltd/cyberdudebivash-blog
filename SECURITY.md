# Security Policy

CYBERDUDEBIVASH® SENTINEL APEX takes the security of this platform and its
users seriously. This document covers how to report a vulnerability and
summarizes the automated security controls already running against this
repository.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Email **bivash@cyberdudebivash.com** with:
- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code/requests welcome)
- Any relevant logs, screenshots, or affected URLs

We aim to acknowledge reports within 3 business days. Once a fix is
confirmed, we credit reporters (with permission) in the fix's commit
message unless anonymity is requested.

## Automated Security Controls

| Control | Where | Cadence |
|---|---|---|
| Node dependency audit (`npm audit --audit-level=high`) | `security-audit.yml` | Every push touching `package.json`/`api/**`, plus weekly |
| Python dependency audit (`pip-audit`) | `security-audit.yml` | Every push touching `requirements.txt`, plus weekly |
| Secret-pattern scan (Stripe/AWS/GitHub/Slack key shapes) | `security-audit.yml` | Same triggers — **fails the build** on a match |
| Security headers validation (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) | `security-audit.yml` | Same triggers |
| Rate limiting (per-IP, per-endpoint) | `api/_lib/security.js` (Redis-backed, fails open) | Every request to `api/v1/*` |
| Input validation & sanitization at API boundaries | `api/_lib/security.js` (`sanitize`, `validateEmail`, `assertFieldWhitelist`) | Every request to `api/v1/*` |
| Blogger OAuth2 refresh-token lifecycle handling | `automation/blogger_publisher.py` | Every syndication run |

## Scope

In scope: `blog.cyberdudebivash.in` and its `api/v1/*` endpoints, the
GitHub Actions workflows in this repository, and the generator/orchestrator
scripts that produce site content.

Out of scope: `intel.cyberdudebivash.com` (the separate Sentinel APEX CTI
product — report issues there through its own channel), third-party
services this platform integrates with (Stripe, Razorpay, Resend, Upstash
Redis, Blogger/Google) — report those directly to the vendor.

## Known Design Notes (not vulnerabilities)

- Rate limiting fails **open** on Redis unavailability (`api/_lib/security.js`)
  — a deliberate availability-over-strictness tradeoff for a public content
  platform, not an oversight.
- The public `/api/v1/intel?action=stats` endpoint requires no authentication
  by design (platform-wide aggregate stats only, no per-customer data).
- Internal operational pages (`ops/health/`) are served with a `noindex`
  meta tag but are not access-controlled — no credentials or customer PII
  are rendered there.
