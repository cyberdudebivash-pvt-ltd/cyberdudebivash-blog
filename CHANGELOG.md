# Changelog

All notable changes to the CYBERDUDEBIVASH® SENTINEL APEX platform are
documented here going forward. This file starts with the version-tagging
convention introduced in `v2.1.0` — earlier history (Blogger syndication
engine, CVE intelligence pipeline, AI Security engine, Stripe/Razorpay
checkout, etc.) predates this convention and is not reconstructed here;
see `git log` for that history.

**Versioning:** [SemVer](https://semver.org/), tracked in `package.json`.
Tags are pushed as `v<version>` (e.g. `v2.1.0`). This is a continuously
deployed platform, not a published library — a tag marks a verified-good
point in history for rollback reference (see `OPERATIONS.md` §5.3), not a
downloadable release artifact.

## [2.1.0] — 2026-07-17

### Added — Intelligence Hub
- Vendor & Ecosystem Intelligence Centers (`/vendor/`) — real CVE
  aggregation by genuine technology vendor or open-source package
  ecosystem, filtering out news-source labels.
- Timeline Engine (`/timeline/`) — chronological feed of published
  intelligence.
- Intelligence Collections (`/collections/`) — keyword-matched topic
  groupings (Ransomware, AI Security, Supply Chain, Nation-State/APT,
  CISA KEV, Cloud/DevSecOps).
- Live Detection Feed (`/detections/live-feed.html`) — aggregates real
  per-article Sigma/KQL/Splunk/osquery/Suricata content.
- Threat actor index (`/threat/`) linking the existing profile pages with
  real recent-coverage cross-links.

### Added — Platform Maturity (Build/Observability/Docs/Security)
- **Build orchestrator** (`orchestrator/`) — a safe sequencing/manifest
  layer over the six generators already in production; does not replace
  or reschedule any of their existing workflows.
- **Generator SDK** (`orchestrator/generator-sdk.js`) — common
  metadata/inputs/outputs/dependency contract; `generate-intelligence-hub.js`
  is the reference native (`run()`) implementation.
- **Content graph facade** (`api/_lib/content-graph.js`) — unified
  `getEntity(type, id)` lookup across CVE/vendor/campaign/actor/collection,
  exposed as `api/v1/intel.js?action=entity`.
- **Observability** — freshness monitoring extended from 1-of-6 to 6-of-6
  generators, plus an internal health dashboard (`ops/health/`) surfacing
  a real Blogger-syndication publish-success trend from previously
  write-only run logs.
- **Auto-generated documentation** (`docs/`) — API reference, build-system
  reference, and data-schema reference, all regenerated from source rather
  than hand-maintained prose.
- **Security hardening** — fixed a bash pipeline exit-code bug that made
  the secret-scan step silently non-blocking regardless of findings (same
  bug class as the OAuth incident below); made it fail-blocking. Added
  `pip-audit` for the Python dependency surface (previously unchecked).
  Added `SECURITY.md`.

### Fixed
- Blogger syndication pipeline silently masking failures — CI reported
  green across 660+ failing runs because a piped Python exit code was
  never captured. Root-caused to an `invalid_grant` OAuth token rejection
  following a 429 rate-limit burst.
- External cron dispatcher now throttle-guards each workflow to prevent
  re-triggering the same rate-limit condition.

### Known Issue (surfaced, not yet fixed)
- The health dashboard's initial run shows the Blogger syndication
  pipeline at ~33% run-success over the last 30 runs, most recently
  publishing 0/12 posts on `HTTP 429 rate limited` — the same failure
  signature as the incident above, recurring. Flagged for follow-up
  investigation; see `ops/health/index.html`.
