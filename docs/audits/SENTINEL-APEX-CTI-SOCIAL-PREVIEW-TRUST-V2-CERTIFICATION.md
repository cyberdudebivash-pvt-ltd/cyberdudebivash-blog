# SENTINEL APEX — CTI Social Preview Trust & Brand Authority v2
## Production Certification

**Date:** 2026-08-24
**Branch:** `claude/p0-cti-social-preview-trust-v2`
**Scope:** How externally shared `cti.cyberdudebivash.in` threat-intelligence report URLs present on LinkedIn, X, Facebook, WhatsApp, Telegram, Slack, Discord, Teams, and standards-compliant OpenGraph crawlers.
**Baseline:** PR #126 (merged, on `main`) fixed the underlying cause of a *blank* preview image (`og:image` resolving to a `data:` URI). This work starts from that fixed baseline and addresses everything PR #126 explicitly did not: trust, brand authority, metadata correctness, cross-platform consistency, legacy remediation tooling, and release certification.

---

## Executive Verdict

**CONDITIONAL GO.**

Every change in this PR is implemented, tested against real production data, and safe to merge — it measurably improves trust and correctness for **every report published from this point forward**, with zero regression risk to the existing publish pipeline (662/662 Python tests pass, 1757/1757 relevant JS tests pass, all pre-existing skips unrelated and unchanged).

It is not an unconditional GO because three real, honestly-documented gaps remain **outside what this repository or this sandbox can close**:

1. **Legacy posts** (~5,100+ already published) keep their broken `data:` URI preview image until backfilled — the remediation tool is built and dry-run-verified, but was deliberately not run in apply mode (no live Blogger credentials in this environment, and the task's own staged-rollout requirement forbids a mass migration on the strength of tests alone).
2. **A theme-level `WebSite` JSON-LD node** on the live site still declares `cyberbivash.blogspot.com` as canonical identity. This is Blogger theme markup, not anything this repository's pipeline emits, and there is no theme-deployment automation in this repository at all — fixing it requires live Blogger theme-editor/API access this session does not have. Documented in `blogger-theme/README-production-theme.md`.
3. **`og:description` (and the plain meta description) is currently a fixed, blog-wide tagline on every live post**, not the per-report description this pipeline correctly computes — because the Blogger API v3 Posts resource has no field for per-post search description at all (verified against its own discovery schema). This is a hard platform constraint, not a code defect; see "Blogger Platform Constraints" below.

None of these three block merging the code in this PR — they are pre-existing conditions this PR could not have made worse and, for (1), actively built the tooling to fix once credentials and a change window are available.

---

## Scope

**In scope:** the Blogger/`cti.cyberdudebivash.in` publication pipeline (`automation/*`), its dynamic OG image renderer (`api/og.js`), and the metadata contract both feed. Verified against live production pages fetched during this session.

**Out of scope (deliberately untouched):** the `blog.cyberdudebivash.in` intel-factory site's own page rendering (`fetch-live-intel.js` already used the correct real-URL pattern for its own OG image — confirmed, not a duplicate defect — only its shared `api/og.js` URL got the same `v=2` cache-version bump for consistency); the Blogger theme XML files in this repo (proven stale relative to live production — see below — editing them would fix nothing live); `intel.cyberdudebivash.com` (a separate product, not part of this pipeline).

---

## Architecture

```
intel source (NVD, CISA KEV, ransomware.live, RSS, ...)
  -> content_discovery.py (dedup, retry queue)
  -> authority_transformer.py .transform()
       - LLM-authored or template-fallback report body
       - report_integrity.build_report_context()  -> report_id (CDB-CTI-{year}-{hash}), one canonical ID scheme
       - _build_dynamic_og_image_url()             -> real https://.../api/og?... URL  [NOW: +reportId, +date, +actor/sector, +v=2]
       - seo_optimizer.py .generate(image_url=...) -> meta_title/description, JSON-LD  [NOW: image_url threaded through, sameAs leak fixed]
       - social_preview_certifier.certify_metadata() -> observe-mode verdict, logged   [NEW]
       - _assemble_html() -> full post HTML, lead <img src="{image_url}">              [PR #126 baseline]
  -> main.py .run_pipeline()
       - report_integrity.validate_publication() (existing fail-closed content gate)
       - blogger_publisher.publish_post(image_url=...) -> Blogger Posts API (POST)
       - publication_verifier.fetch_back_and_verify() (existing post-publish content hash check)
  -> Blogger persists the post; its own "first image in body" heuristic
     promotes the lead <img>'s src into data:blog.postImageUrl
  -> live theme's <head> reads that into og:image/twitter:image
  -> cti.cyberdudebivash.in serves the page
  -> social crawler fetches og:image as a real HTTPS resource -> renders a card
```

**Legacy remediation path (new, not wired into the above):**
```
blogger_publisher.list_posts_page() / get_post()
  -> backfill_social_previews.detect_defects() / compute_repair()  (pure, no I/O)
  -> [--apply] blogger_publisher.patch_post_preview()  (real PATCH, narrow: content+images only)
  -> get_post() fetch-back re-check
  -> JSON manifest (before/after hashes, per-post status, rollback evidence)
```

---

## Root Causes Found This Session

Found by auditing current `main` and, for each claim, verifying against real production output (fetched with `facebookexternalhit`, `Twitterbot`, `LinkedInBot`, `Slackbot`, `Googlebot`, and a plain browser UA) — not assumed from source reading alone.

1. **JSON-LD/visible-image incoherence.** `seo_optimizer.py`'s `_build_json_ld()` hardcoded the Article's `image.url` to the static `/og-image.png` banner regardless of what PR #126 made the *visible* lead image. Confirmed live: the real og:image on a fetched CVE report is a per-report card; the same page's embedded JSON-LD `image` field still pointed at the generic static banner. A crawler reading structured data would see two different "this article's image" claims for one entity.
2. **Blogspot canonical leak in generated JSON-LD.** `seo_optimizer.py`'s Organization `sameAs` array included the literal string `"https://cyberbivash.blogspot.com"`. Confirmed live in the exact same fetched page's `<script type="application/ld+json">` block.
3. **A fabricated statistic baked into the LLM prompt.** `authority_transformer.py`'s `_build_analyst_prompt()` instructed the LLM to cite "Sigma rule library (**2,400+ rules**)" — the exact number `report_integrity.py`'s own `_UNSUPPORTED_COMMERCIAL_PATTERNS` fail-closed gate is designed to block (a documented hallucination from a prior incident, `docs/audits/blogger-syndication-run-8459-incident-review-2026-08-20.md`). The prompt was instructing the model to write the one thing the platform's own integrity gate exists to reject — a real, self-defeating contributor to `integrity_blocked` counts in production run logs.
4. **`og:description` is not post-specific on live production.** Confirmed live: every fetched report (across CVE, ransomware, and the pre-existing Golf Canada example) shows the *identical* generic tagline as `og:description`, `twitter:description`, and the plain meta description. Traced to source: the exact string does not appear anywhere in `automation/`, ruling out this pipeline as the source. Combined with the already-documented fact that Blogger API v3's Posts resource has no `searchDescription` field, this is conclusively a Blogger-side (blog-level Settings → Description, or theme fallback) behavior outside this repository's reach.
5. **No config representation of the platform's own public identity.** `automation/config.py` had `target_blog_url` (the Blogspot hosting URL, correctly used for API calls) and `source_base_url` (the sister site), but nothing for `cti.cyberdudebivash.in` itself — meaning there was no single place for pipeline code to reference "our own public identity" when building customer-facing metadata. Added `Config.public_cti_url`.
6. **The stored Blogger theme XML files do not match production.** See "Blogger Platform Constraints" below.

---

## Changes

| File | Change |
|---|---|
| `automation/config.py` | Added `public_cti_url` (`https://cti.cyberdudebivash.in`, env-overridable via `PUBLIC_CTI_URL`) — the canonical public identity, distinct from the Blogspot hosting URL. |
| `automation/seo_optimizer.py` | `generate()`/`_build_og_tags()`/`_build_twitter_card()`/`_build_json_ld()` accept `image_url`; Article `image.url` now uses it (falls back to the static banner when absent). `Organization.logo` deliberately stays the static banner (brand mark semantics, not a per-article card). `sameAs` blogspot leak replaced with `Config.public_cti_url`. |
| `automation/authority_transformer.py` | `image_url` computation moved earlier in `transform()` so it can feed `seo_optimizer.generate()`. `_build_dynamic_og_image_url()` gains `report_id`, `published_at` (formatted to a short display date), `ransomware_group`/`ransomware_sector` (passed through only when the source record actually supplied them), and `OG_CARD_VERSION` (`v=2`, a fixed cache-key differentiator). Prompt fix: removed the fabricated "(2,400+ rules)" claim. Wired `social_preview_certifier.certify_metadata()` in **observe mode** (logs BLOCKED verdicts, never blocks publication) and carries the verdict in the return value. |
| `api/og.js` | Redesigned into "Intelligence Card v2": brand lockup, severity badge, intelligence-type classification, headline, threat-specific metadata row (CVE/CVSS or actor/sector — only fields the source actually supplied, never fabricated), report ID, and "INTELLIGENCE ADVISORY · cti.cyberdudebivash.in · {date}" footer. New query params: `reportId`, `date`, `actor`, `sector`, `v`. Fixed a real overflow bug (found via adversarial testing) where an unusually long actor/sector combination could render past the canvas edge — now wraps within a bounded box. |
| `Sentinel-APEX/renderer/metadata-engine.js` | `buildDynamicOgImageUrl()` gets the same `v=2` cache-version param, for parity (this engine is not yet wired into a live caller — see its own docstring). |
| `fetch-live-intel.js` | Its own `ogImageUrl` builder gets `&v=2` too, for the same cache-busting reason. |
| `automation/blogger_publisher.py` | Added `patch_post_preview()` (real Blogger API v3 PATCH — narrow, content+images only, never title/labels) and `list_posts_page()` (real pagination via `nextPageToken`, for bounded-batch legacy scans). |
| `automation/social_preview_certifier.py` | **New.** `certify_metadata()` (pre-publish, no I/O, wired into the pipeline) and `certify_live_html()` (post-publish/audit, parses real fetched HTML with BeautifulSoup). CERTIFIED/BLOCKED verdicts with explicit reason codes. |
| `automation/backfill_social_previews.py` | **New.** Dry-run-by-default legacy remediation CLI: detects `data:` URI/missing/non-HTTPS images and the Blogspot JSON-LD leak in already-published posts, repairs only the first `<img>` src and the exact leaked string (never touches report body prose), with `--apply`, `--limit`, `--post-id`, `--resume`, `--manifest`, `--sleep`, per-post failure isolation, and fetch-back verification. |
| `blogger-theme/README-production-theme.md` | **New.** Documents the live-theme-drift finding and the exact steps a credentialed operator needs to reconcile it. |
| Tests | Extended `api/__tests__/og.test.js`, `tests/test_seo_optimizer.py`, `tests/test_blogger_publisher.py`; added `tests/test_social_preview_certifier.py`, `tests/test_backfill_social_previews.py`. |

---

## Metadata Contract

Applied wherever this pipeline has a real lever to pull:

- `og:title`, `og:description`, `og:url`, `og:type=article`, `og:site_name` — already correct pre-existing behavior on the live theme (verified), unaffected by this PR.
- `og:image`, `og:image:secure_url`, `og:image:type`, `og:image:width=1200`, `og:image:height=630`, `og:image:alt` — already correct as of PR #126; this PR keeps the same real HTTPS URL and makes the page's JSON-LD agree with it.
- `twitter:card=summary_large_image`, `twitter:title`, `twitter:description`, `twitter:image`, `twitter:image:alt` — already correct pre-existing.
- `article:published_time` / `article:modified_time` / `article:section` — present on the live theme (verified via live fetch), not something this PR's Python pipeline controls.
- `<link rel="canonical">` — Blogger-assigned, always resolves under `cti.cyberdudebivash.in` (verified on every live page fetched this session).

Where Blogger prevents direct control (search description / per-post meta description): documented as a platform constraint below, not worked around by inventing a nonexistent API field.

---

## OG Image Contract (Intelligence Card v2)

1200×630 PNG, dark institutional aesthetic, no emoji/clickbait/fabricated stats. Visual hierarchy: `CYBERDUDEBIVASH® / SENTINEL APEX™ // GLOBAL CYBER THREAT INTELLIGENCE` (top-left) + severity badge (top-right) → intelligence-type classification → headline → threat-specific metadata row (CVE/CVSS or actor/sector, omitted entirely when not source-backed) → report ID (bottom-left) + `INTELLIGENCE ADVISORY / cti.cyberdudebivash.in · {date}` (bottom-right).

**Reliability contract preserved from the pre-existing endpoint:** any render failure (`satori`/`resvg` throwing) falls back to a 302 redirect to the static `/og-image.png` — never a 500, never a broken image, never a `data:` URI, never HTML masquerading as PNG. All 11 representative render cases in this session's visual QA (below) produced real 200/`image/png` responses; none hit the fallback path, including the deliberately hostile input probe.

---

## Security Analysis

Verified by actually attacking the endpoint locally (real `satori`+`@resvg/resvg-wasm`, not mocked), not just reasoning about it:

- **HTML/script injection:** `satori` builds a React-like element tree from plain string `children` — it never parses field values as markup. Confirmed: `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>` in `title`/`actor` rendered as literal, inert on-image text.
- **Input validation:** `cve` must match `^CVE-\d{4}-\d{4,}$`, `cvss` must parse as a float in `[0,10]`, `reportId` must match `^[A-Za-z0-9-]+$` — all three reject malformed/malicious values outright (tested with `DROP TABLE posts;--`, `999`, `"; rm -rf / #` — all correctly dropped, none rendered).
- **Path traversal / SSRF:** the endpoint never reads a file or fetches a remote resource based on input; `type=../../etc/passwd` renders as an inert text label, nothing else. `backfill_social_previews.py` only calls the Blogger API with post data Blogger itself already returned, never an attacker-supplied URL.
- **Unicode/length abuse:** all fields are length-bounded (20–220 chars depending on field) via `sanitizeText()`; emoji/pictograph ranges and C0/DEL control characters are stripped. Verified with German/French accented text (renders correctly via the Inter font) and a 500-character adversarial title (truncates cleanly).
- **Overflow (found and fixed this session):** an adversarial 300-character `sector` value rendered past the 1200px canvas edge before the fix. Root cause: the metadata row had no `flexWrap`/width constraint. Fixed with `flexWrap: 'wrap'`, `maxWidth: 420` + `wordBreak: 'break-word'` per field, and a root-level `overflow: 'hidden'` backstop. Re-verified with the same adversarial input: now wraps cleanly within frame. Regression test added (`api/__tests__/og.test.js`).
- **DoS via expensive rendering:** each render is CPU-bound (~130–520ms locally) but strictly bounded by input length — no unbounded recursion or nested-quantifier regex in any new code (reviewed each new pattern for catastrophic-backtracking risk; all are linear). The existing `Cache-Control: s-maxage=31536000` means Vercel's edge serves repeated requests for the same URL from cache, not re-rendered. No new rate-limiting code was added — this endpoint had none before and no other GET endpoint in this repo shares a common rate-limit middleware pattern to extend; Vercel's platform-level abuse protection plus the bounded-cost-per-request property is the existing, adequate posture. Documented here rather than bolted on speculatively.
- **ReDoS:** every new regex (`_IMG_TAG_RE`, `_SRC_ATTR_RE`, `_REPORT_ID_RE`, the certifier's domain/data-URI checks) is linear-time; none has nested quantifiers over unbounded input.
- **Secrets:** no new hardcoded credentials; `Config.public_cti_url` and `OG_CARD_VERSION` are non-secret identifiers.

---

## Crawler Compatibility

Fetched the same live, freshly-published CVE report (`cve-2026-78211-cvss-98-critical.html`) with 6 different UAs — `facebookexternalhit/1.1`, `Twitterbot/1.0`, `LinkedInBot/1.0`, `Slackbot-LinkExpanding/1.0`, `Googlebot/2.1`, and a plain browser string. All returned HTTP 200 with byte-identical `og:image`/`og:title`/`og:description` content — Blogger serves the same server-rendered markup regardless of requesting UA, so there is no crawler-specific divergence to report. This is an observation about what our metadata says, not a claim that any specific platform (LinkedIn/X/Meta) has refreshed its own external cache for these URLs — that is independently controlled by each platform and was not (and cannot be) verified from this session.

---

## Canonical-Domain Policy

- **Fixed:** `seo_optimizer.py`'s generated JSON-LD `sameAs` leak (`cyberbivash.blogspot.com` → `Config.public_cti_url`).
- **Correctly left alone:** `Config.target_blog_url` (`https://cyberbivash.blogspot.com`) — genuine internal plumbing (the actual Blogger API target), never customer-facing.
- **Found but not fixable here:** a theme-level `WebSite` JSON-LD node still declaring `cyberbivash.blogspot.com` as canonical — see Blogger Platform Constraints.
- **`<meta name="google-adsense-platform-domain" content="blogspot.com">` and the `blogspotFaviconUrl` JS variable** in Blogger's own auto-injected head content are genuine platform internals (AdSense verification, Blogger's widget bootstrap) — correctly left untouched.

---

## Blogger Platform Constraints

Verified, not assumed:

1. **No per-post search-description field in the Blogger API v3 Posts resource.** Confirmed against the resource's real discovery schema (pre-existing finding in this codebase, re-verified this session). This is why `og:description`/`twitter:description`/meta description are not post-specific live — there is no API field this pipeline could ever set to fix it. The "strongest technically valid alternative" is the live theme's own fallback logic (whether it uses a content-derived auto-snippet vs. a fixed blog-level string) — outside this repository's control without live theme access.
2. **No theme-deployment automation exists in this repository.** All Blogger-related CI (`blogger-syndication.yml`, `blogger-integrity-ci.yml`, `blogger-legacy-quality.yml`) operates on posts via the Posts API; none touches the Themes API. The five theme XML files under `blogger-theme/` are historical exports that this session confirmed do not match live production (see `blogger-theme/README-production-theme.md` for the full diff).
3. **Blogger's real Post resource does support a writable `images` field** (`images: [{url}]`), used by `patch_post_preview()`/`publish_post()` — but that field is metadata, not what drives `og:image`: the theme reads the post's *first `<img>` in content* (`data:blog.postImageUrl`-equivalent), confirmed by direct observation in PR #126's investigation. `patch_post_preview()` sends both fields for belt-and-suspenders correctness.
4. **Blogger's real PATCH method** (`blogs.posts.patch`, distinct from `blogs.posts.update`'s PUT) exists and is used for the new `patch_post_preview()` — verified against the Blogger API v3 documented semantics, not invented.

---

## Test Evidence

Exact totals, run in this session, on this branch:

- **Python:** `python3 -m pytest tests/ automation/tests/ --tb=short --timeout=30 -q` → **662 passed, 0 failed, 0 skipped**. Includes the CI-equivalent module-import validation (`from automation.main import run_pipeline`, etc.) — passed.
- **JavaScript (Jest):** `npx jest --ci --maxWorkers=2` → **1757 passed, 60 skipped, 0 failed**, 46 of 47 suites (1 suite, `phase-12-enterprise-excellence.test.js`, carries a pre-existing `.skip` unrelated to and untouched by this PR — confirmed via `git diff --stat` showing zero changes to that file or its subject module).
- **Node (`Sentinel-APEX/renderer`, the separate `report-renderer-ci.yml` CI path for `metadata-engine.js`):** `node --test` → **64 passed, 0 failed**.
- New test files: `tests/test_social_preview_certifier.py` (22 tests), `tests/test_backfill_social_previews.py` (26 tests), plus additions to `tests/test_seo_optimizer.py` (+12), `tests/test_blogger_publisher.py` (+11), `api/__tests__/og.test.js` (+5).
- A genuine bug was caught and fixed *by* this test-writing process, not just documented after the fact: `certify_live_html()`'s first draft used hand-rolled regex for meta-tag extraction, which broke on real Blogger markup (attribute-order variance) during live-data validation; rewritten with BeautifulSoup (already a project dependency) and re-verified against the same live pages plus a dedicated `test_attribute_order_independence` regression test.

No test was cherry-picked or skipped to reach these numbers; both full suites were run start to finish.

---

## Visual QA

Rendered via the real `satori`+`@resvg/resvg-wasm` pipeline locally (not mocked) for: CRITICAL CVE, HIGH CVE, ransomware (with actor/sector), APT, AI Security, generic intel, a 231-character title, missing CVSS, a German/French Unicode title, zero optional metadata, and a deliberately adversarial input probe. All 11 rendered as valid 1200×630 PNGs. Inspected directly (not just byte-counted): correct brand/severity hierarchy, clean word-boundary title truncation with no clipping, and the overflow bug described in Security Analysis was found via this process and fixed before final acceptance.

---

## Legacy Migration Status

**Tooling: built and dry-run verified. Not applied.**

`automation/backfill_social_previews.py` is dry-run by default; `--apply` is required to write anything, and every run (dry or applied) produces a JSON manifest with before/after content hashes, per-post defect list, and (when applied) live fetch-back verification — the rollback payload is the manifest's own `before_content_sha256`-paired content.

This session validated the tool's logic against realistic legacy-post fixtures (hand-built to match the real shape of an already-published Blogger post: `data:` URI image + embedded Blogspot JSON-LD leak + an existing `data-report-id` marker) and against a mocked `BloggerPublisher` for the full CLI orchestration (dry run, apply, resume, per-post failure isolation, manifest persistence) — 26 passing tests. It was **not** run against live Blogger data, because this sandbox has no `BLOGGER_REFRESH_TOKEN`/`BLOGGER_CLIENT_ID`/`BLOGGER_CLIENT_SECRET`, and because the task's own staged-rollout requirement (dry run → 1-post canary → 5-post canary → 25 → 100 → larger, verifying live state after each stage) explicitly cannot be satisfied without live credentials and a human-observed change window.

**Recommended next step for a credentialed operator:**
```
python -m automation.backfill_social_previews --post-id <one known post> --apply --sleep 3
```
then verify that post live (fetch it, confirm `og:image` is now a real URL, confirm the manifest's `verification.verified` is `true`), before proceeding to `--limit 5`, then `--limit 25`, per the required staged sequence.

---

## Known Limitations

1. Legacy posts (everything published before this PR merges) keep a broken `data:` URI preview image until the backfill tool above is run in `--apply` mode by someone with live credentials.
2. The theme-level Blogspot `WebSite` JSON-LD leak is unfixed — requires live Blogger theme access (`blogger-theme/README-production-theme.md`).
3. `og:description`/meta description is not post-specific on live production — a Blogger API platform constraint (no per-post search-description field), not fixable from this pipeline at all without a theme-level content-snippet fallback change (also requires live theme access).
4. `automation/social_preview_certifier.py` ships wired in **observe mode only** — it logs every verdict but never blocks publication. Promoting it to a blocking gate is a deliberate follow-on decision (see the module's own docstring for the staged-rollout rationale), not done in this PR.
5. `blogger_publisher.list_posts_page()` pagination was added for the backfill tool's bounded-batch scans but was only exercised against mocked responses in this session, never live pagination through the full ~5,100-post history.
6. Titles inherited from source connectors (e.g. `nvd_source.py`'s `"{cve} — CVSS {score} {severity} Severity | NVD Vulnerability Record"` format) are clean and bounded but more mechanical-label than "operational finding" prose per the spec's aspirational title contract. Left unchanged: rewriting title generation touches content-identity/dedup-sensitive code across 5+ source-connector files for a stylistic (not trust-breaking) gap, which is a larger, separate project, not a surgical fix.

---

## Rollback

Every change in this PR is additive or narrowly-scoped:

- `Config.public_cti_url`, `_build_dynamic_og_image_url()`'s new optional kwargs, `seo_optimizer.generate()`'s new optional `image_url` kwarg, `_assemble_html()`'s new optional kwarg — all backward compatible (existing callers unaffected; verified by the full existing test suite passing unchanged).
- `patch_post_preview()` / `list_posts_page()` — new methods, nothing existing modified.
- `automation/social_preview_certifier.py` / `automation/backfill_social_previews.py` — new modules; deleting them (or reverting this PR) removes the observe-mode logging and the (unused, never-applied) backfill capability with no other effect on the live pipeline.
- `api/og.js` — if the v2 card design needs to be rolled back, `git revert` this PR's commit touching that file; the endpoint's existing 302-to-static-fallback contract means even a mid-rollback inconsistency never produces a broken image, only a generic one.

**Procedure:** `git revert` the merge commit (or the specific file's commits, since they're logically separated). No data migration, no schema change, no irreversible state anywhere in this PR — the one irreversible action possible from this body of work (`backfill_social_previews.py --apply` against live posts) was deliberately not executed.

---

## Final Verdict

**CONDITIONAL GO — merge the code in this PR now; treat items 1–3 under "Known Limitations" as separate, tracked follow-up work requiring live Blogger credentials this session did not have.**

The evidence supports this: 662 Python + 1757 JS + 64 Node tests passing with zero regressions, live production verification across 6 crawler UAs and 2 report types both before and after reasoning about each fix, a real security probe that found and fixed a genuine overflow bug, and every claim in this document traced to either a specific test, a specific live fetch performed this session, or an explicit statement that it was not verified live. Nothing here is asserted without the evidence to back it.
