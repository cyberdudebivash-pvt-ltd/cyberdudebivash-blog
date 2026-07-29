# ESPMP v1 — ENTERPRISE SOCIAL PREVIEW & METADATA PROGRAM
## Phase 1: Architecture Audit, Dependency Graph, Root-Cause Analysis

---

## What this is

This document is Phase 1 of a 13-phase production task ("Enterprise Social
Preview, SEO & Metadata Enhancement") whose objective is to make every
published Sentinel APEX intelligence report produce premium, consistent
social previews across LinkedIn, Facebook, X, WhatsApp, Telegram, Discord,
Slack, and Google Search, with Sentinel APEX as the single source of truth
(SSOT) for metadata and Blogger reduced to a publishing destination only.

Per the task's own Phase 1 instruction ("Document everything before
modifying code"), this audit was produced **before any implementation
code changed** — full sweep of the repository, every claim below checked
against the actual file and line, not inferred from prior session notes.
It covers spec deliverables 1–3 (architecture review, dependency graph,
root-cause analysis). Deliverable 4 (implementation plan) is the closing
section.

## The headline finding

**This repository runs two entirely separate, independently-scheduled
publishing pipelines that both originate from "threat intelligence" but
share almost no code and no metadata.** Pipeline A (this repo's own
Vercel-hosted site, `blog.cyberdudebivash.in`) has a reasonably complete
— if triplicated — metadata story. Pipeline B (Blogger,
`cyberbivash.blogspot.com`) computes a full SEO metadata set in Python and
then **drops almost all of it on the floor before the Blogger API call**.
Per this platform's own prior audits (`platform/capabilities.md`,
`platform/open-issues.md` Issue 6/7), Blogger syndication is the
higher-volume publishing path. That disconnect — not a missing feature on
the Vercel side — is the largest single cause of inconsistent social
previews, and is what the spec's "Blogger becomes ONLY the publishing
destination, Sentinel APEX is SSOT" requirement is actually asking to fix.

---

## Pipeline dependency graph

### Pipeline A — `blog.cyberdudebivash.in` (this repo, Vercel-deployed)

```
28 live sources ─┐
                  ├─▶ fetch-live-intel.js (every 30 min, sentinel-apex.yml)
                  │     → posts/*.html, index.html, rss.xml, sitemap.xml,
                  │       search-index.json, api/intel/**
                  │
Sentinel-APEX/reports/published/*.md ─▶ Sentinel-APEX/renderer/publish-report.js
                  │     (manual CLI, not scheduled)
                  │     → intelligence/*.html   [sitemap NOT updated — gap]
                  │
api/intel/cve/*.json ─▶ generate-cve-pages.js (every 6h, cve-pages.yml)
                  │     → cve/*.html, sitemap.xml (own appender)
                  │
(all of the above) ─▶ generate-intelligence-hub.js (every 6h, intelligence-hub.yml)
                  │     → vendor/, timeline/, collections/, threat/,
                  │       detections/live-feed.html
                  │
posts/*.html ─▶ generate-rss.js (every 6h + on push, generate-rss.yml)
                        → rss.xml (full rebuild — competes with fetch-live-intel.js's
                          incremental updateRSS())

api/og.js — Vercel serverless fn (satori+resvg), called at request time by
            posts/*.html and intelligence/*.html only (og:image URL baked
            in at generation time); NOT called by cve/*.html or the hub
            pages, which use the static /og-image.png instead.

seo-engine.js — client-side script, re-injects Article/BreadcrumbList/FAQ
                JSON-LD in-browser on top of whatever the server already
                rendered.
```

### Pipeline B — `cyberbivash.blogspot.com` (Blogger, independent domain)

```
content_discovery.py (RSS/API sources, incl. this repo's own rss.xml/live-intel.json)
   │
   ▼
authority_transformer.py ──▶ seo_optimizer.py
   │  _build_blogger_title()    _build_meta_title()      [dead — never used]
   │  _generate_svg_thumbnail() _build_meta_description() [dead — never reaches Blogger]
   │  _template_enhance() /     _build_og_tags()          [dead]
   │    LLM analyst prompt      _build_twitter_card()     [dead]
   │                            _build_json_ld() / FAQPage / HowTo / DefinedTermSet
   │                                                       [alive — embedded in body]
   ▼
_assemble_html()  →  content (HTML body string, incl. inline SVG hero + schema <script> blocks)
   │
   ▼
main.py: publisher.publish_post(title, content, labels)  ◀── only these 3 fields
   │
   ▼
blogger_publisher.py → POST /blogs/{id}/posts  { kind, title, content, labels }
   │
   ▼
Blogger renders via blogger-theme/*.xml (data:view.*/data:post.*/data:blog.* —
knows nothing about CVE IDs, CVSS, or any Sentinel-APEX-computed value)
   │
   ▼
social_amplifier.py posts blogger_title + blogger_url to X (plain text, no image)
```

Every field `seo_optimizer.py` computes for the meta description, OG tags,
Twitter Card, and page title is discarded between `AuthorityTransformer.transform()`
and the Blogger API call — confirmed by tracing `main.py:161-181` and
`blogger_publisher.py:119-138` directly; the POST payload literally contains
`kind`/`title`/`content`/`labels` and nothing else.

---

## Audit by concern

| # | Concern | Pipeline A | Pipeline B (Blogger) |
|---|---|---|---|
| 1 | Title generation | 3 independent implementations (`fetch-live-intel.js:2214`, `publish-report.js:68`, `generate-cve-pages.js:258` vs. `:261` even disagree with themselves on `<title>` vs. `og:title`) | `_build_blogger_title()` (used) vs. `_build_meta_title()` (computed, dead); theme adds a 3rd/4th suffix (`\| CyberBivash AI SOC` on `<title>`, none on `og:title`) |
| 2 | Summary / meta description | 3 independent algorithms, different truncation lengths (130/155/200/140) | `_build_meta_description()` computed, never sent — Blogger's own auto-derived snippet is what ships |
| 3 | Hero image / thumbnail | `api/og.js` (satori+resvg, dynamic) used by 2 of 4 generators; static `/og-image.png` for the other 2 | Separate hand-rolled SVG (`_generate_svg_thumbnail()`), embedded in-body only, never as `og:image` |
| 4 | HTML generation | 3 different converters (`marked`-based canonical renderer; hand-rolled `mdToSafeHtml()`; template-string assembly with no Markdown at all) | LLM or template HTML assembled directly, no Markdown step |
| 5 | Meta tags (OG/Twitter/canonical) | Present and complete on `posts/`, `intelligence/`; canonical-only + no `twitter:image` on `intelligence/index.html`; **zero Twitter tags** on `cve/*.html` | Entirely theme-derived; `data:view.*` fields only |
| 6 | Structured data / JSON-LD | Server-rendered `Article`/`BreadcrumbList`/`CollectionPage`, **plus** a second, less-accurate client-side copy injected by `seo-engine.js` on top | Up to 9-10 co-existing JSON-LD blocks per post (theme ×4 + Python ×5-6), disagreeing publisher names across blocks |
| 7 | Canonical URL / slug | 2 independently re-typed `slugify()` implementations (`fetch-live-intel.js:217`, `publish-report.js:53`) | None — Blogger assigns the URL server-side; Python only reads it back |
| 8 | Sitemap | 2 independent appenders (`fetch-live-intel.js`, `generate-cve-pages.js`); **`intelligence/*.html` reports are added by neither** | N/A — Blogger has its own URL space |
| 9 | RSS | 2 independently-scheduled generators writing the same file (`fetch-live-intel.js` incremental every 30 min vs. `generate-rss.js` full rebuild every 6h) | N/A — Blogger's native feed is separate and unrelated |
| 10 | robots.txt | Healthy — `/intelligence/`, `/cve/`, `/posts/` etc. are not blocked (prior fix, `b1fd49d`, confirmed still correct) | N/A |
| 11 | Blogger publish call | — | `{ kind, title, content, labels }` only — no `searchDescription`, no image, no canonical, no keywords |

## Duplicate / parallel implementations found

Ten distinct duplication points, all confirmed by direct grep + line-level
inspection, not inferred:

1. **RSS** — `fetch-live-intel.js:updateRSS()` vs. `generate-rss.js`, both scheduled, both write `rss.xml`.
2. **Sitemap** — `fetch-live-intel.js:updateSitemap()` vs. `generate-cve-pages.js:appendSitemapEntries()`; `intelligence/` reports reach neither.
3. **Search index** — `fetch-live-intel.js:updateSearchIndex()` (live, wired into the 30-min cron) vs. standalone `generate-search-index.py` (orphaned — not referenced in any workflow).
4. **Markdown/HTML rendering** — canonical `Sentinel-APEX/renderer/report-renderer.js` (`marked`-based) vs. `generate-cve-pages.js:mdToSafeHtml()` (hand-rolled); the former's own docstring names the latter as the reason it was built, yet the latter was patched in place for the same bug class instead of migrated.
5. **`slugify()`** — near-identically re-typed in `fetch-live-intel.js:217-219` and `Sentinel-APEX/renderer/publish-report.js:53-56`.
6. **Title building** — at least 4 independent "title + brand suffix" implementations, 4 different suffix strings.
7. **Meta-description building** — 4 independent implementations, one (`seo_optimizer.py`) fully disconnected from output.
8. **Hero/OG image** — 3 unrelated systems (satori/resvg, hand-rolled Python SVG, one static PNG), used inconsistently even within Pipeline A.
9. **JSON-LD** — up to 9-10 co-existing blocks on a single Blogger post; client-side duplication on Pipeline A too.
10. **Dead code** — `seo_optimizer.py`'s `og_tags`/`twitter_card`/`meta_title`/`meta_description`/`keywords` are computed every run and never consumed (confirmed: zero references outside their own definitions and the unread `transform()` return dict).

## Root-cause analysis — why social previews are currently poor (Deliverable 3)

Ranked by estimated impact, using this platform's own prior finding that
Blogger syndication is the higher-volume path (`platform/capabilities.md`)
and that the hand-authored intelligence reports are "the core
differentiated content asset" (`platform/open-issues.md` Issue 5):

1. **Blogger — the dominant publishing channel — has no connection to any
   of Sentinel APEX's computed metadata.** A real, complete SEO payload
   (`seo_optimizer.py`: title/description/OG/Twitter/keywords) is computed
   on every single run and none of it reaches the Blogger API call. Part
   of this is a wiring gap (the hero image — `publish_post()` never used
   the real, writable `images` field the Blogger API actually offers) and
   part of it is a platform limitation (there is no meta-description/OG/
   Twitter-Card field on the Blogger v3 Post resource at all — confirmed
   against the live API discovery schema, not assumed). This is the
   spec's own framing turned into a measurable defect: Blogger is not
   currently "just a publishing destination" reflecting Sentinel-APEX
   metadata — it's rendering an entirely disconnected, theme-default
   preview for every post, and the image portion of that is now fixed.
2. **The flagship content type has a broken preview on its own index
   page.** `intelligence/index.html` — the hub for the hand-authored
   reports this platform's own documentation calls its most
   differentiated asset — has no `og:image` and no `twitter:image` at
   all (confirmed directly, not just via the audit agent). Sharing the
   index itself produces a blank or platform-default card.
3. **The highest-volume auto-generated page type has no Twitter Card at
   all.** `cve/*.html` (confirmed directly: lines 253-298 contain full
   OG tags but zero `twitter:` tags) — every CVE page shared on X/
   Slack/Discord (all of which honor Twitter Card meta as a fallback)
   gets a bare-link unfurl instead of a rich card.
4. **Two of four Pipeline-A generators never call the dynamic hero-image
   engine**, so `cve/*.html` and the hub pages show the same static,
   generic `/og-image.png` regardless of CVE, severity, or actor —
   exactly the "no missing thumbnails... always display enterprise
   banner" bar the spec sets, currently missed for a large fraction of
   published pages.
5. **Structured-data sprawl risks rich-results eligibility.** Multiple
   disagreeing JSON-LD blocks describing the same entity (different
   `datePublished`, different publisher name) on one page is a known
   trigger for Google Rich Results validator warnings, independent of
   any single block being individually well-formed.
6. **No canonical brand voice across surfaces** — four different
   title-suffix conventions and four different description algorithms
   mean the same underlying report reads differently depending on which
   generator happened to produce the page being shared.

---

## Implementation plan (Deliverable 4)

Consistent with this repository's own established pattern across 130+
prior tracked tasks — and with `CLAUDE.md`'s Architecture Preservation
Rule ("architectural modifications require substantially stronger
evidence than feature additions... when in doubt, add, don't replace")
— this is staged. Full completion of all 13 spec phases (in particular,
rewriting five `blogger-theme/*.xml` templates that render every existing
live post, and de-duplicating RSS/sitemap/search-index generation) is a
multi-sprint effort, not a single-session rewrite; attempting it in one
pass would violate both Minimal Change Surface and Production Stability
First. This sprint (ESPMP v1) scopes to the additive, low-blast-radius,
independently-testable subset that directly closes the root causes above.

**This sprint (ESPMP v1):**

| Item | Addresses root cause # | Risk |
|---|---|---|
| Canonical `metadata-engine.js` (Phase 2 SSOT module) — extracted/generalized from the best of the existing 3-4 implementations, not invented from scratch | 6 | LOW — new file, no existing caller changed yet |
| `intelligence/index.html` — add missing `og:image`/`twitter:image` | 2 | LOW — additive tags only |
| `generate-cve-pages.js` — add missing Twitter Card tags | 3 | LOW — additive tags only |
| `generate-intelligence-hub.js` — wire to `api/og.js` instead of static image | 4 | LOW — same pattern already proven live on 2 other generators |
| `authority_transformer.py` + `blogger_publisher.py` + `main.py` — send the dynamic `api/og.js` card URL via the Blogger Post resource's real `images` field | 1, 3 | LOW — one new field on an existing live POST body, additive, backward compatible (omitting `image_url` reproduces today's exact payload) |

**Correction made before this plan was implemented, not after**: the first
draft of this row proposed sending `seo_optimizer.py`'s computed
`meta_description` as a `searchDescription` field on the Blogger API call.
Checked against the real schema (`blogger.googleapis.com/$discovery/rest?version=v3`)
before writing any code — **no such field exists on the Blogger v3 Post
resource**. The full field list is: `id, trashed, replies, title, status,
customMetaData (deprecated), readerComments, author, content, published,
location, updated, blog, titleLink, labels, selfLink, kind, images, etag,
url`. There is no meta-description, OG-tag, or Twitter-Card equivalent
anywhere on the resource — that gap is a platform limitation, not a wiring
bug, and is not fixable via this API. `images` (shape `[{url: string}]`,
confirmed not `readOnly` and not excluded from `posts.insert`) is the one
real, writable field relevant to this program, so the shipped fix uses it
for the hero image instead. `seo_optimizer.py`'s `meta_title`/
`meta_description`/`og_tags`/`twitter_card`/`keywords` remain computed but
unreachable from Blogger — left in place (not deleted) with a comment
explaining why, for a future non-Blogger publishing target.

**Explicitly staged for a future sprint, not attempted now (evidence-based,
not deferred by default):**

- Rewriting `blogger-theme/*.xml` to read Sentinel-APEX-computed OG/Twitter
  values directly — the theme renders every historical post today; a
  change here has the largest blast radius in this entire audit and needs
  its own dedicated evidence table and a rollback plan tested against a
  preview theme, not a same-sprint edit.
- De-duplicating RSS (`fetch-live-intel.js` vs. `generate-rss.js`) and
  sitemap (`fetch-live-intel.js` vs. `generate-cve-pages.js`) generation —
  both are live, scheduled, revenue-adjacent (SEO) infrastructure; picking
  a canonical implementation is a decision, not a refactor, matching how
  this repo already handled the Scoring/Graph canonical-ownership question
  (`platform/open-issues.md` Issue 1).
- Consolidating the 9-10-block JSON-LD sprawl on Blogger posts — requires
  deciding which schema blocks are authoritative, which is a content/SEO
  strategy call, not an engineering default.
- Migrating `cve/*.html` off `mdToSafeHtml()` onto the canonical
  `report-renderer.js` — flagged, not new: `platform/open-issues.md` Issue
  5 already tracks this exact migration as unresolved.
- Full preview-validation automation (spec Phase 10) and QA gate (Phase
  12) — depend on the metadata engine and consumer migrations above
  existing first; premature before this sprint's foundations land.

---
*CyberDudeBivash® Sentinel APEX — Enterprise Social Preview & Metadata Program, Phase 1 Audit*
