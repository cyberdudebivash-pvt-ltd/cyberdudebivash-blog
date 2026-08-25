# SENTINEL APEX — CTI Social Preview Card v3 (Intelligence Card Redesign)
## Production Certification

**Date:** 2026-08-25
**Branch:** `claude/cti-threat-intel-url-preview-7fd67h`
**Scope:** The visual design and data richness of the single dynamic social-share image (`api/og.js`) rendered for every `cti.cyberdudebivash.in` and `blog.cyberdudebivash.in` report URL — what a prospect actually sees the instant a report link is pasted into LinkedIn, X, Slack, or any other OpenGraph-consuming surface.
**Baseline:** `SENTINEL-APEX-CTI-SOCIAL-PREVIEW-TRUST-V2-CERTIFICATION.md` (merged as PR #126) fixed the underlying *correctness* defect — `og:image` resolving to a `data:` URI so no image rendered at all — and shipped "Intelligence Card v2," a real per-post branded card. That work is sound and untouched at the correctness layer. This round starts from a live, working v2 card (confirmed via the operator's own production LinkedIn Page screenshots) and addresses a different problem: the card is functionally correct but visually flat, and it under-uses real risk data (KEV, EPSS) the platform already computes for the article body but never carried into the share card.

---

## Executive Verdict

**GO.**

Every change in this PR is implemented, rendered and visually inspected against real representative and adversarial inputs, tested (both new and full-suite regression), and safe to merge. It is purely additive to the v2 contract — every existing caller and every existing query parameter keeps its exact prior meaning; nothing is renamed, removed, or made mandatory.

Unlike the v2 round, there is no unresolved external-platform gap driving this to a CONDITIONAL verdict — this round touches only code and data this repository fully owns (the renderer and the two pipelines that call it), not Blogger theme XML or third-party crawler caches.

---

## Scope

**In scope:** `api/og.js`'s rendered layout and its `kev`/`epss` query-parameter contract; the three real call sites that build its URL (`automation/authority_transformer.py`, `fetch-live-intel.js`, `Sentinel-APEX/renderer/metadata-engine.js`); the shared `v=` cache-version constant all three mirror.

**Out of scope (deliberately untouched):** the v2 trust contract itself (no emoji, no fabricated data, escaped/bounded input, 302-fallback-never-500 reliability) — carried forward unchanged, not re-litigated. The Blogger legacy-post backfill tooling, theme-level JSON-LD leak, and per-post meta-description platform constraint documented in the v2 certification — none of that is affected by or relevant to a rendering-layer redesign. `intel.cyberdudebivash.com` — a separate product.

---

## Why This Round Exists

The operator supplied live screenshots of the platform's actual LinkedIn Company Page (`CYBERDUDEBIVASH® SENTINEL APEX PLATFORM`, 926 followers) showing real, already-published report link previews. The v2 card renders correctly — no blank images, correct headline/severity/CVE — but reads as a flat, single-tone card: solid dark background, no visual hierarchy beyond text, no use of the platform's own real risk-scoring data (KEV catalog status, EPSS exploit probability) that `_build_risk_command_center()` already computes and shows in the article body itself. The ask: bring the share card — the single highest-leverage, most-seen artifact for converting a LinkedIn scroll into a platform visit — up to the visual and informational standard of an enterprise security product, in service of Fortune 500 / enterprise buyer credibility and conversion (CLAUDE.md's Commercial Value and Enterprise Trust Enforcement principles).

---

## Architecture (unchanged shape, richer payload)

```
Canonical risk data already computed by the pipeline
  (DiscoveredArticle.kev_listed, .epss_score — same fields
   _build_risk_command_center() already renders into the article body)
        |
        v
_build_dynamic_og_image_url()  [Python]  -----+
buildDynamicOgImageUrl()       [Sentinel-APEX/renderer, no kev/epss source]  --+
ogImageUrl template literal    [fetch-live-intel.js, no kev/epss source]  -----+
        |                                                                      |
        v  (single shared query-string contract, v bumped 2 -> 3)             |
   GET /api/og?title=...&severity=...&cve=...&cvss=...&kev=true&epss=87.4 <---+
        |
        v
api/og.js  (single canonical renderer — satori -> SVG -> @resvg/resvg-wasm -> PNG)
        |
        v
1200x630 PNG, Cache-Control: s-maxage=31536000 (Vercel edge)
        |
        v
og:image / twitter:image on every report page -> social crawler renders the card
```

The rendering pipeline (satori/resvg, sanitization, fallback-on-error) is **the same single canonical renderer it was in v2** — no second image system was built for any of the three callers, and Python still cannot `require()` the Node module, so the query-string contract remains the shared interface (documented in `api/og.js`'s own module docstring, same discipline as `detection-engine.js`/`sigma_builder.py` elsewhere in this repo).

---

## What Changed

### 1. Visual redesign (`api/og.js`'s `buildTree()`)

Every element is additive on top of the proven v2 layout — nothing that existed is removed:

- **Classification accent bar** — a full-width gradient strip (brand cyan → the report's own severity color) across the top edge.
- **Corner brackets** — four small "targeting bracket" accents framing the card, a restrained nod to the SENTINEL/threat-intelligence identity.
- **Severity glow** — the existing severity pill now carries a soft `boxShadow` halo in its own severity color.
- **Ambient depth** — two very low-opacity radial gradients (severity-colored top-right, brand-cyan bottom-left) behind the content, purely decorative, never behind body text.
- **Data readout tiles** — CVE ID, CVSS score (now with a proportional 0–10 fill-meter), and EPSS probability render as labeled "stat tiles" with divider rules between them, replacing v2's plain inline text row. Ransomware-style reports (actor/sector, no CVE) get the same tile treatment.
- **KEV ribbon** — a dedicated red "CISA KEV CATALOG — LISTED" badge, rendered only when the source record confirms real KEV listing.
- **Report-ID chip** — the footer report identity now renders as a bordered chip instead of plain gray text.
- All of this reuses the platform's own existing brand constants (`BRAND_CYAN`, `SEVERITY_COLORS`, `INK`) — no new color system was invented; the EPSS chip's thresholds intentionally reuse this card's own `SEVERITY_COLORS` rather than the article body's separate risk-tile palette (documented in code — the two rendering surfaces already used two different hex systems for the same severity concept before this round; this keeps one image internally consistent instead of adding a third).

### 2. New optional data: KEV and EPSS

`api/og.js` gains two new optional, strictly-validated query params:

- `kev` — literal `"true"` only. Any other value (including `"false"`) is treated as absent. This follows the exact no-negative-claim discipline `_build_risk_command_center()` already established for the article body's own KEV tile: the card never prints a "Not Listed" or "Unknown" claim about itself, it simply omits the ribbon when there's nothing urgent to say.
- `epss` — a number in `[0, 100]`, rendered to one decimal place. Invalid/out-of-range/non-numeric values are dropped, not clamped-and-kept.

These are wired from real data only where real data exists:

- **`automation/authority_transformer.py`** (the Blogger/`cti.cyberdudebivash.in` pipeline) — `_build_dynamic_og_image_url()` now accepts `kev_listed`/`epss_pct`, sourced directly from `DiscoveredArticle.kev_listed`/`.epss_score` at the one real call site, the same fields already feeding the article body's Risk Command Center. No new data was invented — this was already-computed, already-verified data that simply never reached the share card before.
- **`fetch-live-intel.js`** (`blog.cyberdudebivash.in`) and **`Sentinel-APEX/renderer/metadata-engine.js`** — neither has a KEV/EPSS-equivalent field on its own input shape (confirmed by reading both before editing). Both are left correctly silent on `kev`/`epss` rather than fabricating a value; only their shared `v` cache-buster was bumped.

### 3. Cache-version bump: `v=2` → `v=3`

`OG_CARD_VERSION` (Python), the `fetch-live-intel.js` template literal, and `Sentinel-APEX/renderer/metadata-engine.js`'s `buildDynamicOgImageUrl()` all mirror one fixed value — updated together, the same mechanism already proven correct for the v1→v2 transition. This is a pure cache-key differentiator; `api/og.js` never reads `v` itself. Because Vercel's edge cache is keyed by full URL with `s-maxage=31536000` (one year), a previously-cached `v=2` URL would otherwise keep serving the old flat-card PNG indefinitely regardless of this code change. New posts built after this merges get `v=3` URLs — a fresh cache key, guaranteeing the new design renders. Already-published posts with `v=2` baked into their HTML will pick up the new design automatically the next time their specific cached entry expires or is evicted (the renderer doesn't fork behavior on `v`, so any cache-miss on an old URL still hits the new code) — there is no destructive migration and nothing to backfill.

---

## Bug Found and Fixed This Session (via actual visual inspection, not just status-code tests)

Rendering the redesign against the same kind of adversarial input the v2 security review used (a very long field with **no whitespace at all** — e.g. `'A'.repeat(220)`) and **looking at the resulting PNG**, not just checking it returned HTTP 200, surfaced a real layout defect: satori's flex-layout text measurement under-reported the headline's own rendered height for this specific pathological shape (a single unbroken run of identical wide characters), so the layout engine reserved too little vertical space for it while still painting every wrapped line — visually overlapping the data tiles beneath it.

This exact gap existed in the v2 code too (the headline text node never had a `maxHeight`), just never exercised by v2's own adversarial tests, which used prose-like long titles that wrap normally at word boundaries. Fixed with a hard `maxHeight: 165, overflow: 'hidden'` clip on the headline node — this makes the reserved layout box exact regardless of any future text-measurement edge case, rather than patching this one input shape. Re-rendered and re-inspected: the pathological case now clips cleanly at three lines with zero collision; every realistic (space-containing) long title — including the exact 46-character and 90-character real titles from the operator's own screenshots — was already comfortably within that budget before the fix and is unaffected by it.

A regression test for this exact case was added to `api/__tests__/og.test.js` (status/PNG-validity only, as that suite already does throughout — it cannot assert on pixels, so the visual claim above is asserted here in this document from actual rendered-and-inspected PNGs, not inferred from the test suite).

---

## Security Analysis (delta from v2 — nothing in v2's analysis is invalidated)

- **No new injection surface.** `kev`/`epss` are the most tightly constrained fields in the whole contract: `kev` accepts exactly one literal string (`"true"`) via an equality check, `epss` must parse as a finite float in `[0, 100]` — both fail closed to "omitted" on anything else, including `<script>`, SQL-injection strings, and out-of-range numbers (tested).
- **No change to the text-rendering trust model.** satori still builds a React-like element tree from plain string children for every new text node (tile labels/values, KEV ribbon) exactly as v2's text nodes did — never parsed as markup. The v2 security review's injection testing methodology applies unchanged to every new node.
- **No new I/O, no new remote fetches.** The two new decorative radial-gradient "glows" and the corner brackets are pure CSS-in-JS gradient/border properties satori renders natively — not images, not external resources. The renderer's zero-network-dependency property (part of why it can reliably 302-fallback rather than hang) is unchanged.
- **Overflow protection extended, not weakened.** The new stat-tile values reuse the exact `maxWidth` + `wordBreak: 'break-word'` pattern the v2 security review proved safe for the actor/sector row, plus the tile row itself keeps `flexWrap`. The headline gained a *new*, stronger protection (see above) that v2 didn't have.
- **Reliability contract unchanged.** The same try/catch → 302-to-static-`/og-image.png` fallback wraps the entire redesigned render path; a rendering failure still never surfaces as a 500 or a broken image.

---

## Test Evidence

Exact totals, run in this session, on this branch:

- **`api/__tests__/og.test.js`:** 8 pre-existing + 5 new = **13 passed, 0 failed.** New tests: valid `kev`+`epss` render correctly; `kev=false` takes the same code path as `kev` absent; invalid/out-of-range/non-numeric `epss` values are dropped; the pathological unbroken-title case no longer falls back to the static image; a CVE-with-EPSS-no-KEV and a ransomware-with-neither case both render.
- **`tests/test_authority_transformer.py`:** **6 new tests, all passed**, run both isolated (`-k "og_builder or svg_thumbnail_and_dynamic"`) and as part of the full suite below: `kev` sent only when `True` (both `False` and `None` correctly omit it); `epss` formatted to exactly one decimal; `epss=0.0` correctly distinguished from "unknown" (not dropped by a truthiness check); a full end-to-end `transform()` call with a real `DiscoveredArticle(kev_listed=True, epss_score=0.874)` produces `kev=true&epss=87.4` in the actual published `image_url`, not just in the builder function tested in isolation.
- **Full Python suite:** `python3 -m pytest tests/ automation/tests/ --tb=short --timeout=60 -q` → **677 passed, 0 failed, 0 skipped.**
- **Full JavaScript suite:** `npx jest --ci --maxWorkers=2` → **1951 passed, 60 skipped, 0 failed**, 57 of 58 suites (1 pre-existing, unrelated skip carried forward unchanged, same one v2's certification already documented).
- **`Sentinel-APEX/renderer` (`node --test`, the separate CI path for `metadata-engine.js`):** **64 passed, 0 failed** — confirms the `v=2`→`v=3` bump there didn't disturb anything (no test hardcoded the literal version value).
- **TypeScript:** `npx tsc --noEmit` → clean, zero errors.

No test was cherry-picked or skipped to reach these numbers.

---

## Visual QA

Rendered via the real `satori` + `@resvg/resvg-wasm` pipeline locally (not mocked, the exact code path production uses) and **each PNG was actually viewed and inspected**, not just byte-counted, for:

1. CRITICAL CVE with both KEV listed and a high EPSS score (87.4%) — full data-tile row, KEV ribbon, near-full CVSS meter.
2. HIGH CVE with EPSS but no KEV — confirms the ribbon correctly does not render absent a true `kev` value.
3. MEDIUM CVE with a low EPSS score (0.8%) — confirms the green low-probability EPSS color path and a proportionally low meter fill.
4. Ransomware victim report with short actor/sector (matching the operator's own live "qilin ... Financial Services" example).
5. Ransomware victim report with long actor/sector and a long, realistic title (matching the operator's own live "Deadlock ... SHAHEEN LAW GROUP PLC - Richmond, Virginia, USA" example) — confirmed clean wrapping, no overlap.
6. Generic/type-only report with no CVE, CVSS, actor, or sector — confirms the data-tile row is correctly omitted entirely rather than rendering an empty box, and the redesign still looks intentional and premium with only header/headline/footer present.
7. The adversarial 220-character unbroken-title + 300-character unbroken actor/sector probe — found the headline-overflow bug described above, then re-rendered and re-inspected after the fix to confirm clean resolution.

All 8 rendered as valid 1200×630 PNGs; the one visual defect found (headline overflow on pathological input) was fixed and re-verified before this round was considered complete.

---

## Known Limitations

1. **Already-published posts keep their old-design cached image until Vercel's edge cache entry for that exact `v=2` URL expires or is evicted** — there is no forced-purge step in this PR (matches the same, already-accepted precedent from the v1→v2 transition; not a new limitation introduced here).
2. **`fetch-live-intel.js` and `Sentinel-APEX/renderer/metadata-engine.js` cannot supply `kev`/`epss`** — neither has that data on its own input model today. Only the Python/Blogger pipeline (`cti.cyberdudebivash.in`) currently produces KEV/EPSS-enriched cards. Documented rather than fabricated; closing this gap would require adding real KEV/EPSS sourcing to those two pipelines' own data models first, which is outside a rendering-layer redesign.
3. **No control over third-party crawler-side caching** (LinkedIn/X/Slack each cache a fetched preview independently of Vercel, typically for some days, and each platform's own re-scrape/"inspect" tool is outside this repository's control) — same disclosed, unfixable-from-here limitation the v2 certification already documented for the equivalent concern.
4. **Country is deliberately not added** as a third ransomware-report data tile even though `DiscoveredArticle.ransomware_country` exists — the source-connector title format already bakes location into the headline text itself (e.g. "... - Richmond, Virginia, USA"), so a fourth tile would be redundant clutter rather than new signal. A deliberate scope decision, not an oversight.

---

## Rollback

Purely additive and confined to one renderer plus three of its callers:

- `api/og.js` — revert to restore the exact v2 layout; the `kev`/`epss` query params simply stop being read (no schema/storage to unwind, this endpoint is stateless).
- `automation/authority_transformer.py`, `fetch-live-intel.js`, `Sentinel-APEX/renderer/metadata-engine.js` — revert the `v` bump and (Python only) the two new call-site kwargs; no data model or persisted state changed in any of the three.
- No database, no migration, no schema, no new dependency, no new binding. A `git revert` of this PR's commits fully restores prior behavior.

---

## Final Verdict

**GO — merge when ready.** Zero known regressions, one real bug found and fixed via actual visual inspection (not just automated status checks), full existing trust/security contract preserved and extended consistently, all new capability sourced from real already-verified data or correctly left silent where no real data exists.

---

*CYBERDUDEBIVASH® SENTINEL APEX — Production Certification*
