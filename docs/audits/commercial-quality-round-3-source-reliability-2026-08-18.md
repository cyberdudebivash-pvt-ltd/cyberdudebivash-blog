# Commercial Quality — Round 3: Real Two-Axis Source Reliability Model

**Scope:** the "Source reliability display" gap the platform's own architecture doc (`REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md`) already flagged as a documented, deliberate simplification and named as a real follow-up — and which an external review independently identified in the exact same terms: a blended `"nvd: A/B — Reliable"` line instead of the real, independent 2-axis Admiralty matrix, and a `"global_rss: F"` grade that discarded which of ~40 distinct, individually-curated outlets an article actually came from.

## Root cause, traced before writing any code

1. `discovery_bridge.build_source_record()` set `publisher=article.source` — the ingestion *connector* name (`"global_rss"`), not the real outlet. `DiscoveredArticle` had no field to carry the real publisher at all.
2. `rss_aggregator.py`'s `_GLOBAL_FEEDS` list already names each of its ~40 feeds individually (`"BleepingComputer"`, `"Dark Reading"`, `"Krebs on Security"`, ...) — the real name existed at fetch time (even embedded, uselessly, inside `full_content`'s free text) but was discarded when constructing the article, collapsing every one of them to the same generic `"global_rss"` bucket.
3. `source_reliability()` then graded every `global_rss` article `Reliability.UNKNOWN` ("F") regardless of which of those pre-vetted, curated outlets it came from — the same blanket grade as a completely unknown source.
4. `admiralty_label()` only ever rendered one blended line from the single `Reliability` enum, even though `CorroborationState` (a real, independent, already-computed field via `EvidenceGraph.recompute_corroboration()`) was sitting right there, unused for this display.

## Fix

- Added `DiscoveredArticle.source_publisher` (optional, backward compatible); `rss_aggregator.py` now populates it from `feed.name`.
- `build_source_record()` now uses `article.source_publisher or article.source` for `publisher=`.
- `source_reliability()` now grades a known, curated RSS publisher the same as this file's own existing "named CTI vendor" policy (`MODERATE`), not `UNKNOWN` — it does not (yet) differentiate reliability *between* those ~40 outlets, which would need an editorial trust policy per outlet (named as follow-up, not attempted here).
- New, real two-axis model in `executive_products.py`: `source_reliability_grade()` (Reliability → a single real letter grade, never `"A/B"`), `information_credibility()` (`CorroborationState` → the real 1–6 Admiralty credibility scale + label), `overall_analytical_confidence()` (a defensible combination of both axes — deliberately conservative, since the pipeline has no active corroboration-fetching engine yet, so most reports today honestly land at MEDIUM or LOW, not HIGH), and `two_axis_reliability()` composing all three into the real display.
- `pipeline_composer.py`'s "Source Reliability & Corroboration" section now renders the real three-line output and an honest, corroboration-state-specific note, instead of one blended line plus an unconditionally-static disclaimer sentence.

## Verification

- 1251 tests pass across root + `Sentinel-APEX/engine` (same one pre-existing, environment-only failure as #91–#94, unrelated).
- 21 new tests covering every `Reliability`/`CorroborationState` combination, the publisher-preference fallback chain, and end-to-end rendered-HTML proof (not just the helper functions in isolation).
- Live reconstruction, real Dark Reading-shaped article: renders `Dark Reading` / `Source Reliability: C` / `Information Credibility: 3 (Possibly True)` / `Overall Analytical Confidence: MEDIUM` — not `global_rss` / `A/B — Reliable`.

## Explicitly not attempted here

Differentiating reliability *between* the ~40 curated outlets (needs an editorial trust policy, a business/judgment call, not a mechanical fix); an active corroboration-fetching engine (so `CorroborationState` can ever compute to `MULTI_SOURCE_INDEPENDENT` in practice, not just be ready for when one exists); historical/campaign correlation; ATT&CK justification depth; the numeric 100-point scoring model. Each remains a real, separate, substantial piece of work.
