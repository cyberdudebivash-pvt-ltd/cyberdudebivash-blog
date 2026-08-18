# Commercial Quality — Round 5: The Numeric Scorecard Was Never Wired In

**Scope:** the mandate's Section 21/25 ask for a real, measurable commercial-quality score and observability data — plus a real, well-evidenced ATT&CK justification bug found while investigating it.

## The big finding

The 20-dimension, weighted commercial-readiness scorecard (`intelligence_validation.py`, built and validated against 5 real canary exports in PR #90) was **never called anywhere in the live publish path**. It existed only as a standalone CLI command (`reportx-validate`). This is the same class of defect as the certification-gate issue PR #93 fixed — real, tested capability, never actually wired in.

`evaluate_intelligence_validation(bundle, control_results)` takes exactly the same `ReportBundle`/`control_results` `compose_report()` already builds for `commercial_readiness.py` — wiring it in costs nothing extra in evidence computation. Added as a new `scorecard` field on `ComposedReport`, and threaded through as real observability data (`quality_score`, `quality_score_eligible`) into `transform()`'s result and every run report's `posts[]` entries.

## Why this is not (yet) a hard gate — with real evidence, not a guess

Ran a live dry-run against real, fresh CVE/KEV articles before deciding anything. Every one scored well (84–90/100) but **`publication_eligible` was `False` for all of them.** Digging into `blocking_reasons` for a real article:

```text
overall_score: 85 | eligible: False
- MITRE ATT&CK Justification: 0/1 cited technique(s) are valid and evidenced. Unjustified: T1059.
- Analytical Completeness: failing "30-40 page premium depth"
- Production Readiness: failing "Fortune-500 commercial deliverable" (a 22-control roll-up)
```

Two of those three are a genuine **calibration mismatch, not a defect**: PR #90's scorer was validated against premium-dossier canary fixtures. This pipeline's real, live output is deliberately `FLASH_READY`-tier, lean, high-volume content (`pipeline_composer._lean_role_decisions()`'s own documented design: "the full 10-role treatment is reserved for premium dossiers"). Requiring 30–40 pages and all 22 premium-only `commercial_readiness` controls from intentionally-lean content would have blocked **100% of today's real publishing** had this been wired in as a hard gate without checking first. Making the scorer tier-aware (don't apply premium-only completeness expectations to `FLASH_READY`/`TACTICAL_READY` content) is real, necessary, separate work — a deliberate design decision, not something to rush in behind an unrelated wiring change.

## The third blocking reason was a real, fixable bug — and I already knew the root cause

The MITRE ATT&CK Justification failure was not calibration — it was `sentinel_engine/attack_mapper.py`'s negation-heuristic, a bug already root-caused during the original Intelligence Validation Framework work (PR #90) and explicitly deferred as out of scope for a shared module.

Root cause, confirmed against real rendered HTML: `_RE_SENTENCE_BOUNDARY` required sentence-ending punctuation to be followed by whitespace or end-of-string. Real rendered report HTML ends sentences like `"...execution.</div>"` — punctuation immediately followed by a closing tag, never whitespace. The negation scan then ran straight through the tag boundary into the next, unrelated paragraph (MITRE's standard disclaimer: "not claims that the technique occurred") and incorrectly negated a clean, unhedged citation.

**Fix:** added a lookahead alternative (`(?=<)`) to the existing sentence-boundary pattern — the same incremental-fix style already used for this regex's two prior real-bug fixes (GFM table rows, `SA-2026-0001`). Verified live: MITRE ATT&CK dimension went from `score=0/FAIL` to `score=100/PASS` for the same real article; `overall_score` improved 85 → 91.

## Verification

- 1257 tests pass across root + `Sentinel-APEX/engine` (same one pre-existing, environment-only failure documented in #91–#97).
- 3 new regression tests: the scorecard is real computed data on `ComposedReport`/`transform()`'s result; the exact HTML-boundary negation bug, reproduced and fixed.
- Live dry-run against real, fresh sources, before and after the `attack_mapper.py` fix, with `blocking_reasons` inspected directly — not inferred.

## What remains, named plainly

- **Tier-aware scoring**: `Analytical Completeness`/`Production Readiness` must not apply premium-dossier-only expectations to `FLASH_READY`/`TACTICAL_READY` content. Until this is done, `publication_eligible` stays observability-only, not a gate — flipping it on today would block all real publishing.
- **Source expansion / an active corroboration engine** (fetching a genuine second source, not just grading whatever's already in the graph).
- **Historical/campaign correlation** beyond the false-positive fix in Round 4.
