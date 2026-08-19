# Production Pipeline — As Is

**Date:** 2026-08-19
**Method:** Traced from actual call sites, `require()`/`import` graphs, and `.github/workflows/*.yml` triggers — not inferred from file or directory names. Every claim below is grounded in a specific file:line or a directly-observed run. Where something could not be independently confirmed (one item, noted inline), that is stated explicitly rather than assumed.
**Trigger:** REPORTX Finished Intelligence Engine P0 mandate, Section 3 ("First reverse-engineer the actual production path... DO NOT IMPLEMENT ANYTHING YET").

## 0. The central fact this document exists to establish

**There are two entirely independent, parallel, live production pipelines, publishing to two different public sites, with no shared code between their content-generation or publication-gating logic.** Nothing in the P0 mandate's own framing anticipated this, and no single-pipeline architecture document would be accurate. Both are described in full below; §5 is a direct, side-by-side comparison.

| | Pipeline A (Python) | Pipeline B (Node.js) |
|---|---|---|
| Entry point | `automation/main.py` | `fetch-live-intel.js` (repo root) |
| Triggering workflow | `.github/workflows/blogger-syndication.yml` | `.github/workflows/sentinel-apex.yml` |
| Schedule | Interleaved `:15`/`:45` (~30 min cadence) | `:00`/`:30` (~30 min cadence) |
| Publish target | `cyberbivash.blogspot.com` via Blogger API | `blog.cyberdudebivash.in` (this repo's own `posts/*.html` + `index.html`, hosted on **Vercel**) |
| Content model | LLM-first with deterministic fallback | Fully deterministic, rule-based, **no LLM at all** |
| Publication gate | Real evidence-integrity gate (`report_integrity.py::validate_publication()`), fail-closed on fabrication/contradiction/placeholder patterns | Structural-completeness gate only (`qualityGate()`); **no fabrication/contradiction re-validation exists** |
| Certification | A real, tested, dormant automated-certification engine exists (`Sentinel-APEX/engine/sentinel_engine/reportx/`) and is partially wired for observability | No certification concept of any kind |
| Volume (current corpus) | Blogger post history (not directly counted here) | 4,210 files in `posts/` |

## 1. Pipeline A — Python / Blogger

### 1.1 Execution graph

```
.github/workflows/blogger-syndication.yml (schedule + workflow_dispatch)
  → python -m automation.main
    automation/main.py:run_pipeline()
      → ContentDiscoveryEngine.discover()          [automation/content_discovery.py]
          sources: cisa_kev_source.py, nvd_source.py, threat_feeds.py
                   (CISA advisories, ransomware intel, breach intel, threat-actor intel),
                   rss_aggregator.py (79 feeds; ~35-45 typically fail with 403/404/parse errors
                   on any given run — observed live, not assumed)
      → retry queue merge (PublicationState.get_retry_queue() / _merge_retry_and_fresh())
      → AuthorityTransformer.transform(article)     [automation/authority_transformer.py]
          → llm_client.call_llm()                    tries groq → deepseek → openrouter → anthropic
              (see §4 — confirmed broken; every real call in this session fell back)
          → on LLM success: LLM-authored path
          → on LLM failure: _composer_enhance()
              → sentinel_engine.reportx.pipeline_composer.compose_report()
                  (dormant engine, see §3 — computes achieved_tier + 20-dim
                  commercial-readiness scorecard; observability only, one hard
                  gate: blocks PUBLIC_REFERENCE_DRAFT)
              → falls back further to _legacy_template_enhance() (the real
                production fallback since PR restoring RX-PR0; render_evidence_report()/
                _template_enhance() exist but nothing in the live pipeline calls them —
                confirmed dead-but-kept code, per deprecation policy)
          → report_integrity.build_report_context() / validate_publication()
              [automation/report_integrity.py] — fail-closed evidence gate (§4.2)
          → report_renderer.render_evidence_report()  [automation/report_renderer.py]
          → SEOOptimizer.generate(), InternalLinker, MonetizationInjector,
            industry_intelligence, product_recommendations, download_center
            (MITRE Navigator layer) — all real, called, non-dormant
      → BloggerPublisher.publish_post()               [automation/blogger_publisher.py]
      → SearchConsoleSubmitter.submit_url(), SocialAmplifier.amplify()
      → PublicationState.mark_published() → data/published_posts.json
      → _write_run_report() → logs/run-<timestamp>.json
```

### 1.2 Publication gate (real, fail-closed)

`report_integrity.py::validate_publication()` blocks on: missing required fields (report ID, source hash, source URL, review status, certification status), body under 3000 chars, placeholder-pattern matches, unsupported commercial-scale claims, unverified exploitation assertions, false KEV assertions, cross-family schema contamination, false human-attribution byline, false human-review claims (added this session), and — the one real evidence-based hard gate from the dormant engine — `achieved_tier == "PUBLIC_REFERENCE_DRAFT"`. A blocked article is retried up to 3 times via `PublicationState.add_to_retry_queue()`, then drops.

### 1.3 Post-publication validation

Exists as tooling (`automation/legacy_quality_auditor.py`) but is **not automated** — `.github/workflows/blogger-legacy-quality.yml` is `workflow_dispatch`-only (no `schedule:` trigger). An operator must manually run it, choosing `dry-run` (default) or `quarantine` mode. It flags KEV/exploitation contradictions, placeholders, false human attribution, ransomware/AI schema contamination, and (as of this session) tracks stale pre-fix disclaimer language as an informational count — never auto-applied.

### 1.4 State, retry, feature flags

- State: `data/published_posts.json` (3.3 MB), read/written by `content_discovery.py`/`internal_linker.py`/`authority_transformer.py`.
- Retry queue: capped at 3 attempts (`get_retry_queue()` filters `attempts <= 3`).
- Feature flags / env-dependent behavior: entirely API-key presence (`Config.from_env()`, `automation/config.py`) — no explicit feature-flag system. Four LLM provider keys, two data-source keys (NVD, AlienVault OTX), four Blogger OAuth values, four Twitter/X keys, Search Console key. Missing Blogger keys hard-fail `config.validate()`; missing LLM/OTX keys degrade gracefully (template fallback / skipped source).

## 2. Pipeline B — Node.js / Vercel

### 2.1 Execution graph

```
.github/workflows/sentinel-apex.yml (schedule :00/:30 + workflow_dispatch)
  concurrency: {group: main-content-writers, cancel-in-progress: false}  ← real overlap protection
  → node fetch-live-intel.js
      acquireLock() [fail-open by design; pipeline.lock is gitignored and
                      removed by the workflow each run, so effectively inert
                      in CI — real protection is the workflow concurrency group above]
      → tiered fetch, 28 sources (NVD, CISA KEV/Alerts, GitHub Advisories, MSRC,
        ExploitDB, PacketStorm, Full Disclosure, Sentinel APEX's own CTI portal,
        6 vendor/outlet RSS feeds, URLhaus, ThreatFox, Reddit, CERT-EU, MS Sec Blog,
        Wired, Recorded Future, MalwareBazaar, NCSC-UK, Cisco PSIRT, OTX,
        RansomWatch, AI Incident DB)
      → correlateAndMerge()          — dedup by id, source-rank tie-break
      → filterSignalFromNoise()      — lightweight local pre-filter
      → runEnrichmentPipeline()      [api/_lib/enrichment-pipeline.js — hard require]
          → threat-graph.js, campaign-engine.js, threat-scorer.js
          computes actor_attribution, data_confidence, campaign clustering,
          _explanation per item — see §2.3, this output is discarded
      → normalizeToUniversalSchema(), sentinelApexStamp()
      → writeLiveIntel() / writeAPIFiles()
          → runS2N() [api/_lib/s2n-engine.js — hard require, zero dependencies
                       of its own] — quality/priority scoring for the JSON API
                       feeds only, never gates HTML publication
      → per candidate item (capped 15/run, 30-day dedup TTL):
          qualityGate()               — the ONLY publication gate (§2.2)
          → generatePostHTML()
              → detEngine.buildDetections()          [engine-node/detection-engine.js]
              → analystMemory.priorContext()          [engine-node/analyst-memory.js]
              → reasoningEngine.buildReasoning()       [engine-node/reasoning-engine.js]
              → productsEngine.buildProducts()         [engine-node/products-engine.js]
          → safeWriteSync(posts/${slug}.html)          atomic write
      → index/RSS/sitemap/search-index regeneration
      → saveState() → intel-state.json ; analystMemory.save() → intel-memory.json
  → workflow: git add -A → git commit -m "...[skip ci]" → git push origin main
      (3-attempt rebase-retry; nothing downstream re-validates the commit)
  → Vercel's native Git integration auto-deploys on push to main
      (throttled for bot commits to the first 10 min of each even UTC hour,
       via vercel-ignore-build.sh; human/code commits always deploy immediately)
```

### 2.2 Publication gate — structural completeness only, not evidence-based

`qualityGate()` (`fetch-live-intel.js:2047-2099`) checks: required fields present, minimum title/description length, a severity signal present (CVSS or threat level), at least one reference URL, numeric priority, a recognized type enum, and one narrow placeholder-title regex (`/^test|^placeholder|^sample/i`). **It does not re-read the assembled HTML for fabricated claims, cross-section contradiction, or false certainty** — there is no equivalent of Pipeline A's `validate_publication()`. What substitutes is defensive template wording baked into the generator functions (e.g., hedged exploitation language) — prevention by construction, not detection by validation.

### 2.3 A significant existing defect: computed-but-discarded enrichment

`enrichment-pipeline.js` runs a real 8-step graph-based enrichment pass every single cycle — actor attribution (two-pass, with campaign context), `data_confidence` tiering, campaign clustering, cross-item correlation — and persists it to `api/intel/threat-graph.json`. **None of this reaches `posts/*.html` or the public API JSON files**: confirmed by grep, `generatePostHTML()` and the API formatters never read `item.actor_attribution`, `item.data_confidence`, or `item._explanation`. The same file also contains a complete, unused "API tier gating" subsystem (`applyTierGating`/`filterForFree`/`filterForPro`/`filterForEnterprise`) with zero callers anywhere in the repo outside its own test. This is real, working infrastructure that computes exactly the kind of source-confidence/attribution data the P0 mandate asks for — currently wasted, not absent.

### 2.4 ATT&CK mapping — two unreconciled systems, one of which is already close to mandate-spec

- `getMitre()` (`fetch-live-intel.js:1633`) — a simple, single-technique-per-item regex classifier, no confidence, no evidence.
- `engine-node/detection-engine.js::mapTechniques()` — matches against a curated 34-entry validated technique registry; each match carries `HIGH`/`MEDIUM` confidence **plus the literal matched evidence substring**; syntactic rule validators (`validateKql`/`validateSplunk`/`validateOsquery`/`validateSuricata`) `throw` rather than emit malformed output.

The two run independently and are never reconciled in the same report. The second is a genuinely solid foundation for the mandate's ATT&CK semantic-validation requirement (§11 of the mandate) — it already does evidence-gated technique assignment with confidence and quoted rationale, just not universally applied and not integrated with the Python-side `report_contract.py` model.

### 2.5 State, dedup, retry

`intel-state.json` — TTL-based dedup (30 days; older entries can republish), 60-day GC purge, 3000-entry cap. Committed to git in the same step as the generated content — no separate approval stage. `fetchWithRetry()` retries individual source HTTP fetches 3x with linear backoff; there is no persisted "retry this rejected item" queue distinct from an item naturally reappearing next run if its source still returns it. A mid-run workflow timeout (5 min ceiling) is treated as non-fatal — partial results already written atomically still commit and go live, with no rollback.

### 2.6 Disclaimer/provenance text — real, present, but not uniform across the historical corpus

The current generator's closing signature block self-identifies as *"Automated, source-attributed intelligence report"* and instructs readers to *"Verify technical claims in the linked primary sources before operational use."* Detection/Sigma/YARA/IOC sections all carry explicit "not environment-validated / not production-validated" caveats. `about.html` separately discloses the automation model site-wide.

**This exact current wording exists in only 63 of 4,210 published posts.** Posts are written once and never rewritten, so the disclaimer/signature text a given historical post shows depends on which pipeline version was live when it was generated (confirmed variants found live: v3.0, v4.0, category-specific taglines, and the current wording). This is the Node-pipeline analog of — and larger in scope than — the historical-disclaimer-backfill gap already flagged for the Blogger side.

### 2.7 LLM usage: none, by design

Confirmed via exhaustive grep of `fetch-live-intel.js` and its full dependency tree: zero references to any LLM provider, endpoint, or API key. `reasoning-engine.js` states this explicitly: *"Deterministic and composed from artifacts already produced — no model calls, no fabrication."* This is architecturally different from Pipeline A, which is *designed* to use an LLM and is currently degraded by a broken provider chain. Pipeline B was never designed to use one — it is already operating at its designed ceiling, not a degraded state.

## 3. The dormant automated-certification engine

`Sentinel-APEX/engine/sentinel_engine/reportx/` — a real, well-tested Python package (`automated_certification.py`, `human_review.py`, `release_certification.py`, `tier_downgrade.py`, `quality_sampling.py`, `release_health.py`, `commercial_readiness.py`, `pipeline_composer.py`, `audit_log.py`). Implements exactly the release-level (not per-report) human-review model the P0 mandate's own Mandate 14 recommends: a human reviews four fixed canary reports once; that certifies the release's demonstrated correctness; a separate mechanism then decides per-report whether that correctness extends to new evidence, with zero further human involvement. **No `ReviewRecord` exists yet for any of the four canaries** — `reportx-release certify` today honestly returns `NOT_CERTIFIED`.

Wired into Pipeline A only, via `authority_transformer.py::_composer_enhance()`. Computes `achieved_tier` and a 20-dimension commercial-readiness scorecard for every article; both are recorded as observability (`quality_score`, `quality_score_eligible`, `achieved_tier` fields flow through to `logs/run-*.json`). **One hard gate exists**: `PUBLIC_REFERENCE_DRAFT` blocks publication. No other tier threshold currently gates anything. **Not connected to Pipeline B at all** — confirmed via exhaustive grep across all Node-side files for `reportx|sentinel_engine|automated_certification|tier_downgrade|human_review`: zero code-level hits, one documentation comment noting `detection-engine.js` is a one-time design port of *different*, unrelated Python modules (`attack_mapper`/`detection_specs`/`detection_builder`, not `reportx`).

## 4. Cross-cutting finding: the LLM provider chain is fully broken (Pipeline A only)

`automation/config.py` defines a 4-provider chain (Groq → DeepSeek → OpenRouter → Anthropic). A same-day code comment records a prior live trigger where Groq/DeepSeek/OpenRouter keys were wired through and failed on their own account-side issues (Groq: retired model ID → 404; DeepSeek/OpenRouter: 402 Payment Required); Anthropic's key was unset in that run. **In this session's environment, all four keys are simply absent** (`no_api_key` for all four, confirmed via a live `--dry-run` against 20 real current articles — see baseline document). Either way, the conclusion is identical: **no report currently produced by Pipeline A can reach LLM-authored status.**

This is structurally significant, not merely a content-quality nuisance: `automation/analytical_depth_gate.py` requires `content_source` to be one of `{groq, deepseek, openrouter, anthropic}` before a report is even *eligible* for `PREMIUM_LONG_FORM` tier — regardless of how complete its evidence sections are. **Every real report observed this session landed at `content_source: "reportx_composer"` and `achieved_tier: "TACTICAL_READY"`**, capped by this gate, not by evidence quality. Fixing this is very likely the single highest-leverage unblock for Pipeline A's side of this mandate — much of what sections 5-23 ask for (Key Judgements, richer analytical assessment) requires LLM authorship to populate at all under the current architecture, independent of any new data model built on top.

## 5. Direct comparison: what's already mandate-compliant vs. genuinely missing

| Mandate concern | Pipeline A (Python) | Pipeline B (Node) |
|---|---|---|
| Fail-closed fabrication/contradiction gate | Yes, real (§1.2) | No — structural completeness only (§2.2) |
| Automated certification / tier model | Yes, dormant engine, partially wired (§3) | None |
| Human review scoped correctly (release-level, optional) | Yes (§3) | N/A (no human-review concept present at all) |
| Source corroboration tracking | Yes — `find_independent_prior_source()`, real, fails closed | Yes — two layers (in-run merge + persistent cross-run `AnalystMemory`), real |
| ATT&CK semantic validation (confidence + evidence) | Partial — mapping exists, not confidence/evidence-annotated | Yes — `detection-engine.js::mapTechniques()` already does this well, just not universally reconciled |
| Detection maturity model | Yes — named states (`syntax_validated_experimental`, `telemetry_specification_only`, etc.) | Partial — rule-provenance/versioning store exists, no named maturity lifecycle |
| Forecasting | Not implemented | Partial — qualitative "Forward Outlook," confidence-labeled; real EPSS data fetched but never reaches the rendered post |
| Fixed long-form section contract | Yes — the 24-section `report_contract.py` model, evaluated per-article | No — variable ~15-18 conditionally-assembled sections, correctly omitted (not fabricated) when unsupported |
| LLM-authored analytical depth | Blocked — LLM chain fully broken (§4) | N/A — never designed to use one; already at design ceiling |
| Post-publication validation | Exists, manual-trigger only | Does not exist |
| Historical disclaimer/byline consistency | ~4,800+ legacy Blogger posts likely still carry pre-fix text (flagged separately) | Current wording present in only 63/4,210 posts; multiple historical variants in the wild |
| Orphaned/duplicated computation | None found | Two real instances: enrichment-pipeline attribution/confidence data, and the unused API-tier-gating subsystem |

## 6. What was explicitly NOT investigated in this pass

- Live inspection of the actual Vercel project/dashboard settings (the auto-deploy conclusion rests on strong, multi-source internal repo evidence — workflow comments, `vercel.json`'s `ignoreCommand`, `vercel-ignore-build.sh`, `smoke-test.yml` — not a direct Vercel API/dashboard check, which this session has no credentials for).
- `api/_lib/` beyond what's reachable from `fetch-live-intel.js`'s dependency graph — the broader CTI-platform product surface (`governance-engine.js`, `publishing-pipeline.js`, `intelligence-manager.js`, and ~80 other files in that directory) remains out of scope for *this* mandate, per the already-established finding that it is a separate, human-operated product with no scheduled trigger into either content pipeline (re-confirmed independently three times across this session, including twice more during this investigation).
- CTI.CYBERDUDEBIVASH.IN specifically, named in the mandate's own header alongside Blogger — not yet identified as a distinct third surface or confirmed as a naming variant of one of the two domains already traced (`intel.cyberdudebivash.com` per `Config.sentinel_apex_url`, vs. `blog.cyberdudebivash.in`). Worth clarifying with the user before assuming which is meant.
