# Commercial Quality — Round 8: Live-Report Audit Against Five Real Published Reports

**Scope:** a direct commercial-quality audit of five real, live, currently-published reports (three CVE advisories, two ransomware-claim reports), pulled straight from what is actually publishing to Blogger today — not a synthetic sample. Trigger: "genuinely in main production does not mean all expectations achieved... find out the gaps, issues on our latest intel reports... so that they must be sellable in public globally with highest max price."

## Method

Read five real exports verbatim (CVE-2026-75912, CVE-2026-75914, CVE-2026-60698, and two ransomware-claim reports: SilentRansomGroup/Troutman Pepper Locke, shinyhunters/Logitech-Streamlabs), then traced every observation back to the exact code path that produced it, live-verifying each root cause against the actual repository state rather than trusting the symptom alone. One investigative dead end is documented here because it changed what "the corpus" even means for this pipeline (see Finding 2).

## Finding 1 — 100% of live publishing has been running on the lean fallback, not the LLM-authored path

`automation/authority_transformer.py`'s `transform()` tries `call_llm()` (Groq → DeepSeek → OpenRouter → Anthropic, in order) before falling back to the leaner `reportx_composer` path. Every real run log checked (`logs/run-20260818-104630.json`, `-124710.json`, `-155047.json`, `-164833.json` — spanning 10:46–16:48 UTC on 2026-08-18) shows `content_source: "reportx_composer"` and `llm_attempts` failing `no_api_key` on all four providers, for every single post, in every run.

Root cause: `.github/workflows/blogger-syndication.yml`'s "⚡ Run Syndication Pipeline" step wired Blogger/NVD/AlienVault/Google/Twitter/Newsletter secrets into its `env:` block, but never referenced `GROQ_API_KEY`, `DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY`, or `ANTHROPIC_API_KEY` at all — regardless of whether those secrets exist in the repository, the workflow YAML never passed them through. `automation/config.py`'s `Config.from_env()` reads them via plain `os.environ.get(...)`, so they came back `""` unconditionally in every CI run.

**Fix:** added the four missing secret references to the workflow's `env:` block, with an inline comment explaining the diagnosis. This is necessary but **not sufficient** — see "What this does not do."

## Finding 2 — CWE-88 missing from the vulnerability classifier (direct, live self-contradiction)

CVE-2026-75912's live report shows `CWE: CWE-88` twice (Verified Facts, Source Evidence Extract) but `Vulnerability class: Unclassified` in Technical Analysis of the *same document* — a direct, visible self-contradiction in a customer-facing report.

Root cause: `automation/report_integrity.py`'s `_CWE_CLASS` dict (14 entries) never mapped `CWE-88` (Argument Injection), and the regex fallback in `_vulnerability_class()` has no argument-injection pattern (the closest, `path_traversal`'s `arbitrary file (?:read|write)`, doesn't match this CVE's actual phrasing, "read arbitrary files"). Same defect class as Round 4/PR #94's `CWE-639` fix, recurring for a different CWE.

**Corpus-scan dead end, resolved:** an initial attempt to measure corpus-wide prevalence by grepping `posts/*.html` for this pattern returned 0 matches — which contradicted the report directly in hand. Root cause: `posts/*.html` (4,197 files) is written and committed by a completely separate pipeline (`git log` shows its commits as `"SENTINEL APEX v5.0: +N reports..."`), never by the Blogger-syndication pipeline this audit is about — `blogger-syndication.yml`'s own commit step only touches `data/published_posts.json` and `logs/*.json`. No local archive of historical Blogger-published HTML exists, so corpus-wide prevalence can't be measured locally; the fix proceeded on the strength of the one directly-proven live case plus the exact Round-4 precedent, not a frequency count.

**Fix:** added `"CWE-88": "argument_injection"` to `_CWE_CLASS`, mirroring the `CWE-639` precedent exactly (single dict entry, no regex pattern added, consistent with two other existing classes — `memory_corruption`, `cross_site_request_forgery` — that also have no independent regex fallback).

Live-verified against CVE-2026-75912's real data: `Vulnerability class` now renders `Argument Injection`.

## Finding 3 — "Vulnerabilities" label degrades CVE-to-CVE "Related Intelligence Reports" into a recency feed

CVE-2026-60698 and CVE-2026-75912's live "Related Intelligence Reports" are each five *other, unrelated* CVEs (different vendors, different products, no shared CVE ID) — functionally a recency feed within the CVE population, not correlation.

Root cause: `content_discovery._infer_labels()` maps every `"cve"`-keyword title to `"Vulnerabilities"` unconditionally — the identical mechanism Round 4 fixed for `"CYBERDUDEBIVASH"` / `"Threat Intelligence"` / `"Global Intel"`, left ungeneralized for this one label. `automation/internal_linker.py`'s `_NON_DISCRIMINATING_LABELS` didn't include it, so two CVE reports sharing only `"Vulnerabilities"` (which is to say: any two "vanilla" CVE reports with no other keyword-matched label) still counted as a "shared label" match.

**Fix:** added `"Vulnerabilities"` to `_NON_DISCRIMINATING_LABELS`. One pre-existing test (`test_cve_match_ranks_above_label_only_match`) had used `"Vulnerabilities"` as its example of "some real shared label" — updated its fixture to `"Zero-Day"` (a genuinely discriminating label) since it was, by construction, relying on the exact defect being fixed; its assertion (CVE match ranks above label-only match) is preserved unchanged.

## Finding 4 — Generic "Assessment" sentence identical across every non-KEV-confirmed CVE report

Three of the three sample CVE reports (CVE-2026-75912, -75914, -60698) show the byte-for-byte identical Technical Analysis "Assessment" sentence, despite having materially different real exploit prerequisites — e.g. CVE-2026-75914 requires no user interaction (`UI:N`) while CVE-2026-75912 requires it (`UI:R`), a real, already-displayed distinction in each report's own "Verified Facts" CVSS vector, invisible in the Assessment text.

**Fix:** added `_exploit_prerequisites_clause()` to `automation/report_renderer.py` — a deterministic reading of the CVSS vector's Attack Vector / Privileges Required / User Interaction metrics (already shown verbatim elsewhere in the same report) into a short factual clause, e.g. *"This vulnerability is exploitable over the network, requiring no privileges and user interaction."* Nothing is inferred beyond the standard CVSS metric definitions; a missing/unparseable vector falls back to the exact original static sentence, unchanged.

Live-verified: CVE-2026-75914 (`UI:N`) and CVE-2026-75912 (`UI:R`) now render genuinely different Assessment text, correctly reflecting each CVE's real exploit prerequisites.

## Finding 5 — Ransomware reports' Executive Risk Command Center collapses to a single generic tile

Both ransomware-claim samples (SilentRansomGroup/Troutman Pepper Locke, shinyhunters/Logitech-Streamlabs) show an Executive Risk Command Center with exactly one tile: `CISA KEV: Unknown`. Real threat-actor group, sector, and country data is already known — it's in the report's own prose (Executive Summary, Source Evidence Extract) — but invisible to the scannable dashboard a buyer's eyes actually go to first.

Root cause: `authority_transformer._build_risk_command_center()` only builds tiles from CVE-specific fields (`cve_id`, `cvss_score`, `epss_score`, `kev_listed`, `affected_vendor`/`affected_product`), none of which a ransomware claim ever populates. The underlying data (`group`, `sector`, `country`) existed only as local variables in `threat_feeds.RansomwareIntelSource`, baked into formatted title/summary/`full_content` text — never carried on `DiscoveredArticle` as structured fields the renderer could read.

**Fix:** added three fields to `DiscoveredArticle` (`ransomware_group`, `ransomware_sector`, `ransomware_country`; all `Optional[str] = None`, never fabricated when the source record didn't supply a value), populated them in `RansomwareIntelSource.discover()` from the exact same values it already renders into prose, and added three tiles (`Threat Actor`, `Sector`, `Country`) to `_build_risk_command_center()`. Deliberately did not add a redundant "Victim" tile — the victim name is already the article's title.

Live-verified against the real SilentRansomGroup/Troutman Pepper Locke data: dashboard now shows 4 tiles (Threat Actor, Sector, Country, CISA KEV) instead of 1.

## Verification — test suite

- 4 new/updated test files: `tests/test_authority_transformer.py` (+2 test classes: CWE-88 classification, risk-command-center ransomware tiles), `tests/test_internal_linker.py` (+2 tests, +1 fixed pre-existing test), `tests/test_report_renderer.py` (+1 test class, 3 tests).
- 360/360 pass at the repository root (`pytest tests/ automation/tests/`).
- Every fix additionally live-verified by reconstructing the exact real `DiscoveredArticle` data from the user's own uploaded reports and calling the real rendering functions directly — not just synthetic test fixtures (see per-finding "Live-verified" notes above).

## What this does *not* do

- **Finding 1 is necessary but not sufficient.** The workflow fix only wires the four secret *references* through — at least one of `GROQ_API_KEY` / `DEEPSEEK_API_KEY` / `OPENROUTER_API_KEY` / `ANTHROPIC_API_KEY` must actually exist as a GitHub Actions repository secret (Settings → Secrets and variables → Actions) for `call_llm()` to ever succeed. This cannot be verified or set by an automated session — it requires direct repository-owner action.
- **No corpus-wide prevalence count for Finding 2.** No local archive of historical Blogger-published HTML exists (see the dead-end note above); the fix rests on one directly-proven live case and an exact prior-round precedent, not a frequency measurement.
- **Does not touch `posts/*.html` or the "SENTINEL APEX v5.0" pipeline.** That is a separate content pipeline (confirmed via `git log`) from the Blogger-syndication pipeline this audit is scoped to; out of scope for this round.

## What remains, named plainly

- Setting at least one live LLM API key as a GitHub Actions secret (owner action, Finding 1).
- A corpus-wide CWE-coverage audit against real historical NVD data (would require either a new local cache or a scoped live NVD sampling pass — not attempted this round).
- Extending `_exploit_prerequisites_clause()`-style differentiation to other still-generic report sections, if found on a future audit pass.
- Auditing the separate "SENTINEL APEX v5.0" / `posts/*.html` pipeline on its own terms — not evaluated in this round at all.
