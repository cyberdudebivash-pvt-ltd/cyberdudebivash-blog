# Canonical Writer Trace

ReportX Section 1. Traces every system in this repository capable of
producing "intelligence report" content, from the exact strings observed in
live output, through their generator functions, upstream data sources,
workflow triggers, and publication surfaces. Every claim below is backed by
a direct `git grep` match, file read, or workflow-trigger inspection —
nothing here is inferred from naming conventions or prior architecture
discussions.

**Headline finding: there is no single canonical writer. Five materially
different systems each generate "intelligence"-labeled content, three of
them from overlapping upstream sources, with no shared evidence model
between any of them. Classified P0 per this task's own Section 1 criterion
("more than one writer can generate materially different intelligence
products from the same source event").**

---

## Search results — exact strings traced to source

| String searched | Found in |
|---|---|
| `"Ransomware encryption of production systems carries average recovery costs"` | `automation/authority_transformer.py`, `Sentinel-APEX/engine/tests/fixtures/INTEL-REPORT-7.txt` |
| `"DETECTION STATUS: WITHHELD_INSUFFICIENT_EVIDENCE"` | No match anywhere in the repository at this session's HEAD (see note below) |
| `"Campaign continuation (HIGH CONFIDENCE)"` | `automation/authority_transformer.py`, `Sentinel-APEX/engine/tests/fixtures/INTEL-REPORT-7.txt` |
| `"Push Sigma detection rules covering T1486"` | `automation/authority_transformer.py`, `Sentinel-APEX/engine/tests/fixtures/INTEL-REPORT-7.txt` |
| `"Operational technology and industrial control system targeting"` | `automation/authority_transformer.py` |
| `"Public reference draft"` | `automation/report_integrity.py`, `data/published_posts.json`, multiple `logs/run-*.json` |
| `"Automated intelligence synthesis"` | `automation/report_integrity.py`, `data/published_posts.json`, multiple `logs/run-*.json` |
| `"Evidence Engine v3.0"` | `automation/authority_transformer.py` |
| `"Source published"` | `automation/report_renderer.py` |
| `"Executive Decision Matrix"` | `automation/authority_transformer.py`, `Sentinel-APEX/prompts/master-prompt.md`, `Sentinel-APEX/reports/published/SA-2026-0001-*.md`, `intelligence/sa-2026-0001-cve-2026-50522.html`, `posts/cisco-catalyst-sdwan-*.html`, `tests/test_authority_transformer.py` |

**Note on `"DETECTION STATUS: WITHHELD_INSUFFICIENT_EVIDENCE"`**: this exact
string does not appear anywhere in the current repository. It was not
fabricated as a finding — it is simply absent at this SHA. Either the task
description observed it in a live-rendered page (not the source template —
possible if the phrase is built from concatenated variables rather than a
literal string) or in an artifact this repository no longer contains. This
is flagged honestly rather than silently dropped; anyone continuing this
trace should re-grep after checking whether `automation/authority_transformer.py`
or `Sentinel-APEX/engine/sentinel_engine/detection_specs.py` construct this
phrase from parts (e.g. an f-string with a `WITHHELD_INSUFFICIENT_EVIDENCE`
enum value) rather than as a literal.

**Governing conclusion from this table**: `automation/authority_transformer.py`
is the writer directly responsible for the largest share of matched
strings, and is the writer whose fixture output (`Sentinel-APEX/engine/tests/fixtures/INTEL-REPORT-7.txt`)
matches 3 of the original strings verbatim. But `"Executive Decision Matrix"`
*also* appears in `Sentinel-APEX/prompts/master-prompt.md` (a prompt
template, consumed by a different system — see System 3 below) and in
published output from that different system
(`Sentinel-APEX/reports/published/SA-2026-0001-*.md`). Two independently
maintained systems produce text carrying the same section heading. That is
the concrete, repository-observed instance of the "duplicate/divergent
writer" pattern this section's acceptance criterion asks to watch for.

---

## The five systems

### System 1 — JS high-volume content pipeline (the site's bulk writer)

**Role**: produces the overwhelming majority of published volume — every
`posts/*.html`, `cve/*.html`, and `api/intel/*.json` file (thousands of
files; `git log` shows continuous auto-commits roughly every 15–30 minutes).

| Field | Value |
|---|---|
| Entry points | `fetch-live-intel.js`, `ai-security-intel-engine.js`, `auto-intel-engine.js`, `generate-cve-pages.js`, `generate-intelligence-hub.js` |
| Workflow triggers | `sentinel-apex.yml` (`schedule: "0,30 * * * *"`), `ai-security-intel.yml` (`schedule: "0 */2 * * *"`), `cve-pages.yml` (push-cascade + `schedule: "0 */6 * * *"`), `intelligence-hub.yml` (push-cascade + schedule), `generate-rss.yml` (push-cascade + schedule) |
| Data sources | NVD, CISA KEV, RSS threat feeds, and other live external feeds (per `PRE-MIGRATION-FORENSICS.md`'s prior inventory, not re-verified line-by-line this session) |
| Publication surface | `blog.cyberdudebivash.in` directly (`posts/`, `cve/`, `api/intel/*.json`, `sitemap.xml`, `rss.xml`) |
| Evidence model | None found — no shared claim/evidence schema; content is templated HTML generation from source JSON records |
| State/identity | This is the **primary, highest-traffic public writer**. It is what most site visitors and crawlers see. |

### System 2 — Python Blogger-syndication pipeline (LLM-rewritten derivative)

**Role**: reads back the *already-published* output of System 1 and uses an
LLM to rewrite/"elevate" it into a second, syndicated version published to
a *different* domain.

| Field | Value |
|---|---|
| Entry point | `automation/main.py` (`python -m automation.main`), orchestrating `content_discovery.py` → `automation/authority_transformer.py` → `blogger_publisher.py` |
| Workflow trigger | `blogger-syndication.yml` (`schedule`, interleaved at :15/:45 per that workflow's own comment) |
| Data source | **`blog.cyberdudebivash.in`'s own RSS feed, sitemap, and `live-intel.json`** (`automation/config.py`: `source_rss_url`, `source_live_intel_url`, `source_sitemap_url` all point at `https://blog.cyberdudebivash.in/...`) — i.e., this system's input is System 1's output, not a raw external source |
| Transform mechanism | `AuthorityTransformer.transform()` (`automation/authority_transformer.py:1775`) calls `call_llm()` (`automation/llm_client.py`), tried in priority order Groq → DeepSeek → OpenRouter → Anthropic (`config.py`) — **free-form LLM generation from a source article, not a structured evidence pipeline** |
| Publication surface | `cyberbivash.blogspot.com` (Blogger.com), via `blogger_publisher.py`'s direct `requests.post`/`requests.put` calls to the Blogger v3 API — confirmed no local file writes in that module beyond state/log bookkeeping |
| Evidence model | None — `authority_transformer.py`'s prompts (e.g. the `"Executive Decision Matrix"`, `"Campaign continuation (HIGH CONFIDENCE)"` strings) instruct the LLM to produce confidence labels, MITRE mappings, and detection guidance directly in free text, with no claim/evidence/source data structure backing them |
| State/identity | **This is the system most directly implicated by this task's motivating examples.** It takes System 1's factual output and has an LLM freely re-assert confidence levels, campaign continuation judgments, and detection guidance not present in (or not traceable to) the original source. |

### System 3 — Python evidence-first intelligence engine (`sentinel_engine`)

**Role**: a genuinely evidence-first pipeline — already built to nearly the
same design philosophy this task is asking for — but **not wired into any
scheduled production trigger**.

| Field | Value |
|---|---|
| Location | `Sentinel-APEX/engine/sentinel_engine/` (`normalizer.py`, `ioc_extractor.py`, `attack_mapper.py`, `entities.py`, `enrichment.py`, `knowledge_graph.py`, `detection_specs.py`, `detection_builder.py`, `scoring.py`, `quality.py`, `report_parser.py`, `pipeline.py`), invoked via `Sentinel-APEX/engine/cli.py` |
| Workflow trigger | **None with a `schedule:` trigger.** `intelligence-engine-ci.yml` and `continuous-assurance.yml` both trigger only on `push`/`pull_request` to their own paths, plus `workflow_dispatch` — i.e., these run the engine's *test suite* on code changes, they do not run the engine to *generate* new reports on any recurring basis. |
| Design philosophy (from its own README, `Sentinel-APEX/engine/README.md`) | *"Evidence first, never fabricate. Every ATT&CK mapping stores the source phrase that triggered it. Enrichment fields stay `None` when a live source is unreachable — scores are never estimated. Sections without evidence are omitted, never padded."* — this is close to word-for-word alignment with this task's own mandate |
| Already-implemented capabilities directly overlapping ReportX's asks | Executable per-report + corpus-level quality gates (`quality.py`) including corpus-level **duplicate-content detection** ("block: identical Sigma rule published across multiple reports; warn: MITRE/IOC/Threat Hunting sections ≥80% shingle-identical between reports") — this is a working implementation of ReportX Section 24 (Template Repetition Control); deterministic 10-dimension publication scoring with FREE/PRO/ENTERPRISE tiering (`scoring.py`) — a partial analog to ReportX Section 27's product-tier engine; format-specific detection-rule validators that "cannot emit a syntactically broken rule" (`detection_builder.py`) |
| Publication surface | `Sentinel-APEX/reports/{drafts,final,published}/*.md`, rendered by System 4 |
| Data source | A raw source article/text file supplied as a CLI argument (`cli.py run source.txt --id CDB-2026-0001 --url ...`) — **manual/on-demand invocation**, not an automated feed subscription |
| State/identity | Only **3 reports** exist in `Sentinel-APEX/reports/published/` (`SA-2026-0001` through `SA-2026-0003`). Their `git log` history traces only through squash-commit boundaries (`52bb6f46e`, `5b256a499`) that do not isolate a single "generated by `cli.py run`" commit — **this session cannot conclusively determine whether these 3 were produced by this engine, hand-authored, or produced by a since-removed automation.** Stated as an open question, not resolved by assumption. |

### System 4 — JS report renderer

**Role**: renders `Sentinel-APEX/reports/published/*.md` (System 3's output
format) into presentable HTML/print output.

| Field | Value |
|---|---|
| Location | `Sentinel-APEX/renderer/report-renderer.js`, `Sentinel-APEX/renderer/metadata-engine.js` (imported by `generate-cve-pages.js` for OG-image URL construction — the one direct code-level link found between System 1 and System 4) |
| Workflow trigger | `report-renderer-ci.yml` — push/PR-triggered only (tests the renderer against `Sentinel-APEX/reports/**` changes), no scheduled generation trigger |
| Publication surface | Consumes System 3's markdown; downstream rendering target not fully traced this session (out of scope for a first-pass trace — flagged for follow-up, not assumed) |

### System 5 — JS intelligence-product composition engine

**Role**: assembles discrete "products" (Executive Brief, Board Summary,
Technical Product, Detection Product, Threat Intelligence Product, Machine
Product) from CTI-platform investigation/case records — this is the system
most likely to be the actual intended target for "Fortune-500-grade premium
intelligence products," based on its own terminology, but it operates on a
**different upstream data model** (investigations/cases) than any of
Systems 1–4 (articles/source text).

| Field | Value |
|---|---|
| Entry point | `api/_lib/product-composition-engine.js`, chaining `Phase8Orchestrator` (`api/_lib/phase-8-orchestrator.js` — includes the evidence-traceability step this session already touched during Stage 6, see below) through at least `Phase9Orchestrator`, plus `phase-10-orchestrator.js` through `phase-15-product-excellence.js` |
| Trigger | **On-demand, via API**, not a scheduled batch job — invoked through `api/v1/products/*`, `api/v1/workbench/*`, `api/v1/reports/*` handlers (already inventoried in this repo's Cloudflare-migration route census as Redis-dependent) |
| Data source | `investigation`/`report`/`qualityReview` objects — presumably sourced from Redis-backed case/investigation records (`case-manager.js`, `investigation-manager.js`), which this session has not traced further upstream |
| Related evidence infrastructure already in place | `api/_lib/evidence-traceability-engine.js` (fixed for a real duplicate-key bug during Stage 6 of the Cloudflare migration work, same repository) — implements a `sources[]` array with `type`/`subtype` discriminators per evidence source, `traceability: 'Full'/'None'`, and coverage-percentage scoring; a real, if partial, precursor to ReportX Section 9's Claim-Support Matrix, though scoped to statement-level "traceability," not the full claim/evidence/corroboration/temporal model ReportX Section 3 specifies |
| Product model | `api/_lib/product-models.js` defines `ExecutiveProduct`, `TechnicalProduct`, `DetectionProduct`, `ThreatIntelligenceProduct`, `MachineProduct` — a real, typed product taxonomy, though not yet the claim-level evidence model ReportX Section 3 requires |
| State/identity | Never produces the string patterns searched for in Section 1 of this trace (no direct hits) — this system is **not** the source of the task's motivating examples, but its existing `evidence-traceability-engine.js`/`product-models.js`/phase-orchestrator scaffolding is architecturally the closest existing foundation to build ReportX's claim/evidence model on top of, if System 5 turns out to be the intended target. |

---

## Duplicate/divergent path — concrete instance

`"Executive Decision Matrix"` is produced by **two independently
maintained systems with no shared code**:

1. System 2 (`automation/authority_transformer.py`) — an LLM free-text
   generation, present in its own hardcoded prompt/template text
2. System 3 (`Sentinel-APEX/prompts/master-prompt.md` → published in
   `Sentinel-APEX/reports/published/SA-2026-0001-*.md`) — a
   human/LLM-drafted report following the `sentinel_engine` prompt template

These two "Executive Decision Matrix" sections, for the same or adjacent
source events, would have **no guaranteed consistency** with each other —
different confidence framing, different evidentiary basis, potentially
different conclusions — because neither system is aware the other exists,
and neither shares a claim/evidence data model with the other. **This is
the P0 architecture defect this task's Section 1 asks to identify.**

---

## Legacy / secondary classification

| System | Classification | Reason |
|---|---|---|
| System 1 (JS content pipeline) | **Canonical for public-site volume content** | Highest volume, primary public surface, scheduled/automated, no evidence model but also not making the kind of analytical-confidence claims Systems 2/3 make (mostly structured CVE/IOC data rendered into templates) |
| System 2 (Python Blogger syndication) | **Legacy / highest-risk writer** | LLM free-text rewriting of System 1's own output with no evidence model — directly matches this task's motivating defect examples |
| System 3 (`sentinel_engine`) | **Best-aligned architecture, not production-wired** | Already implements evidence-first principles this task asks for, but only 3 reports exist and no scheduled trigger runs it |
| System 4 (report renderer) | **Secondary renderer** | Consumes System 3's output; not a content generator itself |
| System 5 (product-composition engine) | **Separate product line, undetermined relationship to "premium reports"** | Operates on investigation/case data, not article data; closest existing evidence-traceability infrastructure; likely candidate for where ReportX's claim model should live, but this requires operator confirmation — see below |

---

## Open question this trace cannot resolve alone

ReportX's later sections (claim models, threat-schema isolation, the
ransomware/CVE premium dossiers, the specific named victim fixtures) assume
a single pipeline to modify. **This repository has five.** Before building
schemas, validators, or golden fixtures on top of any of them, the operator
needs to confirm which system(s) are actually in scope:

- Is ReportX meant to **fix System 2** (the Blogger-syndication LLM
  rewriter) directly, since it is the most literal match to the task's
  motivating examples?
- Is ReportX meant to **mature System 3** (`sentinel_engine`) into the
  production-wired premium pipeline, since it already carries the closest
  design philosophy?
- Is ReportX meant to **extend System 5** (product-composition engine),
  since it already has a typed product model and a real (if partial)
  evidence-traceability engine, and "premium intelligence product" language
  matches its own terminology most closely?
- Some combination — e.g., System 3 becomes the evidence/claim engine, and
  System 5's product-composition layer becomes the rendering/delivery tier?

Guessing wrong here means building the claim model, contradiction engine,
and 40-section ransomware dossier template (Sections 2–46) against the
wrong pipeline — a large amount of work that would need to be redone.
