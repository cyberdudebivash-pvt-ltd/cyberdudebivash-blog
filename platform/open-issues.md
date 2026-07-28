# EIPS — OPEN ARCHITECTURAL ISSUES

Findings surfaced by applying `eito/lifecycle.md` Stage 2 (Repository
Intelligence) honestly. Not fixes — this session already made two
unilateral consolidation calls (`Sentinel-APEX/prompts/` vs. root
`/prompts/`, both inert documentation) and should not make a third on live
revenue-bearing code without explicit sign-off. That is the difference
between this entry and the two prior ones.

## Issue 1 — Independently-evolved parallel implementations (Python offline engine vs. live JS product)

**Found while researching EIPS Layer 2/3; the pattern recurred twice more
during EIOS-X v1/GIOP v1 and is formalized here as one recurring
architectural theme, not four unrelated issues.**

| | `Sentinel-APEX/engine/sentinel_engine/` (Python, offline) | `api/_lib/` + `fetch-live-intel.js` (JS, live) |
|---|---|---|
| Graph | `knowledge_graph.py` — entities + relation triples, JSON-persisted | `threat-graph.js` (656 lines) — "Threat Actor Graph Engine v2.0," CVE→Actor→Campaign→IOC, 4-factor confidence attribution formula |
| Scoring | `scoring.py` — 9 weighted dimensions, 0–100, deterministic, FREE/PRO/ENTERPRISE tiering | `threat-scorer.js` (303 lines) — "AI Threat Scoring Engine v2.0," 7 weighted normalized features, 0–100, explicit `reasoning[]` per score |
| Normalization | `models.py:NormalizedDoc`, produced by `normalizer.normalize()` | ad hoc `item` object reshaped by `normalizeToUniversalSchema()` in `fetch-live-intel.js` |
| Entity aliasing | `entities.py:LEXICON` — canonical name → aliases tuple | `threat-graph.js` — per-actor objects each carrying their own `aliases: [...]` |
| Runtime status | Offline tooling — no CI wires it automatically | **Live** — `threat-scorer.js` is required by `api/_lib/intel.js` (a live endpoint) and `api/_lib/enrichment-pipeline.js`; the rest feed the live bot pipeline |
| Cross-references | Zero — confirmed by grep in both directions, all four rows | Zero |

### EIF v1 Phase 11 — formal convergence classification

Evaluated each row against "keep, merge, deprecate, or leave separate with
justification" (not a decision made unilaterally where one doesn't belong
to engineering):

| Pairing | Classification | Justification |
|---|---|---|
| **Scoring** (`scoring.py` / `threat-scorer.js`) | **Leave separate — pending executive decision** | `threat-scorer.js` sits behind a live, paid API endpoint. A customer asking "why did this get a different score in two places" has no single answer today — that's a real drift risk, not a hypothetical one, and the fix is a functional change to revenue infrastructure. Requires a decision on canonical ownership before any merge; not resolved here. |
| **Graph** (`knowledge_graph.py` / `threat-graph.js`) | **Leave separate — pending executive decision** | Same reasoning as Scoring, same live/offline split, same blocking dependency on the same decision — this is one decision, not two. |
| **Normalization schema** (`NormalizedDoc` / `normalizeToUniversalSchema()`) | **Leave separate — justified, no decision needed** | No shared consumer: the Python shape only feeds `pipeline.py`/`quality.py`/the certification framework; the JS shape only feeds the live bot's rendering. Unlike Scoring, there is no customer-visible symptom of the two shapes disagreeing — nothing compares them side by side or presents both to the same customer. Unifying two internal data shapes with no interoperability requirement would be consolidation for its own sake, which Phase 11 explicitly rules out ("do not merge systems solely for aesthetic reasons"). |
| **Entity aliasing** (`entities.py:LEXICON` / `threat-graph.js` aliases) | **Leave separate — justified, no decision needed** | Same reasoning as Normalization: different pipelines, different consumers, no cross-need, no customer-visible inconsistency today. |
| **Detection generation** (`detection_builder.py`/`sigma_builder.py` / `engine-node/detection-engine.js`) | **Leave separate — justified, not actually a duplication problem** | Confirmed (GIOP v1 audit) this is a *deliberate* parity port — same technique registry, same four-plus-one output formats (Sigma/KQL/Splunk/OSQuery/Suricata), built specifically because the live bot runs on a 5-minute cadence and can't shell out to Python per cycle. This is the documented, justified pattern for maintaining one piece of logic in two runtimes — closer to how `report_parser.py` and `report-renderer.js` mirror the same section-marker convention on purpose. Flagging this as equivalent to Scoring's drift risk would be wrong; it's listed here only to close the question explicitly, not because it needs action. |

**Net effect of this classification**: two of five pairings (Scoring,
Graph — genuinely one decision) remain blocked on executive sign-off,
unchanged after five sprints of surfacing them. Three of five (Normalization,
Entity aliasing, Detection generation) are resolved *as findings* — each
has an explicit, defensible "why this is fine as two" answer now on record,
rather than sitting as an open question repeated in every future audit.

**Recommendation, not action**: decide canonical ownership for Scoring/Graph,
then either (a) have the offline engine call the live scorer's logic (or
vice versa) via a shared formula definition, or (b) explicitly document why
two are intentional and keep this table as the record of that decision.

## Issue 2 — `industry-intelligence.md` has no home

Noted in `extensibility.md` — the one idea from the deprecated `/prompts/`
directory with no canonical replacement. Low stakes (nothing depends on it
today); listed here so it doesn't get silently lost.

## Issue 3 — Three real defects found producing the platform's first report (SA-2026-0001)

Found by actually running real source material (a well-corroborated, multi-source
CVE-2026-50522 writeup) through the pipeline end to end for the first time —
exactly the kind of gap that stays invisible until something real goes
through the machinery.

1. **`ioc_extractor.py` treats citation URLs as indicators.** `cli.py run`
   against source text containing a "Sources:" list extracted the cited
   news-article URLs themselves (thehackernews.com, helpnetsecurity.com,
   securityweek.com) as IOCs, then generated Suricata rules flagging
   traffic to those legitimate outlets as `classtype:trojan-activity`.
   Reproducible: feed any source document with a references/sources
   section through `cli.py run`. Needs a citation-vs-indicator
   distinction — e.g. excluding URLs that appear after a "Sources:"/
   "References:" marker, or requiring an explicit malicious-context cue —
   before this engine's raw IOC/Suricata output can be trusted unreviewed.

2. **`attack_mapper.py`'s keyword matching produces confident wrong
   mappings.** The same run mapped **T1486 (Data Encrypted for Impact)** at
   a stated HIGH CONFIDENCE from a sentence about attribution being
   unknown — no ransomware/encryption content existed anywhere in the
   source. A keyword-proximity false match presented with the same
   confidence label as a correct match is a real trust problem: nothing in
   the current output distinguishes "matched cleanly" from "matched a
   coincidental keyword."

3. **`scoring.py`'s dimensions measure auto-extractable structure, not
   analyst-report quality.** SA-2026-0001, hand-authored, quality-gate
   PASSED, independently-verified Sigma rule, honestly reports zero public
   IOCs (because none exist yet for this campaign, not because none were
   sought) — scored 43/100, BLOCKED tier. `detection_value`/`soc_value`/
   `dfir_value` are computed from `PipelineResult.detections[]`/`iocs[]`,
   populated by the automated extractor, not from a hand-embedded,
   independently-validated Sigma rule in report prose. A correct, honest,
   gate-passing report on a fresh vulnerability with no public IOCs yet
   will structurally score low under the current model. This is either
   evidence the scoring model needs an analyst-authored-content path, or
   a deliberate signal that fresh-vulnerability bulletins with no IOCs
   aren't meant to be premium-tier by design — which one is true is a
   product decision, not an engineering one, and is not resolved here.

**Resolved (EIOS-X v1 sprint)** — (1) and (2) fixed at root cause; (3) remains
open, a product-tiering policy question, not an engineering one.

1. `ioc_extractor.py` now detects a "Sources:"/"References:" marker line
   (`_RE_CITATION_MARKER` — recognizes bare, ATX-heading, and bold-heading
   forms) and excludes any URL match at or after that position from IOC
   extraction. Scoped narrowly to URLs, matching the documented defect;
   domains embedded in excluded URLs were already excluded from separate
   domain extraction via the existing `url_spans` mechanism, so no
   additional change was needed there. Verified: the three real citation
   domains from SA-2026-0001's own "Sources:" list (thehackernews.com,
   helpnetsecurity.com, securityweek.com) no longer extract as IOCs or
   generate Suricata rules; a genuine malicious URL earlier in the same
   document, and in documents with no citation marker at all, still
   extracts correctly (backward compatible). 5 new regression tests in
   `test_ioc_extractor.py` (14 total in that file).
2. `attack_mapper.py`'s keyword-proximity matching had no concept of
   negation — reproduced directly against SA-2026-0001's own published text
   (its retrospective note that T1486 "was considered and rejected" *itself*
   contains "ransomware"/"encryption" and re-triggered a HIGH CONFIDENCE
   T1486 mapping when fed back through `map_techniques()`). Root cause was
   broader than the one reported keyword: any negated mention anywhere in
   the `_LEXICON` ("no ransomware," "has not been observed deploying
   ransomware," explicit citations like "T1486 ... was ... rejected") still
   matched as a confident positive. Fixed generally, not per-keyword: a
   sentence-scoped negation guard (`_is_negated` — searches the clause
   containing the match, bounded by the nearest sentence boundaries on
   either side, so a negation elsewhere in the document can't suppress an
   unrelated genuine finding) now applies to both the lexicon loop and the
   explicit-technique-ID citation loop. The lexicon loop was changed from
   `re.search` (first match only) to `re.finditer`, skipping negated
   occurrences so a genuine *later* positive mention in the same document
   still maps correctly. Verified end-to-end with `cli.py run` against a
   reconstruction of the original SharePoint/CVE-2026-50522 source material
   (hedged attribution language, negated ransomware mention, real citation
   list): output now maps only the two genuine techniques (T1059.001,
   T1190), zero false T1486. 6 new regression tests in
   `test_attack_mapper.py` (12 total in that file), including a check that
   an unrelated genuine technique elsewhere in a document with an
   unconnected negation is still correctly mapped.

Both fixes are additive guards layered onto the existing extraction/mapping
logic — no existing signature, return shape, or passing test changed. Full
engine suite: 114 passed (was 103; +11 net: +5 ioc_extractor, +6
attack_mapper).

## Issue 4 — Quality gate's required-section taxonomy doesn't match template naming (found while fixing the `►`/`##` marker mismatch)

`report_parser.py`'s `_RE_SECTION` was fixed (IXP v1 Stage 2) to recognize
`##` ATX headings, not just the legacy `►` marker — `parse_report()` now
correctly finds all 24 sections in SA-2026-0001 instead of zero. Running
`cli.py gate` against that report for the first time with real parsing now
surfaces two **new, legitimate, previously-invisible** findings that were
never fixable before because the gate couldn't parse the report at all:

1. **`BLOCK [structure] required section missing: Technical Analysis`** —
   `quality.py`'s required-section list expects a section literally named
   "Technical Analysis." SA-2026-0001 (and the `executive-brief.md` template
   it's derived from) uses "Strategic Assessment," "Attack Chain," "Kill
   Chain Analysis," etc. instead — different, arguably more precise names
   for the same analytical content. Whether the gate's taxonomy should
   accept these as equivalents, or whether report authors should conform to
   the gate's exact section names, is a product/process decision, not
   something to resolve by silently loosening the gate or renaming a
   published report's sections.
2. **`BLOCK [structure] severity missing or invalid: ''`** — `_extract_severity()`
   looks for a bare line containing exactly `LOW`/`MEDIUM`/`HIGH`/`CRITICAL`
   (a convention from the old `►`-based page-dump format). SA-2026-0001
   states severity in prose and YAML front matter instead, so extraction
   finds nothing. Needs either a severity field in front matter that the
   parser reads directly, or a broader in-text pattern.

**Resolved (EIPP v1)**, since first real publication required a genuine
pass, not a bypass:

1. Verified "Attack Chain"'s actual content (step-by-step exploitation
   mechanics: initial access → execution → credential access), confirmed
   it satisfies "Technical Analysis" in substance, and added it as a
   documented alias in `quality.py`'s `SECTION_ALIASES` — the requirement
   is still enforced (tested: a report with neither name still blocks),
   just no longer name-literal.
2. `report_parser.py` now also parses YAML front matter (mirroring
   `Sentinel-APEX/renderer/report-renderer.js`'s approach) and prefers a
   `severity:` field there over the old bare-line text scan, which stays
   as a fallback for the legacy format. SA-2026-0001 didn't have a
   `severity` field at all — added `severity: "CRITICAL"` to its front
   matter, an honest addition directly supported by data already in the
   same report (CVSS 9.8, and the title's own "Critical").

`cli.py gate` now returns **PASS** for SA-2026-0001 (two non-blocking WARNs
about ATT&CK IDs to manually verify — expected, not a defect). 6 new
regression tests added (`test_report_parser.py`, `test_quality.py`).

## Issue 5 — The existing Markdown-to-HTML converter cannot render real Sentinel-APEX reports (tested, not assumed)

Before committing to a full pipeline-unification effort (`report-experience-audit.md`
Phase 1/Stage 3), tested the specific proof-of-concept that document's
"Recommended Next Sprint" proposed: render SA-2026-0001's actual Markdown
through the one Markdown→HTML converter that already exists in this repo,
`mdToSafeHtml()` in `generate-cve-pages.js:37-71`. Result: **not viable
as-is** — verified by actually running it, not by inspecting the code:

1. **Every Markdown table is destroyed.** All 5 pipe-tables in the report
   (Verified Facts, Related CVEs, MITRE Mapping, Confidence Assessment,
   etc.) flatten into a single unreadable line of literal `|`-delimited
   text — `mdToSafeHtml()` has no table handling at all.
2. **The Sigma YAML code fence causes cascading corruption.** The converter's
   inline-code regex (`` `([^`]+)` ``) is written for single backticks; it
   has no concept of a triple-backtick fence. Confirmed empirically: it
   greedily pairs the fence's 3rd backtick with whatever backtick appears
   *next* in the entire document, swallowing the full YAML block into one
   scrambled `<code>` span — and desyncs backtick-pairing for legitimate
   inline code (e.g. `` `w3wp.exe` ``) in every section *after* the fence,
   which end up with `<code>`/`</code>` boundaries around the wrong words
   entirely. Verified: 20 opening and 20 closing tags (so the HTML doesn't
   break outright), but the content each tag wraps is semantically wrong
   from the Sigma section onward.

Basic inline handling (`**bold**`, standalone `` `code` `` outside a table
or fence, `#`-`######` headings, `-`/`*` bullets) converts correctly — the
converter just was never built for tables or fenced code blocks, both of
which real analyst reports use throughout.

**Conclusion**: a minimal Pipeline B → HTML path needs either a real
Markdown library (something that handles GFM tables and fenced code blocks
correctly — a new dependency decision, not one to make unilaterally here)
or purpose-built table/fence handling added to `mdToSafeHtml()`. Reusing
the existing converter unmodified, which looked like the cheapest path, is
now a tested dead end rather than an assumption — this is exactly the
outcome a proof-of-concept is supposed to produce. Not fixed in this pass.

## Issue 6 — Template-fallback detection content is category-generic, not vulnerability-specific (read the code, not just the stats)

**Status update (GEIOM v1):** the confidence-framing gap noted below is now
partially addressed — the MITRE ATT&CK Mapping section (and, by its own
text, the Sigma/SIEM/hunt/SOC content that follows it) now carries an
explicit "Reflects known patterns for this threat category (MEDIUM
CONFIDENCE) — not unique correlation against this specific article's
details" disclosure, matching the confidence-labeling convention the same
function already uses elsewhere (exploitability, attribution, predictive
intelligence). This is a labeling fix, not a detection-logic fix — the
underlying category-generic Sigma/SIEM content described below is
unchanged; readers are now told plainly what kind of guidance they're
looking at. The CWE-specific reclassification described as "not fixed in
this pass" remains not fixed.

Prior audits established *that* ~98% of Blogger-syndication posts use the
template fallback rather than an LLM (GTIOC v1). Reading `_template_enhance()`
(`automation/authority_transformer.py:634-1646`) end to end shows *what that
actually means* for content quality — more nuanced than "lower quality":

- **Executive Summary / Technical Analysis are genuinely per-article** —
  they directly quote `article.summary` and any extracted CVE/CVSS.
- **MITRE ATT&CK mapping, Sigma rule, the 5 SIEM queries, hunt queries, and
  SOC playbook are selected from exactly 8 mutually-exclusive category
  buckets** (`is_ot` / `is_ransomware` / `is_apt` / `is_cve` / `is_ato` /
  `is_extension` / `is_supply_chain` / generic else, lines 673-1057). Within
  the `is_cve` bucket — the one most NVD/KEV-sourced posts hit, per the
  source-priority ordering in `content_discovery.py` — the Sigma rule and
  SIEM queries detect a fixed "path traversal + web shell" pattern
  (`../`, `%2e%2e`, `cmd.exe`, `/etc/passwd`) regardless of the specific
  CVE's actual vulnerability class. A deserialization CVE and an
  unrelated auth-bypass CVE both get the identical detection logic; only
  the CVE ID string and severity are substituted in.
- This is exactly the failure mode the LLM prompt (`_build_analyst_prompt`,
  lines 540-627) explicitly guards against — "Sigma rules must be specific
  to the attack technique described... not template placeholders" — so the
  platform's own design already recognizes the difference; the fallback
  path just can't clear that bar the way the LLM path is instructed to.
- **Existing, real mitigation, not absent**: the Sigma rule is emitted with
  `status: experimental`, and the SIEM query block already carries "VALIDATE
  FIELD NAMES AGAINST YOUR ENVIRONMENT BEFORE DEPLOYING." Readers aren't
  told these are ready-to-deploy as-is — but the detection *logic*, not
  just field names, may not match the actual vulnerability.

**Not fixed in this pass** — properly fixing this means classifying by
vulnerability mechanism (CWE class: deserialization/SSRF/auth-bypass/RCE/…)
instead of the current 8 broad categories, which means new per-class
Sigma/SIEM content and materially more branching in an already
1000+-line function. That's a bigger-scoped change than this sprint's two
fixes, though `tests/test_authority_transformer.py` already has 56 tests
(several targeting `_template_enhance()` directly) to build on, so it
isn't starting from zero coverage. Flagged as the most evidence-justified
candidate for a dedicated future sprint, not attempted here.

**Addendum (GCTIX v1) — verified against live output, and the LLM path
doesn't fully close this either.** Fetched two real published posts (one
per path, both real `blogger_url` values from `logs/run-*.json`, not
guessed) to check the code-reading conclusion above against what a
customer actually sees:

- **Template** (`CVE-2026-14490`): exactly as the code predicts — Sigma
  title says "CVE-2026-14490 Payload and Web Shell Activity," but the
  selection logic is the same fixed `../`, `%2e%2e`, `cmd.exe`,
  `/etc/passwd` set every `is_cve` post gets. The CVE ID appears only in
  the label, never in the detection logic itself.
- **LLM** (`CVE-2026-16585`, groq): genuinely better in the ways the
  prompt asks for — it correctly names the real vulnerable component (a
  WordPress plugin's `delete_sticker` function) and maps a single, correct
  technique (T1204) instead of the template's padded five. But its own
  generated Sigma rule is still just `c-uri: '*../*'` with no correlation
  to that specific endpoint — better than the template's cross-post
  duplication, but not the fully vulnerability-specific rule its own
  narrative just described.

Net effect: raising LLM adoption (the GTIOC v1 finding) would reduce how
often the *same* generic rule repeats verbatim across unrelated CVEs, but
wouldn't by itself make generated detection logic correlate to the
specific finding — that gap exists on both paths, just more severely on
the template one. Doesn't change the "not attempted here" conclusion
above; narrows what the eventual fix needs to cover.

## Issue 7 — Template narrative sections are truncated source text, not original synthesis (GEIOM v1 Phase 2)

Issue 6 covers whether the template's *detection* content is original.
This is the narrower, distinct question of whether its *narrative*
content is: Executive Summary is `article.summary[:350].rstrip('.')` plus
one fixed templated sentence; Technical Analysis is `article.summary[:800]`
verbatim (`automation/authority_transformer.py:1484,1528`). For the ~90%
of posts on the template path, the reader-facing "analysis" in these two
sections is the source feed's own summary text, truncated at a fixed
character count — not correlation, timeline reconstruction, or synthesis
across sources.

This is not a fabrication problem — nothing is invented, and the source is
the article itself, not a misattributed one — so it doesn't carry Issue
6's detection-deployment risk. But it does mean the honest answer to "what
does this section add beyond the source article" is, for most posts:
severity/CVSS extraction and category labeling, not original analytical
value. The real differentiation (per GCTIX v1's own Phase 6 framing —
"what would make a customer choose Sentinel APEX instead of reading the
original advisory") on the template path is structure and packaging
(severity scoring, MITRE labeling, Sigma/SIEM starting points, SEO/schema),
not novel correlation.

**Not fixed in this pass.** Genuine narrative synthesis needs either real
LLM analysis (already gated behind the provider-availability question
GTIOC v1 raised — most runs don't get one) or new summarization logic
distinct from truncation, and either is a larger content-strategy decision
than a labeling fix. Documented so it isn't mistaken for something this
sprint already addressed, since Issue 6's confidence-disclosure fix (above)
covers the detection block only, not these two sections.

---
*CyberDudeBivash® Sentinel APEX — Open Architectural Issues*
