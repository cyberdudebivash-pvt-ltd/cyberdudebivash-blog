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

## Issue 8 — The live knowledge graph's correlation layer covers ~2% of its own content (GCTIKF v1)

**Status update (GEPMO v1):** the "no edge type connects two entities of
the same kind" finding below is now partially addressed —
`linkCorrelatedCampaigns()` (`api/_lib/enrichment-pipeline.js`, called as
pipeline Step 6b) adds a new `co_occurs_with` edge between Campaign nodes
that share an included CVE, computed additively from existing
Campaign→CVE data. This closes the Campaign↔Campaign gap specifically.
Still open: no CVE↔CVE or Actor↔Actor edges exist, actor-attribution
coverage is still ~2%/~1% (this fix doesn't touch attribution, only
campaign-to-campaign correlation), and the Malware node type remains
fully unpopulated. First-ever tests for this file:
`tests-js/campaign-correlation.test.js`.

Distinct from Issue 1's architectural question (should the offline Python
graph and the live `api/_lib/threat-graph.js` merge) — this is about what's
actually *inside* the live graph today. Read the real, current
`api/intel/threat-graph.json` directly (9,315 nodes, 3,378 edges, 208,006
lines) rather than the code that builds it, then checked the code
(`api/_lib/threat-graph.js`) to confirm what the data showed:

- **Node types**: 8 ThreatActor, 2,554 CVE, 954 Campaign, 4,945 Intel, 854
  IOC — and 0 Malware, despite `Malware` being a fully-supported node type
  in the schema (`normalizeNodeId`, `computeStats` both handle it). Nothing
  in the current ingestion path ever creates one, even though actor
  descriptions reference specific malware variants in free text (e.g.
  LockBit's own node description mentions "LockBit 3.0 (Black)").
- **Actor attribution covers a small fraction of the graph.** Only 20 of
  954 Campaign nodes (2.1%) and 35 of 2,554 CVE nodes (1.4%) have any
  inbound edge from one of the 8 curated ThreatActor nodes. The 8 actors
  themselves are genuinely well-researched (real aliases, TTPs with valid
  ATT&CK IDs, CISA/DOJ/Mandiant citations) — this isn't a quality problem
  with what exists, it's a coverage problem with how little of the graph
  it reaches.
- **No edge type connects two entities of the same kind.** All 3,378 edges
  are exactly one of four relationships — `linked_to` (Intel→IOC, CVE→IOC),
  `includes` (Campaign→Intel, Campaign→CVE), `exploits` (Actor→Intel,
  Actor→CVE), `executes` (Actor→Campaign) — every one hierarchical/
  membership, none symmetric. There is no Campaign↔Campaign,
  CVE↔CVE, or Actor↔Actor edge anywhere. "Campaign correlation" in the
  sense GCTIKF v1 Phase 4 asks about (shared infrastructure, shared TTPs,
  shared victimology across campaigns) isn't representable in the current
  schema at all — two campaigns that happen to share a CVE aren't linked
  to each other, only independently to that CVE.

**Not fixed in this pass.** `api/_lib/threat-graph.js` regenerates
`api/intel/threat-graph.json` on the live ~30-minute ingestion cycle and
feeds `getGraphForTier()` (paid-tier-gated), making it exactly the kind of
shared, revenue-adjacent infrastructure Issue 1 already flags for extra
caution — a same-run code change would take effect on production data on
the next bot cycle with no review window. The smallest well-scoped fix
worth considering next: an additive `co_occurs_with`-style edge computed
purely from existing Campaign→CVE `includes` data (no new node/edge
removed or modified, no new external data needed) — but that's a decision
for a dedicated sprint with room to test against the real 9,315-node graph
first, not appended here.

## Issue 9 — SA-2026-0001 had never been ingested into the offline knowledge graph; running it for the first time found a real ATT&CK mapper defect (GIKEP v1)

Distinct from Issue 8 (the live JS `api/_lib/threat-graph.js`) — this is
the offline Python engine's own `knowledge_graph.py`. `KnowledgeGraph()` was
never constructed anywhere except `cli.py run`/`score`, both of which only
ever build a `NormalizedDoc` from the pre-publication automated pipeline
(`normalizer.py`). Nothing connected the graph to a report once it reached
`Sentinel-APEX/reports/published/` — so SA-2026-0001, the one report that
has actually passed the quality gate, had never once been ingested.

**Fixed**: `report_ingest.py` (new) adapts a `ParsedReport` into a
`NormalizedDoc` by composing the existing extractors unchanged, and
`cli.py graph` is the new entry point. Running it for real against
SA-2026-0001 surfaced a genuine, previously-undiscovered defect in
`attack_mapper.py`, not a defect in the new adapter: `_RE_SENTENCE_BOUNDARY`
didn't recognize a markdown table row as a clause boundary, so a multi-row
table with no terminal punctuation between rows (a MITRE ATT&CK Mapping
table, this platform's own standard structure for that section) was
treated as one giant sentence — a hedge word in any row's Evidence cell
suppressed every technique ID cited elsewhere in the same table, including
ones with a fully clean citation of their own (T1190 in SA-2026-0001,
suppressed by T1606's row containing "not explicitly confirmed" three rows
down). **Fixed** by adding a trailing-pipe-then-newline as an additional
clause boundary; 1 new regression test, all 13 existing `attack_mapper`
tests still pass unchanged.

**Not fixed — documented, needs more evidence than one report provides**:
two further real false positives, same run, deliberately left alone rather
than patched into shared production logic on n=1 evidence:

- A second "ransomware" mention in SA-2026-0001's Future Outlook section
  ("(c) any confirmed ransomware or data-theft impact tied to this specific
  access vector") contains no negation-cue word of its own (the report's
  *first* ransomware mention, "No source... describes ransomware...", is
  correctly suppressed) — so T1486 still gets mapped via this second,
  hedged-but-uncued sentence. `_is_negated()`'s cue-word list would need to
  recognize forward-looking/monitoring phrasing generally, not just one
  found phrase, to fix this safely.
- "ASP.NET" (mentioned as the credential-theft mechanism throughout the
  report) is misclassified as a domain IOC — it's shaped like one
  (`word.tld`). `DEFAULT_ALLOWLIST` (`ioc_extractor.py`) is documented as
  citation/reference infrastructure specifically, not "technology names
  that happen to look like domains" — a different, open-ended category
  that would need its own list rather than an ad hoc addition to one
  scoped for something else.

Also confirmed, not a defect: the embedded Sigma rule's own
`falsepositives:`/`selection_child:` fields were producing four *more*
spurious technique matches (T1053.005, T1059.001, T1059.003, T1218.005) —
a detection rule's own selection criteria legitimately names exactly the
keywords the mapper looks for. Fixed in `report_ingest.py` by excluding
fenced code blocks before extraction, not in `attack_mapper.py` itself,
since this is specific to feeding it a document that contains embedded
detection logic — something no caller had ever done before this adapter.

Separately: `entities.py::LEXICON` has no `SharePoint` product entry —
SA-2026-0001's own central subject extracts zero product entities; only
"Microsoft" (vendor) is recognized. `Entity.type`'s docstring already
anticipates `sector`/`country` types that the lexicon has no entries for
at all. Extending the lexicon is low-risk (additive, no existing behavior
changed) and flagged as a Recommendation, not attempted here — determining
which products/sectors are worth curating deserves its own pass across
more than one report.

`Sentinel-APEX/knowledge-graph.json` (new) is the first real, persisted
graph this platform has ever produced — 10 entities, 9 relations, built by
actually running `cli.py graph` against the real report, not asserted.

**Update (GIPPP v1) — a second report tested whether these findings
generalize, and surfaced two more, distinct from the first three:**

- **T1486 keyword-conflation reproduces via a different mechanism.**
  SA-2026-0002 (CVE-2026-0257, Palo Alto Networks PAN-OS) truthfully reports
  a CISA-confirmed fact: this CVE's KEV entry carries
  `knownRansomwareCampaignUse: Known`. Writing that fact plainly ("CISA's
  KEV catalog... flags this CVE with `knownRansomwareCampaignUse: Known`")
  contains no negation cue — because it isn't negated, it's a true,
  confirmed positive — and `_LEXICON`'s `ransomware|encrypt...` pattern maps
  T1486 (Data Encrypted for Impact) from it anyway. This is a different root
  cause than SA-2026-0001's hedge-without-cue-word gap: here the mapper
  conflates "this vulnerability is associated with actors who separately
  conduct ransomware operations" (an actor/campaign-linkage fact, which is
  what CISA's flag actually means) with "ransomware encryption was directly
  observed in this exploitation chain" (what T1486 actually claims). Two
  reports, two different sentence shapes, both mapping T1486 incorrectly —
  stronger evidence the keyword pattern itself is imprecise, but for two
  unrelated reasons, meaning no single narrow fix (more cue words, or a
  smarter clause check) addresses both. Still not patched, now with twice
  the evidence for why any fix needs to be more structural than the
  current phrase-pattern approach.
- **`entities.py::extract_entities()` has no negation awareness at all** —
  unlike `attack_mapper.py`, which has `_is_negated()`/`_clause_span()`.
  SA-2026-0002 explicitly names "Qilin" only to flag it as an unverified,
  no-supporting-reference claim from this platform's own aggregator
  (`[Unresolved Reference]`, Intelligence Gaps) — and `extract_entities()`
  extracted it into the knowledge graph as a confirmed `malware` entity
  anyway (`Sentinel-APEX/knowledge-graph.json`, `malware:qilin`, tagged to
  `SA-2026-0002`), with nothing in the graph distinguishing "this report
  confirmed this entity" from "this report explicitly rejected this
  entity." Not fixed here — the same reasoning as the other findings in
  this issue: one example, a change to a shared extraction path, needs more
  evidence and a designed approach (most plausibly: teach the graph
  ingestion path to skip entities whose only textual context is inside an
  `[Unresolved Reference]`/`[Intelligence Gap]`-tagged span) before it's
  safe to build.

Both found by actually running a second, independently-sourced report
(NVD + FIRST.org EPSS + CISA KEV + the vendor's own advisory, all
live-queried) through the exact same real pipeline — not by re-inspecting
the first report differently.

**Update (GIEP v1) — a third report, one true positive confirmed, one new
false-positive mechanism found, two coverage gaps fixed additively:**

SA-2026-0003 (CVE-2024-27198/CVE-2024-27199, JetBrains TeamCity) is the
first report where genuine ransomware impact — not just campaign
association — was independently confirmed via primary-source vendor
telemetry (Trend Micro's own observed process tree, naming ransomware
strain "Jasmin"). Running it through `map_techniques()` mapped T1486 from
that confirmed-impact sentence, correctly this time: a real positive,
included in the published report for contrast with the two prior
incorrect mappings above. Not every T1486 mapping this platform produces
is wrong — this is the first evidenced case of the mapper getting a
ransomware-impact claim right, and it's recorded here for the same reason
the incorrect ones are: this issue should track the mapper's actual
precision, not just its failures.

A third, distinct false-positive mechanism was found in the same run,
different from both prior ones:

- **A report's own analyst-authored ATT&CK Mapping table can supply the
  false-positive text.** SA-2026-0003's table uses "Command and Control"
  as the **Tactic** column label for its T1105 row — standard ATT&CK
  terminology, not a claim that a C2 channel was used. `_LEXICON`'s
  `c2|command-and-control|beacon(?:ing)?` pattern matched that label text
  anyway and mapped T1071 (Application Layer Protocol) with no supporting
  evidence anywhere in the report. Unlike the first two findings (a hedge
  sentence with no cue word; a true association-fact conflated with an
  impact-fact), this one is self-referential: the mapper has no way to
  distinguish a document's own structural output (a table header/label) from
  prose making an evidentiary claim, because it scans the full report text
  indiscriminately. **Not fixed** — same reasoning as the other findings in
  this issue: one example, a change to shared extraction logic, needs a
  designed approach (most plausibly: exclude the "MITRE ATT&CK Mapping"
  section's own table cells from the text handed to `map_techniques()`
  during graph ingestion, since that section is this platform's own output,
  not source evidence) before it's safe to build. The published report
  documents the divergence explicitly and excludes T1071 from its own
  table; the graph's `report:sa-2026-0003 → technique:t1071` edge should be
  read accordingly.

Two narrower, purely additive gaps *were* fixed in this pass, distinguished
from the finding above by carrying no regression risk (new lookup entries,
zero changes to existing matching logic or existing reports' output):

- `attack_mapper.py KNOWN_TECHNIQUES` had T1218 (System Binary Proxy
  Execution) and its Mshta sub-technique (T1218.005) curated, but not
  T1218.007 (Msiexec) — despite `msiexec` being the exact LOLBin in this
  report's own verified attack chain. Added the technique entry and a
  `msiexec` lexicon pattern; 1 new regression test
  (`test_msiexec_maps_to_t1218_007`).
- `entities.py::LEXICON` had no entry for JetBrains, TeamCity, BianLian, or
  Jasmin — all four real, independently-verified entities central to this
  report — the same class of gap Issue 9's original SharePoint finding
  already named ("extending the lexicon is low-risk... flagged as a
  Recommendation, not attempted"). Added all four (JetBrains as vendor,
  TeamCity as product with "TeamCity On-Premises" as an alias, BianLian and
  Jasmin as malware, matching the existing convention of curating
  ransomware-strain names under the malware type rather than threat_actor).
  This module had zero test coverage before this change; added
  `tests/test_entities.py` (5 tests) covering the existing lexicon/alias
  behavior plus these four additions specifically — not full retroactive
  coverage of the whole file, which is a larger, separate task.

Net effect on this specific report: `cli.py gate` dropped its only WARN
(the T1218.007 uncurated-ID notice) after the fix, and `cli.py certify`
moved from CERTIFIED WITH CONDITIONS (both prior reports' result) to
**CERTIFIED** outright — the first report this platform has produced to
reach that verdict. Engine suite: 150 passed (was 144; +6 net: +1
attack_mapper, +5 entities).

## Issue 10 — "API Starter" is priced above "SOC Professional" despite having strictly fewer features (GCGMP v1)

Found while verifying `pricing.html` directly for the commercial growth
review, not assumed from prior session summaries. Confirmed in three
independent places, not just one: the rendered `pricing.html` feature
grid, the page's own `PLANS` JS object, and `api/_lib/payment-utils.js` —
the backend's actual charge amount and, per `docs/PRICING.md`, the sole
canonical source of truth. All three agree: Starter ₹2,499/$29, Pro (“SOC
Pro”) ₹1,499/$18, Enterprise ₹4,999/$60. This is **not** a stale-fallback
bug of the kind `docs/PRICING.md` was written to catch — every copy is
internally consistent with the documented canonical value.

The problem is the canonical value itself, relative to what each tier
includes. Pro's feature list (`pricing.html:686-712`) is a strict superset
of Starter's (`pricing.html:659-684`): 50 vs. 10 threat items/request, full
CVE descriptions vs. CVSS-only, a complete IOC feed vs. none, 25,000 vs.
5,000 API calls/day, Sigma+Yara detection rules vs. none, IOC
type/confidence filters vs. none. A rational buyer comparing the two tiers
side by side gets strictly more for 40% less money by choosing the
cheaper-looking-but-actually-pricier "Pro" over "Starter."

`docs/PRICING.md`'s own incident record explains a plausible mechanism,
not a fix: on 2026-07-17, Pro was correctly dropped from $49 to $18
everywhere it was hardcoded, following a documented, verified direction
(`OPERATIONS.md`, `AUDIT-REPORT-2026-05-28.md`). That incident's scope was
"does every copy of Pro's price match the new canonical $18" — it was not,
and by its own text was never intended to be, "does Pro's new price still
make sense relative to Starter's unchanged $29." Nothing in this
repository indicates the resulting order (Starter > Pro) was itself a
deliberate packaging decision versus an unexamined side effect of a
price cut scoped narrowly to one tier.

**Not fixed here, deliberately** — unlike this issue's engine-code
neighbors, this is not a code defect to patch: the code correctly and
consistently implements the documented canonical value in every location
`docs/PRICING.md` requires. Changing `PLANS.starter.amount` or
`PLANS.pro.amount` is a live pricing change on revenue-bearing production
infrastructure, and which of the two tiers should move (or whether the
current order is in fact intentional for reasons not recorded here) is a
business decision outside engineering's authority to make unilaterally.
Recorded here, per this file's own precedent (Issue 1's "pending
executive decision" pairings), so the finding isn't lost before that
decision is made.

## Issue 11 — Registration welcome email: built and tested, held pending activation sign-off (GECTP v1)

Closes the gap GCGMP v1 found: `api/_lib/resend.js` supported only
`addContact()` (the newsletter audience), so a user who closed the tab
after registering had no way to recover their API key — nothing emailed
it anywhere. Implemented additively: `resend.js` gained `sendEmail()`
(generic transactional send via Resend's `/emails` endpoint) and
`canSendEmail()` (true whenever `RESEND_API_KEY` is set, independent of
`RESEND_AUDIENCE_ID` — `configured()` itself is untouched and still
requires both, exactly as before, for the newsletter feature). `auth.js`
gained `buildWelcomeEmail()` and a call site in `handleRegister()` that
sends the new user's API key, tier, rate limit, and the same
dashboard/docs/upgrade URLs already in the JSON response — awaited but
error-swallowed (`.catch(() => {})`), matching this same function's
existing best-effort pattern for its analytics counters, so a Resend
outage can never fail a registration. 6 new tests
(`tests-js/registration-welcome-email.test.js`): `canSendEmail()`'s
independence from `configured()`, `sendEmail()`'s request shape, and
`buildWelcomeEmail()`'s content (API key present in both html/text,
name-present vs. anonymous greeting, all three URLs and the tier/rate
limit rendered). Full root JS suite: 50 passed (was 44).

**Deliberately not yet merged to `main`.** Everything above is implemented
and tested on the feature branch only. Merging to `main` is the step that
activates it in production — from that point, every real registration
would trigger a real, automatic email to a real address under this
company's brand, with no per-instance human review. That is a
customer-communication/business-policy activation, not a pure engineering
one, so it is held pending explicit owner sign-off rather than merged
unilaterally alongside the rest of this session's changes. If approved,
merging `claude/cti-platform-standards-f64l5x` into `main` is sufficient —
no further code change is needed to activate it.

---
*CyberDudeBivash® Sentinel APEX — Open Architectural Issues*
