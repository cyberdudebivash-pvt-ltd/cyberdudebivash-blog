# EIOS LAYER 13 — EDITORIAL STYLE GUIDE

Cross-references `prompts/master-prompt.md` § Writing Style — this layer
does not restate it, only adds what v1 left implicit.

## Carried forward from v1 (unchanged)

Professional, authoritative, analytical, objective, evidence-driven,
executive-friendly, technically accurate. Never sensational, never
clickbait, never exaggerated. Avoid unnecessary adjectives.

## Added by this revision

### Consistent terminology has a canonical source — use it, don't invent one

`engine/sentinel_engine/entities.py`'s `LEXICON` is the single source of
truth for canonical actor and malware names and their known aliases (e.g.
canonical `APT28`, aliases `Fancy Bear` / `Forest Blizzard` / `Sofacy`;
canonical `APT29`, aliases `Cozy Bear` / `Midnight Blizzard` / `Nobelium`).
When a report mentions a name in the lexicon, use the
canonical form on first reference and may use an alias afterward, but never
introduce a *new* spelling or alias not already in the lexicon without
extending the lexicon first — a report inventing its own naming convention
for an actor Sentinel APEX already tracks is exactly the "two code paths,
same output" problem CLAUDE.md's Single Source of Truth principle
prohibits, applied to prose.

If a report needs to name an actor or malware family not yet in the
lexicon, that is real signal the lexicon should be extended
(`entities.py::LEXICON`) — not a reason to write around it.

### Confirmed vs. assessed language must match its Layer 2 label

"Confirmed," "established," and "known" are reserved for claims labeled
`VERIFIED FACT`. "Likely," "assessed," and "appears to" are reserved for
labeled assessments. Do not use confirmatory language to hedge, and do not
use hedging language for a claim the source directly states — both are
editorial defects, not style preferences, because the words themselves are
what a reader (and the Layer 4 gate) uses to detect an unlabeled assessment.

### Inline evidentiary tags (GIAAP v1)

SA-2026-0001 established, in practice, a bracket-tag convention for marking
each claim's evidentiary status inline rather than only in a summary table:
`[Verified Fact]`, `[Analyst Assessment]`, and `[Intelligence Gap]`, each
paired with a confidence level where applicable. This was never written
down as a standard — it existed only as one report's practice. Formalizing
it here so future hand-authored reports follow it consistently rather than
reinventing their own convention:

- `[Verified Fact] (HIGH CONFIDENCE)` — directly stated or confirmed by a
  cited source.
- `[Analyst Assessment] (LOW/MEDIUM/HIGH CONFIDENCE)` — inferred, not
  directly stated; the confidence level reflects how strongly the
  inference is supported.
- `[Intelligence Gap]` — explicitly state what is not known rather than
  leaving a claim's absence ambiguous or silently omitting it.
- `[Unresolved Reference — verify before next revision]` — new in this
  revision. Use when a source is named in prose (e.g., a researcher or
  vendor cited for a specific finding) but a formal, checkable reference
  entry could not be located or verified at authoring time. This is the
  correct alternative to either fabricating a plausible-looking citation
  or silently leaving the claim uncited — found as a real gap in
  SA-2026-0001 v1.0 (two named sources, watchTowr and Defused, cited in
  prose with no reference entry; fixed in v1.1 for the one that had a
  locatable URL, see its change_log) and formalized as a standing rule:
  every narrative citation supporting a material claim must either appear
  in the References section or carry this tag.

The mechanically-checkable half of this rule (a source declared in
front-matter metadata but not visible in the rendered References section)
is enforced automatically by `quality.py`'s `_gate_reference_completeness`
gate. The bare-name-citation half (no metadata entry at all) is not
reliably automatable without excessive false positives on proper nouns
that are correctly cited elsewhere — it remains an authoring-time
discipline, checked by whoever authors or reviews the report.

### One severity vocabulary

Severity words (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`) come from
`report_parser.py::SEVERITIES` — the same four words the gate checks for.
Don't introduce "Severe," "Elevated," or other synonyms; they will not be
recognized by `_gate_structure` and the report will fail the gate on a
wording choice, not a substance problem.

### Numbers over adjectives

"Significant exposure" is not a claim; "412 internet-facing hosts running
the affected version" is. Where CONVENTIONS.md or the CVE prompt's
prioritization model already produces a number (CVSS, EPSS, host count),
use it instead of an adjective.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 13*
