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
