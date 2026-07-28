# GLOBAL INTELLIGENCE AUTHORING & ANALYSIS PLATFORM (GIAAP)
## Version 1.0 — Authoring Methodology

---

## What GIAAP is, and isn't

`Sentinel-APEX/eios/` governs **what** a Sentinel APEX intelligence report
must look like: object model, quality gates, confidence dimensions,
detection maturity, editorial style. GIERQP (the review rubric applied to
SA-2026-0001) governs **how a finished report is scored** before
publication. GIAAP is the piece between them: **how an analyst produces a
report that already meets those standards**, rather than writing first and
correcting afterward.

```
Collection → Correlation → Analysis → Authoring (GIAAP) → Quality Review (GIERQP) → Publication
```

GIAAP is not a new automated pipeline. It does not generate Diamond
Models, attack graphs, or infrastructure graphs from raw feeds, and it
does not auto-publish one intelligence model into STIX/PDF/RSS/API
objects simultaneously. None of that exists in this codebase today, and
this document does not claim otherwise — see "What this is not" below for
the honest boundary. What GIAAP *is*: a documented authoring discipline —
principally, that every paragraph should answer a specific analytical
question rather than fill a template slot — plus one concrete, shipped
rule that came directly out of reviewing this platform's own published
work.

## Placement

This lives inside `Sentinel-APEX/`, a sibling to `eios/`, not at the
repository root like `eito/` — its scope is CTI report authoring
specifically, not repository-wide task execution. `eios/` stays the
canonical source for report structure and gate logic; GIAAP points to it
rather than re-specifying it.

## The authoring discipline

Structure a report around the questions it must answer, not a fixed list
of section headings to fill: What happened? How do we know? Why does it
matter? What evidence contradicts this? What remains unknown? What should
defenders do today? What should executives decide this week? A section
that cannot answer one of these in its own right is filler, regardless of
which named template slot it occupies. SA-2026-0001 — reviewed against the
full GIERQP rubric — scores well specifically because sections like "Why
This Matters" and the hunt→patch→rotate sequencing argument answer a real
question the source articles don't, not because every named section from
some template is present.

## Inline evidentiary tags

Formalized in `eios/layer-13-editorial-style-guide.md`: `[Verified Fact]`,
`[Analyst Assessment]`, `[Intelligence Gap]`, and — new in this revision —
`[Unresolved Reference — verify before next revision]`. See that file for
the full definitions; not duplicated here.

## The reference-completeness rule

The concrete rule this revision adds, found while reviewing SA-2026-0001
against GIERQP: **every narrative citation that supports a material claim
must also appear in the formal References section, or be explicitly
tagged `[Unresolved Reference]`.** Two halves, two different mechanisms:

- **Mechanically enforced today**: `quality.py`'s `_gate_reference_completeness`
  gate checks that every source declared in a report's front-matter
  `sources:` metadata is actually visible in the rendered References
  section. It found and SA-2026-0001 v1.1 fixed a real instance — the live
  NVD REST API endpoint was declared as a source but never surfaced to the
  reader.
- **Not mechanically enforceable**: a source named only in prose, with no
  metadata entry at all (SA-2026-0001's watchTowr/Defused citations), is
  not reliably detectable by pattern-matching without false-positiving on
  correctly-cited proper nouns elsewhere in the same report. This half
  stays an authoring-time discipline — the `[Unresolved Reference]` tag
  exists precisely so an analyst (human or AI) has a correct alternative
  to fabricating a citation or silently leaving one out.

## What this is not (yet)

Explicitly aspirational, not built, and not claimed as built:

- Automated Diamond Model / attack graph / infrastructure graph
  construction from raw intelligence. `api/_lib/threat-graph.js` builds a
  real, live entity graph (nodes, edges, actor attribution), but it is not
  a Diamond Model and does not construct attack-path or infrastructure
  graphs — see `platform/open-issues.md` Issue 8 for its actual, measured
  scope.
- One shared intelligence model auto-published into STIX, JSON, Markdown,
  HTML, PDF, RSS, and API objects simultaneously. Real, separate pieces of
  this exist — `api/v1/intel.js`'s `buildSTIXBundle()`, the renderer
  module's Markdown→HTML pipeline, `rss.xml` generation — but they are
  independent mechanisms, not one authoring model fanned out to many
  formats.
- Full-corpus collection against the Stage 1 source list (Shodan, Censys,
  FOFA, VirusTotal, GreyNoise, MISP, OpenCTI, etc.) for every report. This
  platform's real collection sources are documented in
  `platform/capabilities.md` and `platform/automation.md`; extending to
  the full aspirational list is a distinct, larger effort this revision
  does not attempt.

Building any of the above is a legitimate future direction, but doing so
by fabricating a demonstration report against a threat that hasn't been
independently, freshly verified would violate this platform's own
anti-hallucination standard (`_gate_hype_language`, the LLM authoring
prompt's explicit fabrication rules, and GIERQP's Stage 8 credibility
review) — worse than not building it at all.

---
*CyberDudeBivash® Sentinel APEX — Intelligence Authoring Methodology*
