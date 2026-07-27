# EITO — THE 10-STAGE EXECUTION LIFECYCLE

Every non-trivial task moves through these stages. Most are not new
inventions — `CLAUDE.md` already mandates the underlying mechanism for most
of them; this lifecycle names the stage and points to where the mechanism
already lives, rather than re-specifying it. Two stages (1 and, in its
sharpest clause, 7) are genuinely new and are elaborated below the table.

| # | Stage | Existing mechanism it invokes |
|---|---|---|
| 1 | Mission Understanding | **New** — no existing repo mechanism does task-intake triage explicitly |
| 2 | Repository Intelligence | `CLAUDE.md` Principle 4 (Reuse Before Build) + Implementation Decision Framework Q2, made procedural |
| 3 | Impact Analysis | `CLAUDE.md` Production Blast Radius Assessment (technical/commercial) + EIOS Layers 4/7/10 (intelligence-specific impact) |
| 4 | Solution Architecture | `CLAUDE.md` Architecture Preservation Rule's required documentation set |
| 5 | Implementation Plan | `CLAUDE.md` Proof Before Change table + the `TaskCreate`/`TaskUpdate` tools |
| 6 | Intelligence Validation | EIOS Layer 4 (`quality.py`'s executable gates) |
| 7 | Engineering Validation | `CLAUDE.md`'s QA pipeline + Principles 5/6 — **plus a new, sharper rule below** |
| 8 | Commercial Evaluation | `CLAUDE.md` Level 7 (Commercial Value) + Enterprise Revenue Intelligence Layer + EIOS Layer 10 |
| 9 | Enterprise Readiness Review | Right-sized version of `CLAUDE.md`'s 15-dimension God-Mode gate (see below) |
| 10 | Continuous Improvement | `CLAUDE.md`'s Continuous Self-Improvement Engine + EIOS Layer 11 (CTI-specific) |

## Stage 1 — Mission Understanding (new)

Before producing anything, answer explicitly — not silently assume:

- What is the requested deliverable, concretely?
- Who is the audience (see EITO `modes.md` for how audience maps to mode)?
- Is the objective strategic, operational, tactical, or technical?
- What evidence is already available, and what is missing?
- What assumptions would be required to proceed, and are they safe to make
  or do they need to be surfaced first?

State assumptions as assumptions. An assumption silently treated as
established fact is exactly the failure mode EIOS Layer 2 prohibits in
intelligence content — the same discipline applies to task intake.

## Stage 2 — Repository Intelligence

Before proposing a change, check, in this order: existing implementation →
existing architecture → existing quality gates → existing templates →
existing object models → existing validators → existing report schemas →
existing APIs → existing workflows. Only then decide: extend, refactor,
replace, or build new — in that order of preference
(`CLAUDE.md` Principle 4's reuse priority order).

**Do this before opening an editor**, not as a mental afterthought — see
`eito/README.md`'s worked example: this exact stage, applied retroactively,
found a duplicate CTI prompt architecture two conversation turns had missed.

## Stage 7 — Engineering Validation: the sharp clause

> **Claude should not claim that tests passed or deployments succeeded
> unless that information is actually available.**

This is stricter than it sounds and is the one clause in this entire
document worth memorizing over the others: it prohibits stating a test
result from memory of an earlier run, inferring "should pass" from reading
code, or writing "tests passing" as a formality. Only a freshly executed
command in the current context counts as "available." In practice, this
means re-running the full suite after every code change in the same task —
not once at the start — because a later edit can silently invalidate an
earlier green result.

## Stage 9 — Enterprise Readiness Review (right-sized)

`CLAUDE.md`'s God-Mode Release Governance (15 dimensions) remains the
mandatory final gate immediately before a production push. This stage is
the lighter-weight version for everything before that moment — a design
review, a mid-flight architecture proposal, a documentation deliverable that
isn't shipping to `main` today. Mark each item complete, pending, or N/A;
don't force God-Mode's full pass/fail rigor onto work that isn't a
production push yet, and don't skip this lighter check just because it
isn't:

- [ ] Architecture complete
- [ ] Documentation complete
- [ ] Quality gates defined
- [ ] Operational guidance available
- [ ] Security considerations addressed
- [ ] Release notes prepared

---
*CyberDudeBivash® Sentinel APEX — EITO Lifecycle*
