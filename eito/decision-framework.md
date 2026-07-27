# EITO — DECISION FRAMEWORK & DELIVERABLE CONTRACT

## Mandatory Decision Framework

`CLAUDE.md` already has a 4-question Implementation Decision Framework
(minimal change surface? equivalent logic exists? blast radius? evidence?).
The questions below merge with it rather than sitting beside it as a second
checklist — three are the same question, three are genuinely new:

| # | Question | New, or same as `CLAUDE.md`? |
|---|---|---|
| 1 | Does this already exist? | Same as CLAUDE.md Q2 |
| 2 | Can it be extended instead of rebuilt? | Same idea, restated as the resulting action |
| 3 | Does it preserve compatibility? | Same as CLAUDE.md Q3 (blast radius) |
| 4 | Does it improve maintainability? | **New** |
| 5 | Does it increase customer value? | **New** |
| 6 | Does it reduce operational complexity? | **New** |
| 7 | Is there sufficient evidence to support this recommendation? | Same as CLAUDE.md Q4 |

Run all seven, once, per task — not the CLAUDE.md four and then these seven
again as a separate pass. If any answer is negative, the recommendation must
say why the proposed approach is still appropriate despite that — a
negative answer is not automatically disqualifying, but it is never silent.

## Enterprise Deliverable Contract

`CLAUDE.md` already mandates a Reuse Report (a metrics table: components
reused, duplicates introduced — must be 0, backward compatibility PASS/FAIL,
build PASS/FAIL) at the end of every implementation. The contract below is
not a second, competing summary — the Reuse Report's table is the evidence
that belongs inside this contract's Technical Assessment section. Produce
one document, not two.

Every significant task concludes with:

1. **Executive Summary** — what was accomplished, in the terms Stage 1's
   audience answer identified. One paragraph.
2. **Architecture Summary** — what changed and why. For an architectural
   change (`CLAUDE.md`'s Architecture Preservation Rule sense), this is
   Stage 4's Solution Architecture output restated concisely, not
   re-derived.
3. **Technical Assessment** — benefits, constraints, trade-offs, **and the
   `CLAUDE.md` Reuse Report table** (existing components reused / new
   components introduced / duplicates introduced — must be 0 / backward
   compatibility / build status).
4. **Operational Considerations** — testing actually performed (Stage 7's
   sharp clause: only what was actually run), deployment path, monitoring,
   rollback, maintenance.
5. **Commercial Assessment** — customer value, market differentiation,
   monetization opportunity, *where relevant* — a pure refactor with no
   customer-facing surface can say so and skip the elaboration, not
   manufacture a commercial angle that doesn't exist.
6. **Future Work** — logical next steps, named specifically (Stage 10)
   rather than "continue monitoring" as unfalsifiable filler — the same
   anti-padding rule EIOS Layer 11 applies to intelligence reports applies
   here to engineering reports.

## When to use the full contract vs. a short answer

Not every task warrants all six sections. A one-line question gets a
one-line answer — the system prompt's own guidance on matching response
length to the question already governs this, and EITO does not override it.
The full contract applies to "significant tasks": anything that already
triggered Stage 4 (Solution Architecture) or touched more than a couple of
files. Forcing six headers onto a two-line fix is the same failure mode as
padding an intelligence report's Future Outlook section with boilerplate.

---
*CyberDudeBivash® Sentinel APEX — EITO Decision Framework*
