> ⚠ **Superseded** — see `prompts/README.md`. Canonical equivalent:
> `Sentinel-APEX/prompts/report-prompt.md` with `audience_priority: executive`
> (see `Sentinel-APEX/prompts/master-prompt.md`'s Report Type Taxonomy table
> for the cadence-report row).

# REPORT TYPE — WEEKLY THREAT DIGEST

**Version:** 1.0 · **Layer 3** · Inherits Constitution + Production Workflow
**Use when:** producing the recurring weekly intelligence roundup.

---

## Objective
Save subscribers time. In one read, a defender should know the week's few things
that actually matter for *their* prioritization — not a link dump. Curation and
ranking are the value; comprehensiveness is not.

## Principles
- **Ruthless curation.** Include an item only if it changes a defender's
  priorities. A quiet week is a short digest, stated honestly.
- **Rank by decision impact**, not recency or drama.
- **Every item is evidence-labeled and sourced**, same as a full report.

## Section structure
1. **Week in One Line** — the single most important development.
2. **Priority Movers** — 3–7 items, each: what it is · why it matters · KEV/
   exploitation status · the one action. Ranked by impact.
3. **New KEV Additions** — CVEs added to CISA KEV this week, with vendor/product
   and remediation deadline (straight from the catalog).
4. **Ransomware & Actor Activity** — notable, evidence-backed only; label claims.
5. **AI Security Watch** — one or two framework-grounded AI-security items.
6. **Quiet-but-Watch** — low-urgency items worth monitoring, with why.
7. **Intelligence Gaps** — what we're still tracking / cannot yet confirm.
8. **Sources** — every item links to its primary source.

## Cadence honesty
Publish on the real cadence. Never pad a slow week with filler to hit a length —
a credible "little of enterprise significance changed this week; here is the one
thing to watch" is more valuable than manufactured volume.

## Do not
- Include items purely for volume. · Repeat vendor marketing as intelligence.
- Restate last week without new decision value.
