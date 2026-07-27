# EIOS LAYER 11 — CONTINUOUS INTELLIGENCE

A report is not finished at publication. This extends the two existing v1
report sections that already gesture at this (`prompts/master-prompt.md` §
56 Future Outlook, § 57 Intelligence Gaps) into an explicit, checkable
post-publication contract.

## Required fields (extend, don't replace, sections 56–57)

Add to the existing Intelligence Gaps / Future Outlook sections:

- **Known Unknowns** — what would change the assessment if learned; more
  specific than a generic "attribution is uncertain." State the exact
  missing evidence (e.g., "no sample obtained — capability list is
  inferred from vendor advisory prose only").
- **Monitoring Priorities** — the specific indicators, entities, or CVEs
  this report's analyst will watch going forward. This is the operational
  link to Layer 9: monitoring priorities are exactly the entities that
  should be queried against `KnowledgeGraph.prior_context()` on every new
  ingest.
- **Triggers for Update** — concrete conditions that require revising this
  report: a patch shipping, a second victim confirmed, a decryptor released,
  attribution firming from `LIKELY` to `VERIFIED FACT`. Not "if something
  changes" — name the specific something.
- **Revision History** — human-readable narrative companion to Layer 8's
  machine-parseable `change_log` front-matter field. The front matter says
  *what* changed structurally; this says *why*, in prose, for a reader who
  won't parse YAML.

## Operational loop

```
Publish → Monitoring Priorities watched (Layer 9 graph queries)
        → Trigger condition met
        → New evidence enters via Layer 2 Stage 1 (Collection)
        → Correlated against this report (Stage 3, prior_context)
        → Revision drafted: version bump (Layer 8), supersedes prior
          report_id if the assessment materially changed
        → Superseded version archived (docs/CONVENTIONS.md), never deleted
```

This closes Layer 2's 10th lifecycle stage (Continuous Updates), which
`pipeline/WORKFLOW.md`'s 8-stage operational pipeline does not yet name
explicitly — WORKFLOW.md's `archive/` step is the mechanical result of this
loop, not the loop itself.

## Anti-pattern

A report with an empty or boilerplate "Future Outlook" section
("developments will continue to be monitored") fails this layer even if it
passes every other gate — this is exactly the kind of unfalsifiable filler
the platform's mission (Layer 1) prohibits. If there is genuinely nothing
specific to monitor, say why, don't pad the section.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 11*
