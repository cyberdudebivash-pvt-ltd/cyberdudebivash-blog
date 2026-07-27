# EIOS LAYER 8 — REPORT VERSION CONTROL

Extends the existing front-matter contract (`prompts/report-prompt.md` §
Output Contract) with version-control metadata. This is additive: every
field already required there (`title`, `report_id`, `date`, `tlp`,
`report_type`, `threat_actors`, `malware_families`, `cves`, `sectors`,
`attack_ids`, `overall_confidence`, `sources`) stays exactly as defined. The
fields below are new keys in the same YAML block, not a new file or a new
contract.

## New front-matter fields

```yaml
version: "1.0"
last_updated: "<YYYY-MM-DD>"
supersedes: "<prior report_id, or null>"
review_status: "<draft|technical-review|detection-review|intelligence-review|editorial-review|executive-approval|published>"
analyst: "<name or handle>"
reviewer: "<name or handle, or null if not yet reviewed>"
change_log:
  - version: "1.0"
    date: "<YYYY-MM-DD>"
    change: "Initial publication"
```

## Field semantics

| Field | Rule |
|---|---|
| `version` | Semantic-ish: increment the minor version (1.0 → 1.1) for a correction or new evidence; increment the major version (1.0 → 2.0) only when the assessment or attribution materially changes |
| `last_updated` | Every time the report content changes, even a typo fix — this is what Layer 11's "living intelligence" model depends on to show staleness |
| `supersedes` | Set when this report replaces an earlier one on the same subject; the earlier report moves to `archive/` per `docs/CONVENTIONS.md`, it is not deleted |
| `review_status` | One of Layer 14's release-pipeline stages — see that layer for the full gate sequence |
| `analyst` / `reviewer` | Accountability, not blame — required so a question about a specific claim has a named person to ask |
| `change_log` | Append-only. Never rewrite a prior entry — if an earlier change_log entry was wrong, add a new entry correcting it |

## Why this doesn't touch the physical storage lifecycle

`docs/CONVENTIONS.md`'s `drafts/` → `final/` → `published/` → `archive/`
directory lifecycle already tracks *where* a report is. `version` /
`change_log` track *what changed and when* within that lifecycle — a report
can move from `final/` to `published/` without its version changing, and a
published report can get a `version: "1.1"` correction without moving
directories. These are orthogonal, not competing, mechanisms.

## Cross-reference

`prompts/report-prompt.md`'s Output Contract now points here for the
version-control fields — see the one-line addition to its `report_type`
row's neighbor fields.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 8*
