# Commercial Quality — Round 2: Verified Live Defects

**Trigger:** External review (ChatGPT) of 4 live-published reports, cross-checked directly against the real, currently-live pages at `cti.cyberdudebivash.in` before writing any code — not accepted secondhand.

## What was independently re-verified against the live site (not just the transcript)

Fetched `cti.cyberdudebivash.in/2026/08/cve-2026-75105-cvss-75-high-severity.html` directly. Confirmed on the real page:
- `Vulnerability class: Unclassified` despite `CWE-639` being present in the same report.
- `Vulnerability Manager: Monitor per "not confirmed by available evidence; not in verified kev snapshot" status...` — grammatically broken, mid-sentence variable interpolation.
- `Public reference draft — not a certified customer deliverable` — expected; the fix for this (PR #93) was tested and ready but had not been merged yet. **Merged now** — first action this round.

## Four real defects fixed, each independently confirmed (code trace + live reconstruction), not assumed from the transcript

1. **`CWE-639` was missing from `_CWE_CLASS`** (`automation/report_integrity.py`) — the dict-lookup path that should have classified it never had an entry, so a report with a clearly-named weakness fell through to `Unclassified`. This isn't cosmetic: `report_renderer.py` branches its technical-evidence and IOC-generation logic on `vulnerability_class` (e.g. the `authorization_failure` branch) — the misclassification also silently cost the report that class's technical depth, which is part of why this and similar reports read as shallow. Added the mapping (`CWE-639 → authorization_failure`, the same class as the existing `CWE-862`).

2. **`ransomware_claim` was still in `_VULNERABILITY_MANAGER_FAMILIES`** (`pipeline_composer.py`) — confirmed directly in the merged code, not just the transcript. An unverified leak-site victim claim has no CVE, no patch, no exploitation-status dimension — it is not a vulnerability-management concern, and the existing IR Manager decision already covers it correctly. Removed. (This is the exact gap PR #91's own fix left behind — it fixed the phishing/PhaaS case but not the structurally identical ransomware-claim case.)

3. **Role labels were mangled by `str.title()` on the raw enum value** — "Ir Manager", "Soc Manager", "Ciso Cio", "Ot Team", "Mssp" instead of the correct acronym-aware forms. Two separate render call sites had this bug (`executive_products.py`'s markdown renderer and `pipeline_composer.py`'s HTML renderer); fixed once, at the source (`ROLE_DISPLAY_LABELS`, a single lookup table both now call), so it can't drift back out of sync between them.

4. **The Vulnerability Manager decision sentence was grammatically broken for most real exploitation-status values** — `f"...severity commensurate with {exploitation_label.lower()}."` only reads correctly when `exploitation_label` happens to be a short adjectival phrase. For the actual, common value `"Not confirmed by available evidence; not in verified KEV snapshot"` it produced exactly the broken sentence seen live. Restructured to present exploitation and patch status as their own clauses (`"Exploitation status: {X}. Patch status: {Y}."`), which is grammatically correct for every current and future value — not a one-off string patch for this specific phrase.

## Verification

- 1232 tests pass across the full repo (root + `Sentinel-APEX/engine`); the one failure is the same pre-existing, environment-only gap already documented in PRs #91/#92/#93.
- Live reconstruction of the exact CVE-2026-75105 evidence: `vulnerability_class` now `authorization_failure` (was `unclassified`); role text now reads "Exploitation status: Not confirmed by available evidence; not in verified KEV snapshot. Patch status: ..." (was the broken "severity commensurate with..." sentence).
- Live reconstruction of a ransomware victim-claim: no "Vulnerability Manager" section at all; "IR Manager" renders with correct capitalization.

## Explicitly not attempted in this round (real gaps, not fixed here)

Source expansion/corroboration engine, the two-axis Admiralty reliability model (Source Reliability A-F separate from Information Credibility 1-6), historical/campaign correlation for "Related Intelligence," ATT&CK justification depth, the expanded report-family set, and the numeric 100-point scoring model are all real, substantial, separate efforts — each comparable in size to one of the four fixes above, each deserving its own evidence-first pass rather than being rushed in behind these. Not silently dropped; not implemented here either.
