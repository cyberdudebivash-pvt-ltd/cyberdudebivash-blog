# SENTINEL APEX — CONVENTIONS

> The lifecycle states below are the physical (directory) view of report
> progression. `Sentinel-APEX/eios/layer-02-intelligence-governance.md`
> defines the conceptual 10-stage view and `layer-14-release-pipeline.md`
> the governance/approval view — same process, three lenses. This file
> remains the authority for file naming, directory placement, and TLP.

## Report Identifiers
- `SA-<YYYY>-<NNNN>` — zero-padded sequential per year (e.g. `SA-2026-0042`).

## File Naming
- Reports: `SA-<YYYY>-<NNNN>-<slug>.md`
- Per-entity intelligence: `intelligence/cves/CVE-YYYY-NNNNN.md`,
  `intelligence/malware/<family>.md`, `intelligence/apt/<actor>.md`
- Detection artifacts: `<subject>_<behavior>_<yyyymmdd>.<ext>` in the matching
  library directory (`sigma/`, `yara/`, `kql/`, `suricata/`, `osquery/`).

## Lifecycle States
`drafts/` → (quality gate) → `final/` → (publish) → `published/`.
Superseded versions move to `archive/` with the date appended.

**Documentation-vs-practice gap, recorded not silently fixed (GCIEP v1,
2026-07-29)**: this 4-stage lifecycle has never actually been followed.
Git history shows SA-2026-0001 was renamed directly from `drafts/` to
`published/` (never touched `final/`, despite its own publication commit
message claiming otherwise); SA-2026-0002 and SA-2026-0003 were added
directly to `published/` and never existed under `drafts/` or `final/` in
git at all. `Sentinel-APEX/reports/final/` has contained only `.gitkeep`
since the initial scaffolding commit. No `archive/` directory exists
anywhere in the repository — no report has ever been superseded. This is
recorded as an open executive decision (see
`Sentinel-APEX/eios/sentinel-intelligence-standard.md` and the GCIEP v1
Intelligence Excellence Report's "Remaining Executive Decisions"): either
start actually using `final/`/`archive/` for future reports, or simplify
this documented lifecycle to the 2-stage `drafts/` → `published/` reality
and retire the unused stages. Neither option is chosen here.

## TLP
Default `TLP:CLEAR` for published media products. Mark higher restriction
explicitly and do not publish restricted material to the blog.

## Confidence & Labeling
Use the master-prompt taxonomy verbatim. Every non-verified claim is labeled
and confidence-scored. Never blend verified facts with assessments.

## Detection Content
- Sigma meta: include `id` (UUID), `author: CyberDudeBivash Sentinel APEX`,
  `status`, `references`, `level`.
- YARA meta: `author`, `description`, `date`, `reference`, `confidence`, `tlp`.
- Never commit invented byte patterns, hashes, or exploit payloads.

## Governance
All work follows the repository-root `CLAUDE.md` Governance Constitution and the
`quality/quality-gate.md` gate. Priority: Trust → Quality → Security → Revenue →
Scalability → Authority → Stability → Speed.
