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
