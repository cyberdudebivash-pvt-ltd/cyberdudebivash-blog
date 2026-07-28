# EIOS LAYER 4 — PRODUCTION QUALITY GATES

Automated, executable validation. A report that fails a blocking gate is not
publication-ready — no exception, no override. This layer is implemented
today in `engine/sentinel_engine/quality.py`, invoked via
`python3 cli.py gate <report...>` (exits non-zero on any blocking finding).
It is not a checklist for a human to eyeball; it is code with tests
(`engine/tests/test_quality.py`).

## Gates implemented before this EIOS revision

| Gate | Function | Severity |
|---|---|---|
| Required sections present | `_gate_structure` | block |
| Severity / title present | `_gate_structure` | block |
| ATT&CK mapping present | `_gate_attack` | block |
| ATT&CK technique ID recognized | `_gate_attack` | warn (unverifiable offline, not necessarily wrong) |
| Live (undefanged) network IOC in IOC section | `_gate_ioc_defanging` | block |
| Sigma rule present but unparseable | `_gate_sigma` | block |
| Sigma required fields / valid level / condition references / unknown ATT&CK tag | `validate_sigma` (called from `_gate_sigma`) | block |
| Sigma tag not present in report's own ATT&CK mapping | `_gate_sigma` | warn |
| Assessment language without a confidence label | `_gate_confidence` | block |
| Scraper/aggregator noise leaked into Technical Analysis | `_gate_content_integrity` | block |
| Technical Analysis too thin (source passthrough) | `_gate_content_integrity` | warn |
| Executive Summary is a verbatim copy of the analysis opening | `_gate_content_integrity` | warn |
| Identical Sigma rule published across unrelated reports | `gate_corpus` | block |
| Near-duplicate ATT&CK/IOC/Hunting sections across reports (≥80% shingle similarity) | `gate_corpus` | warn |
| Same indicator reused across unrelated reports | `gate_corpus` | warn |

## Gates added by this EIOS revision

The v2 specification asked for YARA syntax validation, missing-evidence
detection, empty detection sections, duplicate indicators, and STIX schema
validation. Each was checked against what already existed before writing
code, to avoid a parallel validator:

| New gate | Function | Severity | Why it was a real gap |
|---|---|---|---|
| YARA rule present but invalid (unbalanced braces, missing required sections/meta fields) | `_gate_yara` | block | `malware-prompt.md` and `docs/CONVENTIONS.md` both *require* YARA meta fields (`author`, `description`, `date`, `reference`, `confidence`, `tlp`), but nothing checked them — Sigma had `validate_sigma`, YARA had nothing. |
| Detection section header present but body empty/whitespace-only | `_gate_empty_detection` | block | A heading with no content is worse than an omitted section — it implies coverage that isn't there. |
| STIX bundle present but structurally invalid (not a `bundle` object, missing `objects[]`, or an object missing `type`/`id`/`spec_version`) | `_gate_stix` | block | STIX/TAXII was added as an optional output in the v1 update (`master-prompt.md` § Technical Depth) with no validation. This is a **structural** check, not full STIX 2.1 schema validation — no new dependency was added to keep `dependencies: {}` in `package.json` and the Python engine's minimal `pyyaml`+`pytest` footprint intact. Full schema validation is a documented future increment if STIX output volume justifies a dedicated library. |
| Superlative/hype language (`unprecedented`, `catastrophic`, ...) | `_gate_hype_language` | warn | Absorbed from the deprecated root `prompts/20-editorial-qa.md`'s "Automated failure detectors" during the `/prompts/` consolidation — this was a genuinely new, never-implemented check. `warn`, not `block`: a heuristic word match can false-positive on a report quoting a source's own hyperbolic language for critique. |
| "Actively exploited" / "in the wild" claim with no CISA KEV or citation in the same section | `_gate_hype_language` | warn | Same absorption. `warn` for the same reason — the citation-proximity check is heuristic, not a guarantee the claim is actually uncited. |

The "duplicate indicators" ask above is satisfied by `gate_corpus`'s existing
cross-report IOC-reuse check (first table) — a per-report, cross-category
consistency check (e.g. the same value marked both "Confirmed" and
"Historical") would need the `IOC` model to carry a category field, which it
does not; this table previously and incorrectly claimed such a gate
(`_gate_ioc_consistency`) existed. Corrected here rather than left stale —
building that model change is a new feature, out of scope for a
certification-of-what-exists pass (EICF v1).

All four are additive functions appended to `gate_report()`'s call list in
`quality.py`, following the exact pattern of the existing gates (small,
focused `_gate_x(report) -> list[GateFinding]` functions). None of them can
retroactively fail existing content: `reports/{drafts,final,published}/`
contain no reports today (verified — only `.gitkeep` placeholders), and no
CI workflow invokes `cli.py gate` automatically, so this is additive tooling
available on demand, not a new build-breaking check.

## Relationship to Layer 10 (Commercial Readiness)

`quality.py` answers **"is this report correct and safe to publish"** — a
binary, blocking gate. It is deliberately separate from `scoring.py`, which
answers **"how valuable is this report and to which commercial tier does it
belong"** — a graded, weighted score. `pipeline.py::run()` composes both:
a report is publication-eligible only when the score clears its threshold
**and** the quality gate passes (`eligible = overall >= threshold and
gate_passed` in `scoring.py::score()`). Correctness is a precondition for
value, never a trade-off against it — see Layer 10 for the scoring engine
itself.

## Running the gate

```
cd Sentinel-APEX/engine
python3 cli.py gate reports/drafts/SA-2026-0042-example.md
```

Exit code 0 = no blocking findings (warnings may still be present and should
be reviewed). Exit code 1 = blocking finding(s) — return to draft.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 4*
