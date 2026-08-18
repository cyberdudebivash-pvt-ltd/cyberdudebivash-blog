"""Reviewer pack generator (ReportX Section 44 human-review workflow,
task-list item #10/#50).

Renders a human-readable Markdown briefing from the SAME artifact
`reportx-gate --export` produces -- every fact here is read directly out
of that JSON, never recomputed. A reviewer must be able to assess the
artifact from this document alone, without reading Python source.
"""

from __future__ import annotations

import hashlib


def _artifact_sha256(rendered_text: str) -> str:
    return hashlib.sha256(rendered_text.encode("utf-8")).hexdigest()


def _fmt_list(items: list, empty: str = "_none_") -> str:
    if not items:
        return empty
    return "\n".join(f"- {i}" for i in items)


def render_reviewer_pack_markdown(export: dict, render_preview_path: str | None = None,
                                   previous_export: dict | None = None) -> str:
    bundle = export["bundle"]
    cr = export["commercial_readiness"]
    artifact_hash = _artifact_sha256(bundle["rendered_text"])

    lines: list[str] = []
    lines.append(f"# Reviewer Pack — {bundle['report_id']}")
    lines.append("")
    lines.append(f"**Artifact SHA-256:** `{artifact_hash}`")
    lines.append(f"**Premium tier:** {bundle['is_premium_tier']}")
    if render_preview_path:
        lines.append(f"**Render preview:** `{render_preview_path}`")
    lines.append("")

    lines.append("## 23-Control Commercial Readiness Matrix")
    lines.append("")
    lines.append(f"**{cr['pass_count']} / {cr['total_count']} PASS — {cr['verdict']}**")
    lines.append("")
    lines.append("| # | Control | Status | Evidence |")
    lines.append("|---|---|---|---|")
    for i, c in enumerate(cr["controls"], start=1):
        lines.append(f"| {i} | {c['name']} | {c['status']} | {c['evidence']} |")
    failing = [c for c in cr["controls"] if c["status"] != "PASS"]
    if failing:
        lines.append("")
        lines.append("**Rows not PASS:**")
        for c in failing:
            lines.append(f"- **{c['name']}** ({c['status']}): {'; '.join(c['failures']) if c['failures'] else c['evidence']}")

    lines.append("")
    lines.append("## Sources")
    lines.append("")
    lines.append("| Source ID | Publisher | Type | Reliability | URL |")
    lines.append("|---|---|---|---|---|")
    for s in bundle["sources"]:
        lines.append(f"| {s['source_id']} | {s['publisher']} | {s['source_type']} | {s['reliability']} | {s['url']} |")

    lines.append("")
    lines.append("## Material Claims")
    lines.append("")
    lines.append("| Claim ID | Type | Status | Corroboration | Evidence/Source Refs |")
    lines.append("|---|---|---|---|---|")
    for c in bundle["claims"]:
        refs = list(c.get("evidence_refs", [])) + list(c.get("source_refs", []))
        lines.append(f"| {c['claim_id']} | {c['claim_type']} | {c['status']} | "
                      f"{c.get('corroboration_state', 'UNCORROBORATED')} | {', '.join(refs) or '—'} |")

    lines.append("")
    lines.append("## Threat Products")
    lines.append("")
    if bundle["threat_products"]:
        for tp in bundle["threat_products"]:
            lines.append(f"- `{tp['product_id']}` ({tp['threat_type']})")
    else:
        lines.append("_none_")

    lines.append("")
    lines.append("## Statistics (Metrics Registry)")
    lines.append("")
    if bundle["metrics"]:
        lines.append("| Metric ID | Name | Value | Unit | Source | Retrieved |")
        lines.append("|---|---|---|---|---|---|")
        for m in bundle["metrics"]:
            lines.append(f"| {m['metric_id']} | {m['name']} | {m['value']} | {m['unit']} | {m['source']} | {m['retrieved_at']} |")
    else:
        lines.append("_none_")

    lines.append("")
    lines.append("## Regulatory Determinations")
    lines.append("")
    if bundle["regulatory_applicabilities"]:
        for r in bundle["regulatory_applicabilities"]:
            lines.append(f"- **{r['regulation']}**: {r['applicability_state']} — {r['basis'] or '(no basis recorded)'}")
    else:
        lines.append("_none_")

    lines.append("")
    lines.append("## Detection Status")
    lines.append("")
    if bundle["detection_rules"]:
        for d in bundle["detection_rules"]:
            extra = f" — withheld: {d['evidence_gap_rationale']}" if d.get("evidence_gap_rationale") else ""
            lines.append(f"- `{d['rule_id']}` ({d['technique_id']}, {d['format']}): {d['validation_state']}{extra}")
    else:
        lines.append("_none_")

    lines.append("")
    lines.append("## Forecasts")
    lines.append("")
    if bundle["forecasts"]:
        for f in bundle["forecasts"]:
            if f.get("withheld"):
                lines.append(f"- WITHHELD ({f['topic']}): {f['reason']}")
            else:
                lines.append(f"- {f['judgment']} (confidence: {f.get('confidence', '—')}) — {f.get('confidence_rationale', '')}")
    else:
        lines.append("_none_")

    lines.append("")
    lines.append("## Alternative Hypotheses")
    lines.append("")
    if bundle["hypothesis_sets"]:
        for hs in bundle["hypothesis_sets"]:
            if hs.get("applicable") is False:
                lines.append(f"- N/A — {hs['question']}: {hs['rationale']}")
            else:
                lines.append(f"- {hs['question']} ({len(hs.get('hypotheses', []))} hypotheses)")
    else:
        lines.append("_none_")

    lines.append("")
    lines.append("## Known Intelligence Gaps")
    lines.append("")
    lines.append(_fmt_list([g["description"] for g in bundle["intelligence_gaps"]]))

    if bundle.get("review"):
        lines.append("")
        lines.append("## Existing Review Record")
        lines.append("")
        r = bundle["review"]
        lines.append(f"- Decision: {r['decision']} by {r['reviewer_identity']} ({r.get('reviewer_role', '—')}) at {r['review_timestamp']}")
        lines.append(f"- Bound artifact SHA-256: `{r['artifact_sha256']}`")
        lines.append(f"- **{'MATCHES' if r['artifact_sha256'] == artifact_hash else 'STALE — DOES NOT MATCH'}** current artifact.")

    if previous_export is not None:
        lines.append("")
        lines.append("## Changes Since Previous Artifact")
        lines.append("")
        prev_hash = _artifact_sha256(previous_export["bundle"]["rendered_text"])
        if prev_hash == artifact_hash:
            lines.append("No change — identical rendered text.")
        else:
            prev_pass = previous_export["commercial_readiness"]["pass_count"]
            lines.append(f"Artifact changed (`{prev_hash[:12]}…` → `{artifact_hash[:12]}…`). "
                          f"Gate result: {prev_pass}/{previous_export['commercial_readiness']['total_count']} "
                          f"→ {cr['pass_count']}/{cr['total_count']}.")

    return "\n".join(lines) + "\n"
