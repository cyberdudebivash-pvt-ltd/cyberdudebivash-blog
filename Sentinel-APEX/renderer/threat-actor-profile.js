'use strict';
/**
 * SENTINEL APEX — Threat Actor Profile Renderer (GTIEP v1)
 *
 * Populates Sentinel-APEX/templates/threat-actor/threat-actor-profile.md
 * FROM the platform's own curated actor records
 * (api/_lib/threat-graph.js's THREAT_ACTOR_DB — 8 real, sourced actors),
 * rather than inventing new threat-actor content. This is the first
 * subject-type report template GTIEP v1 asks for that's actually built
 * (platform/gtiep-v1-audit.md item 9), and it closes report structure's
 * "Threat Actor Analysis" gap (item 1) with real data.
 *
 * Deliberately partial by design: fields the curated DB actually has
 * (identity, targeting, TTP IDs, known CVEs, description, refs) are
 * populated directly. Fields that need analyst judgment and don't exist
 * in the curated data today — campaign narrative beyond the one-paragraph
 * description, per-technique hunting guidance, confidence ratings,
 * intelligence gaps — are left as the template's own `<...>` placeholders.
 * Filling those in with invented content would be exactly the fabrication
 * this platform's content governance prohibits.
 */

function escMd(str) {
  return String(str == null ? '' : str).replace(/\|/g, '\\|');
}

function todayISO() {
  return new Date().toISOString().slice(0, 10);
}

function formatList(arr) {
  return Array.isArray(arr) && arr.length ? arr.map((x) => escMd(x)).join(', ') : '<none curated>';
}

/**
 * @param {object} actorEntry - one value from THREAT_ACTOR_DB, e.g.
 *   THREAT_ACTOR_DB['actor:lockbit']
 * @param {object} [opts]
 * @param {string} [opts.reportId] - e.g. 'SA-TA-2026-0001'; left as a
 *   template placeholder if omitted, since report-ID sequencing is a
 *   separate, existing platform convention this function shouldn't invent
 * @returns {string} full Markdown document, front matter included
 */
function buildThreatActorProfileMarkdown(actorEntry, opts = {}) {
  if (!actorEntry || !actorEntry.attributes) {
    throw new Error('threat-actor-profile.buildThreatActorProfileMarkdown: actorEntry with .attributes is required');
  }
  const a = actorEntry.attributes;
  const name = actorEntry.name || 'Unknown Actor';
  const reportId = opts.reportId || 'SA-TA-<YYYY>-<NNNN>';
  const status = a.active === true ? 'active' : a.active === false ? 'dormant' : '<unknown>';

  const ttpRows = (a.ttps || []).map((id) =>
    `| ${escMd(id)} | <look up technique name> | <cite the specific incident/behavior, if known> |`
  ).join('\n');

  const cveRows = (a.known_cves || []).map((id) =>
    `| ${escMd(id)} | <initial access \\| privilege escalation \\| ...> | <cite the specific campaign/incident, if known> |`
  ).join('\n');

  const sources = (a.refs || []).map((url) => `- ${escMd(url)}`).join('\n') || '<none curated>';
  const attackIdsYaml = (a.ttps || []).length
    ? `\n${(a.ttps || []).map((id) => `  - "${escMd(id)}"`).join('\n')}`
    : ' []';

  return `---
title: "${escMd(name)} — Threat Actor Profile"
report_id: "${escMd(reportId)}"
date: "${todayISO()}"
tlp: "TLP:CLEAR"
audience: "soc"
attack_ids:${attackIdsYaml}
overall_confidence: "<VERY LOW|LOW|MEDIUM|HIGH|VERY HIGH>"
---

# ${escMd(name)} — Threat Actor Profile

## Executive Summary
${a.description || '<no curated description available — do not fabricate one>'}

## Identity

| Field | Value |
|---|---|
| Primary name | ${escMd(name)} |
| Known aliases | ${formatList(a.aliases)} |
| Category | ${escMd(a.category || '<uncurated>')} |
| Motivation | ${escMd(a.motivation || '<uncurated>')} |
| Sophistication | ${escMd(a.sophistication || '<uncurated>')} |
| Suspected origin | ${escMd(a.origin || '<uncurated>')} |
| Status | ${status} |
| First observed | ${escMd(a.first_seen || '<uncurated>')} |
| Last observed | ${escMd(a.last_seen || '<no confirmed end date>')} |

## Targeting

**Target sectors**: ${formatList(a.target_sectors)}

**Target regions**: ${formatList(a.target_regions)}

<One paragraph: is targeting broad/opportunistic or narrow/deliberate?
State the evidence, not just the list.>

## Known TTPs (MITRE ATT&CK)

| Technique ID | Name | Notes |
|---|---|---|
${ttpRows || '| <none curated> | | |'}

*Every technique ID above comes directly from this actor's curated
\`ttps[]\` entry (api/_lib/threat-graph.js) — names and incident-specific
notes need a human/analyst pass, not fabricated here.*

## Associated CVEs

| CVE ID | Role | Notes |
|---|---|---|
${cveRows || '| <none curated> | | |'}

## Campaign History
<Narrative: major named campaigns/incidents, dated, evidence-cited. Link
to this platform's own intelligence/ or cve/ pages where a campaign
overlaps a report already published here.>

## Detection & Hunting Guidance
<Hunt hypotheses keyed to this actor's specific TTPs listed above, not
generic technique-based hunting already covered elsewhere.>

## Confidence Assessment

| Dimension | Rating | Basis |
|---|---|---|
| Attribution | | |
| TTP accuracy | | |
| Targeting scope | | |
| Overall | | |

## Intelligence Gaps
- <Honest list of what isn't known/confirmed about this actor>

## Sources
${sources}

---
*CyberDudeBivash® Sentinel APEX — Threat Actor Intelligence*
`;
}

module.exports = { buildThreatActorProfileMarkdown };
