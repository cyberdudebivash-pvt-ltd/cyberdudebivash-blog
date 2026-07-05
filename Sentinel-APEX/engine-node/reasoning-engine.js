'use strict';
/**
 * SENTINEL APEX Analyst Reasoning Engine.
 *
 * Produces a structured analytical narrative that makes the platform's core
 * discipline explicit and auditable: it separates what is KNOWN from what is
 * ASSESSED, attaches a confidence label to every assessment, and states
 * honestly what is NOT known. Five stages:
 *
 *   1. Verified Facts        — only directly-supported statements (evidence,
 *                              authoritative enrichment). No inference.
 *   2. Correlated Observations — relationships from the knowledge graph.
 *   3. Analyst Assessments   — labeled inferences, each with LOW/MEDIUM/HIGH
 *                              confidence and a stated basis.
 *   4. Intelligence Gaps     — explicit unknowns (the credibility anchor).
 *   5. Forward Outlook       — labeled, evidence-anchored expectations.
 *
 * Deterministic and composed from artifacts already produced — no model
 * calls, no fabrication. Confidence is never asserted without a basis; facts
 * and assessments never blur.
 */

const detEngine = require('./detection-engine');

function _safe(fn, dflt) { try { return fn(); } catch (_) { return dflt; } }

/**
 * @param {object} item      generator item (title/desc/cves/vendor/cvss/...)
 * @param {object} [mem]     AnalystMemory instance for correlation (optional)
 * @returns {{facts:string[],observations:string[],assessments:object[],gaps:string[],outlook:object[]}}
 */
function buildReasoning(item, mem) {
  const facts = [], observations = [], assessments = [], gaps = [], outlook = [];
  if (!item || typeof item !== 'object' || Array.isArray(item)) {
    return { facts, observations, assessments, gaps, outlook };
  }

  const text = `${item.title || ''}. ${item.desc || ''}`;
  const techniques = _safe(() => detEngine.mapTechniques(text), []);
  const tids = new Set(techniques.map((t) => t.technique_id));
  const cves = Array.isArray(item.cves) ? item.cves
    : (item.id && /^CVE-/i.test(item.id) ? [item.id] : []);
  const cvss = (typeof item.cvss === 'number' && item.cvss > 0) ? item.cvss : null;
  const kev = !!item.cisaKev;
  const exploited = !!item.exploited;
  const iocCount = (Array.isArray(item.iocs) ? item.iocs : []).filter((i) => i && i.value).length;

  // ── 1. Verified Facts (directly supported only) ─────────────────────────
  if (cves.length) facts.push(`Affected CVE(s): ${cves.join(', ')}.`);
  if (item.vendor || item.product) {
    facts.push(`Affected technology: ${[item.vendor, item.product].filter(Boolean).join(' ')}.`);
  }
  if (cvss != null) facts.push(`CVSS base score of ${cvss} assigned by an authoritative source.`);
  if (kev) facts.push('Listed in the CISA Known Exploited Vulnerabilities (KEV) catalog — exploitation confirmed by federal advisory.');
  if (exploited && !kev) facts.push('Active exploitation reported in source intelligence.');
  if (iocCount) facts.push(`${iocCount} indicator(s) of compromise extracted from source reporting.`);
  if (item.sourceCount > 1) facts.push(`Corroborated across ${item.sourceCount} independent source(s).`);
  if (techniques.length) facts.push(`${techniques.length} MITRE ATT&CK technique(s) evidenced in the source material.`);

  // ── 2. Correlated Observations (knowledge graph) ────────────────────────
  if (mem && typeof mem.correlationNotes === 'function') {
    for (const n of _safe(() => mem.correlationNotes(item), [])) observations.push(n);
  }

  // ── 3. Analyst Assessments (labeled, with basis) ────────────────────────
  const A = (confidence, text_) => assessments.push({ confidence, text: text_ });
  if (tids.has('T1486') || tids.has('T1490')) {
    A('HIGH', 'Activity is consistent with a ransomware operation — data encryption and/or recovery inhibition (shadow-copy deletion) was observed.');
  }
  if (tids.has('T1566') || tids.has('T1566.001') || tids.has('T1566.002')) {
    A('MEDIUM', 'Initial access is assessed to occur via phishing, based on delivery indicators in the source.');
  }
  if (tids.has('T1190')) {
    A('MEDIUM', 'Exploitation of a public-facing application is the assessed initial-access vector.');
  }
  if (tids.has('T1003') || tids.has('T1003.001')) {
    A('MEDIUM', 'Credential theft is assessed as an objective, based on credential-access (LSASS) activity.');
  }
  if (cvss != null) {
    const sev = cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : 'moderate';
    A(cvss >= 9 ? 'HIGH' : 'MEDIUM',
      `Technical severity is assessed as ${sev} (CVSS ${cvss}); realized business impact depends on asset exposure and data classification.`);
  }
  if (kev || exploited) {
    A('HIGH', 'Unpatched exposure represents an active — not theoretical — risk, given confirmed exploitation.');
  } else if (cvss != null && cvss >= 9) {
    A('MEDIUM', 'Exploitation is assessed as likely to follow disclosure, given high severity and typical weaponization timelines.');
  }
  // attribution is ALWAYS an assessment, never a fact — surfaced only when the
  // knowledge graph associates named actors, and always low/medium confidence
  const actorObs = observations.filter((o) => /^(Threat actor|Malware) /.test(o));
  if (actorObs.length) {
    A('LOW', 'Any actor attribution derives from historical TTP/infrastructure overlap and requires corroboration before operational use.');
  }

  // ── 4. Intelligence Gaps (honest unknowns) ──────────────────────────────
  if (!iocCount) gaps.push('No confirmed public IOCs are available at report time; detection currently relies on behavioral analytics.');
  if (cvss == null) gaps.push('No authoritative CVSS score is available at report time.');
  if (!kev && !exploited) gaps.push('In-the-wild exploitation is unconfirmed as of this report.');
  if (!actorObs.length) gaps.push('Attribution to a specific threat actor is not established by the available evidence.');
  if (!techniques.length) gaps.push('The source lacks sufficient technical detail for confident MITRE ATT&CK mapping.');

  // ── 5. Forward Outlook (labeled, evidence-anchored) ─────────────────────
  const O = (confidence, text_) => outlook.push({ confidence, text: text_ });
  if (kev || exploited) {
    O('HIGH', 'Continued and broadening exploitation is expected; additional threat actors are likely to adopt this vector.');
  }
  if (tids.has('T1486') || tids.has('T1490')) {
    O('MEDIUM', 'Double-extortion and data-leak-site activity is anticipated to accompany encryption events.');
  }
  if (observations.some((o) => /recurring target/.test(o))) {
    O('MEDIUM', 'Given the repeated targeting pattern, further activity against this vendor/sector is probable.');
  }
  if (!outlook.length && cvss != null && cvss >= 7) {
    O('LOW', 'Exploitation activity may emerge as technical details become public; monitor vendor advisories.');
  }

  return { facts, observations, assessments, gaps, outlook };
}

/** True when the reasoning has enough substance to render. */
function hasSubstance(r) {
  return (r.facts.length + r.assessments.length + r.observations.length) > 0;
}

module.exports = { buildReasoning, hasSubstance };
