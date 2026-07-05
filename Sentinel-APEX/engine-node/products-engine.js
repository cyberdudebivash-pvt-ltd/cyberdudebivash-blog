'use strict';
/**
 * SENTINEL APEX Multi-Audience Intelligence Products Engine.
 *
 * The commercial multiplier: one evidence effort → many deliverables, each
 * tailored to a real audience and composed ONLY from artifacts already
 * produced (reasoning, detections, correlation, IOCs, enrichment). No new
 * claims are introduced; every product is a re-projection of the same
 * evidence for a different reader.
 *
 * Products:
 *   - executiveAdvisory  (CISO)         situation, business risk, decisions
 *   - boardBrief         (Board)        3–5 strategic bullets
 *   - socBulletin        (SOC analyst)  severity, detections, IOCs, actions
 *   - huntingGuide       (Threat hunter) hypotheses + ready queries
 *   - iocFeed            (defenders)    defanged IOC list w/ confidence
 *   - apiPackage         (MSSP / API)   machine-readable JSON intelligence
 *
 * Deterministic and defensive — malformed input yields empty products, never
 * throws — so it can wrap the live generator safely.
 */

const detEngine = require('./detection-engine');
const reasoning = require('./reasoning-engine');

function _safe(fn, dflt) { try { return fn(); } catch (_) { return dflt; } }
const _FMT_KEYS = ['sigma', 'kql', 'splunk', 'osquery'];
function _formatsOf(d) {
  const out = {};
  for (const k of _FMT_KEYS) if (d && d[k]) out[k] = d[k];
  return out;
}
function _defang(type, value) {
  const t = detEngine.normalizeIocType(type);
  const v = detEngine.refang(value);
  if (['domain', 'ipv4', 'ip', 'url'].includes(t)) {
    return v.replace(/https?/gi, (m) => m.toLowerCase() === 'https' ? 'hxxps' : 'hxxp').replace(/\./g, '[.]');
  }
  return v;
}

/**
 * @param {object} item  generator item
 * @param {object} [mem] AnalystMemory for correlation
 * @returns {object} the full product set (+ apiPackage)
 */
function buildProducts(item, mem) {
  const empty = {
    executiveAdvisory: null, boardBrief: null, socBulletin: null,
    huntingGuide: null, iocFeed: [], apiPackage: null,
  };
  if (!item || typeof item !== 'object' || Array.isArray(item)) return empty;

  const text = `${item.title || ''}. ${item.desc || ''}`;
  const r = _safe(() => reasoning.buildReasoning(item, mem), reasoning.buildReasoning({}));
  const techniques = _safe(() => detEngine.mapTechniques(text), []);
  const rawIocs = (Array.isArray(item.iocs) ? item.iocs : []).filter((i) => i && i.value);
  const refs = [];
  if (item.id && /^CVE-/i.test(item.id)) refs.push(`https://nvd.nist.gov/vuln/detail/${item.id}`);
  const { detections, suricata } = _safe(
    () => detEngine.buildDetections(text, rawIocs.map((i) => ({ type: i.type, value: i.value })), { references: refs }),
    { detections: [], suricata: [] },
  );
  const correlations = (mem && typeof mem.correlationNotes === 'function')
    ? _safe(() => mem.correlationNotes(item), []) : [];

  const cves = Array.isArray(item.cves) ? item.cves
    : (item.id && /^CVE-/i.test(item.id) ? [item.id] : []);
  // an item with no title, CVE, technique, or IOC has nothing to productize
  if (!item.title && !cves.length && !techniques.length && !rawIocs.length) return empty;

  const cvss = (typeof item.cvss === 'number' && item.cvss > 0) ? item.cvss : null;
  const kev = !!item.cisaKev;
  const severity = cvss != null ? (cvss >= 9 ? 'CRITICAL' : cvss >= 7 ? 'HIGH' : cvss >= 4 ? 'MEDIUM' : 'LOW')
    : (item.threatLevel || 'HIGH').toUpperCase();
  const tech = [item.vendor, item.product].filter(Boolean).join(' ') || 'the affected technology';

  const iocFeed = rawIocs.slice(0, 50).map((i) => ({
    value: _defang(i.type, i.value),
    type: detEngine.normalizeIocType(i.type),
    confidence: typeof i.confidence_score === 'number' ? i.confidence_score : 0.8,
  }));

  // ── Executive Advisory (CISO) ───────────────────────────────────────────
  const executiveAdvisory = {
    audience: 'CISO / Security Leadership',
    headline: `${severity} threat affecting ${tech}`,
    situation: r.facts.slice(0, 4),
    businessRisk: r.assessments.filter((a) => /severity|risk|impact|ransomware|credential/i.test(a.text))
      .map((a) => `(${a.confidence}) ${a.text}`),
    decisions: _decisions(severity, kev, item),
    recommendedActions: _timeline(severity, kev, detections.length),
  };

  // ── Board Brief ─────────────────────────────────────────────────────────
  const boardBrief = {
    audience: 'Board of Directors',
    bullets: [
      `A ${severity.toLowerCase()}-severity cyber threat affects ${tech}${kev ? ', with exploitation confirmed by U.S. federal advisory (CISA KEV)' : ''}.`,
      cvss != null ? `Technical severity is rated ${cvss}/10.` : `Severity is assessed as ${severity.toLowerCase()}.`,
      'Primary exposure is operational disruption, data loss, and potential regulatory liability (e.g. GDPR, NIS2, DORA, SOC 2) where in-scope systems are affected.',
      detections.length
        ? `Detection coverage is available and can be deployed to reduce exposure now.`
        : `Mitigation depends on vendor guidance and compensating controls.`,
      'Recommended posture: authorize prioritized remediation and confirm detection coverage with the security team.',
    ],
  };

  // ── SOC Bulletin ────────────────────────────────────────────────────────
  const platforms = new Set();
  for (const d of detections) for (const f of Object.keys(_formatsOf(d))) platforms.add(f);
  const socBulletin = {
    audience: 'SOC / Detection Engineering',
    severity,
    affectedTechnology: tech,
    cves,
    detectionCoverage: {
      techniques: detections.map((d) => d.technique_id),
      platforms: [...platforms],
      networkRules: suricata.length,
    },
    iocsToBlock: iocFeed,
    immediateActions: _socActions(iocFeed.length, detections.length, suricata.length),
  };

  // ── Threat Hunting Guide ────────────────────────────────────────────────
  const huntingGuide = {
    audience: 'Threat Hunting',
    hypotheses: techniques.map((t) => ({
      technique: `${t.technique_id} — ${t.name}`,
      hypothesis: `Hunt for ${t.name.toLowerCase()} activity (${t.tactic}); evidence basis: ${t.evidence}`.slice(0, 240),
    })),
    queries: detections.flatMap((d) => Object.entries(_formatsOf(d))
      .filter(([fmt]) => fmt !== 'sigma')
      .map(([fmt, body]) => ({ platform: fmt, technique: d.technique_id, query: body }))),
  };

  // ── Machine-readable API package (MSSP / customers) ─────────────────────
  const apiPackage = {
    schema: 'sentinel-apex.intelligence/1.0',
    id: item.id || null,
    title: item.title || null,
    generated: new Date().toISOString(),
    severity,
    cvss,
    cisa_kev: kev,
    exploited: !!item.exploited,
    cves,
    vendor: item.vendor || null,
    product: item.product || null,
    mitre_attack: techniques.map((t) => ({ id: t.technique_id, name: t.name, tactic: t.tactic, confidence: t.confidence })),
    iocs: iocFeed,
    detections: {
      sigma: detections.map((d) => d.sigma).filter(Boolean),
      kql: detections.map((d) => d.kql).filter(Boolean),
      splunk: detections.map((d) => d.splunk).filter(Boolean),
      osquery: detections.map((d) => d.osquery).filter(Boolean),
      suricata,
    },
    assessment: {
      verified_facts: r.facts,
      analyst_assessments: r.assessments,
      intelligence_gaps: r.gaps,
      forward_outlook: r.outlook,
    },
    correlations,
    source: item.link || (refs[0] || null),
    provider: 'CYBERDUDEBIVASH SENTINEL APEX',
  };

  return { executiveAdvisory, boardBrief, socBulletin, huntingGuide, iocFeed, apiPackage };
}

// ── helpers ────────────────────────────────────────────────────────────────
function _decisions(severity, kev, item) {
  const urgent = kev || severity === 'CRITICAL';
  return [
    { owner: 'CISO / SOC Lead', decision: 'Authorize response activation and detection deployment', timeline: urgent ? 'Immediate' : 'Within 24h' },
    { owner: 'Vulnerability Mgmt', decision: `Prioritize remediation/patching of ${item.vendor || 'affected'} assets`, timeline: urgent ? 'Within 24–48h' : 'Within 7 days' },
    { owner: 'Legal / Privacy', decision: 'Assess regulatory notification obligations if in-scope data is at risk', timeline: 'Within 48h' },
  ];
}
function _timeline(severity, kev, detCount) {
  return [
    `Day 1–7 (Immediate): ${kev ? 'Treat as active incident — ' : ''}identify exposed assets, ${detCount ? 'deploy the provided detection rules, ' : ''}apply available mitigations.`,
    'Day 8–30 (Short-term): Validate SIEM/EDR coverage against all mapped ATT&CK techniques; close detection gaps.',
    'Day 31–90 (Strategic): Tabletop this scenario with SOC and executives; integrate continuous intelligence to shorten detection-gap windows.',
  ];
}
function _socActions(iocCount, detCount, suriCount) {
  const a = [];
  if (iocCount) a.push(`P0: Block all ${iocCount} IOC(s) at firewall, proxy, DNS, and EDR simultaneously.`);
  if (detCount) a.push(`P1: Deploy the ${detCount} provided detection rule(s) across SIEM/EDR and validate alerting.`);
  if (suriCount) a.push(`P1: Load the ${suriCount} Suricata network rule(s) at IDS/IPS choke points.`);
  a.push('P1: Sweep 14 days of telemetry for the mapped ATT&CK techniques.');
  a.push('P2: Update threat-intel platform and downstream detection feeds with confirmed indicators.');
  return a;
}

function hasProducts(p) {
  return !!(p && p.apiPackage && (p.socBulletin || p.executiveAdvisory));
}

module.exports = { buildProducts, hasProducts };
