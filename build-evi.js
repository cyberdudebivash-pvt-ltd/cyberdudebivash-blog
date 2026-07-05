#!/usr/bin/env node
/**
 * Exploitation Velocity Index (EVI) builder — CYBERDUDEBIVASH SENTINEL APEX
 *
 * Computes reproducible aggregate statistics from the official CISA Known
 * Exploited Vulnerabilities (KEV) catalog. Every metric is derived directly
 * from primary-source fields — nothing is estimated or fabricated.
 *
 * Source of truth:
 *   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 *
 * Fields used (all present in every KEV record):
 *   dateAdded, dueDate  -> CISA remediation-urgency window (days)
 *   vendorProject       -> vendor representation in the catalog
 *   knownRansomwareCampaignUse -> confirmed ransomware association
 *   cwes                -> weakness categories
 *
 * Output:
 *   api/intel/exploitation-velocity-index.json  (machine-readable, citable)
 *
 * Metrics are intentionally limited to what KEV supports. KEV does NOT contain
 * disclosure-to-exploitation timing, so no such metric is produced. What KEV
 * DOES support: how fast the catalog grows, which vendors dominate it, the
 * confirmed-ransomware share, and how tight CISA's assigned remediation
 * deadlines are (an authority-assigned proxy for assessed urgency).
 */
const fs = require('fs');

const SRC = process.argv[2] || '/tmp/kev-fresh.json';
const catalog = JSON.parse(fs.readFileSync(SRC, 'utf8'));
const V = catalog.vulnerabilities;

const dayDiff = (a, b) => Math.round((new Date(b) - new Date(a)) / 86400000);
const median = arr => {
  if (!arr.length) return null;
  const s = [...arr].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2);
};
const pct = (n, d) => d ? Math.round((n / d) * 1000) / 10 : 0;

// ---- Catalog-wide ----------------------------------------------------------
const total = V.length;
const ransomKnown = V.filter(v => v.knownRansomwareCampaignUse === 'Known').length;
const windows = V.map(v => dayDiff(v.dateAdded, v.dueDate)).filter(n => Number.isFinite(n) && n >= 0);
const medianWindow = median(windows);

// ---- Monthly velocity (last 18 months) ------------------------------------
const byMonth = {};
for (const v of V) {
  const m = v.dateAdded.slice(0, 7); // YYYY-MM
  byMonth[m] = (byMonth[m] || 0) + 1;
}
const months = Object.keys(byMonth).sort();
const last18 = months.slice(-18).map(m => ({ month: m, additions: byMonth[m] }));
const recent12 = months.slice(-12).reduce((a, m) => a + byMonth[m], 0);
const prior12 = months.slice(-24, -12).reduce((a, m) => a + byMonth[m], 0);

// ---- Per-vendor representation --------------------------------------------
const vend = {};
for (const v of V) {
  const k = (v.vendorProject || 'Unknown').trim();
  (vend[k] = vend[k] || { vendor: k, count: 0, ransom: 0, windows: [] });
  vend[k].count++;
  if (v.knownRansomwareCampaignUse === 'Known') vend[k].ransom++;
  const w = dayDiff(v.dateAdded, v.dueDate);
  if (Number.isFinite(w) && w >= 0) vend[k].windows.push(w);
}
const topVendors = Object.values(vend)
  .sort((a, b) => b.count - a.count)
  .slice(0, 15)
  .map(x => ({
    vendor: x.vendor,
    kevEntries: x.count,
    shareOfCatalogPct: pct(x.count, total),
    ransomwareLinked: x.ransom,
    ransomwareSharePct: pct(x.ransom, x.count),
    medianRemediationWindowDays: median(x.windows),
  }));

// ---- Tightest-deadline vendors (highest assessed urgency) ------------------
// Vendors with >=5 KEV entries, ranked by shortest median remediation window.
const urgency = Object.values(vend)
  .filter(x => x.windows.length >= 5)
  .map(x => ({ vendor: x.vendor, kevEntries: x.count, medianRemediationWindowDays: median(x.windows) }))
  .sort((a, b) => a.medianRemediationWindowDays - b.medianRemediationWindowDays)
  .slice(0, 12);

// ---- CWE weakness categories ----------------------------------------------
const cweCount = {};
for (const v of V) for (const c of (v.cwes || [])) cweCount[c] = (cweCount[c] || 0) + 1;
const topCwes = Object.entries(cweCount)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 10)
  .map(([cwe, count]) => ({ cwe, count, sharePct: pct(count, total) }));

// ---- Recent additions (most recent 15) ------------------------------------
const recentAdds = [...V]
  .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded))
  .slice(0, 15)
  .map(v => ({
    cveID: v.cveID,
    vendor: v.vendorProject,
    product: v.product,
    dateAdded: v.dateAdded,
    dueDate: v.dueDate,
    remediationWindowDays: dayDiff(v.dateAdded, v.dueDate),
    ransomware: v.knownRansomwareCampaignUse === 'Known',
    nvd: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
  }));

const out = {
  index: 'CYBERDUDEBIVASH SENTINEL APEX — Exploitation Velocity Index (EVI)',
  description: 'Reproducible aggregate statistics derived from the official CISA Known Exploited Vulnerabilities catalog.',
  methodology: 'https://blog.cyberdudebivash.in/research/exploitation-velocity-index.html#methodology',
  primarySource: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  catalogVersion: catalog.catalogVersion,
  catalogDateReleased: catalog.dateReleased,
  generatedAt: new Date().toISOString(),
  license: 'CC BY 4.0 — attribution: CYBERDUDEBIVASH SENTINEL APEX, derived from CISA KEV (public domain).',
  catalogSummary: {
    totalKevEntries: total,
    earliestEntry: V.reduce((a, x) => x.dateAdded < a ? x.dateAdded : a, '9999'),
    latestEntry: V.reduce((a, x) => x.dateAdded > a ? x.dateAdded : a, '0'),
    ransomwareLinkedEntries: ransomKnown,
    ransomwareLinkedSharePct: pct(ransomKnown, total),
    medianRemediationWindowDays: medianWindow,
  },
  velocity: {
    note: 'KEV additions per calendar month — the rate at which CISA confirms new in-the-wild exploitation.',
    trailing12MonthAdditions: recent12,
    prior12MonthAdditions: prior12,
    yoyChangePct: pct(recent12 - prior12, prior12),
    monthly: last18,
  },
  topVendorsByRepresentation: topVendors,
  highestUrgencyVendors: {
    note: 'Vendors with >=5 KEV entries, ranked by shortest median CISA remediation window (days from catalog addition to federal remediation deadline). A shorter window is CISA signalling higher assessed urgency.',
    vendors: urgency,
  },
  topWeaknessCategories: topCwes,
  recentAdditions: recentAdds,
};

fs.writeFileSync('/home/user/cyberdudebivash-blog/data/exploitation-velocity-index.json', JSON.stringify(out, null, 2));

// Human summary to stdout
console.log('EVI built from KEV', catalog.catalogVersion);
console.log('  total:', total, '| ransomware-linked:', ransomKnown, `(${pct(ransomKnown, total)}%)`);
console.log('  median remediation window:', medianWindow, 'days');
console.log('  trailing 12mo additions:', recent12, '| prior 12mo:', prior12, `(YoY ${pct(recent12 - prior12, prior12)}%)`);
console.log('  top vendor:', topVendors[0].vendor, topVendors[0].kevEntries, 'entries');
console.log('  tightest-deadline vendor:', urgency[0].vendor, urgency[0].medianRemediationWindowDays, 'day median window');
