'use strict';
/**
 * SENTINEL APEX Analyst Memory (persistent cross-report intelligence).
 *
 * Turns a stream of isolated reports into an evolving intelligence asset: as
 * each report is generated, the entities it references (CVEs, network
 * infrastructure, vendors/products, ATT&CK techniques, threat actors, malware
 * families) are recorded with first-seen / last-seen / occurrence count. New
 * reports can then answer "have we seen this before?" instead of treating
 * every event as isolated.
 *
 * Design:
 *  - zero dependencies; JSON-backed so it persists across generator runs and
 *    is versioned alongside the repo (like intel-state.json);
 *  - bounded — capped entity count with least-recently-seen pruning, so the
 *    store can never grow without limit;
 *  - defensive — malformed input is ignored, never thrown, so it can wrap the
 *    live generator without risk.
 */

const detEngine = require('./detection-engine');

// Compact, high-precision lexicon for actors/malware so memory can key on the
// threat-group / family level (the most valuable "seen before" signal).
const ACTOR_LEXICON = [
  ['APT28', /\bAPT28\b|Fancy Bear|Forest Blizzard/i],
  ['APT29', /\bAPT29\b|Cozy Bear|Midnight Blizzard|Nobelium/i],
  ['APT41', /\bAPT41\b|Winnti|Brass Typhoon/i],
  ['Lazarus Group', /\bLazarus\b|Hidden Cobra|Diamond Sleet/i],
  ['Kimsuky', /\bKimsuky\b|Velvet Chollima/i],
  ['Sandworm', /\bSandworm\b|Seashell Blizzard|Voodoo Bear/i],
  ['Volt Typhoon', /Volt Typhoon/i],
  ['Salt Typhoon', /Salt Typhoon/i],
  ['Scattered Spider', /Scattered Spider|Octo Tempest|UNC3944/i],
  ['FIN7', /\bFIN7\b|Carbanak/i],
  ['MuddyWater', /MuddyWater|Mango Sandstorm/i],
  ['Turla', /\bTurla\b|Secret Blizzard|Venomous Bear/i],
  ['NSO Group', /NSO Group/i],
];
const MALWARE_LEXICON = [
  ['Pegasus', /\bPegasus\b/i],
  ['LockBit', /\bLockBit\b/i],
  ['ALPHV/BlackCat', /\bALPHV\b|BlackCat/i],
  ['Cl0p', /\bCl0p\b|\bClop\b/i],
  ['Akira', /\bAkira\b/i],
  ['RansomHub', /RansomHub/i],
  ['Qilin', /\bQilin\b/i],
  ['Emotet', /\bEmotet\b/i],
  ['Qakbot', /\bQakbot\b|\bQBot\b/i],
  ['Cobalt Strike', /Cobalt Strike/i],
  ['LummaC2', /LummaC2|Lumma Stealer/i],
  ['RedLine', /RedLine/i],
  ['AsyncRAT', /AsyncRAT/i],
  ['IcedID', /IcedID/i],
  ['TrickBot', /TrickBot/i],
];

const NETWORK_IOC_TYPES = new Set(['domain', 'ipv4', 'ip', 'url']);
const DEFAULT_MAX_ENTITIES = 50000;

function nowIso() { return new Date().toISOString(); }

class AnalystMemory {
  constructor(data, opts = {}) {
    this.entities = (data && data.entities) || {};
    this.version = (data && data.version) || 1;
    this.maxEntities = opts.maxEntities || DEFAULT_MAX_ENTITIES;
  }

  static key(type, name) { return `${type}:${String(name).toLowerCase()}`; }

  /** Extract the memorable entities from a generator item (read-only). */
  static entitiesOf(item) {
    if (!item || typeof item !== 'object') return [];
    const out = [];
    const text = `${item.title || ''}. ${item.desc || ''}`;

    const cves = Array.isArray(item.cves) ? item.cves
      : (item.id && /^CVE-/i.test(item.id) ? [item.id] : []);
    for (const c of cves) out.push(['cve', String(c).toUpperCase()]);

    if (item.vendor) out.push(['vendor', item.vendor]);
    if (item.product) out.push(['product', item.product]);

    for (const ioc of (Array.isArray(item.iocs) ? item.iocs : [])) {
      if (!ioc || !ioc.value) continue;
      const t = detEngine.normalizeIocType(ioc.type);
      if (NETWORK_IOC_TYPES.has(t)) {
        out.push([`ioc_${t === 'ip' ? 'ipv4' : t}`, detEngine.refang(ioc.value)]);
      }
    }

    try {
      for (const m of detEngine.mapTechniques(text)) out.push(['technique', m.technique_id]);
    } catch (_) { /* mapping is best-effort */ }

    for (const [name, re] of ACTOR_LEXICON) if (re.test(text)) out.push(['actor', name]);
    for (const [name, re] of MALWARE_LEXICON) if (re.test(text)) out.push(['malware', name]);

    // de-dup within the item
    const seen = new Set();
    return out.filter(([t, n]) => {
      const k = AnalystMemory.key(t, n);
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  /**
   * Prior-intelligence notes for an item, computed BEFORE ingesting it, so the
   * counts reflect history only. Returns human-readable strings (may be empty).
   */
  priorContext(item, limit = 6) {
    const notes = [];
    for (const [type, name] of AnalystMemory.entitiesOf(item)) {
      const node = this.entities[AnalystMemory.key(type, name)];
      if (!node || node.count < 1) continue;
      notes.push(this._note(type, name, node));
    }
    // most-recurrent first
    notes.sort((a, b) => b.count - a.count);
    return notes.slice(0, limit).map((n) => n.text);
  }

  _note(type, name, node) {
    const label = {
      cve: 'CVE', vendor: 'Vendor', product: 'Product', technique: 'ATT&CK technique',
      actor: 'Threat actor', malware: 'Malware family',
      ioc_domain: 'Domain', ioc_ipv4: 'IP', ioc_url: 'URL',
    }[type] || type;
    const times = node.count === 1 ? 'once' : `${node.count} times`;
    const since = (node.firstSeen || '').slice(0, 10);
    return {
      count: node.count,
      text: `${label} ${name} — previously observed ${times} in CYBERDUDEBIVASH `
        + `intelligence${since ? ` since ${since}` : ''}`
        + (node.reports && node.reports.length
          ? ` (recent: ${node.reports.slice(-2).join(', ')})` : ''),
    };
  }

  /** Record an item's entities against a report id/slug. */
  ingest(item, reportId) {
    const ts = nowIso();
    for (const [type, name] of AnalystMemory.entitiesOf(item)) {
      const key = AnalystMemory.key(type, name);
      const node = this.entities[key] || {
        type, name, firstSeen: ts, lastSeen: ts, count: 0, reports: [],
      };
      node.count += 1;
      node.lastSeen = ts;
      if (reportId && !node.reports.includes(reportId)) {
        node.reports.push(reportId);
        if (node.reports.length > 5) node.reports = node.reports.slice(-5);
      }
      this.entities[key] = node;
    }
    this._prune();
  }

  _prune() {
    const keys = Object.keys(this.entities);
    if (keys.length <= this.maxEntities) return;
    // drop least-recently-seen entities down to 90% of the cap
    keys.sort((a, b) =>
      (this.entities[a].lastSeen < this.entities[b].lastSeen ? -1 : 1));
    const drop = keys.length - Math.floor(this.maxEntities * 0.9);
    for (const k of keys.slice(0, drop)) delete this.entities[k];
  }

  stats() {
    const byType = {};
    for (const n of Object.values(this.entities)) byType[n.type] = (byType[n.type] || 0) + 1;
    return { entities: Object.keys(this.entities).length, byType };
  }

  toJSON() { return { version: this.version, entities: this.entities }; }

  // ── persistence (defensive: any failure yields an empty/no-op memory) ────
  static load(fs, filePath, opts) {
    try {
      if (fs.existsSync(filePath)) {
        return new AnalystMemory(JSON.parse(fs.readFileSync(filePath, 'utf8')), opts);
      }
    } catch (_) { /* corrupt/unreadable -> start fresh */ }
    return new AnalystMemory(null, opts);
  }

  save(fs, filePath) {
    try {
      fs.writeFileSync(filePath, JSON.stringify(this.toJSON(), null, 0), 'utf8');
      return true;
    } catch (_) { return false; }
  }
}

module.exports = { AnalystMemory, ACTOR_LEXICON, MALWARE_LEXICON };
