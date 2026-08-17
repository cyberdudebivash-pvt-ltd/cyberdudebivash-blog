'use strict';
/**
 * IOC Canonical Store Manager (Stage 2.1)
 * Central repository for all Indicators of Compromise
 *
 * Handles:
 * - IOC normalization across types (IP, domain, hash, file, registry key, MITRE technique)
 * - Deduplication (same value in different representations = single canonical IOC)
 * - Confidence aggregation from multiple sources/mentions
 * - Correlation (which IOCs appear together, which campaigns mention them)
 * - Version history (track how IOC classification changed)
 * - Source tracking (which articles/campaigns/products mention this IOC)
 *
 * API consumers:
 * - Detection rules link to canonical IOCs
 * - Articles/posts reference canonical IOCs
 * - API clients query by IOC type/value
 * - Subscriber feeds deliver latest IOCs
 */

const fs = require('fs');
const crypto = require('crypto');
const { isCloudflareWorkers } = require('./runtime-env');

// Workers has no filesystem — __dirname-based CANONICAL_PATH throws
// there (same failure mode already fixed in intel.js/threat-graph.js/
// detection-rules.js). saveCanonical() below is left fs-only/unguarded:
// a write path for the offline pipeline, not a live request handler.
let CANONICAL_PATH = null;
if (!isCloudflareWorkers()) {
  const path = require('path');
  CANONICAL_PATH = path.join(__dirname, '..', '..', 'data', 'ioc-canonical.json');
}
const WORKERS_CANONICAL_DATA = isCloudflareWorkers() ? require('../../data/ioc-canonical.json') : null;

/**
 * IOC Type definitions (same as threat intel standard)
 */
const IOC_TYPES = {
  ipv4: { pattern: /^\d{1,3}(\.\d{1,3}){3}$/, normalize: v => v.toLowerCase().trim() },
  ipv6: { pattern: /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::)$/, normalize: v => v.toLowerCase().trim() },
  domain: { pattern: /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/, normalize: v => v.toLowerCase().trim() },
  url: { pattern: /^https?:\/\/.+/, normalize: v => v.toLowerCase().trim() },
  file_hash_md5: { pattern: /^[a-fA-F0-9]{32}$/, normalize: v => v.toLowerCase().trim() },
  file_hash_sha1: { pattern: /^[a-fA-F0-9]{40}$/, normalize: v => v.toLowerCase().trim() },
  file_hash_sha256: { pattern: /^[a-fA-F0-9]{64}$/, normalize: v => v.toLowerCase().trim() },
  file_name: { pattern: /^.+\.\w{2,}$/, normalize: v => v.toLowerCase().trim() },
  registry_key: { pattern: /^HKEY_/.i, normalize: v => v.toUpperCase().trim() },
  mitre_technique: { pattern: /^T\d{4}(\.\d{3})?$/, normalize: v => v.toUpperCase().trim() },
};

/**
 * Detect IOC type from value
 */
function detectIOCType(value) {
  value = String(value || '').trim();
  for (const [type, config] of Object.entries(IOC_TYPES)) {
    if (config.pattern.test(value)) {
      return type;
    }
  }
  return 'unknown';
}

/**
 * Normalize IOC value based on type
 */
function normalizeIOC(type, value) {
  const config = IOC_TYPES[type];
  if (!config) return value.toLowerCase().trim();
  return config.normalize(value);
}

/**
 * Generate deterministic IOC ID (same normalized value = same ID)
 */
function generateIOCId(type, normalizedValue) {
  const content = `${type}:${normalizedValue}`;
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
}

/**
 * Load canonical IOC store from disk
 */
function loadCanonical() {
  if (isCloudflareWorkers()) return WORKERS_CANONICAL_DATA;
  try {
    const data = fs.readFileSync(CANONICAL_PATH, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return {
      meta: {
        version: '1.0.0',
        generated: new Date().toISOString(),
        total_iocs: 0,
        by_type: {},
      },
      iocs: [],
      correlations: {},
    };
  }
}

/**
 * Save canonical IOC store to disk (atomic write)
 */
function saveCanonical(store) {
  const tmp = CANONICAL_PATH + '.tmp';
  try {
    fs.writeFileSync(tmp, JSON.stringify(store, null, 2), 'utf8');
    fs.renameSync(tmp, CANONICAL_PATH);
    return true;
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (_) {}
    console.error('[IOC CANONICAL] Failed to save:', e.message);
    return false;
  }
}

/**
 * Store or update an IOC in canonical store
 * If IOC already exists, merge metadata and increment confidence
 */
function storeIOC(value, sourceMetadata = {}) {
  if (!value) throw new Error('IOC value required');

  const type = sourceMetadata.type || detectIOCType(value);
  const normalized = normalizeIOC(type, value);
  const iocId = generateIOCId(type, normalized);

  const store = loadCanonical();
  const timestamp = new Date().toISOString();

  // Check if IOC already exists
  const existingIdx = store.iocs.findIndex(i => i.id === iocId);

  const canonicalIOC = {
    id: iocId,
    type,
    value: normalized,
    original_forms: sourceMetadata.original_forms || [value],

    // Confidence aggregation from multiple sources
    confidence: {
      aggregate: sourceMetadata.confidence || 'MEDIUM',
      sources: sourceMetadata.sources || [],
      corroboration_count: sourceMetadata.corroboration_count || 1,
    },

    // Threat classification
    threat: {
      severity: sourceMetadata.severity || 'MEDIUM',
      classification: sourceMetadata.classification || 'unknown', // malware, c2, phishing, ransomware, etc.
      campaigns: sourceMetadata.campaigns || [],
      threat_actors: sourceMetadata.threat_actors || [],
    },

    // Source tracking (where did we see this IOC)
    sources: {
      articles: sourceMetadata.articles || [],
      feeds: sourceMetadata.feeds || [],
      campaigns: sourceMetadata.campaigns || [],
      detections: sourceMetadata.detections || [],
    },

    // Temporal tracking
    first_seen: existingIdx === -1 ? timestamp : store.iocs[existingIdx].first_seen,
    last_seen: timestamp,
    status: sourceMetadata.status || 'ACTIVE', // ACTIVE, INACTIVE, RETIRED

    // Version history
    history: existingIdx === -1
      ? [{ timestamp, action: 'created', source: sourceMetadata.source || 'unknown', change: 'IOC ingested' }]
      : [...store.iocs[existingIdx].history, {
          timestamp,
          action: sourceMetadata.action || 'updated',
          source: sourceMetadata.source || 'unknown',
          change: sourceMetadata.change || 'IOC corroborated',
        }],
  };

  if (existingIdx === -1) {
    store.iocs.push(canonicalIOC);
    store.meta.by_type[type] = (store.meta.by_type[type] || 0) + 1;
  } else {
    // Merge confidence when updating
    const existing = store.iocs[existingIdx];
    if (!existing.confidence.sources.includes(sourceMetadata.source || 'unknown')) {
      existing.confidence.sources.push(sourceMetadata.source || 'unknown');
      existing.confidence.corroboration_count += 1;
      // Boost confidence if multiple sources mention it
      if (existing.confidence.corroboration_count >= 3 && existing.confidence.aggregate !== 'HIGH') {
        existing.confidence.aggregate = 'HIGH';
      }
    }
    existing.last_seen = timestamp;
    existing.history = canonicalIOC.history;
    store.iocs[existingIdx] = existing;
  }

  store.meta.total_iocs = store.iocs.length;
  store.meta.generated = timestamp;

  saveCanonical(store);
  return canonicalIOC;
}

/**
 * Store multiple IOCs (batch from article/campaign)
 */
function storeIOCs(values, sourceMetadata = {}) {
  const stored = [];
  for (const value of (values || [])) {
    try {
      const ioc = storeIOC(value, sourceMetadata);
      stored.push(ioc);
    } catch (e) {
      console.error(`[IOC CANONICAL] Failed to store IOC ${value}:`, e.message);
    }
  }
  return stored;
}

/**
 * Get IOC by ID
 */
function getIOC(iocId) {
  const store = loadCanonical();
  return store.iocs.find(i => i.id === iocId) || null;
}

/**
 * Find IOC by value (handles normalization)
 */
function findIOC(value, type) {
  const detectedType = type || detectIOCType(value);
  const normalized = normalizeIOC(detectedType, value);
  const iocId = generateIOCId(detectedType, normalized);
  return getIOC(iocId);
}

/**
 * Search IOCs with filters
 */
function searchIOCs(filters = {}) {
  const store = loadCanonical();
  let results = store.iocs;

  if (filters.type) {
    results = results.filter(i => i.type === filters.type);
  }
  if (filters.value) {
    const normalized = normalizeIOC(filters.type || 'unknown', filters.value);
    results = results.filter(i => i.value === normalized);
  }
  if (filters.severity) {
    results = results.filter(i => i.threat.severity === filters.severity);
  }
  if (filters.confidence) {
    results = results.filter(i => i.confidence.aggregate === filters.confidence);
  }
  if (filters.status) {
    results = results.filter(i => i.status === filters.status);
  }
  if (filters.classification) {
    results = results.filter(i => i.threat.classification === filters.classification);
  }
  if (filters.campaign) {
    results = results.filter(i => i.threat.campaigns.includes(filters.campaign));
  }
  if (filters.actor) {
    results = results.filter(i => i.threat.threat_actors.includes(filters.actor));
  }
  if (filters.min_corroboration) {
    results = results.filter(i => i.confidence.corroboration_count >= filters.min_corroboration);
  }
  if (filters.query) {
    const q = filters.query.toLowerCase();
    results = results.filter(i =>
      i.value.toLowerCase().includes(q) ||
      i.original_forms.some(f => f.toLowerCase().includes(q))
    );
  }

  const offset = filters.offset || 0;
  const limit = filters.limit || 100;
  return results.slice(offset, offset + limit);
}

/**
 * Get all mentions of an IOC (articles, campaigns, detections)
 */
function getIOCMentions(iocId) {
  const ioc = getIOC(iocId);
  if (!ioc) return null;
  return {
    ioc_id: iocId,
    type: ioc.type,
    value: ioc.value,
    mentions: {
      in_articles: ioc.sources.articles.length,
      in_detections: ioc.sources.detections.length,
      in_campaigns: ioc.sources.campaigns.length,
      articles: ioc.sources.articles,
      detections: ioc.sources.detections,
      campaigns: ioc.sources.campaigns,
    },
    confidence: ioc.confidence,
    threat: ioc.threat,
  };
}

/**
 * Create correlation between IOCs (e.g., domain resolves to IP)
 */
function correlateIOCs(sourceIOCId, targetIOCId, relationType = 'related', confidence = 'MEDIUM') {
  const store = loadCanonical();
  if (!store.correlations) store.correlations = {};

  const correlationKey = `${sourceIOCId}→${targetIOCId}`;
  store.correlations[correlationKey] = {
    source: sourceIOCId,
    target: targetIOCId,
    type: relationType, // resolves_to, communicates_with, similar, related
    confidence,
    timestamp: new Date().toISOString(),
  };

  saveCanonical(store);
}

/**
 * Get correlated IOCs (IOCs related to this one)
 */
function getCorrelatedIOCs(iocId) {
  const store = loadCanonical();
  if (!store.correlations) return [];

  const correlated = Object.values(store.correlations).filter(c =>
    c.source === iocId || c.target === iocId
  );
  return correlated;
}

/**
 * Export IOCs in specific format
 */
function exportIOCs(format = 'json', filters = {}) {
  const iocs = searchIOCs(filters);

  if (format === 'json') {
    return JSON.stringify({ iocs, count: iocs.length }, null, 2);
  }

  if (format === 'csv') {
    const header = 'IOC ID,Type,Value,Confidence,Severity,Classification,Sources Count,Last Seen\n';
    const rows = iocs.map(i =>
      `${i.id},${i.type},${i.value},${i.confidence.aggregate},${i.threat.severity},${i.threat.classification},` +
      `${i.sources.articles.length + i.sources.detections.length + i.sources.campaigns.length},${i.last_seen}`
    );
    return header + rows.join('\n');
  }

  if (format === 'stix') {
    // STIX 2.1 format for enterprise SIEM integration
    const objects = iocs.map(ioc => {
      const typeMap = { ipv4: 'ipv4-addr', domain: 'domain-name', url: 'url', file_hash_sha256: 'file' };
      return {
        type: 'indicator',
        pattern: `[${typeMap[ioc.type] || 'network-traffic'}:value = '${ioc.value}']`,
        created: ioc.first_seen,
        modified: ioc.last_seen,
        confidence: ioc.confidence.aggregate === 'HIGH' ? 75 : 50,
        labels: [ioc.threat.classification],
      };
    });
    return JSON.stringify({ type: 'bundle', objects }, null, 2);
  }

  throw new Error(`Unknown export format: ${format}`);
}

/**
 * Get IOC store statistics
 */
function getStats() {
  const store = loadCanonical();
  const byType = {};
  const byConfidence = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const byClassification = {};

  for (const ioc of store.iocs) {
    byType[ioc.type] = (byType[ioc.type] || 0) + 1;
    byConfidence[ioc.confidence.aggregate]++;
    bySeverity[ioc.threat.severity]++;
    byClassification[ioc.threat.classification] = (byClassification[ioc.threat.classification] || 0) + 1;
  }

  return {
    total_iocs: store.iocs.length,
    by_type: byType,
    by_confidence: byConfidence,
    by_severity: bySeverity,
    by_classification: byClassification,
    avg_corroboration: store.iocs.length > 0
      ? (store.iocs.reduce((sum, i) => sum + i.confidence.corroboration_count, 0) / store.iocs.length).toFixed(2)
      : 0,
    last_updated: store.meta.generated,
  };
}

module.exports = {
  storeIOC,
  storeIOCs,
  getIOC,
  findIOC,
  searchIOCs,
  getIOCMentions,
  correlateIOCs,
  getCorrelatedIOCs,
  exportIOCs,
  getStats,
  detectIOCType,
  normalizeIOC,
  loadCanonical,
  saveCanonical,
};
