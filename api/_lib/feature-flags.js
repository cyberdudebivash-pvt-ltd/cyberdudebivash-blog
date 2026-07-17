/**
 * SENTINEL APEX — Feature Flags (architecture only)
 *
 * A static, in-code flag registry — no external service, no runtime
 * enforcement wired into any live route yet. Exists so future work
 * (Customer Success workflows, semantic search, etc.) has somewhere to
 * register a flag and check it, without needing this file's shape
 * decided under time pressure later.
 */
'use strict';

const FLAGS = {
  'content-graph-api': { enabled: true, description: 'api/v1/intel.js?action=entity unified lookup' },
  'health-dashboard': { enabled: true, description: 'Internal ops/health/ dashboard' },
  'semantic-search': { enabled: false, description: 'Placeholder — semantic search is not built yet (see docs/data-schemas.md search notes)' },
  'customer-workspace': { enabled: false, description: 'Placeholder — requires a visitor-identity system that does not exist yet' },
};

/**
 * @param {string} flagKey
 * @param {object} [context] reserved for future per-user/per-tier targeting; unused today
 */
function isEnabled(flagKey, context = {}) {
  const flag = FLAGS[flagKey];
  return !!flag && !!flag.enabled;
}

module.exports = { FLAGS, isEnabled };
