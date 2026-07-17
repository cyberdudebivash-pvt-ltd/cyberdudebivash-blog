/**
 * SENTINEL APEX — Freshness Checker
 *
 * Read-only staleness monitoring for every generator registered in
 * orchestrator/generators.js, using each generator's own declared
 * `freshnessCheck`. This extends monitoring from the 1-of-6 generators
 * freshness-check.yml currently watches (live-intel only) to all 6,
 * without modifying freshness-check.yml itself — it stays exactly as-is
 * and this is purely additive.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { ROOT } = require('./generator-sdk');

function getJsonPath(obj, dottedPath) {
  return dottedPath.split('.').reduce((acc, key) => (acc && typeof acc === 'object' ? acc[key] : undefined), obj);
}

/** Newest mtime under a path (file, or directory subtree). 0 if missing. */
function pathNewestMtime(relPath) {
  const base = path.join(ROOT, relPath);
  let newest = 0;
  (function walk(p) {
    let st;
    try {
      st = fs.statSync(p);
    } catch (_) {
      return;
    }
    if (st.isDirectory()) {
      for (const entry of fs.readdirSync(p)) walk(path.join(p, entry));
    } else if (st.isFile() && st.mtimeMs > newest) {
      newest = st.mtimeMs;
    }
  })(base);
  return newest;
}

/**
 * Determine a single generator's freshness. Prefers a declared
 * `jsonPath` timestamp inside the file (authoritative, generator-stamped);
 * falls back to filesystem mtime otherwise.
 */
function checkGeneratorFreshness(gen, now = Date.now()) {
  if (!gen.freshnessCheck) {
    return { id: gen.id, status: 'unmonitored', ageMinutes: null, lastSeen: null, detail: 'No freshnessCheck declared for this generator' };
  }
  const { file, jsonPath, maxAgeMinutes } = gen.freshnessCheck;
  const fullPath = path.join(ROOT, file);

  let timestampMs = null;
  if (jsonPath) {
    try {
      const data = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
      const raw = getJsonPath(data, jsonPath);
      if (raw) timestampMs = new Date(raw).getTime();
    } catch (_) {
      // fall through to mtime
    }
  }
  if (timestampMs == null || Number.isNaN(timestampMs)) {
    const mtime = pathNewestMtime(file);
    timestampMs = mtime || null;
  }

  if (timestampMs == null) {
    return { id: gen.id, status: 'missing', ageMinutes: null, lastSeen: null, detail: `${file} not found` };
  }

  const ageMinutes = Math.round((now - timestampMs) / 60000);
  const status = ageMinutes > maxAgeMinutes ? 'stale' : 'fresh';
  return { id: gen.id, status, ageMinutes, lastSeen: new Date(timestampMs).toISOString(), detail: `maxAgeMinutes=${maxAgeMinutes}` };
}

function checkAllFreshness(generators, now = Date.now()) {
  return generators.map((gen) => checkGeneratorFreshness(gen, now));
}

module.exports = { getJsonPath, pathNewestMtime, checkGeneratorFreshness, checkAllFreshness };
