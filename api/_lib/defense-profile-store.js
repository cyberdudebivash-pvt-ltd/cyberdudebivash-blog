'use strict';
/**
 * SENTINEL APEX -- Customer Defense Profile Persistence (Cloudflare D1)
 *
 * Mirrors watchlist-store.js's established pattern exactly (see
 * docs/audits/SENTINEL-APEX-CUSTOMER-DEFENSE-CONTEXT-INVENTORY-V1.md §2):
 * ownership always re-derived from the caller's authenticate()-issued
 * userId, never trusted from the request body; identical NOT_FOUND for
 * "doesn't exist" and "exists but belongs to someone else"; a best-effort,
 * capped audit log.
 *
 * Schema: migrations/0003_defense_profiles.sql, same `sentinel-apex-core`
 * D1 database watchlists/notifications already use.
 *
 * One profile per owner in v1 (mandate Phase 52 -- no multi-workspace
 * foundation exists to scope multiple profiles under, see the inventory
 * doc). save() is a whole-resource replace (PUT semantics), not a partial
 * PATCH merge: the caller (the Defense Environment wizard) always reads
 * the current profile via get() before rendering the form, so a Save
 * always carries the complete current state forward, and this store never
 * has to guess which unset fields the caller meant to leave alone versus
 * meant to clear (mandate Phase 36's "update must not silently wipe
 * unrelated values" concern, addressed at the contract level rather than
 * with server-side partial-merge complexity).
 */

const crypto = require('crypto');
const d1 = require('./d1');
const { sanitize } = require('./payment-utils');
const taxonomy = require('./defense-taxonomy');

const PROFILE_SCHEMA_VERSION = '1.0';
const MAX_NAME_LENGTH = 100;
const MAX_CUSTOM_LABEL_LENGTH = 100;
const MAX_TECHNOLOGIES_PER_CATEGORY = 10; // abuse-prevention hard cap, not a product limit
const AUDIT_LOG_MAX_ENTRIES = 10000; // matches watchlist_audit_log's own bound

function generateProfileId() {
  return 'dp_' + crypto.randomBytes(12).toString('hex');
}

async function auditProfileAction(action, data = {}) {
  try {
    await d1.run(
      'INSERT INTO defense_profile_audit_log (action, data, ts) VALUES (?, ?, ?)',
      [action, JSON.stringify(data), new Date().toISOString()]
    );
    await d1.run(
      `DELETE FROM defense_profile_audit_log WHERE id NOT IN
       (SELECT id FROM defense_profile_audit_log ORDER BY id DESC LIMIT ?)`,
      [AUDIT_LOG_MAX_ENTRIES]
    ).catch(() => {});
  } catch (_) {
    // Audit failure must never break the main flow.
  }
}

/* ───────────────────────── validation ───────────────────────── */

function validateName(name) {
  if (name === undefined || name === null || name === '') return { value: 'My Defense Environment' };
  const clean = sanitize(name, MAX_NAME_LENGTH).trim();
  if (!clean) return { error: true, message: `name must be 1-${MAX_NAME_LENGTH} characters.` };
  return { value: clean };
}

// Rejects prototype-pollution-shaped keys, unknown categories, and unknown
// technology ids (except the CUSTOM_UNMAPPED 'other' sentinel) before
// anything touches D1. `technologies` is the whole-array wizard payload:
// [{ category, technology_id, custom_label? }, ...].
function validateTechnologies(technologies) {
  if (technologies === undefined) return { value: [] };
  if (!Array.isArray(technologies)) return { error: true, message: 'technologies must be an array.' };
  if (technologies.length > MAX_TECHNOLOGIES_PER_CATEGORY * taxonomy.TECHNOLOGY_CATEGORIES.length) {
    return { error: true, message: 'Too many technologies declared.' };
  }
  const perCategoryCount = {};
  const clean = [];
  const seen = new Set();
  for (const entry of technologies) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return { error: true, message: 'Each technology entry must be an object.' };
    }
    const category = String(entry.category || '').toLowerCase().trim();
    if (['__proto__', 'constructor', 'prototype'].includes(category)) {
      return { error: true, message: 'Unsupported technology category.' };
    }
    if (!taxonomy.TECHNOLOGY_CATEGORIES.includes(category)) {
      return { error: true, message: `Unsupported technology category: "${entry.category}". Supported: ${taxonomy.TECHNOLOGY_CATEGORIES.join(', ')}.` };
    }
    const technologyId = String(entry.technology_id || '').toLowerCase().trim();
    if (['__proto__', 'constructor', 'prototype'].includes(technologyId)) {
      return { error: true, message: 'Unsupported technology id.' };
    }
    if (!taxonomy.isKnownTechnology(category, technologyId)) {
      return { error: true, message: `Unknown technology "${entry.technology_id}" for category "${category}".` };
    }
    let customLabel = '';
    if (technologyId === taxonomy.CUSTOM_UNMAPPED_ID) {
      customLabel = sanitize(entry.custom_label, MAX_CUSTOM_LABEL_LENGTH).trim();
    }
    const dedupeKey = `${category}:${technologyId}`;
    if (seen.has(dedupeKey)) continue; // idempotent de-dup, not an error
    seen.add(dedupeKey);
    perCategoryCount[category] = (perCategoryCount[category] || 0) + 1;
    if (perCategoryCount[category] > MAX_TECHNOLOGIES_PER_CATEGORY) {
      return { error: true, message: `Maximum of ${MAX_TECHNOLOGIES_PER_CATEGORY} technologies per category.` };
    }
    clean.push({ category, technology_id: technologyId, custom_label: customLabel });
  }
  return { value: clean };
}

// telemetry payload: { process_creation: 'AVAILABLE', ... }. A key whose
// value is 'UNKNOWN' (or an empty/omitted value) is dropped rather than
// stored -- "missing row" IS the UNKNOWN representation (see the migration
// file's own design note), so there is exactly one way to express
// "not configured", never two that could drift apart.
function validateTelemetry(telemetry) {
  if (telemetry === undefined) return { value: {} };
  if (!telemetry || typeof telemetry !== 'object' || Array.isArray(telemetry)) {
    return { error: true, message: 'telemetry must be an object.' };
  }
  const clean = {};
  for (const [key, rawValue] of Object.entries(telemetry)) {
    const dataSource = String(key || '').toLowerCase().trim();
    if (['__proto__', 'constructor', 'prototype'].includes(dataSource)) {
      return { error: true, message: 'Unsupported telemetry data source.' };
    }
    if (!taxonomy.DATA_SOURCES.includes(dataSource)) {
      return { error: true, message: `Unknown telemetry data source: "${key}". Supported: ${taxonomy.DATA_SOURCES.join(', ')}.` };
    }
    const status = String(rawValue || 'UNKNOWN').toUpperCase().trim();
    if (!taxonomy.TELEMETRY_STATUS_VALUES.includes(status)) {
      return { error: true, message: `Invalid telemetry status "${rawValue}" for "${dataSource}". Supported: ${taxonomy.TELEMETRY_STATUS_VALUES.join(', ')}.` };
    }
    if (status !== 'UNKNOWN') clean[dataSource] = status; // UNKNOWN == no row, never persisted
  }
  return { value: clean };
}

/* ───────────────────────── serialization ───────────────────────── */

function toPublicProfile(record, technologies, telemetry) {
  return {
    schema_version: record.schema_version || PROFILE_SCHEMA_VERSION,
    id: record.id,
    name: record.name,
    technologies: technologies.map(t => ({
      category: t.category,
      technology_id: t.technology_id,
      label: t.technology_id === taxonomy.CUSTOM_UNMAPPED_ID
        ? (t.custom_label || 'Other')
        : (taxonomy.TECHNOLOGIES[t.technology_id] || {}).label || t.technology_id,
      custom_unmapped: t.technology_id === taxonomy.CUSTOM_UNMAPPED_ID,
    })),
    telemetry: telemetry.reduce((acc, row) => { acc[row.data_source] = row.status; return acc; }, {}),
    created_at: record.created_at,
    updated_at: record.updated_at,
  };
}

/* ───────────────────────── entitlements ───────────────────────── */
// Flat across tiers -- mirrors watchlist-store.js#getWatchlistEntitlements()'s
// documented, deliberate non-differentiation exactly (see platform/open-issues.md).
function getDefenseProfileEntitlements(_tier) {
  return {
    enabled: true,
    max_profiles: 1,
    max_technologies_per_category: MAX_TECHNOLOGIES_PER_CATEGORY,
  };
}

/* ───────────────────────── CRUD ───────────────────────── */

async function getRawByOwner(ownerId) {
  const rows = await d1.query('SELECT * FROM defense_profiles WHERE owner_id = ?', [ownerId]);
  return rows[0] || null;
}

async function loadFull(record) {
  const [technologies, telemetry] = await Promise.all([
    d1.query('SELECT category, technology_id, custom_label FROM defense_profile_technologies WHERE profile_id = ? ORDER BY category, technology_id', [record.id]),
    d1.query('SELECT data_source, status FROM defense_profile_telemetry WHERE profile_id = ? ORDER BY data_source', [record.id]),
  ]);
  return toPublicProfile(record, technologies, telemetry);
}

/** Returns { profile: null } (not an error) when the owner has no profile yet -- mandate Phase 37's safe-default. */
async function getProfile(ownerId) {
  const record = await getRawByOwner(ownerId);
  if (!record) return { profile: null };
  return { profile: await loadFull(record) };
}

/**
 * Whole-resource create-or-replace. Technology/telemetry rows are replaced
 * atomically-in-effect from this module's perspective (delete-then-insert
 * within the same call, matching watchlist-store.js's own non-D1-transaction
 * precedent for bounded, per-owner-only state -- a concurrent double-save
 * by the SAME owner could theoretically interleave, an accepted, disclosed,
 * self-only race identical in kind to watchlist-store.js#addEntity()'s).
 */
async function saveProfile(ownerId, { name, technologies, telemetry }) {
  const nameResult = validateName(name);
  if (nameResult.error) return { error: 'INVALID_NAME', message: nameResult.message };
  const techResult = validateTechnologies(technologies);
  if (techResult.error) return { error: 'INVALID_TECHNOLOGIES', message: techResult.message };
  const telResult = validateTelemetry(telemetry);
  if (telResult.error) return { error: 'INVALID_TELEMETRY', message: telResult.message };

  const nowIso = new Date().toISOString();
  let record = await getRawByOwner(ownerId);
  let profileId;
  if (record) {
    profileId = record.id;
    await d1.run('UPDATE defense_profiles SET name = ?, updated_at = ? WHERE id = ?', [nameResult.value, nowIso, profileId]);
  } else {
    profileId = generateProfileId();
    await d1.run(
      `INSERT INTO defense_profiles (id, owner_id, name, schema_version, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [profileId, ownerId, nameResult.value, PROFILE_SCHEMA_VERSION, nowIso, nowIso]
    );
  }

  await d1.run('DELETE FROM defense_profile_technologies WHERE profile_id = ?', [profileId]).catch(() => {});
  for (const t of techResult.value) {
    await d1.run(
      `INSERT INTO defense_profile_technologies (profile_id, category, technology_id, custom_label, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [profileId, t.category, t.technology_id, t.custom_label || null, nowIso]
    );
  }

  await d1.run('DELETE FROM defense_profile_telemetry WHERE profile_id = ?', [profileId]).catch(() => {});
  for (const [dataSource, status] of Object.entries(telResult.value)) {
    await d1.run(
      `INSERT INTO defense_profile_telemetry (profile_id, data_source, status, updated_at)
       VALUES (?, ?, ?, ?)`,
      [profileId, dataSource, status, nowIso]
    );
  }

  record = await getRawByOwner(ownerId);
  auditProfileAction('DEFENSE_PROFILE_SAVED', { owner: ownerId, profileId, technologyCount: techResult.value.length, telemetryCount: Object.keys(telResult.value).length }).catch(() => {});
  return { profile: await loadFull(record) };
}

async function deleteProfile(ownerId) {
  const record = await getRawByOwner(ownerId);
  if (!record) return { error: 'NOT_FOUND', message: 'No Defense Profile configured.' };
  await d1.run('DELETE FROM defense_profile_technologies WHERE profile_id = ?', [record.id]).catch(() => {});
  await d1.run('DELETE FROM defense_profile_telemetry WHERE profile_id = ?', [record.id]).catch(() => {});
  await d1.run('DELETE FROM defense_profiles WHERE id = ?', [record.id]).catch(() => {});
  auditProfileAction('DEFENSE_PROFILE_DELETED', { owner: ownerId, profileId: record.id }).catch(() => {});
  return { deleted: true };
}

module.exports = {
  PROFILE_SCHEMA_VERSION,
  MAX_TECHNOLOGIES_PER_CATEGORY,
  getDefenseProfileEntitlements,
  getProfile,
  saveProfile,
  deleteProfile,
  auditProfileAction,
};
