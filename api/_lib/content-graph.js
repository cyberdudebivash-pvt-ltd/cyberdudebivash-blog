/**
 * SENTINEL APEX — Content Graph Facade
 *
 * A single read entry point over two subsystems that evolved
 * independently and never shared a lookup surface:
 *  - the intel-graph subsystem (threat-graph.js's actor/CVE/campaign
 *    nodes+edges, already unified behind api/_lib/intel.js's
 *    getGraph/getCampaigns/getCampaignDetail/getTopActorsAPI)
 *  - the intelligence-hub subsystem (api/_lib/intelligence-hub.js's
 *    vendor/timeline/collections/detections aggregation)
 *
 * This delegates to both — it does not reimplement graph logic, CVE
 * parsing, or vendor filtering; those stay single-sourced in their
 * existing modules.
 */
'use strict';
const intel = require('./intel');
const hub = require('./intelligence-hub');

const ENTITY_TYPES = ['cve', 'vendor', 'actor', 'campaign', 'collection'];

function notFound(type, id) {
  return { type, id, found: false, data: null, related: [] };
}

function entityCve(id) {
  const cve = hub.loadCves().find((c) => String(c.id || c.slug || '').toUpperCase() === id.toUpperCase());
  if (!cve) return notFound('cve', id);
  const related = [];
  if (hub.isRealVendor(cve.vendor)) {
    const slug = hub.slugify(cve.vendor);
    related.push({ type: 'vendor', id: slug, label: cve.vendor, url: `/vendor/${slug}.html` });
  }
  return { type: 'cve', id, found: true, data: cve, related };
}

function entityVendor(id) {
  const vendors = hub.buildVendorIndex(hub.loadCves(), { minItems: 1 });
  const slug = hub.slugify(id);
  const vendor = vendors.find((v) => v.slug === slug || v.slug === id);
  if (!vendor) return notFound('vendor', id);
  const related = vendor.items.slice(0, 10).map((i) => ({ type: 'cve', id: i.id, label: i.title, url: i.url }));
  return { type: 'vendor', id, found: true, data: vendor, related };
}

function entityCampaign(id, tier = 'enterprise') {
  const { found, campaign } = intel.getCampaignDetail(id, tier);
  if (!found) return notFound('campaign', id);
  const related = (campaign.related_intel || [])
    .filter((item) => item && (item.id || item.title))
    .slice(0, 10)
    .map((item) => ({ type: 'report', id: item.id || null, label: item.title || item.id || 'related item', url: item.url || null }));
  return { type: 'campaign', id, found: true, data: campaign, related };
}

function entityActor(id, tier = 'enterprise') {
  const { actors } = intel.getTopActorsAPI(tier, 50);
  const slug = hub.slugify(id);
  const actor = (actors || []).find((a) => hub.slugify(a.name || a.id || '') === slug || a.id === id);
  if (!actor) return notFound('actor', id);
  return { type: 'actor', id, found: true, data: actor, related: [] };
}

function entityCollection(id) {
  const collections = hub.buildCollections(hub.loadProducts(), hub.loadCampaigns());
  const collection = collections.find((c) => c.slug === id);
  if (!collection) return notFound('collection', id);
  const related = collection.items.slice(0, 10).map((i) => ({ type: 'report', id: i.slug, label: i.title, url: i.url }));
  return { type: 'collection', id, found: true, data: collection, related };
}

/**
 * Resolve one entity by type+id across both subsystems, returning a
 * normalized shape: { type, id, found, data, related: [{type,id,label,url}] }
 */
function getEntity(type, id, opts = {}) {
  const t = String(type || '').toLowerCase();
  const key = String(id || '').trim();
  if (!key) return notFound(t, key);

  switch (t) {
    case 'cve': return entityCve(key);
    case 'vendor': return entityVendor(key);
    case 'campaign': return entityCampaign(key, opts.tier);
    case 'actor': return entityActor(key, opts.tier);
    case 'collection': return entityCollection(key);
    default: return { ...notFound(t, key), error: `Unknown entity type "${t}". Valid: ${ENTITY_TYPES.join(', ')}` };
  }
}

module.exports = { getEntity, ENTITY_TYPES };
