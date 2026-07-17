/**
 * SENTINEL APEX — Enterprise Account Metadata Schema (architecture only)
 *
 * Shape definition for a future enterprise account record. No storage
 * layer exists for this yet — there is no visitor-identity system in the
 * platform today (same gap noted for the deferred paywall/customer-
 * workspace work). This is purely the data contract, validated by a pure
 * function, so that whenever an identity system is scoped, the shape
 * doesn't need to be invented from scratch under time pressure.
 *
 * @typedef {Object} EnterpriseAccount
 * @property {string} accountId
 * @property {string} companyName
 * @property {string} primaryContactEmail
 * @property {number} seats
 * @property {'starter'|'pro'|'enterprise'} tier
 * @property {string[]} [additionalContacts]
 * @property {string} [salesOwner]
 * @property {string} createdAt  ISO 8601 timestamp
 */
'use strict';
const { TIERS } = require('./middleware');

const REQUIRED_FIELDS = ['accountId', 'companyName', 'primaryContactEmail', 'seats', 'tier', 'createdAt'];

function isValidEnterpriseAccountShape(obj) {
  if (!obj || typeof obj !== 'object') return false;
  for (const field of REQUIRED_FIELDS) {
    if (!(field in obj)) return false;
  }
  if (typeof obj.accountId !== 'string' || !obj.accountId) return false;
  if (typeof obj.companyName !== 'string' || !obj.companyName) return false;
  if (typeof obj.primaryContactEmail !== 'string' || !obj.primaryContactEmail.includes('@')) return false;
  if (typeof obj.seats !== 'number' || obj.seats < 1) return false;
  if (!TIERS.includes(obj.tier)) return false;
  if (Number.isNaN(Date.parse(obj.createdAt))) return false;
  if ('additionalContacts' in obj && !Array.isArray(obj.additionalContacts)) return false;
  return true;
}

module.exports = { REQUIRED_FIELDS, isValidEnterpriseAccountShape };
