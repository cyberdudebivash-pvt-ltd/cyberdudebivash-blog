'use strict';

/**
 * Deterministic JSON canonicalization for hashing and signing.
 *
 * Object keys are sorted so two structurally-equal objects always produce
 * byte-identical output regardless of construction order. Arrays preserve
 * order (order is semantically meaningful there). Anything that cannot be
 * represented unambiguously — undefined, functions, symbols, bigint,
 * non-finite numbers, Date instances, non-plain objects — throws instead of
 * silently coercing, because a hashed/signed payload must never depend on
 * an implicit conversion a verifier might reproduce differently.
 */

const crypto = require('node:crypto');

function canonicalizeValue(value) {
  if (value === null) return 'null';

  const type = typeof value;

  if (type === 'string') return JSON.stringify(value);

  if (type === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`canonicalize: non-finite numbers are not canonicalizable (${value})`);
    }
    return JSON.stringify(value);
  }

  if (type === 'boolean') return JSON.stringify(value);

  if (type === 'undefined') {
    throw new TypeError('canonicalize: undefined is not canonicalizable — use null explicitly');
  }

  if (type === 'bigint' || type === 'function' || type === 'symbol') {
    throw new TypeError(`canonicalize: ${type} is not canonicalizable`);
  }

  if (Array.isArray(value)) {
    return '[' + value.map(canonicalizeValue).join(',') + ']';
  }

  if (type === 'object') {
    if (value instanceof Date) {
      throw new TypeError('canonicalize: Date instances are not canonicalizable — use an explicit ISO string field');
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError('canonicalize: only plain objects, arrays, and primitives are canonicalizable');
    }
    const keys = Object.keys(value).sort();
    const entries = keys.map((key) => {
      const v = value[key];
      if (v === undefined) {
        throw new TypeError(`canonicalize: key "${key}" has undefined value — use null explicitly`);
      }
      return JSON.stringify(key) + ':' + canonicalizeValue(v);
    });
    return '{' + entries.join(',') + '}';
  }

  throw new TypeError(`canonicalize: unsupported type ${type}`);
}

function canonicalize(value) {
  return canonicalizeValue(value);
}

function sha256Hex(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function canonicalHash(value) {
  return sha256Hex(canonicalize(value));
}

module.exports = { canonicalize, sha256Hex, canonicalHash };
