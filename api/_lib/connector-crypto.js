'use strict';
/**
 * SENTINEL APEX — Connector Credential Envelope Encryption
 *
 * Mirrors scripts/backup-customer-data.js's encryptSnapshot()/
 * decryptSnapshot() exactly — same algorithm (AES-256-GCM via Node's
 * crypto.createCipheriv/createDecipheriv), same 12-byte random IV, same
 * 64-hex-char (32-byte) key requirement — rather than inventing a second,
 * divergent crypto convention (Reuse Before Build). That script is the
 * only existing precedent in this codebase for "encrypt a secret this
 * platform must later decrypt" (as opposed to webhook-signing.js's
 * one-way HMAC or middleware.js#hashKey()'s one-way SHA-256 API-key hash).
 *
 * New here, beyond that precedent:
 *   - A key-version prefix ("v1:...") so a future master-key rotation can
 *     decrypt old ciphertext with a retired key while new writes use the
 *     current one (Section 22, credential rotation).
 *   - Applied to a per-customer secret stored in D1 rather than a one-off
 *     local backup file. This is a stronger protection than this
 *     platform's existing D1 secret precedent (notification_preferences.
 *     webhook_secret, migrations/0001_notification_delivery.sql, stored
 *     in PLAINTEXT relying only on Cloudflare's platform-level
 *     encryption-at-rest) — justified because a SIEM connector credential
 *     is a genuine third-party cloud credential (e.g. an Azure service
 *     principal secret): a database compromise that recovers it grants an
 *     attacker the ability to act inside the CUSTOMER's own cloud tenant,
 *     not merely to forge a webhook this platform itself validates.
 *
 * Runs today only under Node (this module is required from Workers-
 * reachable code, same as webhook-signing.js's crypto.createHmac/
 * timingSafeEqual calls, via wrangler.jsonc's nodejs_compat flag) — but,
 * like every other Workers-runtime claim in this codebase's history, has
 * not been proven live on a deployed Worker (no tranche in this
 * repository has ever had authenticated Cloudflare access — `wrangler
 * whoami`: not authenticated). Disclosed, not overclaimed.
 */

const crypto = require('crypto');

const CURRENT_KEY_VERSION = 'v1';
const IV_BYTES = 12; // 96-bit IV, standard for GCM — matches backup-customer-data.js
const KEY_ENV_VAR = 'CONNECTOR_CREDENTIAL_MASTER_KEY';
const PREVIOUS_KEY_ENV_VAR = 'CONNECTOR_CREDENTIAL_MASTER_KEY_PREVIOUS';

function _requireValidKeyHex(keyHex, label) {
  if (!/^[0-9a-f]{64}$/i.test(keyHex || '')) {
    throw new Error(`${label} must be a 64-character hex string (32 bytes / AES-256).`);
  }
}

function _currentKey() {
  const keyHex = process.env[KEY_ENV_VAR];
  if (!keyHex) {
    throw new Error(`${KEY_ENV_VAR} is not set. Refusing to encrypt/decrypt a connector credential without a master key. See docs/architecture/PRODUCTION-SECRETS-INVENTORY.md.`);
  }
  _requireValidKeyHex(keyHex, KEY_ENV_VAR);
  return keyHex;
}

/** AES-256-GCM encrypt. Returns "v<version>:<ivHex>:<authTagHex>:<ciphertextHex>" —
 *  a single flat string, storable as one TEXT column. */
function encryptCredential(plaintext) {
  if (typeof plaintext !== 'string' || !plaintext) {
    throw new Error('encryptCredential() requires a non-empty string.');
  }
  const keyHex = _currentKey();
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [CURRENT_KEY_VERSION, iv.toString('hex'), authTag.toString('hex'), ciphertext.toString('hex')].join(':');
}

/** Inverse of encryptCredential(). `version` in the stored value is a WIRE-
 *  FORMAT tag (currently always "v1" — algorithm/encoding version, bumped
 *  only if the scheme itself changes), NOT a key identifier: GCM gives no
 *  way to tell which of two 32-byte keys produced a given ciphertext
 *  without attempting decryption, so key selection is done by trying,
 *  not by reading a tag. Tries the current master key first; if that
 *  fails (wrong key, surfaced by GCM as an auth-tag verification error)
 *  and CONNECTOR_CREDENTIAL_MASTER_KEY_PREVIOUS is configured (a rotation
 *  in progress), retries with the previous key — the documented rotation
 *  mechanism (Section 22): rotate by setting a new current key and moving
 *  the old one to _PREVIOUS, then re-encrypt-on-next-write
 *  (siem-connector-store.js#rotateCredential()) until nothing references
 *  the previous key, then remove it. Throws (the CURRENT key's own error,
 *  not the fallback attempt's) if neither key verifies — tampered/
 *  corrupted/wrong-key ciphertext is rejected, never silently accepted. */
function decryptCredential(stored) {
  const parts = String(stored || '').split(':');
  if (parts.length !== 4) {
    throw new Error('Malformed encrypted credential (expected version:ivHex:authTagHex:ciphertextHex).');
  }
  const [version, ivHex, tagHex, dataHex] = parts;
  if (version !== CURRENT_KEY_VERSION) {
    throw new Error(`Unrecognized encrypted-credential format version "${version}".`);
  }

  const tryKey = (keyHex) => {
    const key = Buffer.from(keyHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
  };

  try {
    return tryKey(_currentKey());
  } catch (primaryErr) {
    const previousKeyHex = process.env[PREVIOUS_KEY_ENV_VAR];
    if (previousKeyHex) {
      _requireValidKeyHex(previousKeyHex, PREVIOUS_KEY_ENV_VAR);
      try {
        return tryKey(previousKeyHex);
      } catch (_) {
        // Fall through to surface the CURRENT key's error below — it's
        // the primary attempt and the more meaningful failure to report.
      }
    }
    throw primaryErr;
  }
}

/** True only if a master key is configured — connectors that require a
 *  credential must refuse to save one (not silently store plaintext)
 *  when this is false. */
function isConfigured() {
  return !!process.env[KEY_ENV_VAR];
}

module.exports = {
  CURRENT_KEY_VERSION,
  encryptCredential,
  decryptCredential,
  isConfigured,
};
