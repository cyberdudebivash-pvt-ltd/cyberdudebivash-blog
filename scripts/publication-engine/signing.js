'use strict';

/**
 * Injectable Ed25519 signing/verification (node:crypto only — no new
 * dependency). No production private key material lives in this file or
 * anywhere in this repository: signers are constructed from key material
 * the CALLER supplies (env var, KMS response, secret manager, or an
 * ephemeral test keypair). See SKILL.md — "PRODUCTION KEY MANAGEMENT:
 * NOT VERIFIED" — this module defines the interface a real KMS-backed
 * signer must satisfy; it does not itself provide one.
 */

const crypto = require('node:crypto');

/**
 * Test/dev convenience only. Never call this to obtain a production key —
 * production keys must come from a secret manager / KMS, injected into
 * createSigner(), not generated in-process on a publishing host.
 */
function generateEphemeralKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

/**
 * @param {{ keyId: string, privateKey: string|import('crypto').KeyObject }} config
 * @returns {{ keyId: string, sign(payload: string|Buffer): string }}
 */
function createSigner({ keyId, privateKey } = {}) {
  if (typeof keyId !== 'string' || keyId.trim().length === 0) {
    throw new TypeError('createSigner: keyId is required');
  }
  if (!privateKey) {
    throw new TypeError('createSigner: privateKey is required (inject it — never hardcode it)');
  }
  return {
    keyId,
    sign(payload) {
      const data = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
      return crypto.sign(null, data, privateKey).toString('base64');
    },
  };
}

/**
 * A trust store of keyId -> public key, plus a fail-closed verify(): any
 * unknown keyId, malformed signature, or internal exception returns
 * `false` — verify() must never throw past its own boundary and must never
 * return `true` except on a positive cryptographic match.
 *
 * @param {{ trustedKeys: Record<string, string|import('crypto').KeyObject> }} config
 */
function createVerifier({ trustedKeys } = {}) {
  if (!trustedKeys || typeof trustedKeys !== 'object') {
    throw new TypeError('createVerifier: trustedKeys is required');
  }
  return {
    isKnownKey(keyId) {
      return typeof keyId === 'string' && Object.prototype.hasOwnProperty.call(trustedKeys, keyId);
    },
    verify(payload, signatureBase64, keyId) {
      try {
        if (!this.isKnownKey(keyId)) return false;
        if (typeof signatureBase64 !== 'string' || signatureBase64.length === 0) return false;
        const publicKey = trustedKeys[keyId];
        const data = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
        const signature = Buffer.from(signatureBase64, 'base64');
        return crypto.verify(null, data, publicKey, signature);
      } catch {
        return false;
      }
    },
  };
}

module.exports = { generateEphemeralKeypair, createSigner, createVerifier };
