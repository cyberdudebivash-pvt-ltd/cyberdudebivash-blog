'use strict';

const ORIGINAL_KEY = process.env.CONNECTOR_CREDENTIAL_MASTER_KEY;
const ORIGINAL_PREV = process.env.CONNECTOR_CREDENTIAL_MASTER_KEY_PREVIOUS;

afterEach(() => {
  process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = ORIGINAL_KEY;
  process.env.CONNECTOR_CREDENTIAL_MASTER_KEY_PREVIOUS = ORIGINAL_PREV;
  jest.resetModules();
});

function freshModule() {
  jest.resetModules();
  return require('../connector-crypto');
}

describe('connector-crypto', () => {
  test('encrypts and decrypts a round trip correctly', () => {
    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = '1'.repeat(64);
    const crypto = freshModule();
    const encrypted = crypto.encryptCredential(JSON.stringify({ client_secret: 'super-secret-value' }));
    expect(encrypted.startsWith('v1:')).toBe(true);
    const decrypted = JSON.parse(crypto.decryptCredential(encrypted));
    expect(decrypted.client_secret).toBe('super-secret-value');
  });

  test('the ciphertext never contains the plaintext secret verbatim', () => {
    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = '2'.repeat(64);
    const crypto = freshModule();
    const encrypted = crypto.encryptCredential('a-very-recognizable-plaintext-value');
    expect(encrypted).not.toContain('a-very-recognizable-plaintext-value');
  });

  test('refuses to encrypt when no master key is configured', () => {
    delete process.env.CONNECTOR_CREDENTIAL_MASTER_KEY;
    const crypto = freshModule();
    expect(() => crypto.encryptCredential('x')).toThrow(/CONNECTOR_CREDENTIAL_MASTER_KEY/);
  });

  test('rejects a master key that is not 64 hex characters', () => {
    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = 'too-short';
    const crypto = freshModule();
    expect(() => crypto.encryptCredential('x')).toThrow(/64-character hex/);
  });

  test('tampered ciphertext fails to decrypt (auth tag verification)', () => {
    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = '3'.repeat(64);
    const crypto = freshModule();
    const encrypted = crypto.encryptCredential('secret-value');
    const parts = encrypted.split(':');
    // Flip the last hex character of the ciphertext.
    const tamperedCiphertext = parts[3].slice(0, -1) + (parts[3].slice(-1) === 'a' ? 'b' : 'a');
    const tampered = [parts[0], parts[1], parts[2], tamperedCiphertext].join(':');
    expect(() => crypto.decryptCredential(tampered)).toThrow();
  });

  test('decrypting with the wrong key fails rather than returning garbage silently', () => {
    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = '4'.repeat(64);
    const crypto = freshModule();
    const encrypted = crypto.encryptCredential('secret-value');
    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = '5'.repeat(64);
    const crypto2 = freshModule();
    expect(() => crypto2.decryptCredential(encrypted)).toThrow();
  });

  test('rotation: a value encrypted under the previous key still decrypts once it is set as PREVIOUS', () => {
    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = '6'.repeat(64);
    const cryptoOld = freshModule();
    const encryptedUnderOldKey = cryptoOld.encryptCredential('secret-under-old-key');

    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = '7'.repeat(64);
    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY_PREVIOUS = '6'.repeat(64);
    const cryptoNew = freshModule();
    expect(cryptoNew.decryptCredential(encryptedUnderOldKey)).toBe('secret-under-old-key');

    // New writes use the new key.
    const encryptedUnderNewKey = cryptoNew.encryptCredential('secret-under-new-key');
    expect(cryptoNew.decryptCredential(encryptedUnderNewKey)).toBe('secret-under-new-key');
  });

  test('malformed stored value is rejected, not silently accepted', () => {
    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = '8'.repeat(64);
    const crypto = freshModule();
    expect(() => crypto.decryptCredential('not-the-right-format')).toThrow(/Malformed/);
  });

  test('isConfigured() reflects whether the master key is set', () => {
    delete process.env.CONNECTOR_CREDENTIAL_MASTER_KEY;
    const crypto = freshModule();
    expect(crypto.isConfigured()).toBe(false);
    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = '9'.repeat(64);
    const crypto2 = freshModule();
    expect(crypto2.isConfigured()).toBe(true);
  });
});
