'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { generateEphemeralKeypair, createSigner, createVerifier } = require('./signing');

describe('signing: Ed25519 round trip', () => {
  test('a signature made by the signer verifies under the matching public key', () => {
    const { publicKey, privateKey } = generateEphemeralKeypair();
    const signer = createSigner({ keyId: 'key-A', privateKey });
    const verifier = createVerifier({ trustedKeys: { 'key-A': publicKey } });

    const signature = signer.sign('hello world');
    assert.equal(verifier.verify('hello world', signature, 'key-A'), true);
  });

  test('two keypairs are not interchangeable', () => {
    const kp1 = generateEphemeralKeypair();
    const kp2 = generateEphemeralKeypair();
    assert.notEqual(kp1.publicKey, kp2.publicKey);
    assert.notEqual(kp1.privateKey, kp2.privateKey);
  });
});

describe('signing: fail-closed verification', () => {
  test('an altered payload fails verification', () => {
    const { publicKey, privateKey } = generateEphemeralKeypair();
    const signer = createSigner({ keyId: 'key-A', privateKey });
    const verifier = createVerifier({ trustedKeys: { 'key-A': publicKey } });
    const signature = signer.sign('original payload');
    assert.equal(verifier.verify('tampered payload', signature, 'key-A'), false);
  });

  test('an altered signature fails verification', () => {
    const { publicKey, privateKey } = generateEphemeralKeypair();
    const signer = createSigner({ keyId: 'key-A', privateKey });
    const verifier = createVerifier({ trustedKeys: { 'key-A': publicKey } });
    const signature = signer.sign('payload');
    const tampered = signature.slice(0, -4) + (signature.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
    assert.equal(verifier.verify('payload', tampered, 'key-A'), false);
  });

  test('verifying against the wrong public key fails, even for a keyId the verifier trusts', () => {
    const kpReal = generateEphemeralKeypair();
    const kpWrong = generateEphemeralKeypair();
    const signer = createSigner({ keyId: 'key-A', privateKey: kpReal.privateKey });
    // key-A is "trusted" but mapped to the WRONG public key.
    const verifier = createVerifier({ trustedKeys: { 'key-A': kpWrong.publicKey } });
    const signature = signer.sign('payload');
    assert.equal(verifier.verify('payload', signature, 'key-A'), false);
  });

  test('an unknown keyId fails verification even with a technically-valid signature', () => {
    const { publicKey, privateKey } = generateEphemeralKeypair();
    const signer = createSigner({ keyId: 'key-A', privateKey });
    const verifier = createVerifier({ trustedKeys: { 'key-B': publicKey } }); // key-A never registered
    const signature = signer.sign('payload');
    assert.equal(verifier.verify('payload', signature, 'key-A'), false);
    assert.equal(verifier.isKnownKey('key-A'), false);
  });

  test('verify() never throws — garbage inputs fail closed to false', () => {
    const { publicKey } = generateEphemeralKeypair();
    const verifier = createVerifier({ trustedKeys: { 'key-A': publicKey } });
    assert.equal(verifier.verify('payload', null, 'key-A'), false);
    assert.equal(verifier.verify('payload', undefined, 'key-A'), false);
    assert.equal(verifier.verify('payload', 123, 'key-A'), false);
    assert.equal(verifier.verify('payload', 'not-base64-!!!', 'key-A'), false);
    assert.equal(verifier.verify('payload', '', 'key-A'), false);
    assert.equal(verifier.verify('payload', 'AAAA', null), false);
    assert.equal(verifier.verify('payload', 'AAAA', undefined), false);
    assert.equal(verifier.verify('payload', 'AAAA', 123), false);
  });
});

describe('signing: constructor validation', () => {
  test('createSigner requires keyId and privateKey', () => {
    const { privateKey } = generateEphemeralKeypair();
    assert.throws(() => createSigner({ privateKey }));
    assert.throws(() => createSigner({ keyId: 'key-A' }));
    assert.throws(() => createSigner({ keyId: '', privateKey }));
  });

  test('createVerifier requires trustedKeys', () => {
    assert.throws(() => createVerifier({}));
    assert.throws(() => createVerifier({ trustedKeys: null }));
  });
});
