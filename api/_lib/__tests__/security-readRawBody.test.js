'use strict';

const { EventEmitter } = require('events');
const sec = require('../security');

// Minimal fake of Node's IncomingMessage stream-event surface — exactly
// what readRawBody's original (pre-Cloudflare) branch actually calls:
// req.on('data'/'end'/'error') and req.destroy().
function fakeNodeStream() {
  const emitter = new EventEmitter();
  emitter.destroy = jest.fn();
  return emitter;
}

// Minimal fake of the Web Request surface readRawBody's Cloudflare branch
// calls: only .arrayBuffer(). Deliberately has no .on()/.destroy() — if
// the wrong branch were ever taken, the test fails loudly instead of
// silently passing.
function fakeWebRequest(text) {
  const bytes = Buffer.from(text, 'utf8');
  return { arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
}

describe('security.js readRawBody', () => {
  describe('Node stream path (Vercel/Node — unchanged behavior)', () => {
    test('resolves with concatenated data across multiple chunks', async () => {
      const req = fakeNodeStream();
      const promise = sec.readRawBody(req, 1024);
      req.emit('data', 'hello ');
      req.emit('data', 'world');
      req.emit('end');
      await expect(promise).resolves.toBe('hello world');
    });

    test('rejects with PAYLOAD_TOO_LARGE and destroys the stream when over the limit', async () => {
      const req = fakeNodeStream();
      const promise = sec.readRawBody(req, 4);
      req.emit('data', 'toolong');
      await expect(promise).rejects.toThrow('PAYLOAD_TOO_LARGE');
      expect(req.destroy).toHaveBeenCalled();
    });

    test('rejects with the stream error', async () => {
      const req = fakeNodeStream();
      const promise = sec.readRawBody(req, 1024);
      req.emit('error', new Error('socket hang up'));
      await expect(promise).rejects.toThrow('socket hang up');
    });

    test('never touches __cfRequest when absent', async () => {
      const req = fakeNodeStream();
      expect(req.__cfRequest).toBeUndefined();
      const promise = sec.readRawBody(req, 1024);
      req.emit('data', 'x');
      req.emit('end');
      await expect(promise).resolves.toBe('x');
    });
  });

  describe('Cloudflare Workers path (req.__cfRequest present)', () => {
    test('resolves with the raw body text via arrayBuffer()', async () => {
      const req = { __cfRequest: fakeWebRequest('{"signed":"payload"}') };
      await expect(sec.readRawBody(req, 1024)).resolves.toBe('{"signed":"payload"}');
    });

    test('rejects with PAYLOAD_TOO_LARGE when over the limit, matching the Node-stream branch', async () => {
      const req = { __cfRequest: fakeWebRequest('this body is definitely too long') };
      await expect(sec.readRawBody(req, 4)).rejects.toThrow('PAYLOAD_TOO_LARGE');
    });

    test('handles an empty body', async () => {
      const req = { __cfRequest: fakeWebRequest('') };
      await expect(sec.readRawBody(req, 1024)).resolves.toBe('');
    });
  });
});
