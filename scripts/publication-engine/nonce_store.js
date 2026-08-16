'use strict';

/**
 * In-memory, single-process replay guard.
 *
 * This proves the ENFORCEMENT PATTERN — a nonce cannot be consumed twice —
 * but provides no protection across multiple processes, container
 * restarts, or horizontally-scaled publishing hosts: a restart clears it,
 * and two replicas each hold an independent store, so each would accept
 * the same nonce once.
 *
 * REPLAY STATE ENFORCEMENT: NOT VERIFIED for any deployment with more than
 * one process, or with restarts, in scope. Real production replay
 * resistance requires persistent shared state (KV/D1/Redis/DB) keyed on
 * nonce, checked-and-set atomically, retained for at least the
 * authorization's TTL.
 */

class InMemoryNonceStore {
  constructor() {
    this._seen = new Set();
  }
  has(nonce) {
    return this._seen.has(nonce);
  }
  record(nonce) {
    this._seen.add(nonce);
  }
  get size() {
    return this._seen.size;
  }
}

function createInMemoryNonceStore() {
  return new InMemoryNonceStore();
}

module.exports = { InMemoryNonceStore, createInMemoryNonceStore };
