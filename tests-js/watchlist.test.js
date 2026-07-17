'use strict';
const test = require('node:test');
const assert = require('node:assert');
const {
  getSavedSearches, saveSearch, removeSavedSearch,
  getWatchlist, addToWatchlist, removeFromWatchlist, isInWatchlist,
  MAX_SEARCHES, MAX_WATCHLIST,
} = require('../watchlist');

function fakeStorage() {
  const data = new Map();
  return {
    getItem: (k) => (data.has(k) ? data.get(k) : null),
    setItem: (k, v) => { data.set(k, v); },
  };
}

/* ─── saved searches ─────────────────────────────────────────── */

test('getSavedSearches returns an empty array when nothing is stored', () => {
  assert.deepStrictEqual(getSavedSearches(fakeStorage()), []);
});

test('saveSearch stores a new search, most-recent first', () => {
  const storage = fakeStorage();
  saveSearch('ransomware', 'ALL', storage);
  const list = saveSearch('cve-2026', 'CVE', storage);
  assert.strictEqual(list.length, 2);
  assert.strictEqual(list[0].query, 'cve-2026');
  assert.strictEqual(list[1].query, 'ransomware');
});

test('saveSearch is idempotent for the same query+type — re-saves to the front, no duplicate', () => {
  const storage = fakeStorage();
  saveSearch('ransomware', 'ALL', storage);
  saveSearch('cve-2026', 'CVE', storage);
  const list = saveSearch('ransomware', 'ALL', storage);
  assert.strictEqual(list.length, 2);
  assert.strictEqual(list[0].query, 'ransomware');
});

test('saveSearch ignores an empty/whitespace-only query', () => {
  const storage = fakeStorage();
  const list = saveSearch('   ', 'ALL', storage);
  assert.deepStrictEqual(list, []);
});

test('saveSearch caps the list at MAX_SEARCHES', () => {
  const storage = fakeStorage();
  for (let i = 0; i < MAX_SEARCHES + 5; i++) saveSearch('query-' + i, 'ALL', storage);
  assert.strictEqual(getSavedSearches(storage).length, MAX_SEARCHES);
});

test('removeSavedSearch removes only the matching query+type pair', () => {
  const storage = fakeStorage();
  saveSearch('ransomware', 'ALL', storage);
  saveSearch('ransomware', 'RANSOMWARE', storage);
  const list = removeSavedSearch('ransomware', 'ALL', storage);
  assert.strictEqual(list.length, 1);
  assert.strictEqual(list[0].typeFilter, 'RANSOMWARE');
});

/* ─── watchlist ──────────────────────────────────────────────── */

test('getWatchlist returns an empty array when nothing is stored', () => {
  assert.deepStrictEqual(getWatchlist(fakeStorage()), []);
});

test('addToWatchlist stores an item with a real url/label preserved', () => {
  const storage = fakeStorage();
  const list = addToWatchlist({ type: 'cve', id: 'CVE-2026-1234', label: 'Critical RCE', url: '/cve/CVE-2026-1234.html' }, storage);
  assert.strictEqual(list.length, 1);
  assert.strictEqual(list[0].url, '/cve/CVE-2026-1234.html');
});

test('addToWatchlist ignores an item missing type or id', () => {
  const storage = fakeStorage();
  assert.deepStrictEqual(addToWatchlist({ label: 'no id' }, storage), []);
  assert.deepStrictEqual(addToWatchlist(null, storage), []);
});

test('addToWatchlist deduplicates by type+id, moving the re-added item to the front', () => {
  const storage = fakeStorage();
  addToWatchlist({ type: 'vendor', id: 'microsoft', label: 'Microsoft' }, storage);
  addToWatchlist({ type: 'vendor', id: 'cisco', label: 'Cisco' }, storage);
  const list = addToWatchlist({ type: 'vendor', id: 'microsoft', label: 'Microsoft' }, storage);
  assert.strictEqual(list.length, 2);
  assert.strictEqual(list[0].id, 'microsoft');
});

test('addToWatchlist caps the list at MAX_WATCHLIST', () => {
  const storage = fakeStorage();
  for (let i = 0; i < MAX_WATCHLIST + 10; i++) addToWatchlist({ type: 'cve', id: 'CVE-' + i }, storage);
  assert.strictEqual(getWatchlist(storage).length, MAX_WATCHLIST);
});

test('removeFromWatchlist removes only the matching type+id', () => {
  const storage = fakeStorage();
  addToWatchlist({ type: 'cve', id: 'CVE-1' }, storage);
  addToWatchlist({ type: 'vendor', id: 'CVE-1' }, storage); // same id, different type -> must survive
  const list = removeFromWatchlist('cve', 'CVE-1', storage);
  assert.strictEqual(list.length, 1);
  assert.strictEqual(list[0].type, 'vendor');
});

test('isInWatchlist reflects current membership', () => {
  const storage = fakeStorage();
  assert.strictEqual(isInWatchlist('actor', 'lockbit', storage), false);
  addToWatchlist({ type: 'actor', id: 'lockbit', label: 'LockBit' }, storage);
  assert.strictEqual(isInWatchlist('actor', 'lockbit', storage), true);
});

/* ─── storage failure resilience ─────────────────────────────── */

test('a storage that throws on write never propagates the error to the caller', () => {
  const throwingStorage = {
    getItem: () => null,
    setItem: () => { throw new Error('QuotaExceededError'); },
  };
  assert.doesNotThrow(() => addToWatchlist({ type: 'cve', id: 'X' }, throwingStorage));
  assert.doesNotThrow(() => saveSearch('x', 'ALL', throwingStorage));
});

test('a storage returning malformed JSON degrades to an empty list rather than throwing', () => {
  const corruptStorage = { getItem: () => 'not valid json{{{', setItem: () => {} };
  assert.deepStrictEqual(getWatchlist(corruptStorage), []);
  assert.deepStrictEqual(getSavedSearches(corruptStorage), []);
});
