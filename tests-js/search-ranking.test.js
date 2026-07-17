'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { expandWord, daysAgo, scoreEntry, rankEntries, SYNONYMS } = require('../search-ranking');

/* ─── expandWord ─────────────────────────────────────────────── */

test('expandWord includes the original word plus its synonyms', () => {
  const alternates = expandWord('cve');
  assert.ok(alternates.includes('cve'));
  assert.ok(alternates.includes('vulnerability'));
});

test('expandWord returns just the word when no synonym is registered', () => {
  assert.deepStrictEqual(expandWord('xyzabc'), ['xyzabc']);
});

/* ─── daysAgo ────────────────────────────────────────────────── */

test('daysAgo returns null for a missing/unparseable date', () => {
  assert.strictEqual(daysAgo(''), null);
  assert.strictEqual(daysAgo('not-a-date'), null);
});

test('daysAgo computes whole days between the date and now', () => {
  const now = Date.parse('2026-07-17T00:00:00Z');
  assert.strictEqual(daysAgo('2026-07-10', now), 7);
});

/* ─── scoreEntry ─────────────────────────────────────────────── */

const now = Date.parse('2026-07-17T00:00:00Z');

test('scoreEntry returns null when a query word matches nothing', () => {
  const entry = { t: 'LockBit Ransomware Hits Healthcare', desc: 'Extortion group targets hospitals', d: '2026-07-01', tp: 'RANSOMWARE' };
  assert.strictEqual(scoreEntry(entry, ['quantumcomputing'], now), null);
});

test('scoreEntry scores a title match higher than a description-only match', () => {
  const titleMatch = { t: 'Critical CVE Disclosed', desc: 'Details inside', d: '2026-07-01', tp: 'CVE' };
  const descOnlyMatch = { t: 'Weekly Roundup', desc: 'Includes a critical CVE this week', d: '2026-07-01', tp: 'ADVISORY' };
  const s1 = scoreEntry(titleMatch, ['cve'], now);
  const s2 = scoreEntry(descOnlyMatch, ['cve'], now);
  assert.ok(s1 > s2);
});

test('scoreEntry matches via a synonym even when the literal word is absent', () => {
  const entry = { t: 'New Vulnerability Disclosed in Popular Library', desc: '', d: '2026-07-01', tp: 'CVE' };
  assert.notStrictEqual(scoreEntry(entry, ['cve'], now), null);
});

test('scoreEntry gives an exact-phrase bonus over separate word matches', () => {
  const phraseMatch = { t: 'Zero Day Exploit in the Wild', desc: '', d: '2026-07-01', tp: 'ZERO-DAY' };
  const separateWords = { t: 'A Day of Zero Progress on the Exploit', desc: '', d: '2026-07-01', tp: 'ZERO-DAY' };
  const s1 = scoreEntry(phraseMatch, ['zero', 'day'], now);
  const s2 = scoreEntry(separateWords, ['zero', 'day'], now);
  assert.ok(s1 > s2);
});

test('scoreEntry gives a bonus for a title starting with the query word', () => {
  const startsWith = { t: 'Ransomware Group Claims New Victim', desc: '', d: '2026-07-01', tp: 'RANSOMWARE' };
  const containsLater = { t: 'New Attack Involves Ransomware Payload', desc: '', d: '2026-07-01', tp: 'RANSOMWARE' };
  const s1 = scoreEntry(startsWith, ['ransomware'], now);
  const s2 = scoreEntry(containsLater, ['ransomware'], now);
  assert.ok(s1 > s2);
});

test('scoreEntry gives newer content a small recency bonus over otherwise-identical older content', () => {
  const recent = { t: 'CVE Disclosed', desc: '', d: '2026-07-16', tp: 'CVE' };
  const old = { t: 'CVE Disclosed', desc: '', d: '2020-01-01', tp: 'CVE' };
  const s1 = scoreEntry(recent, ['cve'], now);
  const s2 = scoreEntry(old, ['cve'], now);
  assert.ok(s1 > s2);
});

test('scoreEntry recency bonus never dominates a stronger title match elsewhere', () => {
  // An old but exact-phrase title match should still beat a brand-new,
  // weak, description-only match — recency is a tiebreaker, not the ranking.
  const oldStrongMatch = { t: 'Critical Zero Day Exploit', desc: '', d: '2020-01-01', tp: 'ZERO-DAY' };
  const newWeakMatch = { t: 'Weekly Roundup', desc: 'briefly mentions a zero day', d: '2026-07-16', tp: 'ADVISORY' };
  const s1 = scoreEntry(oldStrongMatch, ['zero', 'day'], now);
  const s2 = scoreEntry(newWeakMatch, ['zero', 'day'], now);
  assert.ok(s1 > s2);
});

/* ─── rankEntries ────────────────────────────────────────────── */

const INDEX = [
  { t: 'Weekly Roundup mentions ransomware', s: 'weekly-roundup', d: '2026-07-01', desc: 'briefly covers ransomware trends', tp: 'ADVISORY' },
  { t: 'Ransomware Group Strikes Again', s: 'ransomware-strikes', d: '2026-07-15', desc: '', tp: 'RANSOMWARE' },
  { t: 'Critical CVE in Popular Framework', s: 'critical-cve', d: '2026-07-10', desc: '', tp: 'CVE' },
];

test('rankEntries orders the strongest title match first', () => {
  const results = rankEntries(INDEX, 'ransomware', 'ALL');
  assert.strictEqual(results[0].s, 'ransomware-strikes');
});

test('rankEntries respects an active type filter', () => {
  const results = rankEntries(INDEX, '', 'CVE');
  assert.strictEqual(results.length, 1);
  assert.strictEqual(results[0].s, 'critical-cve');
});

test('rankEntries with empty query and ALL type returns every entry, unscored', () => {
  const results = rankEntries(INDEX, '', 'ALL');
  assert.strictEqual(results.length, INDEX.length);
});

test('rankEntries excludes entries that match no query word at all', () => {
  const results = rankEntries(INDEX, 'quantumcomputing', 'ALL');
  assert.strictEqual(results.length, 0);
});

test('SYNONYMS is a plain object usable for introspection', () => {
  assert.strictEqual(typeof SYNONYMS, 'object');
  assert.ok(SYNONYMS.cve);
});
