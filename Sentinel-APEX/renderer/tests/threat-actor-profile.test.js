'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { buildThreatActorProfileMarkdown } = require('../threat-actor-profile');
const { THREAT_ACTOR_DB } = require('../../../api/_lib/threat-graph');

const LOCKBIT = THREAT_ACTOR_DB['actor:lockbit'];

test('throws without an actorEntry with .attributes (guards against silent garbage output)', () => {
  assert.throws(() => buildThreatActorProfileMarkdown(null));
  assert.throws(() => buildThreatActorProfileMarkdown({ name: 'X' }));
});

test('populates identity fields directly from the real curated actor record', () => {
  const md = buildThreatActorProfileMarkdown(LOCKBIT);
  assert.ok(md.includes('LockBit'));
  assert.ok(md.includes('LockBit 3.0'));
  assert.ok(md.includes('ransomware_group'));
  assert.ok(md.includes('financial'));
  assert.ok(md.includes('advanced'));
  assert.ok(md.includes('criminal'));
  assert.ok(md.includes('| Status | active |'));
});

test('populates the executive summary from the real curated description, never fabricated', () => {
  const md = buildThreatActorProfileMarkdown(LOCKBIT);
  assert.ok(md.includes(LOCKBIT.attributes.description));
});

test('populates every curated TTP as its own table row', () => {
  const md = buildThreatActorProfileMarkdown(LOCKBIT);
  for (const id of LOCKBIT.attributes.ttps) {
    assert.ok(md.includes(`| ${id} |`), `expected a table row for ${id}`);
  }
});

test('populates every curated known CVE as its own table row', () => {
  const md = buildThreatActorProfileMarkdown(LOCKBIT);
  for (const id of LOCKBIT.attributes.known_cves) {
    assert.ok(md.includes(`| ${id} |`), `expected a table row for ${id}`);
  }
});

test('populates real sources from refs[], not a placeholder', () => {
  const md = buildThreatActorProfileMarkdown(LOCKBIT);
  for (const url of LOCKBIT.attributes.refs) {
    assert.ok(md.includes(url));
  }
});

test('leaves genuinely uncurated fields as honest placeholders, not fabricated content', () => {
  const md = buildThreatActorProfileMarkdown(LOCKBIT);
  assert.ok(md.includes('<Narrative: major named campaigns'));
  assert.ok(md.includes('<Hunt hypotheses keyed to'));
  assert.ok(md.includes('<Honest list of what isn\'t known'));
});

test('uses a placeholder report_id when none is supplied, a real one when it is', () => {
  const withoutId = buildThreatActorProfileMarkdown(LOCKBIT);
  assert.ok(withoutId.includes('SA-TA-<YYYY>-<NNNN>'));

  const withId = buildThreatActorProfileMarkdown(LOCKBIT, { reportId: 'SA-TA-2026-0001' });
  assert.ok(withId.includes('SA-TA-2026-0001'));
  assert.ok(!withId.includes('SA-TA-<YYYY>-<NNNN>'));
});

test('escapes pipe characters in curated text so tables stay well-formed', () => {
  const withPipe = {
    name: 'Test|Actor',
    attributes: { aliases: ['A|B'], description: 'x', ttps: [], known_cves: [], refs: [] },
  };
  const md = buildThreatActorProfileMarkdown(withPipe);
  assert.ok(md.includes('Test\\|Actor'));
  assert.ok(md.includes('A\\|B'));
});

test('renders for all 8 real curated actors without throwing', () => {
  for (const [id, actor] of Object.entries(THREAT_ACTOR_DB)) {
    assert.doesNotThrow(() => buildThreatActorProfileMarkdown(actor), `failed for ${id}`);
  }
});
