'use strict';

// Route-handler tests for workbench/cases.js -- mirrors investigations.test.js:
// proves the auth gate blocks unauthenticated requests, proves the bare-ID
// GET fix (id === 'cases' && action, not the always-false pathParts[length-3]
// check it replaced), and proves the named sub-resource routes (notes,
// tasks, close) aren't shadowed by that bare-ID fallback and attribute
// authorship to the verified caller rather than any client-supplied field.
jest.mock('../../../_lib/redis', () => ({}));
jest.mock('../../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn() }));

const { requireAnalyst } = require('../../../_lib/analyst-auth');
const { CaseManager } = require('../../../_lib/case-manager');
const handler = require('../cases');

const CALLER = { id: 'analyst-1', name: 'Analyst One', role: 'analyst' };

function mockReq(method, { apexSubpath, query = {}, body } = {}) {
  const q = { ...query };
  if (apexSubpath !== undefined) q.apexSubpath = apexSubpath;
  return { method, query: q, body, headers: {}, url: '/api/v1/workbench/cases' };
}

function mockRes() {
  const res = { headers: {}, statusCode: null, body: null };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}

beforeEach(() => {
  requireAnalyst.mockReset();
  requireAnalyst.mockResolvedValue(CALLER);
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('unauthenticated requests never reach a manager method', async () => {
  requireAnalyst.mockImplementation(async (req, res, fail) => {
    fail(res, 401, 'UNAUTHORIZED', 'Invalid or missing analyst key');
    return null;
  });
  const spy = jest.spyOn(CaseManager.prototype, 'getCase');

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'case-123' }), res);

  expect(res.statusCode).toBe(401);
  expect(spy).not.toHaveBeenCalled();
});

test('POST /cases creates with the authenticated caller as createdBy', async () => {
  const spy = jest.spyOn(CaseManager.prototype, 'createCase').mockResolvedValue({ id: 'case-new' });

  const res = mockRes();
  await handler(mockReq('POST', { body: { investigationId: 'inv-1', title: 'New Case', description: 'd' } }), res);

  expect(spy).toHaveBeenCalledWith('inv-1', 'New Case', 'd', 'analyst-1');
  expect(res.statusCode).toBe(201);
});

test('GET /cases/{id} (bare ID) resolves the real ID, not the literal "cases"', async () => {
  const getSpy = jest.spyOn(CaseManager.prototype, 'getCase').mockResolvedValue({ id: 'case-123' });
  const summarySpy = jest.spyOn(CaseManager.prototype, 'getCaseSummary').mockResolvedValue({ notes: 0 });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'case-123' }), res);

  expect(getSpy).toHaveBeenCalledWith('case-123');
  expect(summarySpy).toHaveBeenCalledWith('case-123');
  expect(res.body.case.id).toBe('case-123');
});

test('POST /cases/{id}/notes attributes the note to the caller, not a client-supplied author', async () => {
  const spy = jest.spyOn(CaseManager.prototype, 'addNote').mockResolvedValue({ id: 'note-1' });
  const getSpy = jest.spyOn(CaseManager.prototype, 'getCase');

  const res = mockRes();
  await handler(mockReq('POST', {
    apexSubpath: 'case-123/notes',
    body: { content: 'a note', author: 'attacker-supplied' },
  }), res);

  expect(spy).toHaveBeenCalledWith('case-123', 'a note', 'analyst-1');
  expect(getSpy).not.toHaveBeenCalled();
});

test('POST /cases/{id}/tasks adds a task with the given assignee and due date', async () => {
  const spy = jest.spyOn(CaseManager.prototype, 'addTask').mockResolvedValue({ id: 'task-1' });

  const res = mockRes();
  await handler(mockReq('POST', {
    apexSubpath: 'case-123/tasks',
    body: { description: 'do the thing', assignee: 'bob', dueDate: '2026-09-01' },
  }), res);

  expect(spy).toHaveBeenCalledWith('case-123', 'do the thing', 'bob', '2026-09-01');
});

test('PUT /cases/{id}/close closes the case with the given reason', async () => {
  const spy = jest.spyOn(CaseManager.prototype, 'closeCase').mockResolvedValue({ closed: true });

  const res = mockRes();
  await handler(mockReq('PUT', { apexSubpath: 'case-123/close', body: { closureReason: 'resolved' } }), res);

  expect(spy).toHaveBeenCalledWith('case-123', 'resolved');
});

test('unrecognized method/path combinations 404', async () => {
  const res = mockRes();
  await handler(mockReq('DELETE'), res);

  expect(res.statusCode).toBe(404);
});
