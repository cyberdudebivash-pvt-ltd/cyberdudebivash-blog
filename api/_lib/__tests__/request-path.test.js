'use strict';

const { resolvePathParts } = require('../request-path');

describe('resolvePathParts', () => {
  test('bare mount path with no rewrite query param falls back to req.url parsing', () => {
    const req = { url: '/api/v1/workbench/investigations', query: {} };
    expect(resolvePathParts(req, '/api/v1/workbench/investigations'))
      .toEqual(['api', 'v1', 'workbench', 'investigations']);
  });

  test('req.url fallback strips the query string', () => {
    const req = { url: '/api/v1/workbench/investigations?status=open', query: { status: 'open' } };
    expect(resolvePathParts(req, '/api/v1/workbench/investigations'))
      .toEqual(['api', 'v1', 'workbench', 'investigations']);
  });

  test('a single-segment rewritten subpath (string) reconstructs the full absolute path', () => {
    const req = { url: '/api/v1/workbench/investigations?apexSubpath=abc123', query: { apexSubpath: 'abc123' } };
    expect(resolvePathParts(req, '/api/v1/workbench/investigations'))
      .toEqual(['api', 'v1', 'workbench', 'investigations', 'abc123']);
  });

  test('a multi-segment rewritten subpath (string with slashes) reconstructs correctly', () => {
    const req = { query: { apexSubpath: 'abc123/timeline' } };
    expect(resolvePathParts(req, '/api/v1/workbench/investigations'))
      .toEqual(['api', 'v1', 'workbench', 'investigations', 'abc123', 'timeline']);
  });

  test('a multi-segment rewritten subpath delivered as an array (Vercel path-to-regexp style) also works', () => {
    const req = { query: { apexSubpath: ['abc123', 'path', 'def456'] } };
    expect(resolvePathParts(req, '/api/v1/intelligence/graph'))
      .toEqual(['api', 'v1', 'intelligence', 'graph', 'abc123', 'path', 'def456']);
  });

  test('an empty-string subpath (zero-segment wildcard match) resolves to just the mount path', () => {
    const req = { query: { apexSubpath: '' } };
    expect(resolvePathParts(req, '/api/v1/workbench/cases'))
      .toEqual(['api', 'v1', 'workbench', 'cases']);
  });

  test('an empty array subpath also resolves to just the mount path', () => {
    const req = { query: { apexSubpath: [] } };
    expect(resolvePathParts(req, '/api/v1/workbench/cases'))
      .toEqual(['api', 'v1', 'workbench', 'cases']);
  });

  test('mount path with or without a leading slash produces the same result', () => {
    const req = { query: { apexSubpath: 'x' } };
    expect(resolvePathParts(req, 'api/v1/workbench/cases'))
      .toEqual(resolvePathParts(req, '/api/v1/workbench/cases'));
  });

  test('req.query missing entirely does not throw and falls back to req.url', () => {
    const req = { url: '/api/v1/workbench/cases' };
    expect(resolvePathParts(req, '/api/v1/workbench/cases')).toEqual(['api', 'v1', 'workbench', 'cases']);
  });
});
