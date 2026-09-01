'use strict';

jest.mock('../redis', () => ({
  incr: jest.fn(async () => 1),
  expire: jest.fn(async () => 1),
  hgetall: jest.fn(async () => ['userId', 'u1', 'email', 'a@example.com', 'tier', 'pro']),
  hincrby: jest.fn(async () => 1),
  hset: jest.fn(async () => 1),
  zadd: jest.fn(async () => 1),
}));

jest.mock('../security', () => ({
  applySecurityHeaders: jest.fn(),
  guardRequest: jest.fn(async () => true),
  globalIpRateLimit: jest.fn(async () => true),
  safeError: jest.fn((_e, fallback) => fallback),
}));

const middleware = require('../middleware');
const redis = require('../redis');

function res() {
  const r = { statusCode: null, body: null, headers: {} };
  r.setHeader = jest.fn((k, v) => { r.headers[k] = v; });
  r.status = jest.fn(code => { r.statusCode = code; return r; });
  r.json = jest.fn(body => { r.body = body; return r; });
  return r;
}

describe('API key transport', () => {
  beforeEach(() => jest.clearAllMocks());

  test('rejects api_key in URL query string before credential lookup', async () => {
    const response = res();
    const user = await middleware.authenticate({
      method: 'GET',
      query: { api_key: 'sentinel_should-never-be-accepted-from-url' },
      headers: {},
      url: '/api/v1/intel?api_key=redacted',
    }, response);

    expect(user).toBeNull();
    expect(response.statusCode).toBe(400);
    expect(response.body.error.code).toBe('QUERY_API_KEY_REJECTED');
    expect(redis.hgetall).not.toHaveBeenCalled();
  });

  test('continues to accept X-API-Key header', async () => {
    const response = res();
    const user = await middleware.authenticate({
      method: 'GET',
      query: {},
      headers: { 'x-api-key': 'sentinel_valid-header-key' },
      url: '/api/v1/intel?action=live',
    }, response);

    expect(user).toBeTruthy();
    expect(user.tier).toBe('pro');
    expect(redis.hgetall).toHaveBeenCalledTimes(1);
  });

  test('continues to accept Authorization Bearer header', async () => {
    const response = res();
    const user = await middleware.authenticate({
      method: 'GET',
      query: {},
      headers: { authorization: 'Bearer sentinel_valid-bearer-key' },
      url: '/api/v1/intel?action=live',
    }, response);

    expect(user).toBeTruthy();
    expect(user.tier).toBe('pro');
  });
});
