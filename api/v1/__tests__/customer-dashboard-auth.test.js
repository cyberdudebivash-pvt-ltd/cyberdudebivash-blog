'use strict';

jest.mock('../../_lib/middleware', () => ({ authenticate: jest.fn() }));
jest.mock('../../_lib/premium-commerce-service', () => ({ listLibrary: jest.fn() }));
jest.mock('../../_lib/security', () => ({
  guardRequest: jest.fn(async () => true), globalIpRateLimit: jest.fn(async () => true), applySecurityHeaders: jest.fn(),
}));

const { authenticate } = require('../../_lib/middleware');
const premium = require('../../_lib/premium-commerce-service');
const handler = require('../customer/dashboard');

function res(){const r={statusCode:200,body:null,headers:{}};r.setHeader=jest.fn((k,v)=>{r.headers[k.toLowerCase()]=v;return r});r.status=jest.fn(c=>{r.statusCode=c;return r});r.json=jest.fn(b=>{r.body=b;return r});r.end=jest.fn(()=>r);return r}

beforeEach(()=>jest.clearAllMocks());

test('does not use a caller-supplied email as customer identity', async()=>{
  authenticate.mockResolvedValue(null);
  const r=res();
  await handler({method:'GET',query:{email:'victim@example.com'},headers:{}},r);
  expect(premium.listLibrary).not.toHaveBeenCalled();
});

test('authenticated dashboard returns only the caller identity and never API key material', async()=>{
  authenticate.mockResolvedValue({userId:'usr_1',email:'owner@example.com',tier:'pro',keyHash:'sensitive-hash'});
  premium.listLibrary.mockResolvedValue([{report_id:'R1'}]);
  const r=res();
  await handler({method:'GET',query:{email:'victim@example.com'},headers:{}},r);
  expect(r.statusCode).toBe(200);
  expect(r.body.data.customer).toEqual({user_id:'usr_1',email:'owner@example.com',tier:'pro'});
  expect(JSON.stringify(r.body)).not.toContain('sensitive-hash');
  expect(JSON.stringify(r.body)).not.toContain('apiKey');
  expect(premium.listLibrary).toHaveBeenCalledWith(expect.objectContaining({userId:'usr_1'}),100);
});
