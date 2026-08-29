'use strict';

process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = 'a'.repeat(64);

jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const store = require('../siem-connector-store');

beforeEach(() => {
  global.__fakeD1ForTest._reset();
});

describe('entitlements', () => {
  test('sandbox connectors are available on every tier', () => {
    expect(store.getSiemConnectorEntitlements('free').sandbox_connectors.enabled).toBe(true);
  });
  test('live connectors require pro/enterprise', () => {
    expect(store.getSiemConnectorEntitlements('free').live_connectors.enabled).toBe(false);
    expect(store.getSiemConnectorEntitlements('pro').live_connectors.enabled).toBe(true);
  });
});

describe('createConnector', () => {
  test('creates a sandbox connector with no credential required', async () => {
    const result = await store.createConnector('usr_a', 'free', { platform: 'mock-siem', name: 'Test Sandbox', target_config: {} });
    expect(result.connector).toBeTruthy();
    expect(result.connector.credential_configured).toBe(false);
  });

  test('rejects an unknown platform', async () => {
    const result = await store.createConnector('usr_a', 'enterprise', { platform: 'not-a-real-platform', name: 'X', target_config: {} });
    expect(result.error).toBe('UNKNOWN_PLATFORM');
  });

  test('rejects a not-yet-implemented platform (e.g. splunk)', async () => {
    const result = await store.createConnector('usr_a', 'enterprise', { platform: 'splunk-enterprise-security', name: 'X', target_config: {} });
    expect(result.error).toBe('PLATFORM_NOT_IMPLEMENTED');
  });

  test('a free-tier customer cannot create a live (Microsoft Sentinel) connector', async () => {
    const result = await store.createConnector('usr_a', 'free', {
      platform: 'microsoft-sentinel', name: 'Prod', target_config: { tenant_id: 't', subscription_id: 's', resource_group: 'r', workspace_name: 'w', client_id: 'c' }, credential: { client_secret: 'x' },
    });
    expect(result.error).toBe('TIER_RESTRICTED');
  });

  test('rejects a live connector missing a required target field', async () => {
    const result = await store.createConnector('usr_a', 'enterprise', {
      platform: 'microsoft-sentinel', name: 'Prod', target_config: { tenant_id: 't' }, credential: { client_secret: 'x' },
    });
    expect(result.error).toBe('INVALID_TARGET_CONFIG');
  });

  test('enforces the sandbox connector limit', async () => {
    for (let i = 0; i < 3; i++) {
      const r = await store.createConnector('usr_a', 'free', { platform: 'mock-siem', name: `S${i}`, target_config: {} });
      expect(r.connector).toBeTruthy();
    }
    const overLimit = await store.createConnector('usr_a', 'free', { platform: 'mock-siem', name: 'S4', target_config: {} });
    expect(overLimit.error).toBe('CONNECTOR_LIMIT_REACHED');
  });
});

describe('credential secrecy', () => {
  test('listConnectors / getConnectorSafe never expose credential_ciphertext or plaintext', async () => {
    await store.createConnector('usr_a', 'enterprise', {
      platform: 'microsoft-sentinel', name: 'Prod', target_config: { tenant_id: 't', subscription_id: 's', resource_group: 'r', workspace_name: 'w', client_id: 'c' }, credential: { client_secret: 'super-secret' },
    });
    const list = await store.listConnectors('usr_a');
    const serialized = JSON.stringify(list);
    expect(serialized).not.toContain('super-secret');
    expect(list[0].credential_configured).toBe(true);
    expect(list[0].credential_ciphertext).toBeUndefined();
  });

  test('getConnectorWithCredential decrypts the real credential (internal path only)', async () => {
    const created = await store.createConnector('usr_a', 'enterprise', {
      platform: 'microsoft-sentinel', name: 'Prod', target_config: { tenant_id: 't', subscription_id: 's', resource_group: 'r', workspace_name: 'w', client_id: 'c' }, credential: { client_secret: 'super-secret' },
    });
    const result = await store.getConnectorWithCredential('usr_a', created.connector.id);
    expect(result.connector.credential.client_secret).toBe('super-secret');
  });

  test('refuses to store a credential when encryption is not configured', async () => {
    const original = process.env.CONNECTOR_CREDENTIAL_MASTER_KEY;
    delete process.env.CONNECTOR_CREDENTIAL_MASTER_KEY;
    jest.resetModules();
    jest.doMock('../d1', () => global.__fakeD1ForTest);
    const freshStore = require('../siem-connector-store');
    const result = await freshStore.createConnector('usr_a', 'enterprise', {
      platform: 'microsoft-sentinel', name: 'Prod', target_config: { tenant_id: 't', subscription_id: 's', resource_group: 'r', workspace_name: 'w', client_id: 'c' }, credential: { client_secret: 'x' },
    });
    expect(result.error).toBe('ENCRYPTION_NOT_CONFIGURED');
    process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = original;
    jest.resetModules();
  });
});

describe('tenant isolation', () => {
  test("owner B cannot read owner A's connector, and gets the same NOT_FOUND as a nonexistent id", async () => {
    const created = await store.createConnector('usr_a', 'free', { platform: 'mock-siem', name: 'A-Sandbox', target_config: {} });
    const asB = await store.getConnectorSafe('usr_b', created.connector.id);
    const nonexistent = await store.getConnectorSafe('usr_b', 'conn_does_not_exist');
    expect(asB.error).toBe('NOT_FOUND');
    expect(nonexistent.error).toBe('NOT_FOUND');
  });

  test("owner B cannot rotate owner A's credential", async () => {
    const created = await store.createConnector('usr_a', 'enterprise', {
      platform: 'microsoft-sentinel', name: 'Prod', target_config: { tenant_id: 't', subscription_id: 's', resource_group: 'r', workspace_name: 'w', client_id: 'c' }, credential: { client_secret: 'x' },
    });
    const result = await store.rotateCredential('usr_b', created.connector.id, { client_secret: 'stolen' });
    expect(result.error).toBe('NOT_FOUND');
  });
});

describe('disable (disconnect)', () => {
  test('disabling revokes the credential and preserves the row for history', async () => {
    const created = await store.createConnector('usr_a', 'enterprise', {
      platform: 'microsoft-sentinel', name: 'Prod', target_config: { tenant_id: 't', subscription_id: 's', resource_group: 'r', workspace_name: 'w', client_id: 'c' }, credential: { client_secret: 'x' },
    });
    await store.disableConnector('usr_a', created.connector.id);
    const safe = await store.getConnectorSafe('usr_a', created.connector.id);
    expect(safe.connector.disabled).toBe(true);
    expect(safe.connector.credential_configured).toBe(false);
    const withCred = await store.getConnectorWithCredential('usr_a', created.connector.id);
    expect(withCred.error).toBe('CONNECTOR_DISABLED');
  });
});
