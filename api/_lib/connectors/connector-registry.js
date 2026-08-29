'use strict';
/**
 * SENTINEL APEX — Connector Module Registry (Controlled SIEM Deployment
 * Gateway v1)
 *
 * Static require() map, deliberately mirroring workers/lib/router.js's
 * own HANDLER_MODULES discipline (a computed/dynamic require() would
 * silently fail to bundle under esbuild) -- one entry per connector
 * platform this tranche actually implements code for. A platform present
 * in siem-connector-taxonomy.js#KNOWN_PLATFORMS but absent here (Splunk/
 * Elastic/QRadar/Google SecOps) has no module and cannot be dispatched --
 * deployment-engine.js checks taxonomy.capabilities.deploy_supported
 * before ever reaching this registry, so that absence is never surfaced
 * as a confusing "module not found" error to a customer.
 */

const mockSiemConnector = require('./mock-siem-connector');
const microsoftSentinelConnector = require('./microsoft-sentinel-connector');

const REGISTRY = Object.freeze({
  'mock-siem': mockSiemConnector,
  'microsoft-sentinel': microsoftSentinelConnector,
});

function getConnectorModule(platformId) {
  return REGISTRY[platformId] || null;
}

module.exports = { getConnectorModule, REGISTRY };
