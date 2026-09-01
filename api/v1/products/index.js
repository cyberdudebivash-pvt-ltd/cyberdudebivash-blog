'use strict';

/**
 * Protected HTTP entry point for the legacy commercial product factory.
 * Product generation/validation/approval/publication/export is an internal
 * control plane, not an anonymous public API.
 */
const legacyHandler = require('./legacy-index');
const { createInternalFactoryGateway } = require('../../_lib/internal-factory-gateway');

module.exports = createInternalFactoryGateway(legacyHandler);
