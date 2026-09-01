'use strict';

/**
 * Protected HTTP entry point for the legacy report control plane.
 * Public/customer intelligence is delivered through published CTI/report
 * surfaces; report generation, review, approval, publication and export are
 * internal analyst operations and must never trust caller-supplied identity.
 */
const legacyHandler = require('./legacy-index');
const { createInternalFactoryGateway } = require('../../_lib/internal-factory-gateway');

module.exports = createInternalFactoryGateway(legacyHandler);
