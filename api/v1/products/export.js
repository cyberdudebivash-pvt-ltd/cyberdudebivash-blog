'use strict';

const redis = require('../../_lib/redis');
const { ProductFactory } = require('../../_lib/product-factory');
const { DetectionExportEngine } = require('../../_lib/detection-export-engine');

const productFactory = new ProductFactory(redis);
const exportEngine = new DetectionExportEngine();

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const SUPPORTED_FORMATS = {
  'sigma': { type: 'application/yaml', ext: 'yml' },
  'yara': { type: 'application/x-yara', ext: 'yar' },
  'splunk': { type: 'text/plain', ext: 'spl' },
  'elastic': { type: 'application/json', ext: 'json' },
  'sentinel': { type: 'application/json', ext: 'json' },
  'defender': { type: 'application/json', ext: 'json' },
  'chronicle': { type: 'application/json', ext: 'json' },
  'qradar': { type: 'application/json', ext: 'json' },
  'wazuh': { type: 'application/xml', ext: 'xml' },
};

function ok(res, data, status = 200) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: true,
    meta: { timestamp: new Date().toISOString() },
    ...data,
  });
}

function fail(res, status, code, message) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: false,
    error: { code, message },
    meta: { timestamp: new Date().toISOString() },
  });
}

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
    return res.status(200).end();
  }

  const pathParts = (req.url || '').split('?')[0].split('/').filter(Boolean);
  const action = pathParts[pathParts.length - 1];
  const resourceId = pathParts[pathParts.length - 2];

  // Export detection product
  if (req.method === 'GET' && action && resourceId) {
    return handleDetectionExport(req, res, resourceId, action);
  }

  // List supported formats
  if (req.method === 'GET' && action === 'formats') {
    return handleListFormats(req, res);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleDetectionExport(req, res, productId, format) {
  try {
    if (!SUPPORTED_FORMATS[format]) {
      return fail(res, 400, 'UNSUPPORTED_FORMAT', `Format not supported: ${format}. Supported: ${Object.keys(SUPPORTED_FORMATS).join(', ')}`);
    }

    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    if (!['detection', 'threat-intelligence', 'ioc-feed'].includes(product.productType)) {
      return fail(res, 400, 'INVALID_PRODUCT_TYPE', `Product type ${product.productType} cannot be exported as detection rules. Product must be detection, threat-intelligence, or ioc-feed type.`);
    }

    let content;
    const formatInfo = SUPPORTED_FORMATS[format];

    switch (format) {
      case 'sigma':
        content = await exportEngine.exportSigmaRules(product);
        break;
      case 'yara':
        content = await exportEngine.exportYaraRules(product);
        break;
      case 'splunk':
        content = await exportEngine.exportSplunkQueries(product);
        break;
      case 'elastic':
        content = await exportEngine.exportElasticRules(product);
        break;
      case 'sentinel':
        content = await exportEngine.exportSentinelRules(product);
        break;
      case 'defender':
        content = await exportEngine.exportDefenderRules(product);
        break;
      case 'chronicle':
        content = await exportEngine.exportChronicleRules(product);
        break;
      case 'qradar':
        content = await exportEngine.exportQRadarRules(product);
        break;
      case 'wazuh':
        content = await exportEngine.exportWazuhRules(product);
        break;
      default:
        return fail(res, 400, 'UNSUPPORTED_FORMAT', `Format not supported: ${format}`);
    }

    const filename = `${product.productId}-${productId.substring(0, 8)}-detection.${formatInfo.ext}`;

    product.recordExport(`detection-${format}`, new Date().toISOString());
    await productFactory.persistProduct(product);

    res.setHeader('Content-Type', formatInfo.type);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.status(200).send(content);
  } catch (e) {
    return fail(res, 500, 'EXPORT_FAILED', e.message);
  }
}

async function handleListFormats(req, res) {
  try {
    const formats = Object.keys(SUPPORTED_FORMATS).map(key => ({
      format: key,
      contentType: SUPPORTED_FORMATS[key].type,
      extension: SUPPORTED_FORMATS[key].ext,
    }));

    return ok(res, {
      formats,
      count: formats.length,
    });
  } catch (e) {
    return fail(res, 500, 'LIST_FAILED', e.message);
  }
}
