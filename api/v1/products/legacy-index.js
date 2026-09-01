'use strict';

const redis = require('../../_lib/redis');
const { ProductFactory } = require('../../_lib/product-factory');
const { ProductValidationEngine } = require('../../_lib/product-validation-engine');
const { ProductCompositionEngine } = require('../../_lib/product-composition-engine');

const productFactory = new ProductFactory(redis);
const validationEngine = new ProductValidationEngine(redis);

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
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
  const resourceType = pathParts[pathParts.length - 3];

  // Generate product portfolio
  if (req.method === 'POST' && action === 'generate') {
    return handleGeneratePortfolio(req, res);
  }

  // Get portfolio metadata
  if (req.method === 'GET' && action === 'portfolio' && resourceId) {
    return handleGetPortfolio(req, res, resourceId);
  }

  // List portfolio products
  if (req.method === 'GET' && action === 'portfolio-products' && resourceId) {
    return handleListPortfolioProducts(req, res, resourceId);
  }

  // Get single product
  if (req.method === 'GET' && resourceType === 'products' && resourceId && action !== 'validate' && action !== 'approve' && action !== 'publish' && action !== 'export' && action !== 'versions' && action !== 'lineage') {
    return handleGetProduct(req, res, resourceId);
  }

  // List/search products
  if (req.method === 'GET' && action === 'products') {
    return handleListProducts(req, res);
  }

  // Validate product
  if (req.method === 'POST' && action === 'validate' && resourceId) {
    return handleValidateProduct(req, res, resourceId);
  }

  // Approve product
  if (req.method === 'POST' && action === 'approve' && resourceId) {
    return handleApproveProduct(req, res, resourceId);
  }

  // Publish product
  if (req.method === 'POST' && action === 'publish' && resourceId) {
    return handlePublishProduct(req, res, resourceId);
  }

  // Export product
  if (req.method === 'GET' && action === 'export' && resourceId) {
    return handleExportProduct(req, res, resourceId);
  }

  // Get product versions
  if (req.method === 'GET' && action === 'versions' && resourceId) {
    return handleGetVersions(req, res, resourceId);
  }

  // Create new version
  if (req.method === 'POST' && action === 'new-version' && resourceId) {
    return handleCreateNewVersion(req, res, resourceId);
  }

  // Compare versions
  if (req.method === 'GET' && action === 'compare' && resourceId) {
    return handleCompareVersions(req, res, resourceId);
  }

  // Get product lineage
  if (req.method === 'GET' && action === 'lineage' && resourceId) {
    return handleGetLineage(req, res, resourceId);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleGeneratePortfolio(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, reportId, qualityReview } = body;

    if (!investigationId || !reportId) {
      return fail(res, 400, 'MISSING_FIELD', 'investigationId and reportId required');
    }

    const investigation = await redis.hgetall(`investigation:${investigationId}`);
    if (!investigation || investigation.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Investigation not found: ${investigationId}`);
    }

    const report = await redis.hgetall(`report:${reportId}`);
    if (!report || report.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Report not found: ${reportId}`);
    }

    const investigationData = parseRedisHash(investigation);
    const reportData = parseRedisHash(report);
    const qualityReviewData = qualityReview || {};

    const portfolio = await productFactory.generateProductPortfolio(
      investigationData,
      reportData,
      qualityReviewData
    );

    return ok(res, {
      portfolio,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'GENERATION_FAILED', e.message);
  }
}

async function handleGetPortfolio(req, res, investigationId) {
  try {
    const portfolio = await productFactory.getPortfolio(investigationId);

    if (!portfolio) {
      return fail(res, 404, 'NOT_FOUND', `Portfolio not found for investigation: ${investigationId}`);
    }

    return ok(res, { portfolio });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleListPortfolioProducts(req, res, investigationId) {
  try {
    const limit = parseInt(req.query.limit || '50', 10);

    const products = await productFactory.listPortfolioProducts(investigationId, limit);

    return ok(res, {
      investigationId,
      products,
      count: products.length,
    });
  } catch (e) {
    return fail(res, 500, 'LIST_FAILED', e.message);
  }
}

async function handleGetProduct(req, res, productId) {
  try {
    const product = await productFactory.getProduct(productId);

    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    return ok(res, { product });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleListProducts(req, res) {
  try {
    const query = req.query.q || '';
    const limit = parseInt(req.query.limit || '20', 10);
    const productType = req.query.type;
    const classification = req.query.classification;
    const status = req.query.status;

    let products = await productFactory.searchProducts(query, limit * 2);

    if (productType) {
      products = products.filter(p => p.productType === productType);
    }

    if (classification) {
      products = products.filter(p => p.classification === classification);
    }

    if (status) {
      products = products.filter(p => p.status === status);
    }

    products = products.slice(0, limit);

    return ok(res, {
      query,
      filters: {
        type: productType,
        classification,
        status,
      },
      products,
      count: products.length,
    });
  } catch (e) {
    return fail(res, 500, 'SEARCH_FAILED', e.message);
  }
}

async function handleValidateProduct(req, res, productId) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    const validations = await validationEngine.validateProduct(product, productFactory.catalog);
    const summary = validationEngine.getValidationSummary(validations);
    const isPassed = validationEngine.isValidationPassed(validations);

    const validationRecord = await validationEngine.recordValidation(
      productId,
      validations,
      isPassed ? 'PASS' : 'FAIL'
    );

    return ok(res, {
      productId,
      validations,
      summary,
      passed: isPassed,
      validationRecord,
    });
  } catch (e) {
    return fail(res, 500, 'VALIDATION_FAILED', e.message);
  }
}

async function handleApproveProduct(req, res, productId) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { approver, role } = body;

    if (!approver) {
      return fail(res, 400, 'MISSING_APPROVER', 'approver name required');
    }

    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    product.approve(approver, role || 'reviewer');
    product.status = 'APPROVED';
    product.updatedAt = new Date().toISOString();

    await productFactory.persistProduct(product);

    return ok(res, {
      productId,
      product,
      message: 'Product approved',
    });
  } catch (e) {
    return fail(res, 500, 'APPROVAL_FAILED', e.message);
  }
}

async function handlePublishProduct(req, res, productId) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    const validations = await validationEngine.validateProduct(product, productFactory.catalog);
    if (!validationEngine.isValidationPassed(validations)) {
      return fail(res, 400, 'VALIDATION_FAILED', 'Product does not pass validation requirements');
    }

    product.publish();
    await productFactory.persistProduct(product);

    return ok(res, {
      productId,
      product,
      message: 'Product published',
    });
  } catch (e) {
    return fail(res, 500, 'PUBLISH_FAILED', e.message);
  }
}

async function handleExportProduct(req, res, productId) {
  try {
    const format = req.query.format || 'json';

    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    let content, contentType, filename;

    switch (format) {
      case 'json':
        content = JSON.stringify(product, null, 2);
        contentType = 'application/json';
        filename = `${product.productId}-${product.id}.json`;
        break;

      case 'html':
        content = generateHTMLExport(product);
        contentType = 'text/html';
        filename = `${product.productId}-${product.id}.html`;
        break;

      case 'markdown':
        content = generateMarkdownExport(product);
        contentType = 'text/markdown';
        filename = `${product.productId}-${product.id}.md`;
        break;

      case 'pdf':
        content = JSON.stringify(product, null, 2);
        contentType = 'application/json';
        filename = `${product.productId}-${product.id}.pdf`;
        return ok(res, {
          message: 'PDF export requires external PDF service',
          product,
          note: 'Export as JSON or HTML and convert using external service',
        });

      default:
        return fail(res, 400, 'INVALID_FORMAT', `Format not supported: ${format}`);
    }

    product.recordExport(format, new Date().toISOString());
    await productFactory.persistProduct(product);

    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.status(200).send(content);
  } catch (e) {
    return fail(res, 500, 'EXPORT_FAILED', e.message);
  }
}

async function handleGetVersions(req, res, productId) {
  try {
    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    const versionKey = `product:versions:${productId}`;
    const versions = await redis.zrevrange(versionKey, 0, 99);

    return ok(res, {
      productId,
      currentVersion: product.version,
      versions: versions || [],
      count: versions ? versions.length : 0,
    });
  } catch (e) {
    return fail(res, 500, 'GET_VERSIONS_FAILED', e.message);
  }
}

async function handleCreateNewVersion(req, res, productId) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    const newVersion = product.createNewVersion();

    await productFactory.persistProduct(newVersion);

    const versionKey = `product:versions:${productId}`;
    await redis.zadd(versionKey, Date.now(), newVersion.id);

    return ok(res, {
      productId,
      newVersion,
      message: 'New product version created',
    }, 201);
  } catch (e) {
    return fail(res, 500, 'VERSION_FAILED', e.message);
  }
}

async function handleCompareVersions(req, res, productId) {
  try {
    const compareId = req.query.compareId;

    if (!compareId) {
      return fail(res, 400, 'MISSING_ID', 'compareId query parameter required');
    }

    const product1 = await productFactory.getProduct(productId);
    const product2 = await productFactory.getProduct(compareId);

    if (!product1 || !product2) {
      return fail(res, 404, 'NOT_FOUND', 'One or both products not found');
    }

    const differences = {
      product1Id: productId,
      product1Version: product1.version,
      product2Id: compareId,
      product2Version: product2.version,
      differences: [],
    };

    if (JSON.stringify(product1.modules) !== JSON.stringify(product2.modules)) {
      differences.differences.push({
        field: 'modules',
        type: 'CONTENT_CHANGE',
      });
    }

    if (product1.metadata.title !== product2.metadata.title) {
      differences.differences.push({
        field: 'title',
        type: 'METADATA_CHANGE',
        previous: product2.metadata.title,
        current: product1.metadata.title,
      });
    }

    if (product1.classification !== product2.classification) {
      differences.differences.push({
        field: 'classification',
        type: 'CLASSIFICATION_CHANGE',
        previous: product2.classification,
        current: product1.classification,
      });
    }

    if (product1.status !== product2.status) {
      differences.differences.push({
        field: 'status',
        type: 'STATUS_CHANGE',
        previous: product2.status,
        current: product1.status,
      });
    }

    return ok(res, differences);
  } catch (e) {
    return fail(res, 500, 'COMPARE_FAILED', e.message);
  }
}

async function handleGetLineage(req, res, productId) {
  try {
    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    const lineage = product.lineage || {};

    const investigation = await redis.hgetall(`investigation:${lineage.investigation}`);
    const report = await redis.hgetall(`report:${lineage.report}`);

    return ok(res, {
      productId,
      product: {
        id: product.id,
        productId: product.productId,
        version: product.version,
        status: product.status,
        createdAt: product.createdAt,
        publishedAt: lineage.publication,
      },
      lineage: {
        investigationId: lineage.investigation,
        reportId: lineage.report,
        qualityReviewId: lineage.qualityReview,
        publication: lineage.publication,
      },
      sourceMetadata: {
        investigation: investigation ? investigation.id || investigation.title : null,
        report: report ? report.id || report.title : null,
      },
    });
  } catch (e) {
    return fail(res, 500, 'LINEAGE_FAILED', e.message);
  }
}

function parseRedisHash(data) {
  if (!data || data.length === 0) return {};

  const obj = {};
  for (let i = 0; i < data.length; i += 2) {
    const key = data[i];
    const value = data[i + 1];

    if (['modules', 'metadata', 'lineage', 'findings', 'iocs', 'threats', 'relationships'].includes(key)) {
      try {
        obj[key] = JSON.parse(value);
      } catch (e) {
        obj[key] = value;
      }
    } else {
      obj[key] = value;
    }
  }
  return obj;
}

function generateHTMLExport(product) {
  const title = product.metadata?.title || product.productId;
  const description = product.metadata?.description || '';

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${escapeHTML(title)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 900px; margin: 0 auto; padding: 20px; }
    .header { border-bottom: 2px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }
    h1 { margin: 0 0 10px 0; }
    .meta { color: #666; font-size: 14px; }
    .section { margin-bottom: 40px; }
    .section h2 { color: #007bff; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
    .badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; margin-right: 8px; margin-bottom: 8px; }
    .badge-status { background: #e3f2fd; color: #1976d2; }
    .badge-classification { background: #fff3e0; color: #f57c00; }
    code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
  </style>
</head>
<body>
  <div class="header">
    <h1>${escapeHTML(title)}</h1>
    <p>${escapeHTML(description)}</p>
    <div>
      <span class="badge badge-status">${escapeHTML(product.status || 'DRAFT')}</span>
      <span class="badge badge-classification">${escapeHTML(product.classification || 'UNCLASSIFIED')}</span>
    </div>
  </div>

  <div class="section">
    <h2>Product Information</h2>
    <table style="width: 100%; border-collapse: collapse;">
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 10px; font-weight: bold; width: 30%;">Product ID</td>
        <td style="padding: 10px;"><code>${escapeHTML(product.productId)}</code></td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 10px; font-weight: bold;">Type</td>
        <td style="padding: 10px;">${escapeHTML(product.productType || 'unknown')}</td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 10px; font-weight: bold;">Version</td>
        <td style="padding: 10px;">${escapeHTML(product.version || '1.0')}</td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 10px; font-weight: bold;">Created</td>
        <td style="padding: 10px;">${new Date(product.createdAt).toISOString()}</td>
      </tr>
      <tr>
        <td style="padding: 10px; font-weight: bold;">Updated</td>
        <td style="padding: 10px;">${new Date(product.updatedAt).toISOString()}</td>
      </tr>
    </table>
  </div>

  <div class="section">
    <h2>Metadata</h2>
    <table style="width: 100%; border-collapse: collapse;">
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 10px; font-weight: bold; width: 30%;">Author</td>
        <td style="padding: 10px;">${escapeHTML(product.metadata?.author || 'unknown')}</td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 10px; font-weight: bold;">Audience</td>
        <td style="padding: 10px;">${escapeHTML(product.audience || 'unknown')}</td>
      </tr>
      <tr>
        <td style="padding: 10px; font-weight: bold;">Tags</td>
        <td style="padding: 10px;">${(product.metadata?.tags || []).map(t => `<code>${escapeHTML(t)}</code>`).join(' ')}</td>
      </tr>
    </table>
  </div>

  <div class="section">
    <h2>Export Information</h2>
    <p>Exported: ${new Date().toISOString()}</p>
    <p>Format: HTML</p>
  </div>

  <footer style="border-top: 1px solid #ddd; padding-top: 20px; margin-top: 40px; color: #666; font-size: 12px;">
    <p>CYBERDUDEBIVASH® SENTINEL APEX — Enterprise Threat Intelligence Product</p>
  </footer>
</body>
</html>`;
}

function generateMarkdownExport(product) {
  const title = product.metadata?.title || product.productId;
  const description = product.metadata?.description || '';

  let md = `# ${title}\n\n`;
  md += `${description}\n\n`;
  md += `## Product Information\n\n`;
  md += `- **Product ID**: \`${product.productId}\`\n`;
  md += `- **Type**: ${product.productType}\n`;
  md += `- **Version**: ${product.version}\n`;
  md += `- **Status**: ${product.status}\n`;
  md += `- **Classification**: ${product.classification}\n`;
  md += `- **Audience**: ${product.audience}\n`;
  md += `- **Created**: ${product.createdAt}\n`;
  md += `- **Updated**: ${product.updatedAt}\n\n`;

  if (product.metadata?.author) {
    md += `## Metadata\n\n`;
    md += `- **Author**: ${product.metadata.author}\n`;
    if (product.metadata.tags && product.metadata.tags.length > 0) {
      md += `- **Tags**: ${product.metadata.tags.join(', ')}\n`;
    }
    md += '\n';
  }

  if (product.lineage) {
    md += `## Lineage\n\n`;
    md += `- **Investigation**: ${product.lineage.investigation}\n`;
    md += `- **Report**: ${product.lineage.report}\n`;
    if (product.lineage.publication) {
      md += `- **Published**: ${product.lineage.publication}\n`;
    }
    md += '\n';
  }

  if (product.approvals && product.approvals.length > 0) {
    md += `## Approvals\n\n`;
    product.approvals.forEach(a => {
      md += `- **${a.approver}** (${a.role}) — ${a.approvedAt}\n`;
    });
    md += '\n';
  }

  md += `---\n\n`;
  md += `**CYBERDUDEBIVASH® SENTINEL APEX** — Enterprise Threat Intelligence Product\n`;
  md += `Exported: ${new Date().toISOString()}\n`;

  return md;
}

function escapeHTML(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
