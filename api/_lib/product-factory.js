'use strict';

const redis = require('./redis');
const crypto = require('crypto');
const { ProductCatalog } = require('./product-catalog');
const { ProductCompositionEngine } = require('./product-composition-engine');
const { ProductLineage } = require('./product-models');

class ProductFactory {
  constructor(redisClient = redis) {
    this.redis = redisClient;
    this.catalog = new ProductCatalog();
    this.compositionEngine = new ProductCompositionEngine(redisClient);
  }

  async generateProductPortfolio(investigation, report, qualityReview) {
    console.log(`[PRODUCT FACTORY] Generating portfolio for investigation ${investigation.id}`);

    const products = [];
    const lineage = new ProductLineage(investigation.id);

    try {
      // Determine applicable products
      const applicableProducts = this.catalog.getProductsForInvestigation(investigation);

      for (const productDef of applicableProducts) {
        try {
          const product = await this.generateProduct(productDef.id, investigation, report, qualityReview);

          if (product) {
            // Add to lineage
            lineage.addStage('product', product.id);

            // Persist product
            await this.persistProduct(product);

            products.push({
              id: product.id,
              productId: product.productId,
              type: product.productType,
              status: product.status,
              classification: product.classification,
            });

            console.log(`[PRODUCT FACTORY] Generated ${productDef.id}`);
          }
        } catch (e) {
          console.error(`[PRODUCT FACTORY] Failed to generate ${productDef.id}: ${e.message}`);
        }
      }

      // Also generate all technical and detection products
      products.push(...await this.generateTechnicalProducts(investigation, report, qualityReview));
      products.push(...await this.generateDetectionProducts(investigation, report));
      products.push(...await this.generateMachineProducts(investigation, report));

      // Store portfolio metadata
      await this.storeProductPortfolio(investigation.id, report.id, products, lineage);

      return {
        investigationId: investigation.id,
        reportId: report.id,
        portfolioSize: products.length,
        products,
        lineage: lineage.getFullLineage(),
        generatedAt: new Date().toISOString(),
      };
    } catch (e) {
      console.error(`[PRODUCT FACTORY] Portfolio generation failed: ${e.message}`);
      throw e;
    }
  }

  async generateProduct(productId, investigation, report, qualityReview) {
    switch (productId) {
      case 'executive-brief':
        return await this.compositionEngine.composeExecutiveBrief(investigation, report, qualityReview);
      case 'board-summary':
        return await this.compositionEngine.composeBoardSummary(investigation, report, qualityReview);
      case 'technical-report':
        return await this.compositionEngine.composeTechnicalReport(investigation, report, qualityReview);
      case 'ioc-feed':
        return await this.compositionEngine.composeIOCFeed(investigation, report);
      case 'threat-actor-profile':
        if (investigation.threatActors && investigation.threatActors.length > 0) {
          return await this.compositionEngine.composeThreatActorProfile(investigation, report);
        }
        return null;
      case 'campaign-intelligence':
        if (investigation.campaigns && investigation.campaigns.length > 0) {
          return await this.compositionEngine.composeCampaignIntelligence(investigation, report);
        }
        return null;
      case 'stix-bundle':
        return await this.compositionEngine.composeSTIXBundle(investigation, report);
      case 'json-object':
        return await this.compositionEngine.composeJSONIntelligenceObject(investigation, report);
      default:
        return null;
    }
  }

  async generateTechnicalProducts(investigation, report, qualityReview) {
    const products = [];

    const technicalReport = await this.compositionEngine.composeTechnicalReport(investigation, report, qualityReview);
    if (technicalReport) {
      await this.persistProduct(technicalReport);
      products.push({
        id: technicalReport.id,
        productId: technicalReport.productId,
        type: 'technical',
      });
    }

    return products;
  }

  async generateDetectionProducts(investigation, report) {
    const products = [];

    // Only generate detection products if we have the required data
    if (investigation.iocs && investigation.iocs.length > 0) {
      // Generate vendor-specific packages (extension points for vendor implementations)
      const detectionFormats = [
        'sigma-package',
        'yara-package',
        'suricata-package',
        'splunk-package',
        'elastic-package',
        'sentinel-package',
        'defender-package',
        'chronicle-package',
        'qradar-package',
        'wazuh-package',
      ];

      for (const format of detectionFormats) {
        const productDef = this.catalog.getProduct(format);
        if (productDef && investigation.iocs.length > 0) {
          // Create detection product with extension point for vendor-specific logic
          const product = await this.createDetectionProduct(format, investigation, report);
          if (product) {
            await this.persistProduct(product);
            products.push({
              id: product.id,
              productId: product.productId,
              type: 'detection',
              format: format,
            });
          }
        }
      }
    }

    return products;
  }

  async generateMachineProducts(investigation, report) {
    const products = [];

    const stixBundle = await this.compositionEngine.composeSTIXBundle(investigation, report);
    if (stixBundle) {
      await this.persistProduct(stixBundle);
      products.push({
        id: stixBundle.id,
        productId: 'stix-bundle',
        type: 'machine',
      });
    }

    const jsonObject = await this.compositionEngine.composeJSONIntelligenceObject(investigation, report);
    if (jsonObject) {
      await this.persistProduct(jsonObject);
      products.push({
        id: jsonObject.id,
        productId: 'json-object',
        type: 'machine',
      });
    }

    return products;
  }

  async createDetectionProduct(format, investigation, report) {
    // Extension point for vendor-specific detection product generation
    const product = {
      id: crypto.randomBytes(16).toString('hex'),
      productId: format,
      productType: 'detection',
      investigationId: investigation.id,
      reportId: report.id,
      audience: 'TECHNICAL',
      classification: 'TLP:WHITE',
      status: 'DRAFT',
      version: '1.0',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      modules: {
        detectionRules: await this.buildDetectionRules(format, investigation),
        indicators: investigation.iocs || [],
        metadata: {
          format,
          ruleCount: (investigation.iocs || []).length,
          generatedAt: new Date().toISOString(),
        },
      },
      metadata: {
        title: `${format}: ${investigation.id}`,
        description: `${format} detection rules for ${investigation.title}`,
        author: 'Sentinel APEX',
        tags: ['detection', format],
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        detection: new Date().toISOString(),
      },
    };

    return product;
  }

  async buildDetectionRules(format, investigation) {
    // Placeholder for vendor-specific rule generation
    // This is an extension point for adding vendor-specific implementations
    return {
      format,
      ruleCount: investigation.iocs ? investigation.iocs.length : 0,
      note: `Detection rules for ${format} would be generated by vendor-specific implementation`,
      indicators: investigation.iocs || [],
    };
  }

  async persistProduct(product) {
    const key = `product:${product.id}`;
    const productData = { ...product };

    // Stringify complex objects
    productData.modules = JSON.stringify(productData.modules);
    productData.metadata = JSON.stringify(productData.metadata);
    productData.lineage = JSON.stringify(productData.lineage);
    productData.validations = JSON.stringify(productData.validations || {});
    productData.approvals = JSON.stringify(productData.approvals || []);
    productData.exportHistory = JSON.stringify(productData.exportHistory || []);

    await this.redis.hset(key, Object.entries(productData).flat());
    await this.redis.zadd(`products:investigation:${product.investigationId}`, Date.now(), product.id);
    await this.redis.zadd(`products:report:${product.reportId}`, Date.now(), product.id);
    await this.redis.zadd(`products:all`, Date.now(), product.id);
  }

  async storeProductPortfolio(investigationId, reportId, products, lineage) {
    const portfolioKey = `portfolio:${investigationId}`;
    const portfolio = {
      investigationId,
      reportId,
      productCount: products.length,
      productIds: products.map(p => p.id).join(','),
      generatedAt: new Date().toISOString(),
      lineage: JSON.stringify(lineage.getFullLineage()),
    };

    await this.redis.hset(portfolioKey, Object.entries(portfolio).flat());
    await this.redis.zadd('portfolios:all', Date.now(), investigationId);
  }

  async getProduct(productId) {
    const key = `product:${productId}`;
    const data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return null;
    }

    return this.parseProductData(data);
  }

  async getPortfolio(investigationId) {
    const portfolioKey = `portfolio:${investigationId}`;
    const data = await this.redis.hgetall(portfolioKey);

    if (!data || data.length === 0) {
      return null;
    }

    const portfolio = {};
    for (let i = 0; i < data.length; i += 2) {
      portfolio[data[i]] = data[i + 1];
    }

    // Parse productIds and lineage
    portfolio.products = portfolio.productIds ? portfolio.productIds.split(',') : [];
    try {
      portfolio.lineage = JSON.parse(portfolio.lineage);
    } catch (e) {
      portfolio.lineage = {};
    }

    return portfolio;
  }

  async listPortfolioProducts(investigationId, limit = 50) {
    const productIds = await this.redis.zrevrange(`products:investigation:${investigationId}`, 0, limit - 1);
    const products = [];

    for (const productId of productIds) {
      const product = await this.getProduct(productId);
      if (product) products.push(product);
    }

    return products;
  }

  async searchProducts(query, limit = 20) {
    const allProductIds = await this.redis.zrevrange('products:all', 0, limit * 3 - 1);
    const results = [];

    for (const productId of allProductIds) {
      const product = await this.getProduct(productId);
      if (product && this.matchesQuery(product, query)) {
        results.push(product);
        if (results.length >= limit) break;
      }
    }

    return results;
  }

  matchesQuery(product, query) {
    const queryLower = query.toLowerCase();
    return (
      product.productId.toLowerCase().includes(queryLower) ||
      (product.metadata && product.metadata.title && product.metadata.title.toLowerCase().includes(queryLower)) ||
      product.investigationId.includes(query)
    );
  }

  parseProductData(data) {
    const product = {};

    for (let i = 0; i < data.length; i += 2) {
      const key = data[i];
      const value = data[i + 1];

      if (['modules', 'metadata', 'lineage', 'validations', 'approvals', 'exportHistory'].includes(key)) {
        try {
          product[key] = JSON.parse(value);
        } catch (e) {
          product[key] = value;
        }
      } else {
        product[key] = value;
      }
    }

    return product;
  }
}

module.exports = { ProductFactory };
