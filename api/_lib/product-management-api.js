'use strict';

const redis = require('./redis');

class ProductManagementAPI {
  constructor(redisClient = redis, productFactory = null) {
    this.redis = redisClient;
    this.productFactory = productFactory;
  }

  async getProductById(productId) {
    try {
      const key = `product:${productId}`;
      const data = await this.redis.hgetall(key);

      if (!data || data.length === 0) {
        return null;
      }

      return this.parseProductData(data);
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve product ${productId}: ${e.message}`);
      return null;
    }
  }

  async getProductsByInvestigation(investigationId, limit = 100) {
    try {
      const productIds = await this.redis.zrevrange(
        `products:investigation:${investigationId}`,
        0,
        limit - 1
      );

      const products = [];
      for (const productId of productIds) {
        const product = await this.getProductById(productId);
        if (product) products.push(product);
      }

      return products;
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve investigation products: ${e.message}`);
      return [];
    }
  }

  async getProductsByReport(reportId, limit = 100) {
    try {
      const productIds = await this.redis.zrevrange(`products:report:${reportId}`, 0, limit - 1);

      const products = [];
      for (const productId of productIds) {
        const product = await this.getProductById(productId);
        if (product) products.push(product);
      }

      return products;
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve report products: ${e.message}`);
      return [];
    }
  }

  async getProductsByType(productType, limit = 50) {
    try {
      const allProductIds = await this.redis.zrevrange('products:all', 0, limit * 2 - 1);
      const products = [];

      for (const productId of allProductIds) {
        const product = await this.getProductById(productId);
        if (product && (product.type === productType || product.productType === productType)) {
          products.push(product);
          if (products.length >= limit) break;
        }
      }

      return products;
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve products by type: ${e.message}`);
      return [];
    }
  }

  async getProductsByAudience(audience, limit = 50) {
    try {
      const allProductIds = await this.redis.zrevrange('products:all', 0, limit * 3 - 1);
      const products = [];

      for (const productId of allProductIds) {
        const product = await this.getProductById(productId);
        if (product && product.audience) {
          const audiences = Array.isArray(product.audience) ? product.audience : [product.audience];
          if (audiences.includes(audience)) {
            products.push(product);
            if (products.length >= limit) break;
          }
        }
      }

      return products;
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve products by audience: ${e.message}`);
      return [];
    }
  }

  async getProductsByClassification(classification, limit = 50) {
    try {
      const allProductIds = await this.redis.zrevrange('products:all', 0, limit * 2 - 1);
      const products = [];

      for (const productId of allProductIds) {
        const product = await this.getProductById(productId);
        if (product && product.classification === classification) {
          products.push(product);
          if (products.length >= limit) break;
        }
      }

      return products;
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve products by classification: ${e.message}`);
      return [];
    }
  }

  async searchProducts(query, filters = {}, limit = 20) {
    try {
      const allProductIds = await this.redis.zrevrange('products:all', 0, limit * 5 - 1);
      const results = [];
      const queryLower = query.toLowerCase();

      for (const productId of allProductIds) {
        const product = await this.getProductById(productId);
        if (!product) continue;

        const matches =
          product.productId.toLowerCase().includes(queryLower) ||
          (product.metadata && product.metadata.title && product.metadata.title.toLowerCase().includes(queryLower)) ||
          (product.metadata && product.metadata.description && product.metadata.description.toLowerCase().includes(queryLower)) ||
          product.investigationId.toLowerCase().includes(queryLower);

        if (!matches) continue;

        if (filters.type && product.type !== filters.type && product.productType !== filters.type) continue;
        if (filters.audience && !this.hasAudience(product, filters.audience)) continue;
        if (filters.classification && product.classification !== filters.classification) continue;
        if (filters.status && product.status !== filters.status) continue;

        results.push(product);
        if (results.length >= limit) break;
      }

      return results;
    } catch (e) {
      console.error(`[PRODUCT API] Search failed: ${e.message}`);
      return [];
    }
  }

  async getIntelligenceCollection(collectionId) {
    try {
      const key = `collection:${collectionId}`;
      const data = await this.redis.hgetall(key);

      if (!data || data.length === 0) {
        return null;
      }

      const collection = {};
      for (let i = 0; i < data.length; i += 2) {
        const key = data[i];
        const value = data[i + 1];

        if (key === 'productIds') {
          collection[key] = value ? value.split(',') : [];
        } else if (key === 'metadata') {
          try {
            collection[key] = JSON.parse(value);
          } catch (e) {
            collection[key] = value;
          }
        } else {
          collection[key] = value;
        }
      }

      return collection;
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve collection: ${e.message}`);
      return null;
    }
  }

  async getIntelligenceCollections(limit = 20) {
    try {
      const collectionIds = await this.redis.zrevrange('collections:all', 0, limit - 1);
      const collections = [];

      for (const collectionId of collectionIds) {
        const collection = await this.getIntelligenceCollection(collectionId);
        if (collection) collections.push(collection);
      }

      return collections;
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve collections: ${e.message}`);
      return [];
    }
  }

  async getCustomerPackage(packageId) {
    try {
      const key = `package:${packageId}`;
      const data = await this.redis.hgetall(key);

      if (!data || data.length === 0) {
        return null;
      }

      const pkg = {};
      for (let i = 0; i < data.length; i += 2) {
        const key = data[i];
        const value = data[i + 1];

        if (key === 'productIds') {
          pkg[key] = value ? value.split(',') : [];
        } else if (key === 'metadata' || key === 'modules') {
          try {
            pkg[key] = JSON.parse(value);
          } catch (e) {
            pkg[key] = value;
          }
        } else {
          pkg[key] = value;
        }
      }

      return pkg;
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve customer package: ${e.message}`);
      return null;
    }
  }

  async getCustomerPackages(role = null, limit = 10) {
    try {
      let query = 'packages:all';
      if (role) {
        query = `packages:${role}`;
      }

      const packageIds = await this.redis.zrevrange(query, 0, limit - 1);
      const packages = [];

      for (const packageId of packageIds) {
        const pkg = await this.getCustomerPackage(packageId);
        if (pkg) packages.push(pkg);
      }

      return packages;
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve customer packages: ${e.message}`);
      return [];
    }
  }

  async getProductPortfolio(investigationId) {
    try {
      const portfolioKey = `portfolio:${investigationId}`;
      const data = await this.redis.hgetall(portfolioKey);

      if (!data || data.length === 0) {
        return null;
      }

      const portfolio = {};
      for (let i = 0; i < data.length; i += 2) {
        const key = data[i];
        const value = data[i + 1];

        if (key === 'productIds') {
          portfolio[key] = value ? value.split(',') : [];
        } else if (key === 'lineage') {
          try {
            portfolio[key] = JSON.parse(value);
          } catch (e) {
            portfolio[key] = value;
          }
        } else {
          portfolio[key] = value;
        }
      }

      // Fetch full product details for each product in portfolio
      if (portfolio.productIds && portfolio.productIds.length > 0) {
        const products = [];
        for (const productId of portfolio.productIds) {
          const product = await this.getProductById(productId);
          if (product) products.push(product);
        }
        portfolio.products = products;
      }

      return portfolio;
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve portfolio: ${e.message}`);
      return null;
    }
  }

  async getProductStats() {
    try {
      const totalProductIds = await this.redis.zcard('products:all');

      const allProductIds = await this.redis.zrevrange('products:all', 0, -1);
      const stats = {
        totalProducts: totalProductIds,
        byType: {},
        byClassification: {},
        byAudience: {},
      };

      for (const productId of allProductIds) {
        const product = await this.getProductById(productId);
        if (!product) continue;

        const type = product.type || product.productType || 'unknown';
        stats.byType[type] = (stats.byType[type] || 0) + 1;

        const classification = product.classification || 'unknown';
        stats.byClassification[classification] = (stats.byClassification[classification] || 0) + 1;

        if (product.audience) {
          const audiences = Array.isArray(product.audience) ? product.audience : [product.audience];
          for (const audience of audiences) {
            stats.byAudience[audience] = (stats.byAudience[audience] || 0) + 1;
          }
        }
      }

      return stats;
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve stats: ${e.message}`);
      return { totalProducts: 0, byType: {}, byClassification: {}, byAudience: {} };
    }
  }

  async getProductExportOptions(productId) {
    try {
      const product = await this.getProductById(productId);
      if (!product) return null;

      return {
        productId: product.id,
        availableFormats: product.metadata?.exportFormats || ['json', 'pdf', 'html'],
        classification: product.classification,
        audience: product.audience,
        exportHistory: product.exportHistory || [],
      };
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve export options: ${e.message}`);
      return null;
    }
  }

  async getProductLifecycleStatus(productId) {
    try {
      const product = await this.getProductById(productId);
      if (!product) return null;

      return {
        productId: product.id,
        currentStatus: product.status,
        createdAt: product.metadata?.createdAt || product.createdAt,
        updatedAt: product.updatedAt,
        retirementStatus: product.retirementStatus || 'active',
        lastPublished: product.lastPublished,
        versions: product.versions || [],
      };
    } catch (e) {
      console.error(`[PRODUCT API] Failed to retrieve lifecycle status: ${e.message}`);
      return null;
    }
  }

  hasAudience(product, targetAudience) {
    if (!product.audience) return false;

    const audiences = Array.isArray(product.audience) ? product.audience : [product.audience];
    return audiences.includes(targetAudience);
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

module.exports = { ProductManagementAPI };
