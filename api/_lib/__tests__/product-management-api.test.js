'use strict';

const { ProductManagementAPI } = require('../product-management-api');

describe('Product Management API', () => {
  let api;
  let mockRedis;

  beforeEach(() => {
    mockRedis = {
      hgetall: jest.fn().mockResolvedValue([]),
      zrevrange: jest.fn().mockResolvedValue([]),
      zcard: jest.fn().mockResolvedValue(0),
    };

    api = new ProductManagementAPI(mockRedis);
  });

  test('should initialize API with redis client', () => {
    expect(api).toBeDefined();
    expect(api.redis).toBe(mockRedis);
  });

  test('should retrieve product by ID', async () => {
    const mockProductData = ['id', 'prod-001', 'productId', 'exec-brief', 'type', 'executive', 'status', 'draft'];

    mockRedis.hgetall.mockResolvedValueOnce(mockProductData);

    const product = await api.getProductById('prod-001');

    expect(product).toBeDefined();
    expect(product.id).toBe('prod-001');
    expect(product.productId).toBe('exec-brief');
    expect(mockRedis.hgetall).toHaveBeenCalledWith('product:prod-001');
  });

  test('should return null for non-existent product', async () => {
    mockRedis.hgetall.mockResolvedValueOnce([]);

    const product = await api.getProductById('non-existent');

    expect(product).toBeNull();
  });

  test('should retrieve products by investigation', async () => {
    const productIds = ['prod-001', 'prod-002'];
    mockRedis.zrevrange.mockResolvedValueOnce(productIds);

    const mockProductData1 = ['id', 'prod-001', 'productId', 'exec-brief'];
    const mockProductData2 = ['id', 'prod-002', 'productId', 'tech-report'];

    mockRedis.hgetall
      .mockResolvedValueOnce(mockProductData1)
      .mockResolvedValueOnce(mockProductData2);

    const products = await api.getProductsByInvestigation('inv-001', 10);

    expect(Array.isArray(products)).toBe(true);
    expect(products.length).toBe(2);
    expect(mockRedis.zrevrange).toHaveBeenCalledWith('products:investigation:inv-001', 0, 9);
  });

  test('should search products by query', async () => {
    const allProductIds = ['prod-001', 'prod-002', 'prod-003'];
    mockRedis.zrevrange.mockResolvedValueOnce(allProductIds);

    const mockProductData = ['id', 'prod-001', 'productId', 'exec-brief', 'metadata', '{"title":"Executive Brief"}'];

    mockRedis.hgetall.mockResolvedValue(mockProductData);

    const results = await api.searchProducts('brief', {}, 10);

    expect(Array.isArray(results)).toBe(true);
  });

  test('should filter products by type', async () => {
    const allProductIds = ['prod-001', 'prod-002'];
    mockRedis.zrevrange.mockResolvedValueOnce(allProductIds);

    const mockProductData = ['id', 'prod-001', 'type', 'executive', 'productId', 'exec-brief'];

    mockRedis.hgetall.mockResolvedValue(mockProductData);

    const results = await api.searchProducts('', { type: 'executive' }, 10);

    expect(Array.isArray(results)).toBe(true);
  });

  test('should retrieve product portfolio', async () => {
    const portfolioData = [
      'investigationId',
      'inv-001',
      'reportId',
      'report-001',
      'productIds',
      'prod-001,prod-002',
      'productCount',
      '2',
    ];

    mockRedis.hgetall.mockResolvedValueOnce(portfolioData);

    const mockProductData = ['id', 'prod-001', 'productId', 'exec-brief'];
    mockRedis.hgetall.mockResolvedValue(mockProductData);

    const portfolio = await api.getProductPortfolio('inv-001');

    expect(portfolio).toBeDefined();
    expect(portfolio.investigationId).toBe('inv-001');
  });

  test('should retrieve intelligence collections', async () => {
    const collectionIds = ['coll-001', 'coll-002'];
    mockRedis.zrevrange.mockResolvedValueOnce(collectionIds);

    const mockCollectionData = ['id', 'coll-001', 'name', 'Ransomware', 'productIds', 'prod-001,prod-002'];

    mockRedis.hgetall.mockResolvedValue(mockCollectionData);

    const collections = await api.getIntelligenceCollections(10);

    expect(Array.isArray(collections)).toBe(true);
    expect(mockRedis.zrevrange).toHaveBeenCalledWith('collections:all', 0, 9);
  });

  test('should retrieve customer package', async () => {
    const packageData = ['id', 'pkg-ciso-001', 'role', 'ciso', 'productIds', 'prod-001,prod-002,prod-003'];

    mockRedis.hgetall.mockResolvedValueOnce(packageData);

    const pkg = await api.getCustomerPackage('pkg-ciso-001');

    expect(pkg).toBeDefined();
    expect(pkg.role).toBe('ciso');
    expect(pkg.productIds).toEqual(['prod-001', 'prod-002', 'prod-003']);
  });

  test('should retrieve product statistics', async () => {
    const productIds = ['prod-001', 'prod-002', 'prod-003'];
    mockRedis.zcard.mockResolvedValueOnce(3);
    mockRedis.zrevrange.mockResolvedValueOnce(productIds);

    const mockProductData1 = ['id', 'prod-001', 'type', 'executive', 'classification', 'TLP:AMBER'];
    const mockProductData2 = ['id', 'prod-002', 'type', 'technical', 'classification', 'TLP:GREEN'];
    const mockProductData3 = ['id', 'prod-003', 'type', 'executive', 'classification', 'TLP:AMBER'];

    mockRedis.hgetall
      .mockResolvedValueOnce(mockProductData1)
      .mockResolvedValueOnce(mockProductData2)
      .mockResolvedValueOnce(mockProductData3);

    const stats = await api.getProductStats();

    expect(stats).toBeDefined();
    expect(stats.totalProducts).toBe(3);
    expect(stats.byType).toBeDefined();
    expect(stats.byClassification).toBeDefined();
  });

  test('should parse product data with complex objects', () => {
    const rawData = [
      'id',
      'prod-001',
      'modules',
      '{"threat":"APT-28"}',
      'metadata',
      '{"title":"Executive Brief"}',
    ];

    const product = api.parseProductData(rawData);

    expect(product.id).toBe('prod-001');
    expect(typeof product.modules).toBe('object');
    expect(product.modules.threat).toBe('APT-28');
    expect(typeof product.metadata).toBe('object');
  });

  test('should handle audience arrays', () => {
    const product = {
      id: 'prod-001',
      audience: ['executive', 'ciso', 'board'],
    };

    expect(api.hasAudience(product, 'executive')).toBe(true);
    expect(api.hasAudience(product, 'ciso')).toBe(true);
    expect(api.hasAudience(product, 'unknown')).toBe(false);
  });

  test('should retrieve product export options', async () => {
    const mockProductData = [
      'id',
      'prod-001',
      'metadata',
      '{"exportFormats":["json","pdf","html"]}',
      'classification',
      'TLP:AMBER',
    ];

    mockRedis.hgetall.mockResolvedValueOnce(mockProductData);

    const options = await api.getProductExportOptions('prod-001');

    expect(options).toBeDefined();
    expect(options.availableFormats).toContain('json');
  });

  test('should retrieve product lifecycle status', async () => {
    const mockProductData = [
      'id',
      'prod-001',
      'status',
      'published',
      'metadata',
      '{"createdAt":"2024-07-31T00:00:00Z"}',
    ];

    mockRedis.hgetall.mockResolvedValueOnce(mockProductData);

    const lifecycle = await api.getProductLifecycleStatus('prod-001');

    expect(lifecycle).toBeDefined();
    expect(lifecycle.currentStatus).toBe('published');
  });
});
