'use strict';

const { SentinelApexEIXPresentationEngine } = require('./sa-eix-presentation-engine');
const { SentinelApexEIXHTMLRenderer } = require('./sa-eix-html-renderer');
const { SentinelApexEIXDiagramRenderer } = require('./sa-eix-diagram-renderer');

class SentinelApexEIXIntegrationOrchestrator {
  constructor(brandingConfig = {}) {
    this.presentationEngine = new SentinelApexEIXPresentationEngine();
    this.htmlRenderer = new SentinelApexEIXHTMLRenderer(brandingConfig);
    this.diagramRenderer = new SentinelApexEIXDiagramRenderer(brandingConfig);
    this.brandingConfig = brandingConfig;
    this.reportCache = new Map();
    this.renderingMetrics = {
      totalReports: 0,
      cachedReports: 0,
      averageRenderTime: 0,
      renderTimes: [],
    };
  }

  async generateEnhancedReport(product, investigation, report, options = {}) {
    const startTime = Date.now();
    const {
      theme = 'dark',
      mode = 'executive',
      responsive = true,
      renderDiagrams = true,
      cacheReport = true,
    } = options;

    // Check cache first
    const cacheKey = `${product.id}-${theme}-${mode}`;
    if (cacheReport && this.reportCache.has(cacheKey)) {
      this.renderingMetrics.totalReports++;
      this.renderingMetrics.cachedReports++;
      return {
        html: this.reportCache.get(cacheKey),
        cached: true,
        renderTime: 0,
      };
    }

    // Step 1: Generate presentation enhancements
    const enhancement = await this.presentationEngine.enhanceIntelligenceProduct(
      product,
      investigation,
      report
    );

    // Step 2: Render interactive diagrams
    if (renderDiagrams && enhancement.presentationEnhancements.interactiveDiagrams) {
      enhancement.presentationEnhancements.interactiveDiagrams = this.renderInteractiveDiagrams(
        enhancement.presentationEnhancements.interactiveDiagrams
      );
    }

    // Step 3: Generate HTML
    const html = this.htmlRenderer.renderEnhancedReport(enhancement, {
      theme,
      mode,
      responsive,
    });

    // Step 4: Cache and return
    if (cacheReport) {
      this.reportCache.set(cacheKey, html);
    }

    const renderTime = Date.now() - startTime;
    this.updateRenderingMetrics(renderTime);

    return {
      html,
      cached: false,
      renderTime,
      productId: product.id,
      enhancement,
    };
  }

  renderInteractiveDiagrams(diagramsData) {
    if (!diagramsData.diagrams || diagramsData.diagrams.length === 0) {
      return diagramsData;
    }

    const enhancedDiagrams = {
      ...diagramsData,
      diagrams: [],
      svg: {},
    };

    for (const diagram of diagramsData.diagrams) {
      let svg = null;

      switch (diagram.type) {
        case 'attack-chain':
          svg = this.diagramRenderer.renderAttackChain(diagram);
          break;
        case 'kill-chain':
          svg = this.diagramRenderer.renderKillChain(diagram);
          break;
        case 'mitre-matrix':
          svg = this.diagramRenderer.renderMitreMatrix(diagram);
          break;
        case 'timeline':
          svg = this.diagramRenderer.renderTimeline(diagram);
          break;
        case 'infrastructure-graph':
          svg = this.diagramRenderer.renderInfrastructureGraph(diagram);
          break;
        case 'threat-actor-network':
          svg = this.diagramRenderer.renderThreatActorNetwork(diagram);
          break;
        case 'battlefield':
          svg = this.diagramRenderer.renderBattlefieldVisualization(diagram);
          break;
        default:
          svg = this.diagramRenderer.renderPlaceholder(
            diagram.title || 'Diagram',
            'Diagram type not yet supported',
            1200,
            400,
            'dark'
          );
      }

      enhancedDiagrams.diagrams.push({
        ...diagram,
        svg,
        rendered: true,
      });

      enhancedDiagrams.svg[diagram.type] = svg;
    }

    return enhancedDiagrams;
  }

  async generateMultipleReports(products, investigation, options = {}) {
    const reports = [];

    for (const product of products) {
      try {
        const report = await this.generateEnhancedReport(product, investigation, null, options);
        reports.push({
          productId: product.id,
          success: true,
          report,
        });
      } catch (error) {
        reports.push({
          productId: product.id,
          success: false,
          error: error.message,
        });
      }
    }

    return {
      total: products.length,
      successful: reports.filter(r => r.success).length,
      failed: reports.filter(r => !r.success).length,
      reports,
    };
  }

  exportReportAsHTMLFile(htmlContent, filename = 'report.html') {
    return {
      filename,
      content: htmlContent,
      mimeType: 'text/html',
      size: htmlContent.length,
    };
  }

  exportReportAsPDF(htmlContent, options = {}) {
    // Placeholder for PDF generation (would integrate with PDF library)
    return {
      format: 'pdf',
      status: 'requires-library',
      message: 'PDF export requires external library integration (puppeteer, wkhtmltopdf, etc)',
      htmlContent,
      options,
    };
  }

  getReportingMetrics() {
    return {
      ...this.renderingMetrics,
      cacheUtilization: this.renderingMetrics.cachedReports / Math.max(this.renderingMetrics.totalReports, 1),
      cacheSize: this.reportCache.size,
      cachedProductIds: Array.from(this.reportCache.keys()),
    };
  }

  getEnhancedProductSummary(enhancement) {
    if (!enhancement) return null;

    const summary = {
      productId: enhancement.productId,
      threatScore: enhancement.presentationEnhancements.coverPage?.sections?.header?.threatScore || 0,
      threatLevel: enhancement.presentationEnhancements.coverPage?.sections?.header?.threatLevel || 'UNKNOWN',
      confidence: enhancement.presentationEnhancements.coverPage?.sections?.threatInformation?.confidence || 0,
      detectionCoverage: enhancement.presentationEnhancements.coverPage?.sections?.threatInformation?.detectionCoverage || 0,
      keyMetrics: enhancement.presentationEnhancements.coverPage?.sections?.keyMetrics || {},
      sections: Object.keys(enhancement.presentationEnhancements || {}),
    };

    return summary;
  }

  clearCache() {
    this.reportCache.clear();
    this.renderingMetrics.cachedReports = 0;
  }

  getCachedReport(productId, theme = 'dark', mode = 'executive') {
    const cacheKey = `${productId}-${theme}-${mode}`;
    return this.reportCache.get(cacheKey);
  }

  // Private Methods

  updateRenderingMetrics(renderTime) {
    this.renderingMetrics.totalReports++;
    this.renderingMetrics.renderTimes.push(renderTime);

    // Keep only last 100 render times
    if (this.renderingMetrics.renderTimes.length > 100) {
      this.renderingMetrics.renderTimes.shift();
    }

    // Calculate average
    const sum = this.renderingMetrics.renderTimes.reduce((a, b) => a + b, 0);
    this.renderingMetrics.averageRenderTime = Math.round(sum / this.renderingMetrics.renderTimes.length);
  }

  // Report Assembly Methods

  async assembleExecutiveReport(product, investigation, report, options = {}) {
    const enhancedReport = await this.generateEnhancedReport(product, investigation, report, options);

    return {
      type: 'executive-report',
      product,
      investigation,
      enhancement: enhancedReport.enhancement,
      html: enhancedReport.html,
      metadata: {
        generatedAt: new Date().toISOString(),
        theme: options.theme || 'dark',
        renderTime: enhancedReport.renderTime,
        cached: enhancedReport.cached,
      },
    };
  }

  async assembleTechnicalReport(product, investigation, report, options = {}) {
    const optionsWithMode = { ...options, mode: 'technical' };
    const enhancedReport = await this.generateEnhancedReport(product, investigation, report, optionsWithMode);

    return {
      type: 'technical-report',
      product,
      investigation,
      enhancement: enhancedReport.enhancement,
      html: enhancedReport.html,
      metadata: {
        generatedAt: new Date().toISOString(),
        theme: options.theme || 'dark',
        renderTime: enhancedReport.renderTime,
        cached: enhancedReport.cached,
      },
    };
  }

  async assembleOperationalReport(product, investigation, report, options = {}) {
    const optionsWithMode = { ...options, mode: 'operational' };
    const enhancedReport = await this.generateEnhancedReport(product, investigation, report, optionsWithMode);

    return {
      type: 'operational-report',
      product,
      investigation,
      enhancement: enhancedReport.enhancement,
      html: enhancedReport.html,
      metadata: {
        generatedAt: new Date().toISOString(),
        theme: options.theme || 'dark',
        renderTime: enhancedReport.renderTime,
        cached: enhancedReport.cached,
      },
    };
  }

  // Batch Operations

  async generateReportSuite(product, investigation, options = {}) {
    // Generate all three modes in parallel
    const [executive, technical, operational] = await Promise.all([
      this.assembleExecutiveReport(product, investigation, null, options),
      this.assembleTechnicalReport(product, investigation, null, options),
      this.assembleOperationalReport(product, investigation, null, options),
    ]);

    return {
      productId: product.id,
      generated: new Date().toISOString(),
      reports: {
        executive,
        technical,
        operational,
      },
      sizes: {
        executive: executive.html.length,
        technical: technical.html.length,
        operational: operational.html.length,
      },
    };
  }

  // Search/Query Methods

  searchCachedReports(query) {
    const results = [];

    for (const [key] of this.reportCache) {
      if (key.includes(query)) {
        results.push({
          key,
          productId: key.split('-')[0],
          cached: true,
        });
      }
    }

    return results;
  }

  // Validation Methods

  validateEnhancementStructure(enhancement) {
    const required = [
      'productId',
      'presentationEnhancements',
      'metadata',
    ];

    for (const field of required) {
      if (!(field in enhancement)) {
        return {
          valid: false,
          error: `Missing required field: ${field}`,
        };
      }
    }

    if (!enhancement.presentationEnhancements.coverPage) {
      return {
        valid: false,
        error: 'Cover page not generated',
      };
    }

    return { valid: true };
  }

  // Health Check

  getHealthStatus() {
    return {
      status: 'healthy',
      components: {
        presentationEngine: 'active',
        htmlRenderer: 'active',
        diagramRenderer: 'active',
      },
      metrics: this.getReportingMetrics(),
      cacheHealth: {
        size: this.reportCache.size,
        maxSize: 1000,
        utilization: (this.reportCache.size / 1000) * 100,
      },
    };
  }
}

module.exports = { SentinelApexEIXIntegrationOrchestrator };
