'use strict';

const crypto = require('crypto');

class Product {
  constructor(productId, productType, investigationId, reportId, audience, classification) {
    this.id = crypto.randomBytes(16).toString('hex');
    this.productId = productId;
    this.productType = productType;
    this.investigationId = investigationId;
    this.reportId = reportId;
    this.audience = audience;
    this.classification = classification;
    this.status = 'DRAFT';
    this.version = '1.0';
    this.createdAt = new Date().toISOString();
    this.updatedAt = new Date().toISOString();
    this.modules = {};
    this.lineage = {
      investigation: investigationId,
      report: reportId,
      qualityReview: null,
      publication: null,
    };
    this.metadata = {
      title: null,
      description: null,
      author: null,
      tags: [],
      sources: [],
    };
    this.validations = {
      mandatory: [],
      evidence: [],
      confidence: [],
      classification: [],
      policy: [],
      approvals: [],
    };
    this.approvals = [];
    this.exportHistory = [];
  }

  addModule(moduleName, moduleContent) {
    this.modules[moduleName] = {
      name: moduleName,
      content: moduleContent,
      addedAt: new Date().toISOString(),
    };
    this.updatedAt = new Date().toISOString();
  }

  setMetadata(title, description, author, tags = []) {
    this.metadata.title = title;
    this.metadata.description = description;
    this.metadata.author = author;
    this.metadata.tags = tags;
  }

  addSource(sourceId, sourceType) {
    if (!this.metadata.sources.find(s => s.id === sourceId)) {
      this.metadata.sources.push({ id: sourceId, type: sourceType, addedAt: new Date().toISOString() });
    }
  }

  submitForReview(reviewLevel) {
    this.status = 'UNDER_REVIEW';
    this.validations.policy = [
      {
        check: 'REVIEW_LEVEL',
        required: reviewLevel,
        status: 'PENDING',
      },
    ];
    this.updatedAt = new Date().toISOString();
  }

  approve(approverName, approverRole) {
    this.approvals.push({
      id: crypto.randomBytes(8).toString('hex'),
      approver: approverName,
      role: approverRole,
      approvedAt: new Date().toISOString(),
    });
    this.updatedAt = new Date().toISOString();
  }

  publish() {
    this.status = 'PUBLISHED';
    this.lineage.publication = new Date().toISOString();
    this.updatedAt = new Date().toISOString();
  }

  supersede(newProductId) {
    this.status = 'SUPERSEDED';
    this.metadata.supersededBy = newProductId;
    this.updatedAt = new Date().toISOString();
  }

  archive() {
    this.status = 'ARCHIVED';
    this.updatedAt = new Date().toISOString();
  }

  createNewVersion() {
    const versionParts = this.version.split('.');
    versionParts[0] = String(parseInt(versionParts[0]) + 1);
    versionParts[1] = '0';
    return {
      ...this,
      id: crypto.randomBytes(16).toString('hex'),
      version: versionParts.join('.'),
      status: 'DRAFT',
      approvals: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lineage: {
        ...this.lineage,
        previousVersion: this.id,
      },
    };
  }

  recordExport(format, exportedAt) {
    this.exportHistory.push({
      id: crypto.randomBytes(8).toString('hex'),
      format,
      exportedAt: exportedAt || new Date().toISOString(),
    });
  }

  toJSON() {
    return {
      id: this.id,
      productId: this.productId,
      productType: this.productType,
      investigationId: this.investigationId,
      reportId: this.reportId,
      audience: this.audience,
      classification: this.classification,
      status: this.status,
      version: this.version,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      modules: this.modules,
      lineage: this.lineage,
      metadata: this.metadata,
      validations: this.validations,
      approvals: this.approvals,
      exportHistory: this.exportHistory,
    };
  }
}

class ExecutiveProduct extends Product {
  constructor(productId, investigationId, reportId, classification) {
    super(productId, 'executive', investigationId, reportId, 'EXECUTIVE', classification);
    this.modules.executiveSummary = null;
    this.modules.keyRisks = null;
    this.modules.recommendations = null;
  }
}

class TechnicalProduct extends Product {
  constructor(productId, investigationId, reportId, classification) {
    super(productId, 'technical', investigationId, reportId, 'TECHNICAL', classification);
    this.modules.findings = null;
    this.modules.evidence = null;
    this.modules.assessments = null;
    this.modules.technicalDetails = null;
  }
}

class DetectionProduct extends Product {
  constructor(productId, investigationId, reportId) {
    super(productId, 'detection', investigationId, reportId, 'TECHNICAL', 'TLP:WHITE');
    this.modules.detectionRules = null;
    this.modules.indicators = null;
    this.modules.searchStrategies = null;
    this.detectionFormat = null;
  }

  setDetectionFormat(format) {
    this.detectionFormat = format;
  }
}

class ThreatIntelligenceProduct extends Product {
  constructor(productId, investigationId, reportId, classification) {
    super(productId, 'threat-intelligence', investigationId, reportId, 'TECHNICAL', classification);
    this.modules.overview = null;
    this.modules.timeline = null;
    this.modules.indicators = null;
  }
}

class MachineProduct extends Product {
  constructor(productId, investigationId, reportId, format) {
    super(productId, 'machine', investigationId, reportId, 'MACHINE', 'TLP:WHITE');
    this.format = format;
    this.modules.structuredData = null;
    this.modules.metadata = null;
  }
}

class ProductVersion {
  constructor(product, baseVersion) {
    this.productId = product.id;
    this.versionNumber = baseVersion || '1.0';
    this.createdAt = new Date().toISOString();
    this.status = 'DRAFT';
    this.content = JSON.parse(JSON.stringify(product.toJSON()));
    this.changelog = [];
  }

  recordChange(changeType, description, author) {
    this.changelog.push({
      id: crypto.randomBytes(8).toString('hex'),
      type: changeType,
      description,
      author,
      timestamp: new Date().toISOString(),
    });
  }

  compareWith(otherVersion) {
    const differences = [];

    if (this.content.modules !== otherVersion.content.modules) {
      differences.push({
        field: 'modules',
        previous: otherVersion.content.modules,
        current: this.content.modules,
      });
    }

    if (this.content.metadata.title !== otherVersion.content.metadata.title) {
      differences.push({
        field: 'title',
        previous: otherVersion.content.metadata.title,
        current: this.content.metadata.title,
      });
    }

    if (this.content.classification !== otherVersion.content.classification) {
      differences.push({
        field: 'classification',
        previous: otherVersion.content.classification,
        current: this.content.classification,
      });
    }

    return differences;
  }
}

class ProductLineage {
  constructor(investigationId) {
    this.investigationId = investigationId;
    this.chain = [
      { stage: 'investigation', id: investigationId, timestamp: new Date().toISOString() },
    ];
  }

  addStage(stage, id) {
    this.chain.push({
      stage,
      id,
      timestamp: new Date().toISOString(),
    });
  }

  getFullLineage() {
    return {
      investigationId: this.investigationId,
      stages: this.chain,
      depth: this.chain.length,
      traceable: this.chain.every(s => s.id && s.stage),
    };
  }

  trace(productId) {
    return this.chain.filter(s => s.id === productId || this.investigationId === productId);
  }
}

module.exports = {
  Product,
  ExecutiveProduct,
  TechnicalProduct,
  DetectionProduct,
  ThreatIntelligenceProduct,
  MachineProduct,
  ProductVersion,
  ProductLineage,
};
