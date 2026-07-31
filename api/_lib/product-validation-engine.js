'use strict';

const redis = require('./redis');

class ProductValidationEngine {
  constructor(redisClient = redis) {
    this.redis = redisClient;
  }

  async validateProduct(product, productCatalog) {
    const validations = {
      mandatory: [],
      evidence: [],
      confidence: [],
      classification: [],
      policy: [],
      approvals: [],
    };

    const productDef = productCatalog.getProduct(product.productId);
    if (!productDef) {
      validations.mandatory.push({
        check: 'PRODUCT_DEFINED',
        result: 'FAIL',
        message: `Product ${product.productId} not found in catalog`,
        severity: 'critical',
      });
      return validations;
    }

    // Check mandatory modules
    const mandatoryCheck = this.validateMandatoryModules(product, productDef);
    validations.mandatory.push(...mandatoryCheck);

    // Check evidence integrity
    const evidenceCheck = this.validateEvidenceIntegrity(product);
    validations.evidence.push(...evidenceCheck);

    // Check confidence preservation
    const confidenceCheck = this.validateConfidencePreservation(product);
    validations.confidence.push(...confidenceCheck);

    // Check classification
    const classificationCheck = this.validateClassification(product, productDef);
    validations.classification.push(...classificationCheck);

    // Check policy compliance
    const policyCheck = this.validatePolicyCompliance(product, productDef);
    validations.policy.push(...policyCheck);

    return validations;
  }

  validateMandatoryModules(product, productDef) {
    const checks = [];
    const mandatoryModules = productDef.requiredModules || [];

    for (const moduleName of mandatoryModules) {
      if (!product.modules || !product.modules[moduleName]) {
        checks.push({
          check: 'MANDATORY_MODULE',
          module: moduleName,
          result: 'FAIL',
          message: `Required module "${moduleName}" is missing`,
          severity: 'high',
        });
      } else if (!product.modules[moduleName].content && product.modules[moduleName].content !== 0) {
        checks.push({
          check: 'MANDATORY_MODULE_CONTENT',
          module: moduleName,
          result: 'FAIL',
          message: `Required module "${moduleName}" has no content`,
          severity: 'high',
        });
      } else {
        checks.push({
          check: 'MANDATORY_MODULE',
          module: moduleName,
          result: 'PASS',
          message: `Module "${moduleName}" present with content`,
          severity: 'info',
        });
      }
    }

    return checks;
  }

  validateEvidenceIntegrity(product) {
    const checks = [];
    const evidenceModules = product.modules || {};

    if (evidenceModules.evidence) {
      const evidence = evidenceModules.evidence.content || [];

      if (Array.isArray(evidence) && evidence.length > 0) {
        checks.push({
          check: 'EVIDENCE_PRESENT',
          result: 'PASS',
          count: evidence.length,
          message: `Product contains ${evidence.length} evidence references`,
          severity: 'info',
        });

        // Check evidence has required fields
        const intactCount = evidence.filter(e =>
          e.id && e.type && (e.confidence !== undefined)
        ).length;

        if (intactCount === evidence.length) {
          checks.push({
            check: 'EVIDENCE_INTEGRITY',
            result: 'PASS',
            message: `All evidence references are intact`,
            severity: 'info',
          });
        } else {
          checks.push({
            check: 'EVIDENCE_INTEGRITY',
            result: 'WARN',
            intactCount,
            totalCount: evidence.length,
            message: `${evidence.length - intactCount} evidence reference(s) missing required fields`,
            severity: 'medium',
          });
        }
      } else {
        checks.push({
          check: 'EVIDENCE_PRESENT',
          result: 'WARN',
          message: `Product contains no evidence references`,
          severity: 'low',
        });
      }
    }

    return checks;
  }

  validateConfidencePreservation(product) {
    const checks = [];
    const findingsModule = product.modules?.findings;

    if (findingsModule && findingsModule.content) {
      const findings = findingsModule.content;

      if (Array.isArray(findings)) {
        const confidenceValues = {
          confirmed: 1,
          likely: 1,
          possible: 1,
          unlikely: 1,
          unsubstantiated: 1,
        };

        const validFindings = findings.filter(f => f.confidence && confidenceValues[f.confidence]);

        if (validFindings.length === findings.length) {
          checks.push({
            check: 'CONFIDENCE_PRESERVED',
            result: 'PASS',
            message: `All findings have valid confidence levels`,
            severity: 'info',
          });
        } else {
          checks.push({
            check: 'CONFIDENCE_PRESERVED',
            result: 'WARN',
            validCount: validFindings.length,
            totalCount: findings.length,
            message: `${findings.length - validFindings.length} finding(s) have invalid confidence levels`,
            severity: 'medium',
          });
        }
      }
    }

    return checks;
  }

  validateClassification(product, productDef) {
    const checks = [];

    if (!product.classification) {
      checks.push({
        check: 'CLASSIFICATION_ASSIGNED',
        result: 'FAIL',
        message: `Product has no classification assigned`,
        severity: 'high',
      });
    } else {
      const validClassifications = ['TLP:WHITE', 'TLP:GREEN', 'TLP:AMBER', 'TLP:RED', 'INTERNAL'];

      if (validClassifications.includes(product.classification)) {
        checks.push({
          check: 'CLASSIFICATION_VALID',
          result: 'PASS',
          classification: product.classification,
          message: `Product classification is valid`,
          severity: 'info',
        });

        // Check classification matches product requirements
        if (productDef.classification) {
          const classificationHierarchy = {
            'TLP:WHITE': 0,
            'TLP:GREEN': 1,
            'TLP:AMBER': 2,
            'TLP:RED': 3,
            'INTERNAL': 4,
          };

          const productLevel = classificationHierarchy[productDef.classification] || -1;
          const assignedLevel = classificationHierarchy[product.classification] || -1;

          if (assignedLevel >= productLevel) {
            checks.push({
              check: 'CLASSIFICATION_MEETS_REQUIREMENT',
              result: 'PASS',
              message: `Product classification meets or exceeds requirement`,
              severity: 'info',
            });
          } else {
            checks.push({
              check: 'CLASSIFICATION_MEETS_REQUIREMENT',
              result: 'WARN',
              required: productDef.classification,
              assigned: product.classification,
              message: `Product classification lower than recommended`,
              severity: 'medium',
            });
          }
        }
      } else {
        checks.push({
          check: 'CLASSIFICATION_VALID',
          result: 'FAIL',
          classification: product.classification,
          message: `Unknown classification: ${product.classification}`,
          severity: 'high',
        });
      }
    }

    return checks;
  }

  validatePolicyCompliance(product, productDef) {
    const checks = [];

    // Validate review level requirements
    if (productDef.reviewLevel) {
      checks.push({
        check: 'REVIEW_LEVEL_REQUIRED',
        required: productDef.reviewLevel,
        currentStatus: product.status,
        message: `Requires ${productDef.reviewLevel} before publication`,
        severity: 'high',
      });
    }

    // Validate required approvals
    if (productDef.reviewLevel === 'EXECUTIVE_APPROVAL' && (!product.approvals || product.approvals.length === 0)) {
      checks.push({
        check: 'EXECUTIVE_APPROVAL_REQUIRED',
        result: 'FAIL',
        message: `Executive approval required but not obtained`,
        severity: 'high',
      });
    } else if (productDef.reviewLevel === 'MANAGER_APPROVAL' && (!product.approvals || product.approvals.length === 0)) {
      checks.push({
        check: 'MANAGER_APPROVAL_REQUIRED',
        result: 'FAIL',
        message: `Manager approval required but not obtained`,
        severity: 'high',
      });
    }

    // Validate delivery channels
    if (productDef.deliveryChannels) {
      checks.push({
        check: 'DELIVERY_CHANNELS_AVAILABLE',
        channels: productDef.deliveryChannels,
        message: `Product supports delivery via: ${productDef.deliveryChannels.join(', ')}`,
        severity: 'info',
      });
    }

    // Validate export formats
    if (productDef.exportFormats) {
      checks.push({
        check: 'EXPORT_FORMATS_AVAILABLE',
        formats: productDef.exportFormats,
        message: `Product supports export as: ${productDef.exportFormats.join(', ')}`,
        severity: 'info',
      });
    }

    return checks;
  }

  async recordValidation(productId, validations, status) {
    const validationRecord = {
      id: require('crypto').randomBytes(8).toString('hex'),
      productId,
      validations,
      status,
      timestamp: new Date().toISOString(),
    };

    const key = `validation:${productId}`;
    const validationData = {
      ...validationRecord,
      validations: JSON.stringify(validations),
    };

    await this.redis.hset(key, Object.entries(validationData).flat());
    await this.redis.zadd(`validations:all`, Date.now(), productId);

    return validationRecord;
  }

  async getValidationHistory(productId, limit = 10) {
    const key = `validation:${productId}`;
    const data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return null;
    }

    const validation = {};
    for (let i = 0; i < data.length; i += 2) {
      if (data[i] === 'validations') {
        try {
          validation[data[i]] = JSON.parse(data[i + 1]);
        } catch (e) {
          validation[data[i]] = data[i + 1];
        }
      } else {
        validation[data[i]] = data[i + 1];
      }
    }

    return validation;
  }

  isValidationPassed(validations) {
    const allValidations = [
      ...validations.mandatory,
      ...validations.evidence,
      ...validations.confidence,
      ...validations.classification,
      ...validations.policy,
      ...validations.approvals,
    ];

    const criticalFailures = allValidations.filter(v => v.severity === 'critical' && v.result === 'FAIL');
    const highFailures = allValidations.filter(v => v.severity === 'high' && v.result === 'FAIL');

    return criticalFailures.length === 0 && highFailures.length === 0;
  }

  getValidationSummary(validations) {
    const allValidations = [
      ...validations.mandatory,
      ...validations.evidence,
      ...validations.confidence,
      ...validations.classification,
      ...validations.policy,
      ...validations.approvals,
    ];

    const passed = allValidations.filter(v => v.result === 'PASS').length;
    const failed = allValidations.filter(v => v.result === 'FAIL').length;
    const warned = allValidations.filter(v => v.result === 'WARN').length;

    return {
      total: allValidations.length,
      passed,
      failed,
      warned,
      passRate: passed / (allValidations.length || 1),
      isValid: this.isValidationPassed(validations),
    };
  }
}

module.exports = { ProductValidationEngine };
