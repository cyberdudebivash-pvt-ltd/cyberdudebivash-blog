'use strict';

const redis = require('./redis');
const crypto = require('crypto');

class SourceReliabilityEngine {
  constructor(redisClient = redis) {
    this.redis = redisClient;
  }

  async trackSource(sourceName, sourceType, metadata = {}) {
    const key = `source:${sourceName}`;
    const source = {
      id: crypto.randomBytes(8).toString('hex'),
      name: sourceName,
      type: sourceType,
      historicalAccuracy: metadata.historicalAccuracy || 0.5,
      reliabilityScore: metadata.reliabilityScore || 0.5,
      bias: metadata.bias || 'neutral',
      collectionMethod: metadata.collectionMethod || 'unknown',
      verificationHistory: metadata.verificationHistory || [],
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      reportCount: 0,
      confirmationCount: 0,
      rejectionCount: 0,
      accuracyPercentage: 0,
    };

    await this.redis.hset(key, Object.entries(source).flat());
    await this.redis.zadd('sources:all', Date.now(), sourceName);

    return source;
  }

  async updateSourceReliability(sourceName, outcome) {
    const key = `source:${sourceName}`;
    const data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return { success: false, error: `Source not found: ${sourceName}` };
    }

    const source = {};
    for (let i = 0; i < data.length; i += 2) {
      source[data[i]] = data[i + 1];
    }

    source.reportCount = (parseInt(source.reportCount) || 0) + 1;

    if (outcome === 'confirmed') {
      source.confirmationCount = (parseInt(source.confirmationCount) || 0) + 1;
    } else if (outcome === 'rejected') {
      source.rejectionCount = (parseInt(source.rejectionCount) || 0) + 1;
    }

    source.accuracyPercentage = Math.round((source.confirmationCount / source.reportCount) * 100);

    source.reliabilityScore = this.calculateReliabilityScore(
      source.historicalAccuracy,
      source.accuracyPercentage,
      source.confirmationCount,
      source.reportCount
    );

    source.lastSeen = new Date().toISOString();

    await this.redis.hset(key, Object.entries(source).flat());

    return {
      success: true,
      source,
      updated: true,
    };
  }

  async addVerification(sourceName, claimOrIndicator, verificationStatus, verifier = 'system') {
    const key = `source:${sourceName}`;
    const data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return { success: false, error: `Source not found: ${sourceName}` };
    }

    const source = {};
    for (let i = 0; i < data.length; i += 2) {
      source[data[i]] = data[i + 1];
    }

    let verificationHistory = [];
    try {
      verificationHistory = JSON.parse(source.verificationHistory || '[]');
    } catch (e) {
      verificationHistory = [];
    }

    verificationHistory.push({
      id: crypto.randomBytes(8).toString('hex'),
      claim: claimOrIndicator,
      status: verificationStatus,
      verifier,
      verifiedAt: new Date().toISOString(),
    });

    source.verificationHistory = JSON.stringify(verificationHistory.slice(-50));

    await this.redis.hset(key, Object.entries(source).flat());

    return {
      success: true,
      source,
    };
  }

  async getSourceReliability(sourceName) {
    const key = `source:${sourceName}`;
    const data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return null;
    }

    const source = {};
    for (let i = 0; i < data.length; i += 2) {
      source[data[i]] = data[i + 1];
    }

    return source;
  }

  async listSources(limit = 100) {
    const sourceNames = await this.redis.zrevrange('sources:all', 0, limit - 1);
    const sources = [];

    for (const sourceName of sourceNames) {
      const source = await this.getSourceReliability(sourceName);
      if (source) sources.push(source);
    }

    return sources;
  }

  async getSourceContributionToConfidence(sourceName) {
    const source = await this.getSourceReliability(sourceName);
    if (!source) {
      return {
        success: false,
        error: `Source not found: ${sourceName}`,
      };
    }

    const reliabilityScore = parseFloat(source.reliabilityScore) || 0.5;
    const biasAdjustment = this.calculateBiasAdjustment(source.bias);
    const recencyBonus = this.calculateRecencyBonus(source.lastSeen);

    const contributionFactor = (reliabilityScore * 0.6) + (biasAdjustment * 0.2) + (recencyBonus * 0.2);

    return {
      success: true,
      sourceName,
      reliabilityScore: Math.round(reliabilityScore * 100) / 100,
      accuracyPercentage: parseInt(source.accuracyPercentage) || 0,
      biasAdjustment,
      recencyBonus,
      contributionFactor: Math.round(contributionFactor * 100) / 100,
      recommendation: this.getSourceReliabilityRecommendation(contributionFactor),
    };
  }

  calculateReliabilityScore(historicalAccuracy, currentAccuracy, confirmations, total) {
    const weight = Math.min(total / 10, 1.0);
    const historicalWeight = 1 - weight;

    const weighted = (historicalAccuracy * historicalWeight) + ((currentAccuracy / 100) * weight);

    const confirmationBonus = Math.min(confirmations / 20, 0.15);

    return Math.min(weighted + confirmationBonus, 1.0);
  }

  calculateBiasAdjustment(bias) {
    const adjustments = {
      'neutral': 1.0,
      'slight-left': 0.85,
      'slight-right': 0.85,
      'moderate-left': 0.7,
      'moderate-right': 0.7,
      'strong-left': 0.5,
      'strong-right': 0.5,
      'unknown': 0.75,
    };

    return adjustments[bias] || 0.75;
  }

  calculateRecencyBonus(lastSeenDate) {
    const daysSinceLastSeen = (Date.now() - new Date(lastSeenDate).getTime()) / (1000 * 60 * 60 * 24);

    if (daysSinceLastSeen < 7) return 1.0;
    if (daysSinceLastSeen < 30) return 0.9;
    if (daysSinceLastSeen < 90) return 0.7;
    return 0.5;
  }

  getSourceReliabilityRecommendation(factor) {
    if (factor >= 0.85) return 'High confidence in source reliability';
    if (factor >= 0.65) return 'Moderate confidence in source reliability';
    if (factor >= 0.45) return 'Low confidence in source reliability. Consider corroboration.';
    return 'Very low confidence in source. Require independent verification.';
  }

  async evaluateEvidenceQuality(evidence, sourceName) {
    const source = await this.getSourceReliability(sourceName);
    if (!source) {
      return {
        success: false,
        error: `Source not found: ${sourceName}`,
      };
    }

    const sourceReliability = parseFloat(source.reliabilityScore) || 0.5;

    const evidenceStrengthScores = {
      strong: 1.0,
      moderate: 0.6,
      weak: 0.3,
    };

    const evidenceReliabilityScores = {
      high: 1.0,
      medium: 0.6,
      low: 0.3,
    };

    const strengthScore = evidenceStrengthScores[evidence.strength] || 0.5;
    const reliabilityScore = evidenceReliabilityScores[evidence.reliability] || 0.5;

    const adjustedQualityScore = (strengthScore * 0.4 + reliabilityScore * 0.4 + sourceReliability * 0.2);

    return {
      success: true,
      evidence,
      sourceName,
      sourceReliability: Math.round(sourceReliability * 100) / 100,
      unadjustedQuality: Math.round((strengthScore * 0.4 + reliabilityScore * 0.4) * 100) / 100,
      adjustedQualityScore: Math.round(adjustedQualityScore * 100) / 100,
      recommendation: this.getEvidenceQualityRecommendation(adjustedQualityScore),
    };
  }

  getEvidenceQualityRecommendation(score) {
    if (score >= 0.8) return 'High-quality evidence. Suitable for confident findings.';
    if (score >= 0.6) return 'Moderate-quality evidence. Suitable with corroboration.';
    if (score >= 0.4) return 'Low-quality evidence. Requires significant corroboration.';
    return 'Very low-quality evidence. Avoid relying solely on this source.';
  }
}

module.exports = { SourceReliabilityEngine };
