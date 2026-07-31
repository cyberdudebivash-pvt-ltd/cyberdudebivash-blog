'use strict';

class CertificationMetricsTracker {
  constructor() {
    this.metrics = new Map();
    this.aggregates = {
      productCount: 0,
      goldCount: 0,
      silverCount: 0,
      bronzeCount: 0,
      failedCount: 0,
      averageScore: 0,
      categoryAverages: {},
      latestCertifications: [],
      regressions: [],
      improvements: [],
      trendAnalysis: {},
    };
  }

  recordCertification(certification) {
    const productId = certification.productId;

    if (!this.metrics.has(productId)) {
      this.metrics.set(productId, []);
    }

    const productMetrics = this.metrics.get(productId);
    productMetrics.push({
      timestamp: certification.timestamp,
      score: certification.overallScore,
      status: certification.certificationStatus,
      categories: certification.categories,
      passedCategories: certification.passedCategories,
      failedCategories: certification.failedCategories,
    });

    this.updateAggregates();
    this.detectRegressions(productId);
  }

  updateAggregates() {
    let totalScore = 0;
    let productCount = 0;
    const categoryTotals = {};
    const categoryCounts = {};

    // Reset counts
    this.aggregates.goldCount = 0;
    this.aggregates.silverCount = 0;
    this.aggregates.bronzeCount = 0;
    this.aggregates.failedCount = 0;
    this.aggregates.latestCertifications = [];

    for (const [productId, metrics] of this.metrics) {
      if (metrics.length === 0) continue;

      const latest = metrics[metrics.length - 1];
      productCount++;
      totalScore += latest.score;

      // Count by status
      switch (latest.status) {
        case 'GOLD':
          this.aggregates.goldCount++;
          break;
        case 'SILVER':
          this.aggregates.silverCount++;
          break;
        case 'BRONZE':
          this.aggregates.bronzeCount++;
          break;
        default:
          this.aggregates.failedCount++;
      }

      // Track latest certifications
      this.aggregates.latestCertifications.push({
        productId,
        score: latest.score,
        status: latest.status,
        timestamp: latest.timestamp,
        passedCategories: latest.passedCategories,
      });

      // Aggregate category scores
      for (const [categoryName, categoryData] of Object.entries(latest.categories)) {
        if (!categoryTotals[categoryName]) {
          categoryTotals[categoryName] = 0;
          categoryCounts[categoryName] = 0;
        }
        categoryTotals[categoryName] += categoryData.score;
        categoryCounts[categoryName]++;
      }
    }

    this.aggregates.productCount = productCount;
    this.aggregates.averageScore = productCount > 0 ? Math.round(totalScore / productCount) : 0;

    // Calculate category averages
    this.aggregates.categoryAverages = {};
    for (const [categoryName, total] of Object.entries(categoryTotals)) {
      this.aggregates.categoryAverages[categoryName] = Math.round(total / categoryCounts[categoryName]);
    }

    // Keep latest 10 certifications
    this.aggregates.latestCertifications = this.aggregates.latestCertifications
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 10);

    this.calculateTrendAnalysis();
  }

  detectRegressions(productId) {
    const metrics = this.metrics.get(productId);
    if (metrics.length < 2) return;

    const current = metrics[metrics.length - 1];
    const previous = metrics[metrics.length - 2];

    if (current.score < previous.score) {
      const regression = {
        productId,
        timestamp: current.timestamp,
        previousScore: previous.score,
        currentScore: current.score,
        scoreDifference: current.score - previous.score,
        previousStatus: previous.status,
        currentStatus: current.status,
        affectedCategories: this.getAffectedCategories(current.categories, previous.categories),
      };

      this.aggregates.regressions.push(regression);

      // Keep latest 20 regressions
      this.aggregates.regressions = this.aggregates.regressions.slice(-20);
    } else if (current.score > previous.score) {
      const improvement = {
        productId,
        timestamp: current.timestamp,
        previousScore: previous.score,
        currentScore: current.score,
        scoreImprovement: current.score - previous.score,
        previousStatus: previous.status,
        currentStatus: current.status,
        improvedCategories: this.getImprovedCategories(current.categories, previous.categories),
      };

      this.aggregates.improvements.push(improvement);

      // Keep latest 20 improvements
      this.aggregates.improvements = this.aggregates.improvements.slice(-20);
    }
  }

  getAffectedCategories(current, previous) {
    const affected = [];
    for (const [categoryName, currentCat] of Object.entries(current)) {
      const prevCat = previous[categoryName];
      if (prevCat && currentCat.score < prevCat.score) {
        affected.push({
          category: categoryName,
          previousScore: prevCat.score,
          currentScore: currentCat.score,
          decline: prevCat.score - currentCat.score,
        });
      }
    }
    return affected;
  }

  getImprovedCategories(current, previous) {
    const improved = [];
    for (const [categoryName, currentCat] of Object.entries(current)) {
      const prevCat = previous[categoryName];
      if (prevCat && currentCat.score > prevCat.score) {
        improved.push({
          category: categoryName,
          previousScore: prevCat.score,
          currentScore: currentCat.score,
          improvement: currentCat.score - prevCat.score,
        });
      }
    }
    return improved;
  }

  calculateTrendAnalysis() {
    const trends = {
      scoreDirection: 'stable',
      averageScoreTrend: [],
      goldCertificationTrend: [],
      categoriesAboveTarget: {},
      categoriesBelowTarget: {},
      improvementPriorities: [],
    };

    // Analyze score direction
    if (this.aggregates.latestCertifications.length >= 2) {
      const recent = this.aggregates.latestCertifications.slice(0, 2);
      const latest = recent[0].score;
      const previous = recent[1].score;

      if (latest > previous) {
        trends.scoreDirection = 'improving';
      } else if (latest < previous) {
        trends.scoreDirection = 'declining';
      } else {
        trends.scoreDirection = 'stable';
      }
    }

    // Identify categories above/below target
    const targets = {
      executiveIntelligence: 95,
      technicalIntelligence: 95,
      analyticalTradecraft: 95,
      campaignIntelligence: 95,
      intelligenceCorrelation: 95,
      originalAnalyticalValue: 95,
      detectionEngineering: 98,
      multiAudienceDecisionSupport: 98,
      editorialExcellence: 98,
      commercialProductExcellence: 98,
    };

    for (const [categoryName, average] of Object.entries(this.aggregates.categoryAverages)) {
      const target = targets[categoryName] || 95;
      if (average >= target) {
        trends.categoriesAboveTarget[categoryName] = average;
      } else {
        trends.categoriesBelowTarget[categoryName] = {
          average,
          target,
          gap: target - average,
        };
      }
    }

    // Generate improvement priorities (categories with largest gaps)
    trends.improvementPriorities = Object.entries(trends.categoriesBelowTarget)
      .map(([categoryName, data]) => ({
        category: categoryName,
        gap: data.gap,
        priority: data.gap > 15 ? 'High' : 'Medium',
      }))
      .sort((a, b) => b.gap - a.gap)
      .slice(0, 5);

    this.aggregates.trendAnalysis = trends;
  }

  getProductMetrics(productId) {
    return this.metrics.get(productId) || [];
  }

  getAggregateMetrics() {
    return this.aggregates;
  }

  getPublishingGateStatus() {
    const status = {
      overallHealthy: false,
      goldAndSilverPercentage: 0,
      averageScore: this.aggregates.averageScore,
      certificationDistribution: {
        gold: this.aggregates.goldCount,
        silver: this.aggregates.silverCount,
        bronze: this.aggregates.bronzeCount,
        failed: this.aggregates.failedCount,
      },
      recommendedAction: '',
    };

    const totalProducts = this.aggregates.goldCount + this.aggregates.silverCount +
                         this.aggregates.bronzeCount + this.aggregates.failedCount;

    if (totalProducts > 0) {
      const goldAndSilver = this.aggregates.goldCount + this.aggregates.silverCount;
      status.goldAndSilverPercentage = Math.round((goldAndSilver / totalProducts) * 100);
    }

    status.overallHealthy = status.goldAndSilverPercentage >= 80 && this.aggregates.averageScore >= 90;

    if (status.overallHealthy) {
      status.recommendedAction = 'Proceed with publication pipeline at normal capacity';
    } else if (status.goldAndSilverPercentage >= 60) {
      status.recommendedAction = 'Implement enhanced review for non-certified products before publication';
    } else {
      status.recommendedAction = 'Pause publication and conduct quality improvement initiative';
    }

    return status;
  }

  getRegressionReport() {
    return {
      totalRegressions: this.aggregates.regressions.length,
      recentRegressions: this.aggregates.regressions.slice(-5),
      affectedProducts: this.getAffectedProductsFromRegressions(),
      averageRegressionSeverity: this.calculateAverageRegressionSeverity(),
      recommendations: this.generateRegressionRecommendations(),
    };
  }

  getAffectedProductsFromRegressions() {
    const products = new Set();
    for (const regression of this.aggregates.regressions) {
      products.add(regression.productId);
    }
    return Array.from(products);
  }

  calculateAverageRegressionSeverity() {
    if (this.aggregates.regressions.length === 0) return 0;

    const totalSeverity = this.aggregates.regressions.reduce((sum, r) => sum + Math.abs(r.scoreDifference), 0);
    return Math.round(totalSeverity / this.aggregates.regressions.length);
  }

  generateRegressionRecommendations() {
    const recommendations = [];

    if (this.aggregates.regressions.length > 5) {
      recommendations.push({
        priority: 'High',
        recommendation: 'Quality regressions detected in multiple products. Implement focused review process.',
      });
    }

    if (this.calculateAverageRegressionSeverity() > 10) {
      recommendations.push({
        priority: 'High',
        recommendation: 'Significant quality drops detected. Investigate root causes in production process.',
      });
    }

    const trends = this.aggregates.trendAnalysis;
    if (trends.scoreDirection === 'declining') {
      recommendations.push({
        priority: 'Medium',
        recommendation: 'Overall product quality trending downward. Schedule quality improvement review.',
      });
    }

    return recommendations;
  }

  getImprovementReport() {
    return {
      totalImprovements: this.aggregates.improvements.length,
      recentImprovements: this.aggregates.improvements.slice(-5),
      bestPerformingProducts: this.getBestPerformingProducts(),
      categoryImprovements: this.getCategoryImprovements(),
    };
  }

  getBestPerformingProducts() {
    return this.aggregates.latestCertifications
      .filter(c => c.status === 'GOLD')
      .slice(0, 5);
  }

  getCategoryImprovements() {
    return Object.entries(this.aggregates.categoryAverages)
      .map(([categoryName, score]) => ({
        category: categoryName,
        averageScore: score,
        status: score >= 95 ? 'On Target' : 'Below Target',
      }))
      .sort((a, b) => b.averageScore - a.averageScore);
  }

  generateExecutiveSummary() {
    const metrics = this.getAggregateMetrics();
    const gateStatus = this.getPublishingGateStatus();
    const trends = metrics.trendAnalysis;

    return {
      timestamp: new Date().toISOString(),
      productsCertified: metrics.productCount,
      averageScore: metrics.averageScore,
      certificationStatus: {
        gold: metrics.goldCount,
        silver: metrics.silverCount,
        bronze: metrics.bronzeCount,
        failed: metrics.failedCount,
      },
      overallHealth: gateStatus.overallHealthy ? 'Healthy' : 'Needs Attention',
      scoreDirection: trends.scoreDirection,
      topPerformingCategories: Object.entries(metrics.categoryAverages)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([name, score]) => ({ category: name, score })),
      improvementPriorities: trends.improvementPriorities,
      publishingGateStatus: gateStatus.recommendedAction,
    };
  }
}

module.exports = { CertificationMetricsTracker };
