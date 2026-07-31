'use strict';

class EditorialMetricsEngine {
  constructor() {
    this.metrics = new Map();
    this.publishingEvents = [];
    this.qualityMetrics = [];
  }

  recordPublishingEvent(reportId, productType, publishedAt, actor) {
    const event = {
      id: `pub_event_${reportId}_${Date.now()}`,
      reportId,
      productType,
      publishedAt,
      publishedBy: actor,
      recordedAt: new Date().toISOString(),
    };

    this.publishingEvents.push(event);
    return event;
  }

  calculateTurnaroundTime(reportId, createdAt, publishedAt) {
    const created = new Date(createdAt);
    const published = new Date(publishedAt);
    const turnaroundMs = published - created;
    const turnaroundHours = turnaroundMs / (1000 * 60 * 60);
    const turnaroundDays = turnaroundMs / (1000 * 60 * 60 * 24);

    return {
      reportId,
      createdAt,
      publishedAt,
      turnaroundMs,
      turnaroundHours: parseFloat(turnaroundHours.toFixed(1)),
      turnaroundDays: parseFloat(turnaroundDays.toFixed(1)),
      businessDays: this.calculateBusinessDays(created, published),
    };
  }

  calculateBusinessDays(start, end) {
    let count = 0;
    const current = new Date(start);

    while (current <= end) {
      const day = current.getDay();
      if (day !== 0 && day !== 6) {
        count++;
      }
      current.setDate(current.getDate() + 1);
    }

    return count;
  }

  recordQualityMetric(reportId, qualityScore, factors) {
    const metric = {
      id: `quality_${reportId}_${Date.now()}`,
      reportId,
      qualityScore,
      factors: {
        completeness: factors.completeness || 0,
        accuracy: factors.accuracy || 0,
        clarity: factors.clarity || 0,
        relevance: factors.relevance || 0,
        timeliness: factors.timeliness || 0,
      },
      recordedAt: new Date().toISOString(),
    };

    this.qualityMetrics.push(metric);
    return metric;
  }

  calculateThroughput(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);

    const eventsInPeriod = this.publishingEvents.filter(e => {
      const eDate = new Date(e.publishedAt);
      return eDate >= start && eDate <= end;
    });

    const days = (end - start) / (1000 * 60 * 60 * 24);
    const weeks = days / 7;
    const months = days / 30;

    const byType = {};
    eventsInPeriod.forEach(e => {
      byType[e.productType] = (byType[e.productType] || 0) + 1;
    });

    return {
      period: { start: startDate, end: endDate },
      totalPublished: eventsInPeriod.length,
      byProductType: byType,
      perDay: parseFloat((eventsInPeriod.length / days).toFixed(2)),
      perWeek: parseFloat((eventsInPeriod.length / weeks).toFixed(2)),
      perMonth: parseFloat((eventsInPeriod.length / months).toFixed(2)),
    };
  }

  calculateFreshness(lastPublishedDate) {
    const published = new Date(lastPublishedDate);
    const now = new Date();
    const ageMs = now - published;
    const ageHours = ageMs / (1000 * 60 * 60);
    const ageDays = ageMs / (1000 * 60 * 60 * 24);

    let freshnessScore = 100;
    if (ageDays > 30) freshnessScore = 50;
    if (ageDays > 90) freshnessScore = 25;
    if (ageDays > 180) freshnessScore = 10;

    return {
      lastPublishedAt: lastPublishedDate,
      ageHours: parseFloat(ageHours.toFixed(1)),
      ageDays: parseFloat(ageDays.toFixed(1)),
      freshnessScore,
      freshness: freshnessScore >= 75 ? 'fresh' : freshnessScore >= 50 ? 'aging' : freshnessScore >= 25 ? 'stale' : 'very_stale',
    };
  }

  getPublicationMetrics(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);

    const events = this.publishingEvents.filter(e => {
      const eDate = new Date(e.publishedAt);
      return eDate >= start && eDate <= end;
    });

    const byType = {};
    const byPublisher = {};
    const timeline = {};

    events.forEach(e => {
      byType[e.productType] = (byType[e.productType] || 0) + 1;
      byPublisher[e.publishedBy] = (byPublisher[e.publishedBy] || 0) + 1;

      const date = e.publishedAt.split('T')[0];
      timeline[date] = (timeline[date] || 0) + 1;
    });

    return {
      period: { start: startDate, end: endDate },
      totalPublications: events.length,
      byProductType: byType,
      byPublisher,
      timeline,
    };
  }

  getQualityTrends(startDate, endDate, groupBy = 'day') {
    const start = new Date(startDate);
    const end = new Date(endDate);

    const metricsInPeriod = this.qualityMetrics.filter(m => {
      const mDate = new Date(m.recordedAt);
      return mDate >= start && mDate <= end;
    });

    const grouped = {};

    metricsInPeriod.forEach(m => {
      let key;
      const date = m.recordedAt.split('T')[0];

      if (groupBy === 'day') key = date;
      else if (groupBy === 'week') {
        const d = new Date(m.recordedAt);
        const weekStart = new Date(d.setDate(d.getDate() - d.getDay()));
        key = weekStart.toISOString().split('T')[0];
      } else if (groupBy === 'month') {
        key = m.recordedAt.substring(0, 7);
      }

      if (!grouped[key]) {
        grouped[key] = [];
      }
      grouped[key].push(m.qualityScore);
    });

    const trends = {};
    Object.entries(grouped).forEach(([key, scores]) => {
      trends[key] = {
        count: scores.length,
        average: parseFloat((scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(2)),
        min: Math.min(...scores),
        max: Math.max(...scores),
      };
    });

    return {
      period: { start: startDate, end: endDate },
      groupBy,
      trends,
    };
  }

  getAverageQuality(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);

    const metricsInPeriod = this.qualityMetrics.filter(m => {
      const mDate = new Date(m.recordedAt);
      return mDate >= start && mDate <= end;
    });

    if (metricsInPeriod.length === 0) {
      return {
        period: { start: startDate, end: endDate },
        sampleSize: 0,
        averageScore: 0,
        factorAverages: {},
      };
    }

    const scores = metricsInPeriod.map(m => m.qualityScore);
    const factorAverages = {
      completeness: 0,
      accuracy: 0,
      clarity: 0,
      relevance: 0,
      timeliness: 0,
    };

    metricsInPeriod.forEach(m => {
      Object.keys(factorAverages).forEach(factor => {
        factorAverages[factor] += m.factors[factor] || 0;
      });
    });

    Object.keys(factorAverages).forEach(factor => {
      factorAverages[factor] = parseFloat((factorAverages[factor] / metricsInPeriod.length).toFixed(2));
    });

    return {
      period: { start: startDate, end: endDate },
      sampleSize: metricsInPeriod.length,
      averageScore: parseFloat((scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(2)),
      minScore: Math.min(...scores),
      maxScore: Math.max(...scores),
      factorAverages,
    };
  }

  getAnalystProductivity(analyst, startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);

    const events = this.publishingEvents.filter(e => {
      const eDate = new Date(e.publishedAt);
      return e.publishedBy === analyst && eDate >= start && eDate <= end;
    });

    const qualityMetrics = this.qualityMetrics.filter(m => {
      const mDate = new Date(m.recordedAt);
      return mDate >= start && mDate <= end;
    });

    const analysts = {};
    events.forEach(e => {
      if (!analysts[e.publishedBy]) {
        analysts[e.publishedBy] = [];
      }
      analysts[e.publishedBy].push(e.reportId);
    });

    const relevantQualities = qualityMetrics.filter(m => events.some(e => e.reportId === m.reportId));

    return {
      analyst,
      period: { start: startDate, end: endDate },
      publicationsCount: events.length,
      uniqueReports: new Set(events.map(e => e.reportId)).size,
      byProductType: events.reduce((acc, e) => {
        acc[e.productType] = (acc[e.productType] || 0) + 1;
        return acc;
      }, {}),
      averageQuality: relevantQualities.length > 0
        ? parseFloat((relevantQualities.reduce((sum, m) => sum + m.qualityScore, 0) / relevantQualities.length).toFixed(2))
        : 0,
    };
  }

  getEditorialMetricsReport(startDate, endDate) {
    const throughput = this.calculateThroughput(startDate, endDate);
    const qualityAverage = this.getAverageQuality(startDate, endDate);
    const publications = this.getPublicationMetrics(startDate, endDate);

    return {
      period: { start: startDate, end: endDate },
      generatedAt: new Date().toISOString(),
      throughput: {
        totalPublished: throughput.totalPublished,
        perDay: throughput.perDay,
        perWeek: throughput.perWeek,
        perMonth: throughput.perMonth,
        byProductType: throughput.byProductType,
      },
      quality: {
        averageScore: qualityAverage.averageScore,
        sampleSize: qualityAverage.sampleSize,
        factorAverages: qualityAverage.factorAverages,
      },
      distribution: {
        byProductType: publications.byProductType,
        byPublisher: publications.byPublisher,
      },
      insights: this.generateMetricsInsights(throughput, qualityAverage),
    };
  }

  generateMetricsInsights(throughput, quality) {
    const insights = [];

    if (throughput.totalPublished === 0) {
      insights.push('No publications in this period');
    } else {
      insights.push(`Published ${throughput.totalPublished} items (${throughput.perWeek.toFixed(1)} per week)`);
    }

    if (quality.sampleSize === 0) {
      insights.push('No quality metrics recorded');
    } else if (quality.averageScore >= 85) {
      insights.push(`High quality content (${quality.averageScore}/100)`);
    } else if (quality.averageScore >= 70) {
      insights.push(`Acceptable quality (${quality.averageScore}/100)`);
    } else {
      insights.push(`Quality concerns detected (${quality.averageScore}/100)`);
    }

    return insights;
  }

  validateMetricsIntegrity() {
    const integrity = {
      publishingEventsCount: this.publishingEvents.length,
      qualityMetricsCount: this.qualityMetrics.length,
      allEventsHaveTimestamp: this.publishingEvents.every(e => e.recordedAt),
      allQualityMetricsValid: this.qualityMetrics.every(m => m.qualityScore >= 0 && m.qualityScore <= 100),
      noFutureEvents: this.publishingEvents.every(e => new Date(e.publishedAt) <= new Date()),
    };

    return {
      ...integrity,
      status: Object.values(integrity).every(v => v === true || typeof v === 'number') ? 'valid' : 'invalid',
    };
  }
}

module.exports = { EditorialMetricsEngine };
