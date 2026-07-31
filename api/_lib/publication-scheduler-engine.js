'use strict';

class PublicationSchedulerEngine {
  constructor() {
    this.publications = new Map();
    this.schedules = new Map();
    this.publicationTypes = {
      IMMEDIATE: 'immediate',
      SCHEDULED: 'scheduled',
      EMBARGOED: 'embargoed',
      REGIONAL: 'regional',
      CUSTOMER_SPECIFIC: 'customer_specific',
    };
  }

  schedulePublication(reportId, config) {
    const schedule = {
      id: `pub_${reportId}`,
      reportId,
      type: config.type || this.publicationTypes.SCHEDULED,
      publishAt: config.publishAt || new Date().toISOString(),
      metadata: {
        title: config.title,
        classification: config.classification || 'TLP:AMBER',
        audience: config.audience || 'general',
      },
      distribution: {
        channels: config.channels || ['blog', 'api'],
        regions: config.regions || ['global'],
        customerSegments: config.customerSegments || [],
      },
      embargo: config.embargo || null,
      regionalReleases: config.regionalReleases || [],
      customerReleases: config.customerReleases || [],
      status: 'scheduled',
      createdAt: new Date().toISOString(),
      publishedAt: null,
    };

    this.schedules.set(schedule.id, schedule);
    return schedule;
  }

  scheduleImmediatePublication(reportId, config) {
    const schedule = this.schedulePublication(reportId, {
      ...config,
      type: this.publicationTypes.IMMEDIATE,
      publishAt: new Date().toISOString(),
    });

    return {
      schedule,
      action: 'Immediate publication queued',
      timestamp: new Date().toISOString(),
    };
  }

  scheduleEmbargoedPublication(reportId, config) {
    if (!config.embargoUntil) {
      throw new Error('embargoUntil date required for embargoed publication');
    }

    const schedule = this.schedulePublication(reportId, {
      ...config,
      type: this.publicationTypes.EMBARGOED,
      embargo: {
        start: new Date().toISOString(),
        until: config.embargoUntil,
        reason: config.embargoReason || 'Vendor coordination',
      },
      publishAt: config.embargoUntil,
    });

    return schedule;
  }

  scheduleRegionalRelease(reportId, config) {
    const releases = config.regions.map(region => ({
      region,
      publishAt: config.regionalSchedule[region] || config.publishAt,
      language: config.languages?.[region] || 'en',
      localizationStatus: 'pending',
    }));

    const schedule = this.schedulePublication(reportId, {
      ...config,
      type: this.publicationTypes.REGIONAL,
      regionalReleases: releases,
    });

    return schedule;
  }

  scheduleCustomerSpecificRelease(reportId, config) {
    const customerReleases = config.customerList.map(customer => ({
      customerId: customer.id,
      customerName: customer.name,
      publishAt: config.customerSchedule[customer.id] || config.publishAt,
      accessToken: this.generateAccessToken(),
      expiresAt: config.accessDuration ? new Date(Date.now() + config.accessDuration).toISOString() : null,
    }));

    const schedule = this.schedulePublication(reportId, {
      ...config,
      type: this.publicationTypes.CUSTOMER_SPECIFIC,
      customerReleases,
    });

    return schedule;
  }

  getScheduledPublications(filters = {}) {
    let publications = Array.from(this.schedules.values());

    if (filters.status) {
      publications = publications.filter(p => p.status === filters.status);
    }

    if (filters.type) {
      publications = publications.filter(p => p.type === filters.type);
    }

    if (filters.sinceDate) {
      const since = new Date(filters.sinceDate);
      publications = publications.filter(p => new Date(p.publishAt) >= since);
    }

    const upcoming = publications.filter(p => new Date(p.publishAt) > new Date());
    const readyToPublish = upcoming.filter(p => new Date(p.publishAt) <= new Date(Date.now() + 60000));

    return {
      total: publications.length,
      upcoming: upcoming.length,
      readyToPublish: readyToPublish.map(p => ({
        reportId: p.reportId,
        title: p.metadata.title,
        publishAt: p.publishAt,
        type: p.type,
      })),
      all: publications.map(p => ({
        reportId: p.reportId,
        title: p.metadata.title,
        publishAt: p.publishAt,
        type: p.type,
        status: p.status,
      })),
    };
  }

  publishReport(scheduleId) {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) throw new Error(`Schedule not found: ${scheduleId}`);

    if (schedule.status === 'published') {
      throw new Error(`Report already published: ${scheduleId}`);
    }

    const now = new Date();
    if (schedule.embargo && new Date(schedule.embargo.until) > now) {
      throw new Error(`Embargo in effect until ${schedule.embargo.until}`);
    }

    schedule.status = 'published';
    schedule.publishedAt = new Date().toISOString();

    const publishResult = {
      scheduleId,
      reportId: schedule.reportId,
      publishedAt: schedule.publishedAt,
      distribution: this.distributePublication(schedule),
    };

    return publishResult;
  }

  distributePublication(schedule) {
    const distribution = {
      channels: schedule.distribution.channels.map(channel => ({
        channel,
        distributedAt: new Date().toISOString(),
        status: 'success',
      })),
      regions: [],
      customers: [],
    };

    if (schedule.type === this.publicationTypes.REGIONAL) {
      distribution.regions = schedule.regionalReleases.map(release => ({
        region: release.region,
        distributedAt: release.publishAt,
        language: release.language,
        status: 'scheduled',
      }));
    }

    if (schedule.type === this.publicationTypes.CUSTOMER_SPECIFIC) {
      distribution.customers = schedule.customerReleases.map(release => ({
        customerId: release.customerId,
        distributedAt: release.publishAt,
        accessToken: release.accessToken,
        expiresAt: release.expiresAt,
        status: 'scheduled',
      }));
    }

    return distribution;
  }

  generateAccessToken() {
    return `token_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  updatePublicationSchedule(scheduleId, updates) {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) throw new Error(`Schedule not found: ${scheduleId}`);

    if (schedule.status === 'published') {
      throw new Error(`Cannot modify published schedule: ${scheduleId}`);
    }

    Object.assign(schedule, updates);
    return schedule;
  }

  withdrawPublication(scheduleId, reason) {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) throw new Error(`Schedule not found: ${scheduleId}`);

    const withdrawal = {
      scheduleId,
      reportId: schedule.reportId,
      withdrawnAt: new Date().toISOString(),
      reason,
      previousStatus: schedule.status,
    };

    schedule.status = 'withdrawn';
    schedule.withdrawalReason = reason;
    schedule.withdrawnAt = new Date().toISOString();

    return withdrawal;
  }

  getPublicationMetrics(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);

    const publications = Array.from(this.schedules.values())
      .filter(p => p.publishedAt && new Date(p.publishedAt) >= start && new Date(p.publishedAt) <= end);

    const byType = {};
    const byChannel = {};

    publications.forEach(pub => {
      byType[pub.type] = (byType[pub.type] || 0) + 1;
      pub.distribution.channels.forEach(ch => {
        byChannel[ch.channel] = (byChannel[ch.channel] || 0) + 1;
      });
    });

    return {
      period: { start: startDate, end: endDate },
      totalPublications: publications.length,
      byType,
      byChannel,
      avgPublicationsPerDay: (publications.length / ((end - start) / (1000 * 60 * 60 * 24))).toFixed(1),
    };
  }
}

module.exports = { PublicationSchedulerEngine };
