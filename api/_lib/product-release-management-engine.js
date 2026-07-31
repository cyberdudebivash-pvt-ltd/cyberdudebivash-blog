'use strict';

class ProductReleaseManagementEngine {
  constructor() {
    this.releases = new Map();
    this.versions = new Map();
    this.changeHistory = new Map();
  }

  createProductVersion(reportId, versionNumber, productType, changes, actor) {
    const versionId = `v${versionNumber}_${reportId}`;

    const version = {
      id: versionId,
      reportId,
      versionNumber,
      productType,
      createdAt: new Date().toISOString(),
      createdBy: actor,
      changes: changes || [],
      status: 'draft',
      releaseDate: null,
      releasedBy: null,
      releaseNotes: '',
      compatibility: {
        breakingChanges: [],
        deprecations: [],
        newFeatures: [],
      },
    };

    this.versions.set(versionId, version);
    this.recordChange(reportId, 'version_created', version);

    return version;
  }

  recordChange(reportId, changeType, versionData) {
    if (!this.changeHistory.has(reportId)) {
      this.changeHistory.set(reportId, []);
    }

    this.changeHistory.get(reportId).push({
      changeType,
      timestamp: new Date().toISOString(),
      versionId: versionData.id || null,
      versionNumber: versionData.versionNumber || null,
    });
  }

  releaseVersion(versionId, releaseNotes, actor, releaseDate = null) {
    const version = this.versions.get(versionId);
    if (!version) throw new Error(`Version not found: ${versionId}`);

    version.status = 'released';
    version.releasedBy = actor;
    version.releaseDate = releaseDate || new Date().toISOString();
    version.releaseNotes = releaseNotes;

    const release = {
      id: `release_${versionId}_${Date.now()}`,
      versionId,
      reportId: version.reportId,
      versionNumber: version.versionNumber,
      productType: version.productType,
      releaseDate: version.releaseDate,
      releasedBy: actor,
      releaseNotes,
      status: 'published',
      publicAt: new Date().toISOString(),
    };

    this.releases.set(release.id, release);
    this.recordChange(version.reportId, 'version_released', version);

    return release;
  }

  createReleaseNotes(versionId, sections) {
    const version = this.versions.get(versionId);
    if (!version) throw new Error(`Version not found: ${versionId}`);

    const releaseNotes = {
      versionId,
      versionNumber: version.versionNumber,
      generatedAt: new Date().toISOString(),
      sections: {
        summary: sections.summary || '',
        newFeatures: sections.newFeatures || [],
        improvements: sections.improvements || [],
        bugFixes: sections.bugFixes || [],
        breakingChanges: sections.breakingChanges || [],
        deprecations: sections.deprecations || [],
        migratingGuide: sections.migratingGuide || '',
        acknowledgements: sections.acknowledgements || [],
      },
    };

    version.releaseNotes = releaseNotes;
    this.recordChange(version.reportId, 'release_notes_created', version);

    return releaseNotes;
  }

  addCompatibilityInfo(versionId, compatibility) {
    const version = this.versions.get(versionId);
    if (!version) throw new Error(`Version not found: ${versionId}`);

    version.compatibility = {
      breakingChanges: compatibility.breakingChanges || [],
      deprecations: compatibility.deprecations || [],
      newFeatures: compatibility.newFeatures || [],
      backwardCompatible: compatibility.backwardCompatible !== false,
      minimumRequirements: compatibility.minimumRequirements || {},
    };

    this.recordChange(version.reportId, 'compatibility_updated', version);

    return version.compatibility;
  }

  getVersionHistory(reportId) {
    const versions = [];

    this.versions.forEach((version, id) => {
      if (version.reportId === reportId) {
        versions.push({
          versionId: id,
          versionNumber: version.versionNumber,
          status: version.status,
          createdAt: version.createdAt,
          createdBy: version.createdBy,
          releaseDate: version.releaseDate,
          productType: version.productType,
        });
      }
    });

    return {
      reportId,
      versions: versions.sort((a, b) => {
        const aParts = a.versionNumber.split('.').map(Number);
        const bParts = b.versionNumber.split('.').map(Number);
        for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
          if ((aParts[i] || 0) !== (bParts[i] || 0)) {
            return (bParts[i] || 0) - (aParts[i] || 0);
          }
        }
        return 0;
      }),
      totalVersions: versions.length,
      latestVersion: versions[0]?.versionNumber || null,
      latestReleased: versions.find(v => v.status === 'released')?.versionNumber || null,
    };
  }

  getVersionDetails(versionId) {
    const version = this.versions.get(versionId);
    if (!version) throw new Error(`Version not found: ${versionId}`);

    return {
      id: versionId,
      reportId: version.reportId,
      versionNumber: version.versionNumber,
      productType: version.productType,
      status: version.status,
      createdAt: version.createdAt,
      createdBy: version.createdBy,
      releaseDate: version.releaseDate,
      releasedBy: version.releasedBy,
      changes: version.changes,
      releaseNotes: version.releaseNotes,
      compatibility: version.compatibility,
    };
  }

  compareVersions(versionId1, versionId2) {
    const v1 = this.versions.get(versionId1);
    const v2 = this.versions.get(versionId2);

    if (!v1 || !v2) throw new Error('One or both versions not found');

    const comparison = {
      versionId1,
      versionId2,
      versionNumbers: [v1.versionNumber, v2.versionNumber],
      timeline: [
        { versionId: versionId1, createdAt: v1.createdAt, releaseDate: v1.releaseDate },
        { versionId: versionId2, createdAt: v2.createdAt, releaseDate: v2.releaseDate },
      ],
      changesV1: v1.changes,
      changesV2: v2.changes,
      newInV2: v2.changes.filter(c => !v1.changes.some(vc => vc.id === c.id)),
      removedInV2: v1.changes.filter(c => !v2.changes.some(vc => vc.id === c.id)),
      compatibilityV1: v1.compatibility,
      compatibilityV2: v2.compatibility,
    };

    return comparison;
  }

  getReleaseHistory(reportId) {
    const releases = [];

    this.releases.forEach((release, id) => {
      if (release.reportId === reportId) {
        releases.push({
          releaseId: id,
          versionNumber: release.versionNumber,
          productType: release.productType,
          releaseDate: release.releaseDate,
          releasedBy: release.releasedBy,
          status: release.status,
        });
      }
    });

    return {
      reportId,
      releases: releases.sort((a, b) => new Date(b.releaseDate) - new Date(a.releaseDate)),
      totalReleases: releases.length,
      lastReleased: releases[0]?.releaseDate || null,
    };
  }

  getChangeLog(reportId, limitDays = null) {
    const changelog = this.changeHistory.get(reportId) || [];

    let filtered = changelog;
    if (limitDays) {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - limitDays);
      filtered = changelog.filter(c => new Date(c.timestamp) >= cutoff);
    }

    const byType = {};
    filtered.forEach(c => {
      byType[c.changeType] = (byType[c.changeType] || 0) + 1;
    });

    return {
      reportId,
      changeCount: filtered.length,
      period: limitDays ? `Last ${limitDays} days` : 'All time',
      byType,
      timeline: filtered.map(c => ({
        changeType: c.changeType,
        timestamp: c.timestamp,
        versionNumber: c.versionNumber,
      })),
    };
  }

  promoteToProduction(versionId, actor, deploymentInfo = {}) {
    const version = this.versions.get(versionId);
    if (!version) throw new Error(`Version not found: ${versionId}`);
    if (version.status !== 'released') throw new Error('Only released versions can be promoted to production');

    const promotion = {
      versionId,
      versionNumber: version.versionNumber,
      promotedAt: new Date().toISOString(),
      promotedBy: actor,
      environment: 'production',
      deploymentInfo,
      status: 'deployed',
      rollbackAvailable: true,
    };

    version.productionDeployment = promotion;
    this.recordChange(version.reportId, 'deployed_to_production', version);

    return promotion;
  }

  rollbackVersion(versionId, targetVersionId, actor, reason = '') {
    const version = this.versions.get(versionId);
    if (!version) throw new Error(`Version not found: ${versionId}`);

    const rollback = {
      versionId,
      targetVersionId,
      rolledBackAt: new Date().toISOString(),
      rolledBackBy: actor,
      reason,
      status: 'rolled_back',
    };

    version.rollbackDetails = rollback;
    this.recordChange(version.reportId, 'rolled_back', version);

    return rollback;
  }

  getProductMetrics(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);

    const metrics = {
      versionsCreated: 0,
      versionsReleased: 0,
      deploymentsToProduction: 0,
      rollbacks: 0,
      byProductType: {},
    };

    this.versions.forEach(version => {
      if (new Date(version.createdAt) >= start && new Date(version.createdAt) <= end) {
        metrics.versionsCreated++;

        if (!metrics.byProductType[version.productType]) {
          metrics.byProductType[version.productType] = { created: 0, released: 0 };
        }
        metrics.byProductType[version.productType].created++;

        if (version.status === 'released') {
          metrics.versionsReleased++;
          metrics.byProductType[version.productType].released++;
        }

        if (version.productionDeployment) {
          metrics.deploymentsToProduction++;
        }

        if (version.rollbackDetails) {
          metrics.rollbacks++;
        }
      }
    });

    return {
      period: { start: startDate, end: endDate },
      ...metrics,
    };
  }

  validateReleaseIntegrity(reportId) {
    const versions = this.getVersionHistory(reportId);
    const releases = this.getReleaseHistory(reportId);

    const integrity = {
      reportId,
      totalVersions: versions.totalVersions,
      totalReleases: releases.totalReleases,
      allReleasesLinked: this.validateReleaseVersionLinks(reportId),
      releaseOrderCorrect: this.validateReleaseOrdering(reportId),
      allReleasesHaveNotes: releases.releases.every(r => {
        const v = this.versions.get(`v${r.versionNumber}_${reportId}`);
        return v && v.releaseNotes;
      }),
    };

    return {
      ...integrity,
      status: Object.values(integrity).every(v => v === true || typeof v === 'number') ? 'valid' : 'invalid',
    };
  }

  validateReleaseVersionLinks(reportId) {
    const releases = [];
    this.releases.forEach(r => {
      if (r.reportId === reportId) releases.push(r);
    });

    return releases.every(r => {
      return this.versions.has(r.versionId);
    });
  }

  validateReleaseOrdering(reportId) {
    const releases = [];
    this.releases.forEach(r => {
      if (r.reportId === reportId) releases.push(r);
    });

    const sorted = [...releases].sort((a, b) => new Date(b.releaseDate) - new Date(a.releaseDate));

    for (let i = 0; i < sorted.length - 1; i++) {
      if (new Date(sorted[i].releaseDate) < new Date(sorted[i + 1].releaseDate)) {
        return false;
      }
    }

    return true;
  }
}

module.exports = { ProductReleaseManagementEngine };
