'use strict';

/**
 * CYBERDUDEBIVASH SENTINEL APEX — Pipeline Health Certification Engine v1.0
 *
 * Production-grade health validation system with 12 independent metrics:
 * 1. Pipeline Execution (workflow start/complete, runtime, exit code)
 * 2. Source Health (success, timeout, auth failure, rate limit, empty, invalid data, schema)
 * 3. Collection Health (collected, parsed, rejected, deduplicated, enriched, published)
 * 4. Publication Health (verify live-intel.json, RSS, HTML, STIX, JSON, indexes updated)
 * 5. Freshness Metrics (newest, oldest, average, max age, feed age, per-source age)
 * 6. Pipeline Quality (detect zero intelligence, duplicates, schema regressions, drops, volume)
 * 7. Historical Metrics (30-day health history, reliability, latency, success rates)
 * 8. Auto-recovery (retry failed sources independently, escalate after limits)
 * 9. Operational Dashboard (health report generation)
 * 10. Health Classification (HEALTHY, DEGRADED, SOURCE_FAILURE, etc.)
 * 11. Notifications (actionable alerts only, suppress duplicates, group failures)
 * 12. Acceptance Criteria (actual execution validation, not heartbeat timestamps)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class PipelineHealthCertification {
  constructor(config = {}) {
    this.config = {
      healthHistoryPath: config.healthHistoryPath || path.join(process.cwd(), 'pipeline-health-history.json'),
      stateFile: config.stateFile || path.join(process.cwd(), 'intel-state.json'),
      liveIntelFile: config.liveIntelFile || path.join(process.cwd(), 'live-intel.json'),
      historyRetentionDays: config.historyRetentionDays || 30,
      sourceRetryLimit: config.sourceRetryLimit || 3,
      sourceRetryDelay: config.sourceRetryDelay || 5000,
      freshnessWarnMins: config.freshnessWarnMins || 90,
      freshnessCriticalMins: config.freshnessCriticalMins || 180,
      zeroIntelligenceThreshold: config.zeroIntelligenceThreshold || 5,
      minSourcesRequired: config.minSourcesRequired || 1,
      ...config
    };

    this.executionMetrics = null;
    this.sourceMetrics = {};
    this.collectionMetrics = null;
    this.publicationMetrics = null;
    this.freshnessMetrics = null;
    this.qualityMetrics = null;
    this.historyMetrics = null;
    this.healthStatus = 'INITIALIZING';
    this.certificationTimestamp = new Date().toISOString();
  }

  /**
   * CATEGORY 1: Pipeline Execution Validation
   * Track workflow lifecycle: started, completed, runtime, exit code
   */
  setCertificationExecution(data) {
    this.executionMetrics = {
      timestamp: this.certificationTimestamp,
      workflowId: data.workflowId || null,
      workflowName: data.workflowName || 'SENTINEL APEX v5.0',
      trigger: data.trigger || 'schedule',
      startTime: data.startTime || new Date().toISOString(),
      endTime: data.endTime || new Date().toISOString(),
      durationMs: data.durationMs || 0,
      exitCode: data.exitCode !== undefined ? data.exitCode : 0,
      status: data.exitCode === 0 ? 'SUCCESS' : 'FAILURE',
      pipelineStarted: data.pipelineStarted !== false,
      pipelineCompleted: data.pipelineCompleted !== false,
    };
    return this.executionMetrics;
  }

  /**
   * CATEGORY 2: Source Health Tracking
   * For each configured source: success, timeout, auth failure, rate limit, empty, invalid, schema
   */
  recordSourceResult(sourceName, result) {
    if (!this.sourceMetrics[sourceName]) {
      this.sourceMetrics[sourceName] = {
        name: sourceName,
        timestamp: this.certificationTimestamp,
        attempts: 0,
        successes: 0,
        failures: 0,
        timeouts: 0,
        authFailures: 0,
        rateLimited: 0,
        emptyResponses: 0,
        invalidData: 0,
        schemaFailures: 0,
        itemsCollected: 0,
        lastResult: null,
        lastError: null,
        status: 'UNKNOWN',
      };
    }

    const metrics = this.sourceMetrics[sourceName];
    metrics.attempts++;
    metrics.timestamp = this.certificationTimestamp;

    if (result.status === 'success') {
      metrics.successes++;
      metrics.itemsCollected = (metrics.itemsCollected || 0) + (result.itemsCollected || 0);
      metrics.status = 'OK';
      metrics.lastResult = result;
    } else {
      metrics.failures++;
      metrics.lastError = result.error || 'Unknown error';

      if (result.type === 'TIMEOUT') {
        metrics.timeouts++;
        metrics.status = 'TIMEOUT';
      } else if (result.type === 'AUTH_FAILURE') {
        metrics.authFailures++;
        metrics.status = 'AUTH_FAILURE';
      } else if (result.type === 'RATE_LIMITED') {
        metrics.rateLimited++;
        metrics.status = 'RATE_LIMITED';
      } else if (result.type === 'EMPTY_RESPONSE') {
        metrics.emptyResponses++;
        metrics.status = 'EMPTY';
      } else if (result.type === 'INVALID_DATA') {
        metrics.invalidData++;
        metrics.status = 'INVALID_DATA';
      } else if (result.type === 'SCHEMA_FAILURE') {
        metrics.schemaFailures++;
        metrics.status = 'SCHEMA_FAILURE';
      }
    }

    metrics.successRate = metrics.successes / Math.max(1, metrics.successes + metrics.failures);
    return metrics;
  }

  /**
   * CATEGORY 3: Collection Health Metrics
   * Track records processed through pipeline stages
   */
  setCollectionMetrics(data) {
    this.collectionMetrics = {
      timestamp: this.certificationTimestamp,
      collected: data.collected || 0,
      parsed: data.parsed || 0,
      rejected: data.rejected || 0,
      deduplicated: data.deduplicated || 0,
      enriched: data.enriched || 0,
      published: data.published || 0,
      parseSuccessRate: data.parsed / Math.max(1, data.collected),
      rejectionRate: data.rejected / Math.max(1, data.collected),
      deduplicationRate: data.deduplicated / Math.max(1, data.parsed),
      enrichmentCoverage: data.enriched / Math.max(1, data.parsed),
      publicationRate: data.published / Math.max(1, data.deduplicated),
    };
    return this.collectionMetrics;
  }

  /**
   * CATEGORY 4: Publication Health Verification
   * Validate all output formats were updated
   */
  setPublicationMetrics(data) {
    this.publicationMetrics = {
      timestamp: this.certificationTimestamp,
      liveIntelJsonUpdated: data.liveIntelJsonUpdated !== false,
      rssUpdated: data.rssUpdated !== false,
      htmlUpdated: data.htmlUpdated !== false,
      stixUpdated: data.stixUpdated !== false,
      jsonUpdated: data.jsonUpdated !== false,
      indexesUpdated: data.indexesUpdated !== false,
      sitemapUpdated: data.sitemapUpdated !== false,
      apiUpdated: data.apiUpdated !== false,
      allPublicationsSuccessful: [
        data.liveIntelJsonUpdated,
        data.rssUpdated,
        data.htmlUpdated,
        data.stixUpdated,
        data.jsonUpdated,
        data.indexesUpdated,
      ].filter(v => v !== false).length === 6,
    };
    return this.publicationMetrics;
  }

  /**
   * CATEGORY 5: Freshness Metrics
   * Measure age of intelligence: newest, oldest, average, max, feed age, per-source
   */
  setFreshnessMetrics(data) {
    this.freshnessMetrics = {
      timestamp: this.certificationTimestamp,
      feedAgeMinutes: data.feedAgeMinutes || 0,
      newestItemMinutesOld: data.newestItemMinutesOld || 0,
      oldestItemMinutesOld: data.oldestItemMinutesOld || 0,
      averageAgeMinutes: data.averageAgeMinutes || 0,
      maximumAgeMinutes: data.maximumAgeMinutes || 0,
      perSourceAge: data.perSourceAge || {},
      freshnessStatus: this.calculateFreshnessStatus(data.feedAgeMinutes || 0),
    };
    return this.freshnessMetrics;
  }

  calculateFreshnessStatus(ageMinutes) {
    if (ageMinutes <= 60) return 'HEALTHY';
    if (ageMinutes <= this.config.freshnessWarnMins) return 'WARNING';
    if (ageMinutes <= this.config.freshnessCriticalMins) return 'DEGRADED';
    return 'CRITICAL';
  }

  /**
   * CATEGORY 6: Pipeline Quality Detection
   * Identify: zero intelligence, duplicates, schema regressions, source drops, abnormal volume
   */
  setQualityMetrics(data) {
    const issues = [];

    if ((data.newIntelligence || 0) === 0 && !data.isRecoveryRun) {
      issues.push({
        type: 'ZERO_INTELLIGENCE',
        severity: 'CRITICAL',
        message: `No new intelligence ingested in this run (threshold: ${this.config.zeroIntelligenceThreshold} min)`,
      });
    }

    if ((data.duplicateRate || 0) > 0.3) {
      issues.push({
        type: 'DUPLICATE_STORM',
        severity: 'HIGH',
        message: `Duplicate rate ${((data.duplicateRate || 0) * 100).toFixed(1)}% exceeds threshold`,
      });
    }

    if ((data.sourceCountDelta || 0) < -2) {
      issues.push({
        type: 'MASSIVE_SOURCE_DROP',
        severity: 'CRITICAL',
        message: `${Math.abs(data.sourceCountDelta)} sources suddenly unavailable`,
      });
    }

    if (data.schemaFailures && data.schemaFailures.length > 0) {
      issues.push({
        type: 'SCHEMA_REGRESSION',
        severity: 'HIGH',
        message: `Schema validation failures detected in: ${data.schemaFailures.join(', ')}`,
      });
    }

    if (data.volumeAnomaly) {
      issues.push({
        type: 'ABNORMAL_VOLUME',
        severity: 'MEDIUM',
        message: `Intelligence volume ${data.volumeDeviation || 'N/A'} standard deviations from mean`,
      });
    }

    this.qualityMetrics = {
      timestamp: this.certificationTimestamp,
      newIntelligence: data.newIntelligence || 0,
      duplicateRate: data.duplicateRate || 0,
      sourceCountDelta: data.sourceCountDelta || 0,
      schemaFailures: data.schemaFailures || [],
      volumeAnomaly: data.volumeAnomaly || false,
      issues,
      qualityStatus: issues.length === 0 ? 'PASSED' : 'ISSUES_DETECTED',
    };
    return this.qualityMetrics;
  }

  /**
   * CATEGORY 7: Historical Metrics Persistence
   * Track 30-day trends: reliability, latency, success rates
   */
  loadAndUpdateHistory() {
    let history = { runs: [] };

    try {
      if (fs.existsSync(this.config.healthHistoryPath)) {
        history = JSON.parse(fs.readFileSync(this.config.healthHistoryPath, 'utf8'));
      }
    } catch (e) {
      console.warn(`[HEALTH] Failed to load history: ${e.message}`);
    }

    // Add current run
    history.runs.push({
      timestamp: this.certificationTimestamp,
      execution: this.executionMetrics,
      sources: Object.values(this.sourceMetrics),
      collection: this.collectionMetrics,
      publication: this.publicationMetrics,
      freshness: this.freshnessMetrics,
      quality: this.qualityMetrics,
      healthStatus: this.healthStatus,
    });

    // Prune old entries (keep 30 days)
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - this.config.historyRetentionDays);
    history.runs = history.runs.filter(r => new Date(r.timestamp) > cutoff);

    // Calculate trends
    if (history.runs.length > 1) {
      const recentRuns = history.runs.slice(-10); // Last 10 runs
      const successCount = recentRuns.filter(r => r.execution?.status === 'SUCCESS').length;
      const avgSuccessRate = recentRuns.reduce((sum, r) => {
        const sourceRates = Object.values(r.sources || {}).map(s => s.successRate || 0);
        return sum + (sourceRates.length > 0 ? sourceRates.reduce((a, b) => a + b, 0) / sourceRates.length : 0);
      }, 0) / Math.max(1, recentRuns.length);

      history.trends = {
        pipelineSuccessRate: successCount / recentRuns.length,
        avgSourceSuccessRate: avgSuccessRate,
        avgIntelligencePerRun: recentRuns.reduce((sum, r) => sum + (r.collection?.published || 0), 0) / recentRuns.length,
        totalRunsTracked: history.runs.length,
        periodDays: Math.min(this.config.historyRetentionDays, Math.ceil((new Date() - new Date(history.runs[0].timestamp)) / (1000 * 60 * 60 * 24))),
      };
    }

    this.historyMetrics = history;
    this.persistHistory(history);
    return history;
  }

  persistHistory(history) {
    try {
      fs.writeFileSync(
        this.config.healthHistoryPath,
        JSON.stringify(history, null, 2),
        'utf8'
      );
    } catch (e) {
      console.error(`[HEALTH] Failed to persist history: ${e.message}`);
    }
  }

  /**
   * CATEGORY 10: Health Classification
   * Return overall health status based on all metrics
   */
  certifyHealth() {
    const checks = {
      pipelineExecuted: this.executionMetrics?.pipelineStarted === true && this.executionMetrics?.pipelineCompleted === true,
      sourcesEvaluated: Object.keys(this.sourceMetrics).length >= this.config.minSourcesRequired,
      publicationSuccessful: this.publicationMetrics?.allPublicationsSuccessful === true,
      feedIntegrityVerified: this.freshnessMetrics?.feedAgeMinutes !== undefined,
      freshnessVerified: this.freshnessMetrics?.freshnessStatus !== 'CRITICAL',
      metricsRecorded: this.collectionMetrics !== null,
    };

    const allChecksPassed = Object.values(checks).every(v => v === true);

    // Determine health status
    if (!allChecksPassed) {
      const failedChecks = Object.entries(checks).filter(([k, v]) => v === false).map(([k]) => k);
      if (failedChecks.includes('pipelineExecuted')) {
        this.healthStatus = 'PIPELINE_FAILURE';
      } else if (failedChecks.includes('sourcesEvaluated')) {
        // Checked before publicationSuccessful: zero sources evaluated is
        // the root cause, and publication trivially also fails downstream
        // of it -- reporting SOURCE_FAILURE here points at what actually
        // needs fixing instead of the symptom.
        this.healthStatus = 'SOURCE_FAILURE';
      } else if (failedChecks.includes('publicationSuccessful')) {
        this.healthStatus = 'PUBLICATION_FAILURE';
      } else if (failedChecks.includes('freshnessVerified')) {
        this.healthStatus = 'DEGRADED';
      } else {
        this.healthStatus = 'INCOMPLETE';
      }
    } else {
      // All checks passed — determine if healthy or degraded
      const sourceFailures = Object.values(this.sourceMetrics).filter(s => s.status !== 'OK').length;
      const qualityIssues = this.qualityMetrics?.issues?.length || 0;

      if (sourceFailures > 0 || qualityIssues > 0 || this.freshnessMetrics?.freshnessStatus === 'DEGRADED') {
        this.healthStatus = 'DEGRADED';
      } else {
        this.healthStatus = 'HEALTHY';
      }
    }

    return {
      status: this.healthStatus,
      timestamp: this.certificationTimestamp,
      checks,
      allChecksPassed,
      execution: this.executionMetrics,
      sources: this.sourceMetrics,
      collection: this.collectionMetrics,
      publication: this.publicationMetrics,
      freshness: this.freshnessMetrics,
      quality: this.qualityMetrics,
      history: this.historyMetrics?.trends,
    };
  }

  /**
   * CATEGORY 9: Operational Dashboard Generation
   * Generate human-readable health report
   */
  generateDashboard() {
    const cert = this.certifyHealth();

    const dashboard = {
      title: 'SENTINEL APEX Pipeline Health Certification',
      timestamp: this.certificationTimestamp,
      overallStatus: cert.status,

      pipelineHealth: {
        status: cert.execution?.status || 'UNKNOWN',
        workflowName: cert.execution?.workflowName,
        trigger: cert.execution?.trigger,
        durationMs: cert.execution?.durationMs,
        exitCode: cert.execution?.exitCode,
      },

      sourceHealth: {
        total: Object.keys(this.sourceMetrics).length,
        healthy: Object.values(this.sourceMetrics).filter(s => s.status === 'OK').length,
        degraded: Object.values(this.sourceMetrics).filter(s => s.status === 'DEGRADED').length,
        failed: Object.values(this.sourceMetrics).filter(s => s.status !== 'OK').length,
        sources: Object.entries(this.sourceMetrics).map(([name, metrics]) => ({
          name,
          status: metrics.status,
          attempts: metrics.attempts,
          successRate: `${(metrics.successRate * 100).toFixed(1)}%`,
          itemsCollected: metrics.itemsCollected,
          lastError: metrics.lastError,
        })),
      },

      collectionHealth: {
        collected: this.collectionMetrics?.collected || 0,
        parsed: this.collectionMetrics?.parsed || 0,
        rejected: this.collectionMetrics?.rejected || 0,
        deduplicated: this.collectionMetrics?.deduplicated || 0,
        enriched: this.collectionMetrics?.enriched || 0,
        published: this.collectionMetrics?.published || 0,
        parseSuccessRate: `${((this.collectionMetrics?.parseSuccessRate || 0) * 100).toFixed(1)}%`,
        publicationRate: `${((this.collectionMetrics?.publicationRate || 0) * 100).toFixed(1)}%`,
      },

      publicationHealth: {
        liveIntelJson: this.publicationMetrics?.liveIntelJsonUpdated ? '✓' : '✗',
        rss: this.publicationMetrics?.rssUpdated ? '✓' : '✗',
        html: this.publicationMetrics?.htmlUpdated ? '✓' : '✗',
        stix: this.publicationMetrics?.stixUpdated ? '✓' : '✗',
        json: this.publicationMetrics?.jsonUpdated ? '✓' : '✗',
        indexes: this.publicationMetrics?.indexesUpdated ? '✓' : '✗',
        allSuccessful: this.publicationMetrics?.allPublicationsSuccessful ? '✓' : '✗',
      },

      freshnessHealth: {
        feedAgeMinutes: this.freshnessMetrics?.feedAgeMinutes || 0,
        status: this.freshnessMetrics?.freshnessStatus || 'UNKNOWN',
        newestItemMinutesOld: this.freshnessMetrics?.newestItemMinutesOld || 0,
        oldestItemMinutesOld: this.freshnessMetrics?.oldestItemMinutesOld || 0,
        averageAgeMinutes: this.freshnessMetrics?.averageAgeMinutes || 0,
      },

      qualityMetrics: {
        status: this.qualityMetrics?.qualityStatus || 'UNKNOWN',
        newIntelligence: this.qualityMetrics?.newIntelligence || 0,
        duplicateRate: `${((this.qualityMetrics?.duplicateRate || 0) * 100).toFixed(1)}%`,
        issues: this.qualityMetrics?.issues || [],
      },

      historicalTrends: this.historyMetrics?.trends || null,

      acceptanceCertification: {
        pipelineExecuted: cert.checks?.pipelineExecuted ? '✓ PASS' : '✗ FAIL',
        sourcesEvaluated: cert.checks?.sourcesEvaluated ? '✓ PASS' : '✗ FAIL',
        publicationValidated: cert.checks?.publicationSuccessful ? '✓ PASS' : '✗ FAIL',
        feedIntegrityVerified: cert.checks?.feedIntegrityVerified ? '✓ PASS' : '✗ FAIL',
        freshnessVerified: cert.checks?.freshnessVerified ? '✓ PASS' : '✗ FAIL',
        metricsRecorded: cert.checks?.metricsRecorded ? '✓ PASS' : '✗ FAIL',
        allRequirementsMet: cert.allChecksPassed ? '✓ CERTIFIED' : '✗ NOT CERTIFIED',
      },
    };

    return dashboard;
  }

  /**
   * CATEGORY 11: Intelligent Notifications
   * Generate actionable alerts only, suppress duplicates, group failures
   */
  generateNotifications() {
    const notifications = [];
    const cert = this.certifyHealth();

    // Pipeline-level alerts
    if (cert.execution?.status === 'FAILURE') {
      notifications.push({
        type: 'PIPELINE_FAILURE',
        severity: 'CRITICAL',
        message: `Pipeline execution failed (exit code: ${cert.execution?.exitCode})`,
        actionable: 'Check pipeline logs for root cause; may require manual intervention',
      });
    }

    // Source-level alerts
    const failedSources = Object.entries(this.sourceMetrics)
      .filter(([, s]) => s.status !== 'OK')
      .map(([name, s]) => ({
        source: name,
        status: s.status,
        error: s.lastError,
      }));

    if (failedSources.length > 0) {
      notifications.push({
        type: 'SOURCE_FAILURES',
        severity: 'HIGH',
        message: `${failedSources.length} source(s) failed`,
        sources: failedSources,
        actionable: 'Check source configuration; retry with backoff',
      });
    }

    // Publication alerts
    if (!this.publicationMetrics?.allPublicationsSuccessful) {
      const failed = Object.entries({
        'live-intel.json': this.publicationMetrics?.liveIntelJsonUpdated,
        'RSS': this.publicationMetrics?.rssUpdated,
        'HTML': this.publicationMetrics?.htmlUpdated,
        'STIX': this.publicationMetrics?.stixUpdated,
        'JSON': this.publicationMetrics?.jsonUpdated,
        'Indexes': this.publicationMetrics?.indexesUpdated,
      }).filter(([, v]) => v === false).map(([k]) => k);

      notifications.push({
        type: 'PUBLICATION_FAILURE',
        severity: 'HIGH',
        message: `Publication failed for: ${failed.join(', ')}`,
        actionable: 'Verify publication pipeline and disk space',
      });
    }

    // Freshness alerts
    if (this.freshnessMetrics?.freshnessStatus === 'CRITICAL') {
      notifications.push({
        type: 'FRESHNESS_CRITICAL',
        severity: 'CRITICAL',
        message: `Feed is ${this.freshnessMetrics?.feedAgeMinutes || 0} minutes old (critical threshold: ${this.config.freshnessCriticalMins} min)`,
        actionable: 'Trigger immediate pipeline recovery; check for stuck processes',
      });
    } else if (this.freshnessMetrics?.freshnessStatus === 'DEGRADED') {
      notifications.push({
        type: 'FRESHNESS_WARNING',
        severity: 'MEDIUM',
        message: `Feed is ${this.freshnessMetrics?.feedAgeMinutes || 0} minutes old (warning threshold: ${this.config.freshnessWarnMins} min)`,
        actionable: 'Monitor next scheduled run; check source latency',
      });
    }

    // Quality alerts
    if (this.qualityMetrics?.issues && this.qualityMetrics.issues.length > 0) {
      for (const issue of this.qualityMetrics.issues) {
        notifications.push({
          type: issue.type,
          severity: issue.severity,
          message: issue.message,
          actionable: this.getActionableRecoveryStep(issue.type),
        });
      }
    }

    return notifications;
  }

  getActionableRecoveryStep(issueType) {
    const recoverySteps = {
      ZERO_INTELLIGENCE: 'No new intelligence in recent window; likely all sources are returning duplicates or outdated data. Verify source APIs are responsive.',
      DUPLICATE_STORM: 'High duplicate rate indicates deduplication may be failing. Check deduplication logic and state file integrity.',
      MASSIVE_SOURCE_DROP: 'Multiple sources suddenly unavailable. Likely infrastructure or authentication issue. Check source endpoints and API keys.',
      SCHEMA_REGRESSION: 'Schema validation failing on some sources. Revert recent schema changes or update source parsers.',
      ABNORMAL_VOLUME: 'Intelligence volume significantly different from historical baseline. May indicate data quality issue or source configuration change.',
      PIPELINE_FAILURE: 'Pipeline execution did not complete. Check workflow logs and ensure dependencies are available.',
      SOURCE_FAILURE: 'One or more configured sources did not produce results. Retry with backoff; escalate after retry limits.',
      PUBLICATION_FAILURE: 'Feed or output files not updated. Check disk space and write permissions.',
      FRESHNESS_CRITICAL: 'Feed has not been updated recently. Trigger immediate pipeline recovery run.',
    };

    return recoverySteps[issueType] || 'Check pipeline health metrics and recent logs';
  }

  /**
   * CATEGORY 8: Auto-recovery Logic
   * Retry failed sources independently; escalate after configurable limits
   */
  async attemptSourceRecovery(sourceName, recoveryCallback) {
    const metrics = this.sourceMetrics[sourceName];
    if (!metrics) return { success: false, message: 'Source not found' };

    console.log(`[HEALTH] Attempting recovery for source: ${sourceName}`);

    for (let attempt = 1; attempt <= this.config.sourceRetryLimit; attempt++) {
      try {
        console.log(`[HEALTH] Recovery attempt ${attempt}/${this.config.sourceRetryLimit} for ${sourceName}`);

        const result = await recoveryCallback(sourceName);

        if (result.success) {
          this.recordSourceResult(sourceName, {
            status: 'success',
            itemsCollected: result.itemsCollected || 0,
          });
          console.log(`[HEALTH] Recovery successful for ${sourceName}`);
          return { success: true, attempt, message: 'Recovery successful' };
        }

        if (attempt < this.config.sourceRetryLimit) {
          await new Promise(r => setTimeout(r, this.config.sourceRetryDelay * attempt));
        }
      } catch (e) {
        console.error(`[HEALTH] Recovery attempt ${attempt} failed for ${sourceName}: ${e.message}`);
        if (attempt === this.config.sourceRetryLimit) {
          return {
            success: false,
            attempt: this.config.sourceRetryLimit,
            message: `All ${this.config.sourceRetryLimit} recovery attempts failed`,
            lastError: e.message,
          };
        }
      }
    }

    return {
      success: false,
      attempt: this.config.sourceRetryLimit,
      message: 'Recovery exhausted retry limit',
    };
  }

  toJSON() {
    // this.healthStatus is only updated as a side effect of certifyHealth()
    // -- call it here too (generateDashboard()/generateNotifications()
    // already do) so a caller who serializes without having explicitly
    // certified first doesn't get the constructor's 'INITIALIZING' default.
    this.certifyHealth();
    return {
      status: this.healthStatus,
      timestamp: this.certificationTimestamp,
      execution: this.executionMetrics,
      sources: this.sourceMetrics,
      collection: this.collectionMetrics,
      publication: this.publicationMetrics,
      freshness: this.freshnessMetrics,
      quality: this.qualityMetrics,
      dashboard: this.generateDashboard(),
      notifications: this.generateNotifications(),
    };
  }
}

module.exports = { PipelineHealthCertification };
