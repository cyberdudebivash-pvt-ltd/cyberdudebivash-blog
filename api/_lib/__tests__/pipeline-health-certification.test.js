'use strict';

const { PipelineHealthCertification } = require('../pipeline-health-certification');

describe('Pipeline Health Certification Engine', () => {
  let health;

  beforeEach(() => {
    health = new PipelineHealthCertification({
      historyRetentionDays: 30,
      sourceRetryLimit: 3,
      freshnessWarnMins: 90,
      freshnessCriticalMins: 180,
      zeroIntelligenceThreshold: 5,
      minSourcesRequired: 1,
    });
  });

  describe('Category 1: Pipeline Execution Validation', () => {
    test('should record successful pipeline execution', () => {
      const exec = health.setCertificationExecution({
        workflowId: 'run-12345',
        workflowName: 'SENTINEL APEX v5.0',
        trigger: 'schedule',
        startTime: '2026-07-31T17:00:00Z',
        endTime: '2026-07-31T17:05:00Z',
        durationMs: 300000,
        exitCode: 0,
        pipelineStarted: true,
        pipelineCompleted: true,
      });

      expect(exec.status).toBe('SUCCESS');
      expect(exec.exitCode).toBe(0);
      expect(exec.durationMs).toBe(300000);
      expect(exec.pipelineStarted).toBe(true);
      expect(exec.pipelineCompleted).toBe(true);
    });

    test('should record failed pipeline execution', () => {
      const exec = health.setCertificationExecution({
        exitCode: 1,
        pipelineStarted: true,
        pipelineCompleted: false,
      });

      expect(exec.status).toBe('FAILURE');
      expect(exec.exitCode).toBe(1);
      expect(exec.pipelineCompleted).toBe(false);
    });
  });

  describe('Category 2: Source Health Tracking', () => {
    test('should record successful source result', () => {
      const result = health.recordSourceResult('nvd_api', {
        status: 'success',
        itemsCollected: 42,
      });

      expect(result.status).toBe('OK');
      expect(result.successes).toBe(1);
      expect(result.failures).toBe(0);
      expect(result.itemsCollected).toBe(42);
      expect(result.successRate).toBe(1.0);
    });

    test('should categorize source failure types', () => {
      health.recordSourceResult('cisa_kev', { status: 'failure', type: 'TIMEOUT', error: 'Request timeout' });
      expect(health.sourceMetrics.cisa_kev.status).toBe('TIMEOUT');
      expect(health.sourceMetrics.cisa_kev.timeouts).toBe(1);

      health.recordSourceResult('github_advisories', { status: 'failure', type: 'AUTH_FAILURE', error: 'Invalid API key' });
      expect(health.sourceMetrics.github_advisories.status).toBe('AUTH_FAILURE');
      expect(health.sourceMetrics.github_advisories.authFailures).toBe(1);

      health.recordSourceResult('msrc', { status: 'failure', type: 'RATE_LIMITED', error: 'Rate limit exceeded' });
      expect(health.sourceMetrics.msrc.status).toBe('RATE_LIMITED');
      expect(health.sourceMetrics.msrc.rateLimited).toBe(1);

      health.recordSourceResult('exploit_db', { status: 'failure', type: 'EMPTY_RESPONSE', error: 'Empty response' });
      expect(health.sourceMetrics.exploit_db.status).toBe('EMPTY');
      expect(health.sourceMetrics.exploit_db.emptyResponses).toBe(1);

      health.recordSourceResult('packetstorm', { status: 'failure', type: 'INVALID_DATA', error: 'Invalid JSON' });
      expect(health.sourceMetrics.packetstorm.status).toBe('INVALID_DATA');
      expect(health.sourceMetrics.packetstorm.invalidData).toBe(1);

      health.recordSourceResult('full_disclosure', { status: 'failure', type: 'SCHEMA_FAILURE', error: 'Missing required field' });
      expect(health.sourceMetrics.full_disclosure.status).toBe('SCHEMA_FAILURE');
      expect(health.sourceMetrics.full_disclosure.schemaFailures).toBe(1);
    });

    test('should calculate source success rate', () => {
      health.recordSourceResult('test_source', { status: 'success', itemsCollected: 10 });
      health.recordSourceResult('test_source', { status: 'success', itemsCollected: 15 });
      health.recordSourceResult('test_source', { status: 'failure', type: 'TIMEOUT', error: 'Timeout' });

      expect(health.sourceMetrics.test_source.successes).toBe(2);
      expect(health.sourceMetrics.test_source.failures).toBe(1);
      expect(health.sourceMetrics.test_source.successRate).toBeCloseTo(0.667, 2);
    });
  });

  describe('Category 3: Collection Health Metrics', () => {
    test('should calculate collection pipeline metrics', () => {
      const metrics = health.setCollectionMetrics({
        collected: 1000,
        parsed: 950,
        rejected: 50,
        deduplicated: 800,
        enriched: 780,
        published: 750,
      });

      expect(metrics.parseSuccessRate).toBeCloseTo(0.95, 2);
      expect(metrics.rejectionRate).toBeCloseTo(0.05, 2);
      expect(metrics.deduplicationRate).toBeCloseTo(0.842, 2);
      expect(metrics.enrichmentCoverage).toBeCloseTo(0.821, 2);
      expect(metrics.publicationRate).toBeCloseTo(0.9375, 2);
    });
  });

  describe('Category 4: Publication Health Verification', () => {
    test('should verify all publication formats successful', () => {
      const metrics = health.setPublicationMetrics({
        liveIntelJsonUpdated: true,
        rssUpdated: true,
        htmlUpdated: true,
        stixUpdated: true,
        jsonUpdated: true,
        indexesUpdated: true,
        sitemapUpdated: true,
        apiUpdated: true,
      });

      expect(metrics.allPublicationsSuccessful).toBe(true);
    });

    test('should detect partial publication failure', () => {
      const metrics = health.setPublicationMetrics({
        liveIntelJsonUpdated: true,
        rssUpdated: false,
        htmlUpdated: true,
        stixUpdated: true,
        jsonUpdated: true,
        indexesUpdated: true,
      });

      expect(metrics.allPublicationsSuccessful).toBe(false);
      expect(metrics.rssUpdated).toBe(false);
    });
  });

  describe('Category 5: Freshness Metrics', () => {
    test('should classify freshness status correctly', () => {
      const healthy = health.setFreshnessMetrics({ feedAgeMinutes: 30 });
      expect(healthy.freshnessStatus).toBe('HEALTHY');

      const warning = health.setFreshnessMetrics({ feedAgeMinutes: 75 });
      expect(warning.freshnessStatus).toBe('WARNING');

      const degraded = health.setFreshnessMetrics({ feedAgeMinutes: 120 });
      expect(degraded.freshnessStatus).toBe('DEGRADED');

      const critical = health.setFreshnessMetrics({ feedAgeMinutes: 200 });
      expect(critical.freshnessStatus).toBe('CRITICAL');
    });

    test('should track per-source age', () => {
      const metrics = health.setFreshnessMetrics({
        feedAgeMinutes: 45,
        newestItemMinutesOld: 5,
        oldestItemMinutesOld: 180,
        averageAgeMinutes: 60,
        maximumAgeMinutes: 180,
        perSourceAge: {
          nvd: 10,
          cisa_kev: 5,
          msrc: 45,
        },
      });

      expect(metrics.perSourceAge.nvd).toBe(10);
      expect(metrics.perSourceAge.cisa_kev).toBe(5);
      expect(metrics.perSourceAge.msrc).toBe(45);
    });
  });

  describe('Category 6: Pipeline Quality Detection', () => {
    test('should detect zero intelligence issue', () => {
      const quality = health.setQualityMetrics({
        newIntelligence: 0,
        isRecoveryRun: false,
      });

      expect(quality.issues.length).toBeGreaterThan(0);
      expect(quality.issues[0].type).toBe('ZERO_INTELLIGENCE');
      expect(quality.issues[0].severity).toBe('CRITICAL');
      expect(quality.qualityStatus).toBe('ISSUES_DETECTED');
    });

    test('should detect duplicate storm', () => {
      const quality = health.setQualityMetrics({
        newIntelligence: 100,
        duplicateRate: 0.5,
      });

      expect(quality.issues.some(i => i.type === 'DUPLICATE_STORM')).toBe(true);
    });

    test('should detect massive source drop', () => {
      const quality = health.setQualityMetrics({
        newIntelligence: 100,
        sourceCountDelta: -5,
      });

      expect(quality.issues.some(i => i.type === 'MASSIVE_SOURCE_DROP')).toBe(true);
    });

    test('should detect schema regression', () => {
      const quality = health.setQualityMetrics({
        newIntelligence: 100,
        schemaFailures: ['nvd', 'msrc'],
      });

      expect(quality.issues.some(i => i.type === 'SCHEMA_REGRESSION')).toBe(true);
    });

    test('should detect volume anomaly', () => {
      const quality = health.setQualityMetrics({
        newIntelligence: 100,
        volumeAnomaly: true,
        volumeDeviation: 3.5,
      });

      expect(quality.issues.some(i => i.type === 'ABNORMAL_VOLUME')).toBe(true);
    });

    test('should pass quality when no issues', () => {
      const quality = health.setQualityMetrics({
        newIntelligence: 100,
        duplicateRate: 0.05,
        sourceCountDelta: 0,
        schemaFailures: [],
        volumeAnomaly: false,
      });

      expect(quality.issues.length).toBe(0);
      expect(quality.qualityStatus).toBe('PASSED');
    });
  });

  describe('Category 10: Health Classification', () => {
    test('should return HEALTHY status when all checks pass', () => {
      health.setCertificationExecution({
        exitCode: 0,
        pipelineStarted: true,
        pipelineCompleted: true,
      });
      health.recordSourceResult('nvd', { status: 'success', itemsCollected: 50 });
      health.setCollectionMetrics({ collected: 100, parsed: 95, rejected: 5, deduplicated: 85, enriched: 80, published: 80 });
      health.setPublicationMetrics({
        liveIntelJsonUpdated: true,
        rssUpdated: true,
        htmlUpdated: true,
        stixUpdated: true,
        jsonUpdated: true,
        indexesUpdated: true,
      });
      health.setFreshnessMetrics({ feedAgeMinutes: 30 });
      health.setQualityMetrics({ newIntelligence: 80 });

      const cert = health.certifyHealth();
      expect(cert.status).toBe('HEALTHY');
      expect(cert.allChecksPassed).toBe(true);
    });

    test('should return PIPELINE_FAILURE when pipeline did not execute', () => {
      health.setCertificationExecution({
        pipelineStarted: false,
        pipelineCompleted: false,
      });

      const cert = health.certifyHealth();
      expect(cert.status).toBe('PIPELINE_FAILURE');
    });

    test('should return PUBLICATION_FAILURE when outputs not generated', () => {
      health.setCertificationExecution({ exitCode: 0, pipelineStarted: true, pipelineCompleted: true });
      health.recordSourceResult('nvd', { status: 'success', itemsCollected: 50 });
      health.setPublicationMetrics({
        liveIntelJsonUpdated: false,
        rssUpdated: false,
        htmlUpdated: false,
        stixUpdated: false,
        jsonUpdated: false,
        indexesUpdated: false,
      });

      const cert = health.certifyHealth();
      expect(cert.status).toBe('PUBLICATION_FAILURE');
    });

    test('should return SOURCE_FAILURE when no sources evaluated', () => {
      health.setCertificationExecution({ exitCode: 0, pipelineStarted: true, pipelineCompleted: true });

      const cert = health.certifyHealth();
      expect(cert.status).toBe('SOURCE_FAILURE');
    });

    test('should return DEGRADED when quality issues exist', () => {
      health.setCertificationExecution({ exitCode: 0, pipelineStarted: true, pipelineCompleted: true });
      health.recordSourceResult('nvd', { status: 'success', itemsCollected: 50 });
      health.setCollectionMetrics({ collected: 100, parsed: 95, rejected: 5, deduplicated: 85, enriched: 80, published: 80 });
      health.setPublicationMetrics({
        liveIntelJsonUpdated: true,
        rssUpdated: true,
        htmlUpdated: true,
        stixUpdated: true,
        jsonUpdated: true,
        indexesUpdated: true,
      });
      health.setFreshnessMetrics({ feedAgeMinutes: 30 });
      health.setQualityMetrics({ newIntelligence: 0, isRecoveryRun: false });

      const cert = health.certifyHealth();
      expect(cert.status).toBe('DEGRADED');
    });
  });

  describe('Category 9: Operational Dashboard Generation', () => {
    test('should generate comprehensive dashboard', () => {
      health.setCertificationExecution({
        workflowName: 'Test Pipeline',
        trigger: 'schedule',
        durationMs: 300000,
        exitCode: 0,
      });
      health.recordSourceResult('nvd', { status: 'success', itemsCollected: 50 });
      health.setCollectionMetrics({ collected: 100, parsed: 95, rejected: 5, deduplicated: 85, enriched: 80, published: 80 });
      health.setPublicationMetrics({
        liveIntelJsonUpdated: true,
        rssUpdated: true,
        htmlUpdated: true,
        stixUpdated: true,
        jsonUpdated: true,
        indexesUpdated: true,
      });
      health.setFreshnessMetrics({ feedAgeMinutes: 30 });
      health.setQualityMetrics({ newIntelligence: 80 });

      const dashboard = health.generateDashboard();

      expect(dashboard.title).toBe('SENTINEL APEX Pipeline Health Certification');
      expect(dashboard.overallStatus).toBeDefined();
      expect(dashboard.pipelineHealth).toBeDefined();
      expect(dashboard.sourceHealth).toBeDefined();
      expect(dashboard.collectionHealth).toBeDefined();
      expect(dashboard.publicationHealth).toBeDefined();
      expect(dashboard.freshnessHealth).toBeDefined();
      expect(dashboard.qualityMetrics).toBeDefined();
      expect(dashboard.acceptanceCertification).toBeDefined();
    });
  });

  describe('Category 11: Intelligent Notifications', () => {
    test('should generate pipeline failure notification', () => {
      health.setCertificationExecution({
        exitCode: 1,
        pipelineStarted: true,
        pipelineCompleted: false,
      });

      const notifications = health.generateNotifications();
      const failure = notifications.find(n => n.type === 'PIPELINE_FAILURE');

      expect(failure).toBeDefined();
      expect(failure.severity).toBe('CRITICAL');
      expect(failure.actionable).toBeDefined();
    });

    test('should generate source failure notification', () => {
      health.recordSourceResult('nvd', { status: 'failure', type: 'AUTH_FAILURE', error: 'Invalid key' });
      health.recordSourceResult('cisa', { status: 'success', itemsCollected: 10 });

      const notifications = health.generateNotifications();
      const sourceAlert = notifications.find(n => n.type === 'SOURCE_FAILURES');

      expect(sourceAlert).toBeDefined();
      expect(sourceAlert.sources).toBeDefined();
      expect(sourceAlert.sources.length).toBeGreaterThan(0);
    });

    test('should generate freshness alerts', () => {
      health.setFreshnessMetrics({ feedAgeMinutes: 200 });

      const notifications = health.generateNotifications();
      const freshAlert = notifications.find(n => n.type === 'FRESHNESS_CRITICAL');

      expect(freshAlert).toBeDefined();
      expect(freshAlert.severity).toBe('CRITICAL');
    });

    test('should generate quality issue notifications', () => {
      health.setQualityMetrics({
        newIntelligence: 0,
        isRecoveryRun: false,
      });

      const notifications = health.generateNotifications();
      const qualityAlert = notifications.find(n => n.type === 'ZERO_INTELLIGENCE');

      expect(qualityAlert).toBeDefined();
      expect(qualityAlert.actionable).toBeDefined();
    });
  });

  describe('Category 8: Auto-recovery Logic', () => {
    test('should attempt source recovery', async () => {
      health.recordSourceResult('nvd', { status: 'failure', type: 'TIMEOUT', error: 'Timeout' });

      const result = await health.attemptSourceRecovery('nvd', async (source) => {
        return { success: true, itemsCollected: 25 };
      });

      expect(result.success).toBe(true);
      expect(result.attempt).toBe(1);
      expect(health.sourceMetrics.nvd.status).toBe('OK');
    });

    test('should retry on recovery failure', async () => {
      let attemptCount = 0;

      const result = await health.attemptSourceRecovery('nvd', async (source) => {
        attemptCount++;
        if (attemptCount < 2) throw new Error('Temporary failure');
        return { success: true, itemsCollected: 10 };
      });

      expect(result.success).toBe(true);
      expect(attemptCount).toBe(2);
    });

    test('should exhaust retry limit', async () => {
      const result = await health.attemptSourceRecovery('nvd', async (source) => {
        throw new Error('Persistent failure');
      });

      expect(result.success).toBe(false);
      expect(result.attempt).toBe(3);
    });
  });

  describe('Category 7: Historical Metrics Persistence', () => {
    test('should track historical trends', () => {
      health.setCertificationExecution({ exitCode: 0, pipelineStarted: true, pipelineCompleted: true });
      health.recordSourceResult('nvd', { status: 'success', itemsCollected: 50 });
      health.setCollectionMetrics({ collected: 100, parsed: 95, rejected: 5, deduplicated: 85, enriched: 80, published: 80 });

      const history = health.loadAndUpdateHistory();

      expect(history.runs).toBeDefined();
      expect(history.runs.length).toBeGreaterThan(0);
    });
  });

  describe('Integration Tests', () => {
    test('should serialize complete certification state', () => {
      health.setCertificationExecution({ exitCode: 0, pipelineStarted: true, pipelineCompleted: true });
      health.recordSourceResult('nvd', { status: 'success', itemsCollected: 50 });
      health.setCollectionMetrics({ collected: 100, parsed: 95, rejected: 5, deduplicated: 85, enriched: 80, published: 80 });
      health.setPublicationMetrics({
        liveIntelJsonUpdated: true,
        rssUpdated: true,
        htmlUpdated: true,
        stixUpdated: true,
        jsonUpdated: true,
        indexesUpdated: true,
      });
      health.setFreshnessMetrics({ feedAgeMinutes: 30 });
      health.setQualityMetrics({ newIntelligence: 80 });

      const json = health.toJSON();

      expect(json.status).toBe('HEALTHY');
      expect(json.timestamp).toBeDefined();
      expect(json.execution).toBeDefined();
      expect(json.sources).toBeDefined();
      expect(json.collection).toBeDefined();
      expect(json.publication).toBeDefined();
      expect(json.freshness).toBeDefined();
      expect(json.quality).toBeDefined();
      expect(json.dashboard).toBeDefined();
      expect(json.notifications).toBeDefined();
    });
  });
});
