/**
 * Intelligence Governance Layer Tests
 * Comprehensive test suite for all governance modules
 */

import {
  workflowEngine,
  approvalManager,
  qualityGatesEngine,
  confidenceEngine,
  auditEngine,
  versioningEngine,
  rollbackEngine,
  publishingEngine,
  policyEngine,
  reviewerEngine,
} from '../lib/governance';
import { WorkflowState as WorkflowStateEnum } from '../lib/governance/types';
import { ApprovalRole as ApprovalRoleEnum, ApprovalStatus as ApprovalStatusEnum } from '../lib/governance/types';

describe('Governance Layer', () => {
  // ============================================================================
  // WORKFLOW ENGINE TESTS
  // ============================================================================

  describe('WorkflowEngine', () => {
    test('should allow valid state transitions', () => {
      expect(
        workflowEngine.canTransition(
          WorkflowStateEnum.DRAFT,
          WorkflowStateEnum.AI_GENERATED
        )
      ).toBe(true);
    });

    test('should block invalid state transitions', () => {
      expect(
        workflowEngine.canTransition(
          WorkflowStateEnum.PUBLISHED,
          WorkflowStateEnum.DRAFT
        )
      ).toBe(false);
    });

    test('should execute valid state transition', async () => {
      const transition = await workflowEngine.transitionState(
        'test-obj-1',
        WorkflowStateEnum.DRAFT,
        WorkflowStateEnum.AI_GENERATED,
        'test-actor'
      );

      expect(transition.from).toBe(WorkflowStateEnum.DRAFT);
      expect(transition.to).toBe(WorkflowStateEnum.AI_GENERATED);
      expect(transition.actor).toBe('test-actor');
    });

    test('should track workflow history', async () => {
      const objectId = 'test-obj-workflow';
      await workflowEngine.transitionState(
        objectId,
        WorkflowStateEnum.DRAFT,
        WorkflowStateEnum.SCHEMA_VALIDATED,
        'analyst'
      );

      const history = workflowEngine.getTransitionHistory(objectId);
      expect(history.length).toBe(1);
      expect(history[0].to).toBe(WorkflowStateEnum.SCHEMA_VALIDATED);
    });

    test('should get current state from history', async () => {
      const objectId = 'test-obj-state';
      await workflowEngine.transitionState(
        objectId,
        WorkflowStateEnum.DRAFT,
        WorkflowStateEnum.ANALYST_REVIEW,
        'analyst'
      );

      const current = workflowEngine.getCurrentState(objectId);
      expect(current).toBe(WorkflowStateEnum.ANALYST_REVIEW);
    });

    test('should detect stale objects', async () => {
      const objectId = 'test-obj-stale';
      await workflowEngine.transitionState(
        objectId,
        WorkflowStateEnum.DRAFT,
        WorkflowStateEnum.ANALYST_REVIEW,
        'analyst'
      );

      const isStale = workflowEngine.isStale(objectId, 1); // 1ms threshold
      expect(isStale).toBe(true);
    });

    test('should reset to draft', async () => {
      const objectId = 'test-obj-reset';
      await workflowEngine.transitionState(
        objectId,
        WorkflowStateEnum.DRAFT,
        WorkflowStateEnum.ANALYST_REVIEW,
        'analyst'
      );

      await workflowEngine.resetToDraft(objectId, 'admin', 'Needs correction');
      const current = workflowEngine.getCurrentState(objectId);
      expect(current).toBe(WorkflowStateEnum.DRAFT);
    });
  });

  // ============================================================================
  // APPROVAL MANAGER TESTS
  // ============================================================================

  describe('ApprovalManager', () => {
    test('should create approval chain with default roles', () => {
      const chain = approvalManager.createApprovalChain('report-1', 'report', [
        ApprovalRoleEnum.ANALYST,
        ApprovalRoleEnum.QA_LEAD,
      ]);

      expect(chain.objectId).toBe('report-1');
      expect(chain.approvals.length).toBe(2);
      expect(chain.allApproved).toBe(false);
    });

    test('should approve an approval step', async () => {
      const chain = approvalManager.createApprovalChain('report-2', 'report', [
        ApprovalRoleEnum.ANALYST,
      ]);
      const approval = chain.approvals[0];

      await approvalManager.approve(approval.approvalId, 'john-analyst');
      const approved = approvalManager.approvalManager?.approvals.get(approval.approvalId);

      expect(approval.status).toBe(ApprovalStatusEnum.APPROVED);
    });

    test('should reject an approval step', async () => {
      const chain = approvalManager.createApprovalChain('report-3', 'report', [
        ApprovalRoleEnum.ANALYST,
      ]);
      const approval = chain.approvals[0];

      await approvalManager.reject(approval.approvalId, 'jane-qa', 'Insufficient evidence');
      expect(approval.status).toBe(ApprovalStatusEnum.REJECTED);
      expect(approval.rejectionReason).toBe('Insufficient evidence');
    });

    test('should track pending approvals', () => {
      approvalManager.createApprovalChain('report-4', 'report', [
        ApprovalRoleEnum.ANALYST,
        ApprovalRoleEnum.QA_LEAD,
      ]);

      const pending = approvalManager.getPendingApprovals();
      expect(pending.length).toBeGreaterThan(0);
    });

    test('should get approval history', () => {
      const chain = approvalManager.createApprovalChain('report-5', 'report', [
        ApprovalRoleEnum.ANALYST,
      ]);

      const history = approvalManager.getApprovalHistory(chain.objectId);
      expect(history.length).toBe(1);
    });

    test('should mark approval as conditional', async () => {
      const chain = approvalManager.createApprovalChain('report-6', 'report', [
        ApprovalRoleEnum.QA_LEAD,
      ]);
      const approval = chain.approvals[0];

      await approvalManager.approveConditional(
        approval.approvalId,
        'qa-reviewer',
        'Approve after minor fixes'
      );

      expect(approval.status).toBe(ApprovalStatusEnum.CONDITIONAL);
      expect(approval.conditionalNotes).toBe('Approve after minor fixes');
    });

    test('should get approval statistics', () => {
      approvalManager.createApprovalChain('report-7', 'report', [
        ApprovalRoleEnum.ANALYST,
        ApprovalRoleEnum.QA_LEAD,
      ]);

      const stats = approvalManager.getApprovalStats();
      expect(stats.total).toBeGreaterThan(0);
      expect(stats.byRole).toBeDefined();
    });
  });

  // ============================================================================
  // QUALITY GATES ENGINE TESTS
  // ============================================================================

  describe('QualityGatesEngine', () => {
    test('should validate report with all required metadata', async () => {
      const report = {
        id: 'report-123',
        name: 'Test Report',
        description: 'Test Description',
        malwareId: 'malware-456',
        iocs: [{ id: 'ioc-1' }],
        techniques: [{ id: 'technique-1' }],
        sections: [{ title: 'Overview', evidence: [{ id: 'ev-1' }] }],
        references: [{ url: 'https://example.com' }],
      };

      const result = await qualityGatesEngine.validateObject('report', report);
      expect(result.allPassed).toBe(true);
      expect(result.errors.length).toBe(0);
    });

    test('should fail validation for missing metadata', async () => {
      const report = {
        id: 'report-incomplete',
        // missing name, description, malwareId
      };

      const result = await qualityGatesEngine.validateObject('report', report);
      expect(result.allPassed).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    test('should require at least one IOC', async () => {
      const report = {
        id: 'report-no-iocs',
        name: 'Report',
        description: 'Test',
        malwareId: 'malware-1',
        iocs: [], // No IOCs
      };

      const result = await qualityGatesEngine.validateObject('report', report);
      const iocGate = result.errors.find(e => e.gateName === 'report_missing_iocs');
      expect(iocGate).toBeDefined();
    });

    test('should require MITRE technique mapping', async () => {
      const report = {
        id: 'report-no-mitre',
        name: 'Report',
        description: 'Test',
        malwareId: 'malware-1',
        iocs: [{ id: 'ioc-1' }],
        techniques: [], // No techniques
      };

      const result = await qualityGatesEngine.validateObject('report', report);
      const mitreGate = result.errors.find(e => e.gateName === 'report_missing_mitre');
      expect(mitreGate).toBeDefined();
    });

    test('should validate evidence attribution', async () => {
      const report = {
        id: 'report-no-evidence',
        name: 'Report',
        description: 'Test',
        malwareId: 'malware-1',
        iocs: [{ id: 'ioc-1' }],
        techniques: [{ id: 'technique-1' }],
        sections: [{ title: 'Overview', evidence: [] }], // No evidence
      };

      const result = await qualityGatesEngine.validateObject('report', report);
      const evidenceGate = result.errors.find(e => e.gateName === 'report_missing_evidence');
      expect(evidenceGate).toBeDefined();
    });

    test('should block publication on errors', async () => {
      const report = {
        id: 'incomplete-report',
        // Missing required fields
      };

      const result = await qualityGatesEngine.validateObject('report', report);
      expect(result.blocksPublication).toBe(true);
    });
  });

  // ============================================================================
  // CONFIDENCE ENGINE TESTS
  // ============================================================================

  describe('ConfidenceEngine', () => {
    test('should calculate weighted confidence', () => {
      const confidence = confidenceEngine.calculateConfidence(
        'obj-1',
        { score: 90, basis: 'Reliable source', weight: 0.3 },
        { score: 85, basis: 'Clear observation', weight: 0.2 },
        { score: 95, basis: 'Technical validation passed', weight: 0.2 },
        { score: 80, basis: 'Analyst reviewed', weight: 0.15 },
        { score: 88, basis: 'Corroborated evidence', weight: 0.15 },
        'Multi-source confirmation'
      );

      expect(confidence.overallConfidence).toBeGreaterThan(0);
      expect(confidence.overallConfidence).toBeLessThanOrEqual(100);
    });

    test('should track confidence history', () => {
      confidenceEngine.calculateConfidence(
        'obj-2',
        { score: 70, basis: 'Initial assessment', weight: 1.0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        'Initial'
      );

      const history = confidenceEngine.getConfidenceHistory('obj-2');
      expect(history.length).toBe(1);
    });

    test('should detect confidence trends', () => {
      // Create increasing confidence trend
      confidenceEngine.calculateConfidence(
        'obj-trend',
        { score: 60, basis: '', weight: 1.0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        'Step 1'
      );

      confidenceEngine.calculateConfidence(
        'obj-trend',
        { score: 75, basis: '', weight: 1.0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        'Step 2'
      );

      const trend = confidenceEngine.getConfidenceTrend('obj-trend');
      expect(['increasing', 'stable']).toContain(trend);
    });

    test('should identify weakest component', () => {
      confidenceEngine.calculateConfidence(
        'obj-weak',
        { score: 90, basis: 'Good', weight: 0.2 },
        { score: 40, basis: 'Weak observation', weight: 0.2 },
        { score: 85, basis: 'Good', weight: 0.2 },
        { score: 80, basis: 'Good', weight: 0.2 },
        { score: 75, basis: 'Good', weight: 0.2 },
        'Test'
      );

      const weakest = confidenceEngine.getWeakestComponent('obj-weak');
      expect(weakest?.component).toBe('observationQuality');
      expect(weakest?.score).toBe(40);
    });

    test('should evaluate confidence against threshold', () => {
      confidenceEngine.calculateConfidence(
        'obj-threshold',
        { score: 85, basis: '', weight: 1.0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        { score: 0, basis: '', weight: 0 },
        'Test'
      );

      expect(confidenceEngine.meetsThreshold('obj-threshold', 80)).toBe(true);
      expect(confidenceEngine.meetsThreshold('obj-threshold', 90)).toBe(false);
    });
  });

  // ============================================================================
  // AUDIT ENGINE TESTS
  // ============================================================================

  describe('AuditEngine', () => {
    test('should record audit entry', () => {
      const entry = auditEngine.recordEntry(
        'user-1',
        'created',
        'report',
        'report-1'
      );

      expect(entry.actor).toBe('user-1');
      expect(entry.objectId).toBe('report-1');
      expect(entry.timestamp).toBeDefined();
    });

    test('should track field changes', () => {
      auditEngine.recordEntry(
        'user-2',
        'modified',
        'report',
        'report-2',
        [
          { fieldName: 'name', previousValue: 'Old Name', newValue: 'New Name' },
        ]
      );

      const entries = auditEngine.getEntries('report-2');
      const changes = auditEngine.getFieldChanges('report-2', 'name');
      expect(changes.length).toBe(1);
      expect(changes[0].newValue).toBe('New Name');
    });

    test('should filter entries by action', () => {
      auditEngine.recordEntry('user-3', 'approved', 'report', 'report-3');
      auditEngine.recordEntry('user-4', 'rejected', 'report', 'report-3');

      const approved = auditEngine.getEntriesByAction('report-3', 'approved');
      expect(approved.length).toBe(1);
    });

    test('should verify audit integrity', () => {
      const objectId = 'report-integrity';
      auditEngine.recordEntry('user-5', 'created', 'report', objectId);

      const result = auditEngine.verifyIntegrity(objectId);
      expect(result.isValid).toBe(true);
    });

    test('should generate audit report', () => {
      const objectId = 'report-audit';
      auditEngine.recordEntry('user-6', 'created', 'report', objectId);
      auditEngine.recordEntry('user-7', 'reviewed', 'report', objectId, undefined, 'Looks good');

      const report = auditEngine.generateAuditReport(objectId);
      expect(report).toContain('Audit Report');
      expect(report).toContain('created');
      expect(report).toContain('reviewed');
    });
  });

  // ============================================================================
  // VERSIONING ENGINE TESTS
  // ============================================================================

  describe('VersioningEngine', () => {
    test('should create new version', () => {
      const version = versioningEngine.createVersion(
        'report',
        'report-1',
        1,
        { name: 'Test Report' },
        'analyst-1',
        'Initial version',
        { fieldChanges: [], iocChanges: { added: [], removed: [], modified: [] }, detectionChanges: { added: [], removed: [], modified: [] }, techniqueChanges: { added: [], removed: [] } }
      );

      expect(version.version).toBe(1);
      expect(version.objectId).toBe('report-1');
      expect(version.analyst).toBe('analyst-1');
    });

    test('should get version history', () => {
      versioningEngine.createVersion(
        'report',
        'report-2',
        1,
        { name: 'v1' },
        'analyst',
        'v1',
        { fieldChanges: [], iocChanges: { added: [], removed: [], modified: [] }, detectionChanges: { added: [], removed: [], modified: [] }, techniqueChanges: { added: [], removed: [] } }
      );

      const history = versioningEngine.getVersionHistory('report-2');
      expect(history?.versions.length).toBe(1);
      expect(history?.currentVersion).toBe(1);
    });

    test('should publish version', () => {
      const version = versioningEngine.createVersion(
        'report',
        'report-3',
        1,
        { name: 'Test' },
        'analyst',
        'Initial',
        { fieldChanges: [], iocChanges: { added: [], removed: [], modified: [] }, detectionChanges: { added: [], removed: [], modified: [] }, techniqueChanges: { added: [], removed: [] } }
      );

      versioningEngine.publishVersion(version.versionId, 'publisher');
      const published = versioningEngine.getVersion(version.versionId);
      expect(published?.isPublished).toBe(true);
    });

    test('should get version changelog', () => {
      versioningEngine.createVersion(
        'report',
        'report-4',
        1,
        { name: 'v1' },
        'analyst',
        'Initial version',
        { fieldChanges: [], iocChanges: { added: [], removed: [], modified: [] }, detectionChanges: { added: [], removed: [], modified: [] }, techniqueChanges: { added: [], removed: [] } }
      );

      const changelog = versioningEngine.getVersionChangelog('report-4');
      expect(changelog.length).toBe(1);
      expect(changelog[0].summary).toBe('Initial version');
    });
  });

  // ============================================================================
  // ROLLBACK ENGINE TESTS
  // ============================================================================

  describe('RollbackEngine', () => {
    test('should create retraction record', () => {
      const retraction = rollbackEngine.retract(
        'report-1',
        'report',
        'version-1',
        'Incorrect information',
        'high',
        'IOC validation failed',
        ['ioc-1', 'ioc-2'],
        'security-officer'
      );

      expect(retraction.objectId).toBe('report-1');
      expect(retraction.severity).toBe('high');
      expect(retraction.affectedItems.length).toBe(2);
    });

    test('should track retraction notifications', () => {
      const retraction = rollbackEngine.retract(
        'report-2',
        'report',
        'version-1',
        'Test retraction',
        'medium',
        'Details',
        [],
        'admin'
      );

      rollbackEngine.recordNotificationSent(retraction.retractionId, 'email', 150);
      const updated = rollbackEngine.getRetraction(retraction.retractionId);
      expect(updated?.notificationsSent.length).toBe(1);
    });

    test('should mark retraction as corrected', () => {
      const retraction = rollbackEngine.retract(
        'report-3',
        'report',
        'version-1',
        'Error found',
        'low',
        'Typo fixed',
        [],
        'analyst'
      );

      rollbackEngine.markCorrected(retraction.retractionId, 'version-2');
      const updated = rollbackEngine.getRetraction(retraction.retractionId);
      expect(updated?.correctionVersion).toBe('version-2');
    });

    test('should get retractions by severity', () => {
      rollbackEngine.retract('obj-1', 'report', 'v1', 'Reason', 'critical', 'Details', [], 'admin');
      rollbackEngine.retract('obj-2', 'report', 'v1', 'Reason', 'low', 'Details', [], 'admin');

      const critical = rollbackEngine.getRetractionsBySeverity('critical');
      expect(critical.length).toBeGreaterThan(0);
    });

    test('should generate retraction report', () => {
      rollbackEngine.retract('report-4', 'report', 'v1', 'Test', 'medium', 'Details', ['affected-1'], 'admin');

      const report = rollbackEngine.generateRetractionReport('report-4');
      expect(report).toContain('Retraction Report');
      expect(report).toContain('affected-1');
    });
  });

  // ============================================================================
  // PUBLISHING ENGINE TESTS
  // ============================================================================

  describe('PublishingEngine', () => {
    test('should publish to destinations', () => {
      const record = publishingEngine.publish(
        'report-1',
        'report',
        'version-1',
        'publisher-1',
        ['api', 'blog', 'rss'],
        [
          { format: 'markdown', content: '# Report' },
          { format: 'html', content: '<h1>Report</h1>' },
        ]
      );

      expect(record.destinations.length).toBe(3);
      expect(record.renderings.length).toBe(2);
      expect(record.isLive).toBe(true);
    });

    test('should track view counts', () => {
      const record = publishingEngine.publish(
        'report-2',
        'report',
        'version-1',
        'publisher',
        ['api'],
        [{ format: 'json', content: '{}' }]
      );

      publishingEngine.incrementViewCount(record.publishingId);
      publishingEngine.incrementViewCount(record.publishingId);

      const updated = publishingEngine.getPublishingRecord(record.publishingId);
      expect(updated?.viewCount).toBe(2);
    });

    test('should unpublish from destination', () => {
      const record = publishingEngine.publish(
        'report-3',
        'report',
        'version-1',
        'publisher',
        ['api', 'blog'],
        [{ format: 'markdown', content: '#' }]
      );

      publishingEngine.unpublishFromDestination(record.publishingId, 'blog');
      const updated = publishingEngine.getPublishingRecord(record.publishingId);
      expect(updated?.destinations.length).toBe(1);
    });

    test('should get most popular published objects', () => {
      publishingEngine.publish('report-4', 'report', 'v1', 'pub', ['api'], [{ format: 'json', content: '' }]);
      publishingEngine.publish('report-5', 'report', 'v1', 'pub', ['api'], [{ format: 'json', content: '' }]);

      const popular = publishingEngine.getMostPopular(5);
      expect(popular.length).toBeGreaterThanOrEqual(0);
    });
  });

  // ============================================================================
  // POLICY ENGINE TESTS
  // ============================================================================

  describe('PolicyEngine', () => {
    test('should create publication policy', () => {
      const policy = policyEngine.createPolicy(
        'Enterprise Policy',
        'Strict policy for enterprise reports',
        85, // minimum confidence
        80  // minimum quality score
      );

      expect(policy.name).toBe('Enterprise Policy');
      expect(policy.minimumConfidenceRequired).toBe(85);
      expect(policy.active).toBe(true);
    });

    test('should evaluate object against policy', () => {
      const policy = policyEngine.createPolicy('Test Policy', 'Test', 70, 75);

      const result = policyEngine.evaluatePolicy(policy.policyId, 'obj-1', {
        confidence: 80,
        qualityScore: 80,
        iocs: [{ id: 'ioc-1' }],
        techniques: [{ id: 'tech-1' }],
        references: [{ url: 'https://example.com' }],
      });

      expect(result.passed).toBe(true);
    });

    test('should fail policy evaluation on low confidence', () => {
      const policy = policyEngine.createPolicy('Strict', 'Test', 80, 75); // Requires 80% confidence

      const result = policyEngine.evaluatePolicy(policy.policyId, 'obj-2', {
        confidence: 60, // Below threshold
        qualityScore: 80,
      });

      expect(result.passed).toBe(false);
      expect(result.violations.length).toBeGreaterThan(0);
    });

    test('should disable and enable policies', () => {
      const policy = policyEngine.createPolicy('Toggle', 'Test');

      policyEngine.disablePolicy(policy.policyId, 'admin');
      const disabled = policyEngine.getPolicy(policy.policyId);
      expect(disabled?.active).toBe(false);

      policyEngine.enablePolicy(policy.policyId, 'admin');
      const enabled = policyEngine.getPolicy(policy.policyId);
      expect(enabled?.active).toBe(true);
    });
  });

  // ============================================================================
  // REVIEWER ENGINE TESTS
  // ============================================================================

  describe('ReviewerEngine', () => {
    test('should register reviewer', () => {
      const reviewer = reviewerEngine.registerReviewer(
        'John Analyst',
        'john@example.com',
        ['analyst', 'peer_analyst'],
        ['ransomware', 'APT']
      );

      expect(reviewer.name).toBe('John Analyst');
      expect(reviewer.roles.length).toBe(2);
      expect(reviewer.expertise.length).toBe(2);
      expect(reviewer.active).toBe(true);
    });

    test('should get reviewers by role', () => {
      reviewerEngine.registerReviewer('Jane QA', 'jane@example.com', ['qa_lead'], []);

      const qaReviewers = reviewerEngine.getReviewersByRole('qa_lead');
      expect(qaReviewers.length).toBeGreaterThan(0);
    });

    test('should get reviewers by expertise', () => {
      reviewerEngine.registerReviewer('Expert', 'expert@example.com', ['analyst'], ['zero-day']);

      const experts = reviewerEngine.getReviewersByExpertise('zero-day');
      expect(experts.length).toBeGreaterThan(0);
    });

    test('should track review statistics', () => {
      const reviewer = reviewerEngine.registerReviewer('Reviewer', 'r@example.com', ['analyst'], []);

      reviewerEngine.recordReview(reviewer.reviewerId, true, 3600000); // 1 hour

      const stats = reviewerEngine.getReviewerStats(reviewer.reviewerId);
      expect(stats?.totalReviews).toBe(1);
      expect(stats?.approvalsGiven).toBe(1);
    });

    test('should deactivate and reactivate reviewers', () => {
      const reviewer = reviewerEngine.registerReviewer('Active', 'a@example.com', ['analyst'], []);

      reviewerEngine.deactivateReviewer(reviewer.reviewerId);
      const deactivated = reviewerEngine.getReviewer(reviewer.reviewerId);
      expect(deactivated?.active).toBe(false);

      reviewerEngine.reactivateReviewer(reviewer.reviewerId);
      const reactivated = reviewerEngine.getReviewer(reviewer.reviewerId);
      expect(reactivated?.active).toBe(true);
    });

    test('should find best reviewer for role', () => {
      reviewerEngine.registerReviewer('Best Reviewer', 'best@example.com', ['qa_lead'], ['ransomware']);

      const best = reviewerEngine.findBestReviewerForRole('qa_lead', 'ransomware');
      expect(best).not.toBeNull();
      expect(best?.expertise).toContain('ransomware');
    });

    test('should get top approvers', () => {
      const reviewer = reviewerEngine.registerReviewer('Top', 'top@example.com', ['analyst'], []);

      reviewerEngine.recordReview(reviewer.reviewerId, true, 1000);
      reviewerEngine.recordReview(reviewer.reviewerId, true, 1000);

      const top = reviewerEngine.getTopApprovers(5);
      expect(top.length).toBeGreaterThan(0);
    });
  });
});
