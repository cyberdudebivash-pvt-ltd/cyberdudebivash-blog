'use strict';

const { EditorialCalendarEngine } = require('./editorial-calendar-engine');
const { ProductionQueueEngine } = require('./production-queue-engine');
const { AnalystAssignmentEngine } = require('./analyst-assignment-engine');
const { PublicationSchedulerEngine } = require('./publication-scheduler-engine');
const { IntelligencMaintenanceEngine } = require('./intelligence-maintenance-engine');
const { IntelligenceRetirementEngine } = require('./intelligence-retirement-engine');
const { ProductReleaseManagementEngine } = require('./product-release-management-engine');
const { EditorialMetricsEngine } = require('./editorial-metrics-engine');
const { OperationalDashboardsEngine } = require('./operational-dashboards-engine');
const { ContinuousImprovementEngine } = require('./continuous-improvement-engine');

class Phase10Orchestrator {
  constructor() {
    this.calendar = new EditorialCalendarEngine();
    this.queue = new ProductionQueueEngine();
    this.analysts = new AnalystAssignmentEngine();
    this.scheduler = new PublicationSchedulerEngine();
    this.maintenance = new IntelligencMaintenanceEngine();
    this.retirement = new IntelligenceRetirementEngine();
    this.releases = new ProductReleaseManagementEngine();
    this.metrics = new EditorialMetricsEngine();
    this.dashboards = new OperationalDashboardsEngine(
      this.queue,
      this.analysts,
      this.calendar,
      this.scheduler,
      this.metrics
    );
    this.improvement = new ContinuousImprovementEngine();
  }

  async manageProductionWorkflow(product, investigation, report, productType = 'report') {
    try {
      const queueItem = this.queue.createQueueItem(investigation, report.id);

      return {
        queueItemId: queueItem.id,
        status: 'initialized',
        workflow: {
          currentState: queueItem.currentState,
          dueDate: queueItem.dueDate,
          assignments: queueItem.assignments,
        },
      };
    } catch (e) {
      console.warn(`[PHASE 10] Workflow initialization failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async planPublicationStrategy(investigation, report, distributionConfig = {}) {
    try {
      const schedule = this.scheduler.schedulePublication(report.id, {
        type: distributionConfig.type || 'scheduled',
        title: investigation.title,
        classification: investigation.classification || 'TLP:AMBER',
        channels: distributionConfig.channels || ['blog', 'api', 'newsletter'],
        regions: distributionConfig.regions || ['global'],
        customerSegments: distributionConfig.customerSegments || [],
      });

      return {
        scheduleId: schedule.id,
        publishAt: schedule.publishAt,
        type: schedule.type,
        distribution: schedule.distribution,
        status: 'scheduled',
      };
    } catch (e) {
      console.warn(`[PHASE 10] Publication strategy failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async coordinateAnalystAssignment(queueItemId, requiredRoles, preferredSpecialization = null) {
    try {
      const assignments = {};

      for (const role of requiredRoles) {
        const suggestion = this.analysts.suggestAssignee(queueItemId, role, preferredSpecialization);

        if (suggestion.suggestion) {
          const assignment = this.analysts.assignToItem(
            queueItemId,
            suggestion.suggestion.analyst,
            role
          );
          assignments[role] = assignment;
        }
      }

      return {
        queueItemId,
        assignmentCount: Object.keys(assignments).length,
        assignments,
      };
    } catch (e) {
      console.warn(`[PHASE 10] Assignment coordination failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async transitionWorkflowState(queueItemId, newState, actor, reason = '') {
    try {
      const transition = this.queue.transitionState(queueItemId, newState, actor, reason);

      return {
        queueItemId,
        transitioned: {
          from: transition.previousState,
          to: transition.newState,
          timestamp: transition.transitionTime,
        },
      };
    } catch (e) {
      console.warn(`[PHASE 10] Workflow transition failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async recordIntelligenceUpdate(reportId, changeType, previousData, updatedData, actor, reason = '') {
    try {
      const revision = this.maintenance.createIntelligenceRevision(
        reportId,
        changeType,
        previousData,
        updatedData,
        actor,
        reason
      );

      return {
        revisionId: revision.id,
        reportId,
        changeType,
        status: revision.status,
        timestamp: revision.timestamp,
      };
    } catch (e) {
      console.warn(`[PHASE 10] Intelligence update failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async getEditorialMetricsReport(startDate, endDate) {
    try {
      const report = this.metrics.getEditorialMetricsReport(startDate, endDate);

      return {
        period: report.period,
        generatedAt: report.generatedAt,
        metrics: {
          throughput: report.throughput,
          quality: report.quality,
          distribution: report.distribution,
        },
        insights: report.insights,
      };
    } catch (e) {
      console.warn(`[PHASE 10] Metrics report failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async getDashboard(role, userId = null) {
    try {
      let dashboard;

      switch (role) {
        case 'editor':
          dashboard = this.dashboards.getEditorDashboard();
          break;
        case 'analyst':
          dashboard = this.dashboards.getAnalystDashboard(userId);
          break;
        case 'manager':
          dashboard = this.dashboards.getManagerDashboard();
          break;
        case 'executive':
          dashboard = this.dashboards.getExecutiveDashboard();
          break;
        default:
          throw new Error(`Unknown role: ${role}`);
      }

      return {
        role,
        dashboard,
        timestamp: new Date().toISOString(),
      };
    } catch (e) {
      console.warn(`[PHASE 10] Dashboard generation failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async generateImprovementRecommendations(analysisOptions = {}) {
    try {
      const queue = this.queue.getProductionQueue();
      const teamCapacity = this.analysts.getTeamCapacity();
      const qualityMetrics = this.metrics.getAverageQuality(
        new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        new Date().toISOString()
      );
      const throughput = this.metrics.calculateThroughput(
        new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        new Date().toISOString()
      );

      const problems = this.improvement.findProblemAreas(queue, qualityMetrics, teamCapacity, {
        throughput,
      });

      const plan = this.improvement.generateImprovementPlan(problems);

      return {
        problemsIdentified: problems,
        improvementPlan: plan,
        timestamp: new Date().toISOString(),
      };
    } catch (e) {
      console.warn(`[PHASE 10] Improvement analysis failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async retireIntelligence(reportId, retirementType, reason, actor, replacementReportId = null) {
    try {
      let retirement;

      switch (retirementType) {
        case 'archive':
          retirement = this.retirement.archiveIntelligence(reportId, reason, actor);
          break;
        case 'supersede':
          retirement = this.retirement.supersede(reportId, replacementReportId, reason, actor);
          break;
        case 'withdraw':
          retirement = this.retirement.withdrawIntelligence(reportId, reason, actor);
          break;
        case 'retract':
          retirement = this.retirement.retractIntelligence(reportId, reason, actor);
          break;
        case 'deprecate':
          retirement = this.retirement.deprecateIntelligence(reportId, reason, actor, replacementReportId);
          break;
        default:
          throw new Error(`Unknown retirement type: ${retirementType}`);
      }

      return {
        reportId,
        retirementId: retirement.id,
        status: retirement.status,
        timestamp: retirement.timestamp,
        lineage: this.retirement.getLineage(reportId),
      };
    } catch (e) {
      console.warn(`[PHASE 10] Intelligence retirement failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async createProductRelease(reportId, versionNumber, changes, releaseNotes, actor) {
    try {
      const version = this.releases.createProductVersion(reportId, versionNumber, 'report', changes, actor);

      const release = this.releases.releaseVersion(version.id, releaseNotes, actor);

      return {
        versionId: version.id,
        versionNumber,
        releaseId: release.id,
        status: 'released',
        releaseDate: release.releaseDate,
      };
    } catch (e) {
      console.warn(`[PHASE 10] Release creation failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async validatePhase10Integration(product, investigation, report) {
    try {
      const validation = {
        product: {
          id: product.id,
          type: product.type,
        },
        workflowManagement: this.queue.createQueueItem(investigation, report.id) ? true : false,
        publishingCapability: this.scheduler.schedulePublication(report.id, {}) ? true : false,
        analyticsSupport: this.analysts.analysts.size > 0 ? true : false,
        maintenanceTracking: this.maintenance.revisions.size > 0 ? true : false,
        retirementSupport: this.retirement.retirements.size > 0 ? true : false,
        releaseManagement: this.releases.versions.size > 0 ? true : false,
        metricsCapture: this.metrics.publishingEvents.length >= 0 ? true : false,
      };

      const allComponentsReady = Object.values(validation).every(v => v === true);

      return {
        phase10Orchestrator: 'operational',
        componentsReady: validation,
        status: allComponentsReady ? 'ready' : 'partial',
      };
    } catch (e) {
      console.warn(`[PHASE 10] Integration validation failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async enhanceProductWithOperationalContext(product, investigation, report) {
    try {
      const enhancements = {
        workflowManagement: await this.manageProductionWorkflow(product, investigation, report),
        publicationStrategy: await this.planPublicationStrategy(investigation, report),
        operationalMetadata: {
          phase10Enabled: true,
          orchestratorVersion: '1.0',
          capabilities: [
            'workflow_management',
            'publication_scheduling',
            'analyst_assignment',
            'maintenance_tracking',
            'retirement_management',
            'release_management',
            'metrics_capture',
            'dashboard_support',
            'continuous_improvement',
          ],
        },
      };

      product.phase10Enhancements = enhancements;

      return {
        product,
        enhancements,
        status: 'enhanced',
      };
    } catch (e) {
      console.warn(`[PHASE 10] Product enhancement failed gracefully: ${e.message}`);
      return { product, status: 'error', message: e.message };
    }
  }
}

module.exports = { Phase10Orchestrator };
