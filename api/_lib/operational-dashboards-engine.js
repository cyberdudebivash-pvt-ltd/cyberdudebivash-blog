'use strict';

class OperationalDashboardsEngine {
  constructor(queueEngine, analystEngine, calendarEngine, schedulerEngine, metricsEngine) {
    this.queueEngine = queueEngine;
    this.analystEngine = analystEngine;
    this.calendarEngine = calendarEngine;
    this.schedulerEngine = schedulerEngine;
    this.metricsEngine = metricsEngine;
  }

  getEditorDashboard() {
    const queue = this.queueEngine?.getProductionQueue() || {};
    const calendar = this.calendarEngine?.getCalendarView(new Date().toISOString(), new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()) || {};

    return {
      role: 'editor',
      timestamp: new Date().toISOString(),
      widgets: {
        activeQueue: {
          title: 'Items In Progress',
          total: queue.total || 0,
          byState: queue.grouped || {},
          bottlenecks: queue.queueStatus?.bottlenecks || [],
        },
        upcomingPublications: {
          title: 'Scheduled Publications (Next 30 Days)',
          eventCount: calendar.events?.length || 0,
          events: (calendar.events || []).slice(0, 10),
          capacityWarnings: calendar.capacityWarnings || [],
        },
        workloadDistribution: {
          title: 'Editor Workload',
          distribution: calendar.workloadDistribution || {},
        },
        recentPublications: {
          title: 'Recent Publications',
          items: this.getRecentPublications(7),
        },
      },
      actionItems: this.generateEditorActionItems(queue, calendar),
    };
  }

  getAnalystDashboard(analystId) {
    const workload = this.analystEngine?.getAnalystWorkload(analystId) || {};
    const upcomingAssignments = this.getUpcomingAssignments(analystId);
    const recentMetrics = this.getAnalystMetrics(analystId);

    return {
      role: 'analyst',
      analyst: analystId,
      timestamp: new Date().toISOString(),
      widgets: {
        currentWorkload: {
          title: 'Current Workload',
          capacity: workload.capacity || 0,
          currentWorkload: workload.currentWorkload || 0,
          utilizationRate: workload.utilizationRate || 0,
          status: workload.capacity_status || 'normal',
          assignedItems: workload.assignments || [],
        },
        upcomingWork: {
          title: 'Upcoming Assignments',
          assignments: upcomingAssignments,
        },
        performanceMetrics: {
          title: 'My Performance',
          completionRate: recentMetrics.completionRate || 0,
          avgCompletionTime: recentMetrics.avgCompletionTime || 0,
          totalAssignments: recentMetrics.totalAssignments || 0,
          completedAssignments: recentMetrics.completedAssignments || 0,
        },
        skillMatrix: {
          title: 'Skills & Specializations',
          specialization: recentMetrics.specialization || '',
          skills: this.getAnalystSkills(analystId),
        },
      },
      actionItems: this.generateAnalystActionItems(workload),
    };
  }

  getManagerDashboard() {
    const queue = this.queueEngine?.getProductionQueue() || {};
    const teamCapacity = this.analystEngine?.getTeamCapacity() || {};
    const metrics = this.metricsEngine?.getEditorialMetricsReport(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), new Date().toISOString()) || {};

    return {
      role: 'manager',
      timestamp: new Date().toISOString(),
      widgets: {
        teamCapacity: {
          title: 'Team Capacity Status',
          teamSize: teamCapacity.teamSize || 0,
          totalCapacity: teamCapacity.totalCapacity || 0,
          totalUtilization: teamCapacity.totalUtilization || 0,
          utilizationRate: teamCapacity.utilizationRate || 0,
          status: teamCapacity.status || 'normal',
          availableCapacity: teamCapacity.availableCapacity || 0,
          members: teamCapacity.members || [],
        },
        queueHealth: {
          title: 'Production Queue Health',
          totalInFlight: queue.queueStatus?.totalInFlight || 0,
          byState: queue.grouped || {},
          bottlenecks: queue.queueStatus?.bottlenecks || [],
          averageTimeInQueue: queue.queueStatus?.averageTimeInQueue || 0,
        },
        teamMetrics: {
          title: 'Team Performance (Last 30 Days)',
          totalPublished: metrics.throughput?.totalPublished || 0,
          perWeek: metrics.throughput?.perWeek || 0,
          averageQuality: metrics.quality?.averageScore || 0,
          distribution: metrics.distribution || {},
        },
        skillGaps: {
          title: 'Skill Gaps',
          gaps: this.analystEngine?.identifySkillGaps(['detection_engineering', 'technical_analysis', 'editorial_review']) || [],
        },
      },
      actionItems: this.generateManagerActionItems(queue, teamCapacity),
    };
  }

  getExecutiveDashboard() {
    const queue = this.queueEngine?.getProductionQueue() || {};
    const publications = this.schedulerEngine?.getScheduledPublications() || {};
    const metrics = this.metricsEngine?.getEditorialMetricsReport(new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(), new Date().toISOString()) || {};
    const teamCapacity = this.analystEngine?.getTeamCapacity() || {};

    return {
      role: 'executive',
      timestamp: new Date().toISOString(),
      widgets: {
        operationalStatus: {
          title: 'Operational Health',
          itemsInQueue: queue.total || 0,
          averageTimeInQueue: queue.queueStatus?.averageTimeInQueue || 0,
          bottleneckCount: queue.queueStatus?.bottlenecks?.length || 0,
          status: this.assessOperationalHealth(queue),
        },
        publicationPipeline: {
          title: 'Publication Pipeline',
          upcomingPublications: publications.upcoming || 0,
          readyToPublish: publications.readyToPublish?.length || 0,
          scheduledToday: this.countTodaysPublications(publications),
        },
        keyMetrics: {
          title: 'Key Performance Indicators',
          published30Days: metrics.throughput?.totalPublished || 0,
          avgPublicationsPerWeek: metrics.throughput?.perWeek || 0,
          contentQuality: metrics.quality?.averageScore || 0,
          teamUtilization: teamCapacity.utilizationRate || 0,
        },
        riskAssessment: {
          title: 'Risk Assessment',
          overBookedAnalysts: this.countOverBookedAnalysts(teamCapacity),
          stallledItems: this.countStalledQueueItems(queue),
          criticalBottlenecks: queue.queueStatus?.bottlenecks?.filter(b => b.itemCount > 10) || [],
        },
      },
      insights: this.generateExecutiveInsights(queue, publications, metrics, teamCapacity),
    };
  }

  getRecentPublications(days = 7) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);

    const events = this.metricsEngine?.publishingEvents || [];
    return events
      .filter(e => new Date(e.publishedAt) >= cutoff)
      .sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt))
      .slice(0, 10);
  }

  getUpcomingAssignments(analystId) {
    return [];
  }

  getAnalystMetrics(analystId) {
    return this.analystEngine?.getAnalystMetrics(analystId) || {};
  }

  getAnalystSkills(analystId) {
    const analyst = this.analystEngine?.analysts?.get(analystId);
    return analyst?.skillMatrix || {};
  }

  generateEditorActionItems(queue, calendar) {
    const items = [];

    if (queue.queueStatus?.bottlenecks?.length > 0) {
      items.push({
        type: 'warning',
        action: 'Address bottlenecks',
        details: `${queue.queueStatus.bottlenecks.length} bottleneck(s) detected`,
        priority: 'high',
      });
    }

    if (calendar.capacityWarnings?.length > 0) {
      items.push({
        type: 'warning',
        action: 'Manage overloaded dates',
        details: `${calendar.capacityWarnings.length} date(s) overloaded`,
        priority: 'medium',
      });
    }

    if (queue.grouped?.draft?.length > 5) {
      items.push({
        type: 'info',
        action: 'Review drafts',
        details: `${queue.grouped.draft.length} items awaiting analysis`,
        priority: 'normal',
      });
    }

    return items;
  }

  generateAnalystActionItems(workload) {
    const items = [];

    if (workload.capacity_status === 'overbooked') {
      items.push({
        type: 'critical',
        action: 'Workload exceeds capacity',
        details: `${workload.utilizationRate}% utilization`,
        priority: 'critical',
      });
    }

    if (workload.capacity_status === 'high') {
      items.push({
        type: 'warning',
        action: 'High workload',
        details: `${workload.utilizationRate}% utilization`,
        priority: 'high',
      });
    }

    return items;
  }

  generateManagerActionItems(queue, teamCapacity) {
    const items = [];

    if (queue.queueStatus?.bottlenecks?.length > 0) {
      items.push({
        type: 'warning',
        action: 'Resolve queue bottlenecks',
        details: JSON.stringify(queue.queueStatus.bottlenecks),
        priority: 'high',
      });
    }

    if (teamCapacity.status === 'overbooked') {
      items.push({
        type: 'warning',
        action: 'Redistribute team workload',
        details: `Team is ${teamCapacity.utilizationRate}% utilized`,
        priority: 'high',
      });
    }

    const overBookedAnalysts = (teamCapacity.members || []).filter(m => parseFloat(m.utilization) > 100);
    if (overBookedAnalysts.length > 0) {
      items.push({
        type: 'warning',
        action: 'Address overbooked analysts',
        details: `${overBookedAnalysts.length} analyst(s) over capacity`,
        priority: 'high',
      });
    }

    return items;
  }

  generateExecutiveInsights(queue, publications, metrics, teamCapacity) {
    const insights = [];

    if (queue.queueStatus?.bottlenecks?.length > 0) {
      insights.push(`⚠️ Production pipeline has ${queue.queueStatus.bottlenecks.length} bottleneck(s) — escalation recommended`);
    }

    if (teamCapacity.status === 'overbooked') {
      insights.push(`⚠️ Team utilization is critical (${teamCapacity.utilizationRate}%) — resource expansion recommended`);
    }

    if (metrics.throughput?.totalPublished === 0) {
      insights.push(`📉 No publications in the measured period — review strategy`);
    } else if (metrics.throughput?.perWeek < 1) {
      insights.push(`📉 Low publication velocity (${metrics.throughput.perWeek}/week) — consider capacity adjustment`);
    }

    if (metrics.quality?.averageScore >= 85) {
      insights.push(`✅ Content quality is excellent (${metrics.quality.averageScore}/100)`);
    } else if (metrics.quality?.averageScore < 70) {
      insights.push(`⚠️ Content quality is below target (${metrics.quality.averageScore}/100) — review processes`);
    }

    return insights;
  }

  assessOperationalHealth(queue) {
    const bottleneckCount = queue.queueStatus?.bottlenecks?.length || 0;
    const timeInQueue = parseFloat(queue.queueStatus?.averageTimeInQueue || 0);

    if (bottleneckCount > 2 || timeInQueue > 48) return 'critical';
    if (bottleneckCount > 0 || timeInQueue > 24) return 'warning';
    return 'healthy';
  }

  countTodaysPublications(publications) {
    const today = new Date().toISOString().split('T')[0];
    return (publications.all || []).filter(p => p.publishAt.startsWith(today)).length;
  }

  countOverBookedAnalysts(teamCapacity) {
    return (teamCapacity.members || []).filter(m => parseFloat(m.utilization) > 100).length;
  }

  countStalledQueueItems(queue) {
    return (queue.grouped?.monitoring || []).length + (queue.grouped?.revision || []).length;
  }
}

module.exports = { OperationalDashboardsEngine };
