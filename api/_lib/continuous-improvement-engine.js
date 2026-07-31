'use strict';

class ContinuousImprovementEngine {
  constructor() {
    this.recommendations = new Map();
    this.problemAreas = [];
    this.improvements = [];
  }

  analyzeQueueBottlenecks(queue) {
    const problems = [];

    if (queue.grouped?.underReview?.length > 5) {
      problems.push({
        id: `bottleneck_review_${Date.now()}`,
        area: 'review_queue',
        severity: 'high',
        description: `Review stage has ${queue.grouped.underReview.length} items — potential bottleneck`,
        metrics: {
          itemCount: queue.grouped.underReview.length,
          threshold: 5,
          exceededBy: queue.grouped.underReview.length - 5,
        },
        rootCauses: [
          'Insufficient reviewer capacity',
          'Complex items requiring extended review',
          'Reviewer availability constraints',
        ],
        recommendations: this.generateReviewBottleneckRecommendations(queue.grouped.underReview.length),
      });
    }

    if (queue.queueStatus?.averageTimeInQueue > 48) {
      problems.push({
        id: `bottleneck_time_${Date.now()}`,
        area: 'cycle_time',
        severity: 'high',
        description: `Average time in queue is ${queue.queueStatus.averageTimeInQueue} hours — exceeds target`,
        metrics: {
          currentAverage: queue.queueStatus.averageTimeInQueue,
          targetAverage: 24,
          excess: queue.queueStatus.averageTimeInQueue - 24,
        },
        rootCauses: [
          'Items waiting in draft/analysis states',
          'Review process delays',
          'Approval bottlenecks',
        ],
        recommendations: this.generateCycleTimeRecommendations(queue),
      });
    }

    return problems;
  }

  analyzeQualityTrends(qualityMetrics) {
    const problems = [];

    if (qualityMetrics.averageScore < 70) {
      problems.push({
        id: `quality_low_${Date.now()}`,
        area: 'content_quality',
        severity: 'high',
        description: `Average quality score is ${qualityMetrics.averageScore}/100 — below target of 85`,
        metrics: {
          currentAverage: qualityMetrics.averageScore,
          targetAverage: 85,
          gap: 85 - qualityMetrics.averageScore,
        },
        weakAreas: this.identifyWeakQualityFactors(qualityMetrics.factorAverages),
        recommendations: this.generateQualityImprovementRecommendations(qualityMetrics),
      });
    }

    return problems;
  }

  analyzeTeamCapacity(teamCapacity) {
    const problems = [];

    if (teamCapacity.status === 'overbooked') {
      problems.push({
        id: `capacity_overbooked_${Date.now()}`,
        area: 'team_capacity',
        severity: 'critical',
        description: `Team utilization is ${teamCapacity.utilizationRate}% — exceeds 100% capacity`,
        metrics: {
          totalCapacity: teamCapacity.totalCapacity,
          totalUtilization: teamCapacity.totalUtilization,
          utilizationRate: teamCapacity.utilizationRate,
          exceededBy: teamCapacity.totalUtilization - teamCapacity.totalCapacity,
        },
        overBookedMembers: teamCapacity.members?.filter(m => parseFloat(m.utilization) > 100) || [],
        recommendations: this.generateCapacityRecommendations(teamCapacity),
      });
    } else if (teamCapacity.status === 'high') {
      problems.push({
        id: `capacity_high_${Date.now()}`,
        area: 'team_capacity',
        severity: 'medium',
        description: `Team utilization is ${teamCapacity.utilizationRate}% — approaching capacity limits`,
        metrics: {
          totalCapacity: teamCapacity.totalCapacity,
          totalUtilization: teamCapacity.totalUtilization,
          utilizationRate: teamCapacity.utilizationRate,
          bufferRemaining: 100 - teamCapacity.utilizationRate,
        },
        recommendations: this.generateCapacityRecommendations(teamCapacity),
      });
    }

    return problems;
  }

  analyzeThroughputTrends(metrics) {
    const problems = [];

    if (metrics.throughput?.perWeek < 1) {
      problems.push({
        id: `throughput_low_${Date.now()}`,
        area: 'publication_throughput',
        severity: 'medium',
        description: `Publication velocity is ${metrics.throughput.perWeek}/week — below expected rate`,
        metrics: {
          currentRate: metrics.throughput.perWeek,
          targetRate: 2,
          gap: 2 - metrics.throughput.perWeek,
        },
        rootCauses: [
          'Team capacity constraints',
          'Extended cycle times',
          'Quality review delays',
        ],
        recommendations: this.generateThroughputRecommendations(metrics),
      });
    }

    return problems;
  }

  generateReviewBottleneckRecommendations(itemCount) {
    return [
      {
        priority: 'high',
        action: 'Increase reviewer capacity',
        details: `Allocate additional technical and editorial reviewers to reduce backlog`,
        estimatedImpact: 'Reduce review queue by 50%',
      },
      {
        priority: 'high',
        action: 'Implement parallel review',
        details: `Enable concurrent technical and editorial reviews instead of sequential`,
        estimatedImpact: 'Reduce review time by 30%',
      },
      {
        priority: 'medium',
        action: 'Establish review guidelines',
        details: `Create standardized review checklist to accelerate decision-making`,
        estimatedImpact: 'Reduce review time by 15%',
      },
      {
        priority: 'low',
        action: 'Prioritize critical items',
        details: `Fast-track high-priority intelligence through review pipeline`,
        estimatedImpact: 'Improve time-to-publication for urgent content',
      },
    ];
  }

  generateCycleTimeRecommendations(queue) {
    return [
      {
        priority: 'high',
        action: 'Analyze bottleneck stages',
        details: `Identify which stages (draft, analysis, review) are causing delays`,
        estimatedImpact: 'Pinpoint problem areas for targeted improvement',
      },
      {
        priority: 'high',
        action: 'Streamline approval workflow',
        details: `Implement automated approval for low-risk items`,
        estimatedImpact: 'Reduce cycle time by 20%',
      },
      {
        priority: 'medium',
        action: 'Improve handoff efficiency',
        details: `Reduce wait time between workflow states`,
        estimatedImpact: 'Reduce cycle time by 10%',
      },
    ];
  }

  generateQualityImprovementRecommendations(metrics) {
    return [
      {
        priority: 'high',
        action: 'Focus on weakest quality factors',
        details: `Invest in training for lowest-performing quality dimensions`,
        estimatedImpact: 'Improve overall score by 10-15 points',
      },
      {
        priority: 'high',
        action: 'Establish quality standards',
        details: `Define clear quality criteria for each content type`,
        estimatedImpact: 'Create consistency and reduce variance',
      },
      {
        priority: 'medium',
        action: 'Implement quality gates',
        details: `Add automated quality checks at review stage`,
        estimatedImpact: 'Catch quality issues early, reduce rework',
      },
    ];
  }

  generateCapacityRecommendations(teamCapacity) {
    return [
      {
        priority: 'high',
        action: 'Hire additional analysts',
        details: `Expand team by ${Math.ceil((teamCapacity.totalUtilization - teamCapacity.totalCapacity) / 40)} FTE to meet demand`,
        estimatedImpact: `Reduce utilization to 85-90%`,
      },
      {
        priority: 'high',
        action: 'Cross-train team members',
        details: `Develop secondary skills to increase flexibility`,
        estimatedImpact: 'Improve capacity utilization and resilience',
      },
      {
        priority: 'medium',
        action: 'Implement workload balancing',
        details: `Redistribute assignments to level utilization across team`,
        estimatedImpact: 'Reduce individual overload, improve morale',
      },
      {
        priority: 'medium',
        action: 'Review prioritization policy',
        details: `Ensure highest-value work is prioritized`,
        estimatedImpact: 'Maximize output of limited capacity',
      },
    ];
  }

  generateThroughputRecommendations(metrics) {
    return [
      {
        priority: 'high',
        action: 'Accelerate cycle time',
        details: `Reduce time from initiation to publication`,
        estimatedImpact: 'Enable more publications per resource',
      },
      {
        priority: 'high',
        action: 'Automate routine tasks',
        details: `Implement templating and automation for standard content`,
        estimatedImpact: 'Free 20% analyst time for other work',
      },
      {
        priority: 'medium',
        action: 'Establish publication schedule',
        details: `Commit to regular publication cadence`,
        estimatedImpact: 'Build audience expectations and SEO impact',
      },
    ];
  }

  identifyWeakQualityFactors(factors) {
    const weaknesses = [];

    Object.entries(factors).forEach(([factor, score]) => {
      if (score < 70) {
        weaknesses.push({
          factor,
          score,
          gap: 85 - score,
        });
      }
    });

    return weaknesses.sort((a, b) => a.score - b.score);
  }

  findProblemAreas(queue, qualityMetrics, teamCapacity, metrics) {
    const problems = [];

    problems.push(...this.analyzeQueueBottlenecks(queue));
    problems.push(...this.analyzeQualityTrends(qualityMetrics));
    problems.push(...this.analyzeTeamCapacity(teamCapacity));
    problems.push(...this.analyzeThroughputTrends(metrics));

    return problems.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
  }

  generateImprovementPlan(problems) {
    const plan = {
      generatedAt: new Date().toISOString(),
      problemsIdentified: problems.length,
      criticalCount: problems.filter(p => p.severity === 'critical').length,
      highCount: problems.filter(p => p.severity === 'high').length,
      mediumCount: problems.filter(p => p.severity === 'medium').length,
      lowCount: problems.filter(p => p.severity === 'low').length,
      recommendedActions: [],
    };

    const actionMap = new Map();

    problems.forEach(problem => {
      (problem.recommendations || []).forEach(rec => {
        const key = rec.action;
        if (!actionMap.has(key)) {
          actionMap.set(key, {
            action: rec.action,
            details: rec.details,
            priority: rec.priority,
            frequency: 1,
            fromProblems: [problem.id],
          });
        } else {
          const existing = actionMap.get(key);
          existing.frequency++;
          existing.fromProblems.push(problem.id);
        }
      });
    });

    plan.recommendedActions = Array.from(actionMap.values())
      .sort((a, b) => {
        const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        if (priorityOrder[a.priority] !== priorityOrder[b.priority]) {
          return priorityOrder[a.priority] - priorityOrder[b.priority];
        }
        return b.frequency - a.frequency;
      });

    return plan;
  }

  trackImprovement(improvement) {
    const tracked = {
      id: `improvement_${Date.now()}`,
      action: improvement.action,
      status: 'planned',
      startDate: null,
      completionDate: null,
      owner: improvement.owner || null,
      expectedImpact: improvement.expectedImpact || null,
      actualImpact: null,
      createdAt: new Date().toISOString(),
    };

    this.improvements.push(tracked);
    return tracked;
  }

  recordImprovementProgress(improvementId, status, notes) {
    const improvement = this.improvements.find(i => i.id === improvementId);
    if (!improvement) throw new Error(`Improvement not found: ${improvementId}`);

    improvement.status = status;
    if (status === 'in_progress' && !improvement.startDate) {
      improvement.startDate = new Date().toISOString();
    }
    if (status === 'completed' && !improvement.completionDate) {
      improvement.completionDate = new Date().toISOString();
    }
    if (notes) {
      improvement.notes = notes;
    }

    return improvement;
  }

  getImprovementMetrics() {
    const total = this.improvements.length;
    const completed = this.improvements.filter(i => i.status === 'completed').length;
    const inProgress = this.improvements.filter(i => i.status === 'in_progress').length;
    const planned = this.improvements.filter(i => i.status === 'planned').length;

    return {
      total,
      completed,
      inProgress,
      planned,
      completionRate: total > 0 ? ((completed / total) * 100).toFixed(1) : 0,
      improvements: this.improvements,
    };
  }
}

module.exports = { ContinuousImprovementEngine };
