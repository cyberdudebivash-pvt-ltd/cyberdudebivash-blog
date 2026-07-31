'use strict';

class ProductionQueueEngine {
  constructor() {
    this.queue = new Map();
    this.stateHistory = new Map();
    this.workflowStates = {
      DRAFT: 'draft',
      ANALYSIS: 'analysis',
      TECHNICAL_REVIEW: 'technical_review',
      EDITORIAL_REVIEW: 'editorial_review',
      LEGAL_COMPLIANCE: 'legal_compliance',
      EXECUTIVE_APPROVAL: 'executive_approval',
      PUBLICATION: 'publication',
      MONITORING: 'monitoring',
      REVISION: 'revision',
      RETIREMENT: 'retirement',
    };
  }

  createQueueItem(investigation, reportId) {
    const queueItem = {
      id: `queue_${reportId}`,
      investigationId: investigation.id,
      reportId,
      title: investigation.title,
      currentState: this.workflowStates.DRAFT,
      stateHistory: [
        {
          state: this.workflowStates.DRAFT,
          timestamp: new Date().toISOString(),
          actor: 'system',
        },
      ],
      assignments: {},
      dueDate: null,
      priority: 'normal',
      reviewComments: [],
      metadata: {
        createdAt: new Date().toISOString(),
        lastUpdated: new Date().toISOString(),
        estimatedReviewHours: 8,
      },
    };

    this.queue.set(queueItem.id, queueItem);
    this.stateHistory.set(queueItem.id, [queueItem.stateHistory[0]]);

    return queueItem;
  }

  getProductionQueue(filters = {}) {
    const queue = Array.from(this.queue.values());

    let filtered = queue;

    if (filters.state) {
      filtered = filtered.filter(item => item.currentState === filters.state);
    }

    if (filters.analyst) {
      filtered = filtered.filter(item =>
        Object.values(item.assignments).some(a => a.analyst === filters.analyst)
      );
    }

    if (filters.priority) {
      filtered = filtered.filter(item => item.priority === filters.priority);
    }

    const grouped = {
      draft: filtered.filter(i => i.currentState === this.workflowStates.DRAFT),
      underAnalysis: filtered.filter(i => i.currentState === this.workflowStates.ANALYSIS),
      underReview: filtered.filter(i =>
        [this.workflowStates.TECHNICAL_REVIEW, this.workflowStates.EDITORIAL_REVIEW].includes(i.currentState)
      ),
      awaitingApproval: filtered.filter(i =>
        [this.workflowStates.LEGAL_COMPLIANCE, this.workflowStates.EXECUTIVE_APPROVAL].includes(i.currentState)
      ),
      readyForPublication: filtered.filter(i => i.currentState === this.workflowStates.PUBLICATION),
      monitoring: filtered.filter(i => i.currentState === this.workflowStates.MONITORING),
      underRevision: filtered.filter(i => i.currentState === this.workflowStates.REVISION),
    };

    return {
      total: filtered.length,
      grouped,
      queueStatus: this.calculateQueueStatus(grouped),
    };
  }

  transitionState(queueItemId, newState, actor, reason = '') {
    const item = this.queue.get(queueItemId);
    if (!item) throw new Error(`Queue item not found: ${queueItemId}`);

    const oldState = item.currentState;
    const isValidTransition = this.isValidStateTransition(oldState, newState);

    if (!isValidTransition) {
      throw new Error(`Invalid transition from ${oldState} to ${newState}`);
    }

    item.currentState = newState;
    item.metadata.lastUpdated = new Date().toISOString();

    const stateChange = {
      from: oldState,
      to: newState,
      timestamp: new Date().toISOString(),
      actor,
      reason,
    };

    item.stateHistory.push(stateChange);
    this.stateHistory.get(queueItemId).push(stateChange);

    return {
      queueItemId,
      previousState: oldState,
      newState,
      transitionTime: stateChange.timestamp,
      actor,
    };
  }

  isValidStateTransition(from, to) {
    const transitions = {
      [this.workflowStates.DRAFT]: [this.workflowStates.ANALYSIS, this.workflowStates.RETIREMENT],
      [this.workflowStates.ANALYSIS]: [
        this.workflowStates.TECHNICAL_REVIEW,
        this.workflowStates.DRAFT,
        this.workflowStates.REVISION,
      ],
      [this.workflowStates.TECHNICAL_REVIEW]: [
        this.workflowStates.EDITORIAL_REVIEW,
        this.workflowStates.ANALYSIS,
        this.workflowStates.REVISION,
      ],
      [this.workflowStates.EDITORIAL_REVIEW]: [
        this.workflowStates.LEGAL_COMPLIANCE,
        this.workflowStates.EXECUTIVE_APPROVAL,
        this.workflowStates.TECHNICAL_REVIEW,
        this.workflowStates.REVISION,
      ],
      [this.workflowStates.LEGAL_COMPLIANCE]: [
        this.workflowStates.EXECUTIVE_APPROVAL,
        this.workflowStates.EDITORIAL_REVIEW,
      ],
      [this.workflowStates.EXECUTIVE_APPROVAL]: [
        this.workflowStates.PUBLICATION,
        this.workflowStates.EDITORIAL_REVIEW,
        this.workflowStates.REVISION,
      ],
      [this.workflowStates.PUBLICATION]: [
        this.workflowStates.MONITORING,
        this.workflowStates.EXECUTIVE_APPROVAL,
      ],
      [this.workflowStates.MONITORING]: [
        this.workflowStates.REVISION,
        this.workflowStates.RETIREMENT,
      ],
      [this.workflowStates.REVISION]: [
        this.workflowStates.TECHNICAL_REVIEW,
        this.workflowStates.EDITORIAL_REVIEW,
        this.workflowStates.PUBLICATION,
        this.workflowStates.MONITORING,
      ],
      [this.workflowStates.RETIREMENT]: [],
    };

    return (transitions[from] || []).includes(to);
  }

  addReviewComment(queueItemId, reviewer, role, comment, severity = 'info') {
    const item = this.queue.get(queueItemId);
    if (!item) throw new Error(`Queue item not found: ${queueItemId}`);

    const reviewComment = {
      id: `comment_${Date.now()}`,
      reviewer,
      role,
      comment,
      severity,
      timestamp: new Date().toISOString(),
    };

    item.reviewComments.push(reviewComment);
    return reviewComment;
  }

  assignRole(queueItemId, role, analyst) {
    const item = this.queue.get(queueItemId);
    if (!item) throw new Error(`Queue item not found: ${queueItemId}`);

    item.assignments[role] = {
      role,
      analyst,
      assignedAt: new Date().toISOString(),
    };

    return item.assignments[role];
  }

  calculateQueueStatus(grouped) {
    return {
      totalInFlight: Object.values(grouped).reduce((sum, items) => sum + items.length, 0),
      bottlenecks: this.identifyBottlenecks(grouped),
      averageTimeInQueue: this.calculateAverageTime(grouped),
    };
  }

  identifyBottlenecks(grouped) {
    const bottlenecks = [];

    if (grouped.underReview.length > 5) {
      bottlenecks.push({
        stage: 'Review',
        itemCount: grouped.underReview.length,
        recommendation: 'Add additional reviewers',
      });
    }

    if (grouped.awaitingApproval.length > 3) {
      bottlenecks.push({
        stage: 'Approval',
        itemCount: grouped.awaitingApproval.length,
        recommendation: 'Expedite executive review',
      });
    }

    return bottlenecks;
  }

  calculateAverageTime(grouped) {
    let totalItems = 0;
    let totalTime = 0;

    Object.values(grouped).forEach(items => {
      items.forEach(item => {
        totalItems++;
        const createdAt = new Date(item.metadata.createdAt);
        const now = new Date();
        const timeInQueue = (now - createdAt) / (1000 * 60 * 60);
        totalTime += timeInQueue;
      });
    });

    return totalItems > 0 ? (totalTime / totalItems).toFixed(1) : 0;
  }

  getDueItems(daysAhead = 7) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() + daysAhead);

    return Array.from(this.queue.values())
      .filter(item => item.dueDate && new Date(item.dueDate) <= cutoff)
      .sort((a, b) => new Date(a.dueDate) - new Date(b.dueDate));
  }

  getItemHistory(queueItemId) {
    const item = this.queue.get(queueItemId);
    if (!item) throw new Error(`Queue item not found: ${queueItemId}`);

    return {
      queueItemId,
      title: item.title,
      stateHistory: item.stateHistory,
      reviewComments: item.reviewComments,
      assignments: item.assignments,
      totalReviewCycles: item.stateHistory.filter(sh => sh.to === this.workflowStates.REVISION).length,
    };
  }
}

module.exports = { ProductionQueueEngine };
