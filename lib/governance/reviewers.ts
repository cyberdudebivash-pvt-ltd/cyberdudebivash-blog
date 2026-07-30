/**
 * Reviewer Management
 * Credentials, expertise tracking, and assignment
 */

import { v4 as uuidv4 } from 'uuid';
import type { ReviewerCredentials, ReviewerStats, ReviewerAssignment, ApprovalRole } from './types';

// ============================================================================
// REVIEWER ENGINE
// ============================================================================

export class ReviewerEngine {
  private reviewers: Map<string, ReviewerCredentials> = new Map();
  private stats: Map<string, ReviewerStats> = new Map();
  private assignments: Map<string, ReviewerAssignment[]> = new Map();

  /**
   * Register a reviewer
   */
  registerReviewer(
    name: string,
    email: string,
    roles: ApprovalRole[],
    expertise: string[]
  ): ReviewerCredentials {
    const reviewerId = uuidv4();

    const credentials: ReviewerCredentials = {
      reviewerId,
      name,
      email,
      roles,
      expertise,
      active: true,
      joinedDate: new Date(),
    };

    this.reviewers.set(reviewerId, credentials);

    // Initialize stats
    this.stats.set(reviewerId, {
      reviewerId,
      totalReviews: 0,
      approvalsGiven: 0,
      rejectionsGiven: 0,
      averageReviewTime: 0,
      specialism: expertise,
    });

    return credentials;
  }

  /**
   * Get reviewer credentials
   */
  getReviewer(reviewerId: string): ReviewerCredentials | undefined {
    return this.reviewers.get(reviewerId);
  }

  /**
   * Get all active reviewers
   */
  getActiveReviewers(): ReviewerCredentials[] {
    return Array.from(this.reviewers.values()).filter(r => r.active);
  }

  /**
   * Get reviewers by role
   */
  getReviewersByRole(role: ApprovalRole): ReviewerCredentials[] {
    return Array.from(this.reviewers.values()).filter(
      r => r.active && r.roles.includes(role)
    );
  }

  /**
   * Get reviewers by expertise
   */
  getReviewersByExpertise(expertise: string): ReviewerCredentials[] {
    return Array.from(this.reviewers.values()).filter(
      r => r.active && r.expertise.includes(expertise)
    );
  }

  /**
   * Deactivate reviewer
   */
  deactivateReviewer(reviewerId: string): ReviewerCredentials {
    const reviewer = this.reviewers.get(reviewerId);
    if (!reviewer) {
      throw new Error(`Reviewer not found: ${reviewerId}`);
    }

    reviewer.active = false;
    return reviewer;
  }

  /**
   * Reactivate reviewer
   */
  reactivateReviewer(reviewerId: string): ReviewerCredentials {
    const reviewer = this.reviewers.get(reviewerId);
    if (!reviewer) {
      throw new Error(`Reviewer not found: ${reviewerId}`);
    }

    reviewer.active = true;
    return reviewer;
  }

  /**
   * Update reviewer expertise
   */
  updateExpertise(reviewerId: string, expertise: string[]): ReviewerCredentials {
    const reviewer = this.reviewers.get(reviewerId);
    if (!reviewer) {
      throw new Error(`Reviewer not found: ${reviewerId}`);
    }

    reviewer.expertise = expertise;

    // Update stats
    const stat = this.stats.get(reviewerId);
    if (stat) {
      stat.specialism = expertise;
    }

    return reviewer;
  }

  /**
   * Assign reviewer to approval
   */
  assignReviewerToApproval(
    objectId: string,
    role: ApprovalRole,
    reviewerId: string,
    dueDate: Date
  ): ReviewerAssignment {
    const reviewer = this.reviewers.get(reviewerId);
    if (!reviewer) {
      throw new Error(`Reviewer not found: ${reviewerId}`);
    }

    const assignment: ReviewerAssignment = {
      objectId,
      role,
      assignedReviewers: [reviewerId],
      assignedAt: new Date(),
      dueAt: dueDate,
    };

    if (!this.assignments.has(objectId)) {
      this.assignments.set(objectId, []);
    }
    this.assignments.get(objectId)!.push(assignment);

    return assignment;
  }

  /**
   * Get assignments for reviewer
   */
  getReviewerAssignments(reviewerId: string): ReviewerAssignment[] {
    const assignments: ReviewerAssignment[] = [];

    for (const objectAssignments of this.assignments.values()) {
      for (const assignment of objectAssignments) {
        if (assignment.assignedReviewers.includes(reviewerId)) {
          assignments.push(assignment);
        }
      }
    }

    return assignments;
  }

  /**
   * Get pending assignments for reviewer
   */
  getPendingAssignments(reviewerId: string): ReviewerAssignment[] {
    return this.getReviewerAssignments(reviewerId).filter(a => !a.completedAt);
  }

  /**
   * Get overdue assignments for reviewer
   */
  getOverdueAssignments(reviewerId: string): ReviewerAssignment[] {
    return this.getPendingAssignments(reviewerId).filter(a => a.dueAt < new Date());
  }

  /**
   * Mark assignment as completed
   */
  completeAssignment(objectId: string, reviewerId: string): ReviewerAssignment {
    const objectAssignments = this.assignments.get(objectId);
    if (!objectAssignments) {
      throw new Error(`No assignments for object: ${objectId}`);
    }

    const assignment = objectAssignments.find(a =>
      a.assignedReviewers.includes(reviewerId)
    );
    if (!assignment) {
      throw new Error(`Reviewer not assigned to object: ${objectId}`);
    }

    assignment.completedAt = new Date();
    assignment.completedBy = reviewerId;

    return assignment;
  }

  /**
   * Record review completion
   */
  recordReview(
    reviewerId: string,
    approved: boolean,
    reviewTimeMs: number
  ): ReviewerStats {
    const stats = this.stats.get(reviewerId);
    if (!stats) {
      throw new Error(`Reviewer stats not found: ${reviewerId}`);
    }

    stats.totalReviews++;
    if (approved) {
      stats.approvalsGiven++;
    } else {
      stats.rejectionsGiven++;
    }

    // Update average review time
    const previousTotal = stats.averageReviewTime * (stats.totalReviews - 1);
    stats.averageReviewTime = Math.round((previousTotal + reviewTimeMs) / stats.totalReviews);

    stats.lastReviewDate = new Date();

    return stats;
  }

  /**
   * Get reviewer statistics
   */
  getReviewerStats(reviewerId: string): ReviewerStats | undefined {
    return this.stats.get(reviewerId);
  }

  /**
   * Get all reviewer statistics
   */
  getAllReviewerStats(): ReviewerStats[] {
    return Array.from(this.stats.values());
  }

  /**
   * Get top reviewers by approval count
   */
  getTopApprovers(limit: number = 10): Array<{
    reviewerId: string;
    name: string;
    approvalsGiven: number;
    totalReviews: number;
    approvalRate: number;
  }> {
    return Array.from(this.stats.values())
      .map(stat => {
        const reviewer = this.reviewers.get(stat.reviewerId);
        return {
          reviewerId: stat.reviewerId,
          name: reviewer?.name || 'Unknown',
          approvalsGiven: stat.approvalsGiven,
          totalReviews: stat.totalReviews,
          approvalRate:
            stat.totalReviews > 0
              ? Math.round((stat.approvalsGiven / stat.totalReviews) * 100)
              : 0,
        };
      })
      .sort((a, b) => b.approvalsGiven - a.approvalsGiven)
      .slice(0, limit);
  }

  /**
   * Get fastest reviewers
   */
  getFastestReviewers(limit: number = 10): Array<{
    reviewerId: string;
    name: string;
    averageReviewTimeMs: number;
    averageReviewTimeHours: number;
  }> {
    return Array.from(this.stats.values())
      .map(stat => {
        const reviewer = this.reviewers.get(stat.reviewerId);
        return {
          reviewerId: stat.reviewerId,
          name: reviewer?.name || 'Unknown',
          averageReviewTimeMs: stat.averageReviewTime,
          averageReviewTimeHours: Math.round(stat.averageReviewTime / (1000 * 60 * 60) * 100) / 100,
        };
      })
      .sort((a, b) => a.averageReviewTimeMs - b.averageReviewTimeMs)
      .slice(0, limit);
  }

  /**
   * Find best reviewer for object (by expertise and availability)
   */
  findBestReviewerForRole(role: ApprovalRole, requiredExpertise?: string): ReviewerCredentials | null {
    let candidates = this.getReviewersByRole(role);

    if (requiredExpertise) {
      candidates = candidates.filter(c => c.expertise.includes(requiredExpertise));
    }

    if (candidates.length === 0) return null;

    // Sort by least busy (fewest pending assignments)
    const candidatesWithLoad = candidates
      .map(c => ({
        reviewer: c,
        pendingCount: this.getPendingAssignments(c.reviewerId).length,
      }))
      .sort((a, b) => a.pendingCount - b.pendingCount);

    return candidatesWithLoad[0].reviewer;
  }

  /**
   * Get overall reviewer statistics
   */
  getReviewerPoolStats(): {
    totalReviewers: number;
    activeReviewers: number;
    inactiveReviewers: number;
    totalReviews: number;
    averageApprovalRate: number;
    averageReviewTime: number;
    byRole: Record<string, number>;
    byExpertise: Record<string, number>;
  } {
    const activeReviewers = this.getActiveReviewers().length;
    const inactiveReviewers = this.reviewers.size - activeReviewers;

    let totalReviews = 0;
    let totalApprovals = 0;
    let totalReviewTime = 0;
    const byRole: Record<string, number> = {};
    const byExpertise: Record<string, number> = {};
    let reviewerCount = 0;

    for (const stats of this.stats.values()) {
      totalReviews += stats.totalReviews;
      totalApprovals += stats.approvalsGiven;
      totalReviewTime += stats.averageReviewTime;
      if (stats.totalReviews > 0) {
        reviewerCount++;
      }

      const reviewer = this.reviewers.get(stats.reviewerId);
      if (reviewer) {
        for (const role of reviewer.roles) {
          byRole[role] = (byRole[role] || 0) + 1;
        }
        for (const expertise of reviewer.expertise) {
          byExpertise[expertise] = (byExpertise[expertise] || 0) + 1;
        }
      }
    }

    const averageApprovalRate =
      totalReviews > 0 ? Math.round((totalApprovals / totalReviews) * 100) : 0;
    const averageReviewTime =
      reviewerCount > 0 ? Math.round(totalReviewTime / reviewerCount) : 0;

    return {
      totalReviewers: this.reviewers.size,
      activeReviewers,
      inactiveReviewers,
      totalReviews,
      averageApprovalRate,
      averageReviewTime,
      byRole,
      byExpertise,
    };
  }

  /**
   * Export all reviewers
   */
  exportReviewers(): ReviewerCredentials[] {
    return Array.from(this.reviewers.values());
  }
}

export const reviewerEngine = new ReviewerEngine();
