'use strict';

class AnalystAssignmentEngine {
  constructor() {
    this.analysts = new Map();
    this.assignments = new Map();
    this.roles = {
      LEAD_ANALYST: 'lead_analyst',
      TECHNICAL_REVIEWER: 'technical_reviewer',
      EDITORIAL_REVIEWER: 'editorial_reviewer',
      DETECTION_ENGINEER: 'detection_engineer',
      EXECUTIVE_APPROVER: 'executive_approver',
      PUBLISHER: 'publisher',
    };
  }

  createAnalystProfile(analystId, profile) {
    const analyst = {
      id: analystId,
      name: profile.name,
      email: profile.email,
      specialization: profile.specialization || 'general',
      roles: profile.roles || [],
      capacity: profile.capacity || 40,
      currentWorkload: 0,
      assignedItems: [],
      skillMatrix: profile.skillMatrix || {},
      createdAt: new Date().toISOString(),
    };

    this.analysts.set(analystId, analyst);
    return analyst;
  }

  assignToItem(queueItemId, analystId, role, priority = 'normal') {
    const analyst = this.analysts.get(analystId);
    if (!analyst) throw new Error(`Analyst not found: ${analystId}`);

    const assignment = {
      id: `assign_${queueItemId}_${analystId}`,
      queueItemId,
      analyst: analystId,
      role,
      priority,
      assignedAt: new Date().toISOString(),
      status: 'assigned',
      estimatedHours: this.estimateWorkload(role),
      completedAt: null,
    };

    this.assignments.set(assignment.id, assignment);
    analyst.assignedItems.push(queueItemId);
    analyst.currentWorkload += assignment.estimatedHours;

    return assignment;
  }

  estimateWorkload(role) {
    const estimates = {
      [this.roles.LEAD_ANALYST]: 8,
      [this.roles.TECHNICAL_REVIEWER]: 4,
      [this.roles.EDITORIAL_REVIEWER]: 2,
      [this.roles.DETECTION_ENGINEER]: 6,
      [this.roles.EXECUTIVE_APPROVER]: 1,
      [this.roles.PUBLISHER]: 0.5,
    };

    return estimates[role] || 4;
  }

  getAnalystWorkload(analystId) {
    const analyst = this.analysts.get(analystId);
    if (!analyst) throw new Error(`Analyst not found: ${analystId}`);

    const assignments = Array.from(this.assignments.values())
      .filter(a => a.analyst === analystId && a.status !== 'completed');

    const utilizationRate = (analyst.currentWorkload / analyst.capacity) * 100;

    return {
      analyst: analystId,
      name: analyst.name,
      capacity: analyst.capacity,
      currentWorkload: analyst.currentWorkload,
      utilizationRate: utilizationRate.toFixed(1),
      capacity_status: utilizationRate > 100 ? 'overbooked' : utilizationRate > 80 ? 'high' : 'normal',
      assignedItems: assignments.length,
      assignments: assignments.map(a => ({
        queueItemId: a.queueItemId,
        role: a.role,
        priority: a.priority,
        estimatedHours: a.estimatedHours,
      })),
    };
  }

  completeAssignment(assignmentId) {
    const assignment = this.assignments.get(assignmentId);
    if (!assignment) throw new Error(`Assignment not found: ${assignmentId}`);

    assignment.status = 'completed';
    assignment.completedAt = new Date().toISOString();

    const analyst = this.analysts.get(assignment.analyst);
    if (analyst) {
      analyst.currentWorkload = Math.max(0, analyst.currentWorkload - assignment.estimatedHours);
      analyst.assignedItems = analyst.assignedItems.filter(id => id !== assignment.queueItemId);
    }

    return assignment;
  }

  suggestAssignee(queueItemId, role, specialization = null) {
    const candidateAnalysts = Array.from(this.analysts.values())
      .filter(a => a.roles.includes(role))
      .filter(a => !specialization || a.specialization === specialization || a.specialization === 'general')
      .sort((a, b) => {
        const aUtil = (a.currentWorkload / a.capacity);
        const bUtil = (b.currentWorkload / b.capacity);
        return aUtil - bUtil;
      });

    if (candidateAnalysts.length === 0) {
      return {
        suggestion: null,
        reason: `No analysts available with role: ${role}`,
      };
    }

    const suggested = candidateAnalysts[0];
    const utilizationRate = (suggested.currentWorkload / suggested.capacity) * 100;

    return {
      suggestion: {
        analyst: suggested.id,
        name: suggested.name,
        email: suggested.email,
        specialization: suggested.specialization,
        currentUtilization: utilizationRate.toFixed(1),
      },
      reason: `Lowest current utilization (${utilizationRate.toFixed(1)}%)`,
    };
  }

  getTeamCapacity(teamMembers = []) {
    let totalCapacity = 0;
    let totalUtilization = 0;

    const members = teamMembers.length > 0
      ? Array.from(this.analysts.values()).filter(a => teamMembers.includes(a.id))
      : Array.from(this.analysts.values());

    members.forEach(analyst => {
      totalCapacity += analyst.capacity;
      totalUtilization += analyst.currentWorkload;
    });

    const utilizationRate = totalCapacity > 0 ? (totalUtilization / totalCapacity) * 100 : 0;

    return {
      teamSize: members.length,
      totalCapacity,
      totalUtilization,
      utilizationRate: utilizationRate.toFixed(1),
      availableCapacity: Math.max(0, totalCapacity - totalUtilization),
      status: utilizationRate > 100 ? 'overbooked' : utilizationRate > 80 ? 'high' : 'normal',
      members: members.map(a => ({
        analyst: a.id,
        name: a.name,
        capacity: a.capacity,
        workload: a.currentWorkload,
        utilization: ((a.currentWorkload / a.capacity) * 100).toFixed(1),
      })),
    };
  }

  identifySkillGaps(requiredSkills) {
    const gaps = [];

    requiredSkills.forEach(skill => {
      const qualified = Array.from(this.analysts.values())
        .filter(a => a.skillMatrix[skill] && a.skillMatrix[skill] > 0.5);

      if (qualified.length === 0) {
        gaps.push({
          skill,
          qualified: 0,
          recommendation: 'Training needed or external resource required',
        });
      } else if (qualified.length < 2) {
        gaps.push({
          skill,
          qualified: qualified.length,
          recommendation: 'Single point of failure - consider cross-training',
        });
      }
    });

    return gaps;
  }

  getAnalystMetrics(analystId) {
    const analyst = this.analysts.get(analystId);
    if (!analyst) throw new Error(`Analyst not found: ${analystId}`);

    const assignments = Array.from(this.assignments.values())
      .filter(a => a.analyst === analystId);

    const completed = assignments.filter(a => a.status === 'completed');
    const inProgress = assignments.filter(a => a.status !== 'completed');

    const totalHours = assignments.reduce((sum, a) => sum + a.estimatedHours, 0);
    const avgCompletionTime = completed.length > 0
      ? completed.reduce((sum, a) => {
          const duration = new Date(a.completedAt) - new Date(a.assignedAt);
          return sum + (duration / (1000 * 60 * 60));
        }, 0) / completed.length
      : 0;

    return {
      analyst: analystId,
      name: analyst.name,
      specialization: analyst.specialization,
      totalAssignments: assignments.length,
      completedAssignments: completed.length,
      inProgressAssignments: inProgress.length,
      completionRate: assignments.length > 0 ? ((completed.length / assignments.length) * 100).toFixed(1) : 0,
      totalHours,
      avgCompletionHours: avgCompletionTime.toFixed(1),
      currentUtilization: ((analyst.currentWorkload / analyst.capacity) * 100).toFixed(1),
    };
  }
}

module.exports = { AnalystAssignmentEngine };
