/**
 * Approvals Management
 * Tracks approval chain: Analyst → Peer → QA → Security
 */

import type { Approval, ApprovalChain, ApprovalRole, ApprovalStatus } from './types';
import { ApprovalStatus as ApprovalStatusEnum, ApprovalRole as ApprovalRoleEnum } from './types';
import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// APPROVAL HIERARCHY
// ============================================================================

const APPROVAL_HIERARCHY: ApprovalRole[] = [
  ApprovalRoleEnum.ANALYST,
  ApprovalRoleEnum.PEER_ANALYST,
  ApprovalRoleEnum.QA_LEAD,
  ApprovalRoleEnum.SECURITY_OFFICER,
];

// ============================================================================
// APPROVAL MANAGER
// ============================================================================

export class ApprovalManager {
  private approvals: Map<string, Approval> = new Map();
  private chains: Map<string, ApprovalChain> = new Map();

  /**
   * Create approval chain for an object
   */
  createApprovalChain(
    objectId: string,
    objectType: 'report' | 'ioc' | 'detection',
    requiredRoles: ApprovalRole[]
  ): ApprovalChain {
    const approvals: Approval[] = [];

    for (const role of requiredRoles) {
      const approval: Approval = {
        approvalId: uuidv4(),
        objectId,
        objectType,
        requiredRole: role,
        status: ApprovalStatusEnum.PENDING,
        requestedAt: new Date(),
      };
      approvals.push(approval);
      this.approvals.set(approval.approvalId, approval);
    }

    const chain: ApprovalChain = {
      objectId,
      approvals,
      completedApprovals: [],
      pendingApprovals: approvals,
      allApproved: false,
      canPublish: false,
    };

    this.chains.set(objectId, chain);
    return chain;
  }

  /**
   * Get approval chain
   */
  getApprovalChain(objectId: string): ApprovalChain | undefined {
    return this.chains.get(objectId);
  }

  /**
   * Approve a step
   */
  async approve(
    approvalId: string,
    approver: string,
    notes?: string
  ): Promise<Approval> {
    const approval = this.approvals.get(approvalId);
    if (!approval) {
      throw new Error(`Approval not found: ${approvalId}`);
    }

    if (approval.status !== ApprovalStatusEnum.PENDING) {
      throw new Error(`Approval already ${approval.status}: ${approvalId}`);
    }

    approval.status = ApprovalStatusEnum.APPROVED;
    approval.approvedBy = approver;
    approval.approvedAt = new Date();

    // Update chain
    const chain = this.chains.get(approval.objectId);
    if (chain) {
      chain.completedApprovals = chain.approvals.filter(a => a.status === ApprovalStatusEnum.APPROVED);
      chain.pendingApprovals = chain.approvals.filter(a => a.status === ApprovalStatusEnum.PENDING);
      chain.allApproved = chain.pendingApprovals.length === 0;
      chain.canPublish = chain.allApproved;
    }

    return approval;
  }

  /**
   * Reject a step
   */
  async reject(
    approvalId: string,
    rejector: string,
    reason: string
  ): Promise<Approval> {
    const approval = this.approvals.get(approvalId);
    if (!approval) {
      throw new Error(`Approval not found: ${approvalId}`);
    }

    if (approval.status !== ApprovalStatusEnum.PENDING) {
      throw new Error(`Cannot reject ${approval.status} approval`);
    }

    approval.status = ApprovalStatusEnum.REJECTED;
    approval.approvedBy = rejector;
    approval.rejectedAt = new Date();
    approval.rejectionReason = reason;

    // Update chain
    const chain = this.chains.get(approval.objectId);
    if (chain) {
      chain.allApproved = false;
      chain.canPublish = false;
    }

    return approval;
  }

  /**
   * Mark as conditional (approval with notes)
   */
  async approveConditional(
    approvalId: string,
    approver: string,
    conditionalNotes: string
  ): Promise<Approval> {
    const approval = this.approvals.get(approvalId);
    if (!approval) {
      throw new Error(`Approval not found: ${approvalId}`);
    }

    approval.status = ApprovalStatusEnum.CONDITIONAL;
    approval.approvedBy = approver;
    approval.approvedAt = new Date();
    approval.conditionalNotes = conditionalNotes;

    return approval;
  }

  /**
   * Assign reviewer to approval
   */
  assignReviewer(approvalId: string, reviewerId: string): Approval {
    const approval = this.approvals.get(approvalId);
    if (!approval) {
      throw new Error(`Approval not found: ${approvalId}`);
    }

    approval.approverAssigned = reviewerId;
    return approval;
  }

  /**
   * Get pending approvals
   */
  getPendingApprovals(role?: ApprovalRole): Approval[] {
    const pending = Array.from(this.approvals.values()).filter(
      a => a.status === ApprovalStatusEnum.PENDING
    );

    if (role) {
      return pending.filter(a => a.requiredRole === role);
    }

    return pending;
  }

  /**
   * Get approval history for object
   */
  getApprovalHistory(objectId: string): Approval[] {
    const chain = this.chains.get(objectId);
    return chain?.approvals || [];
  }

  /**
   * Check if all approvals complete
   */
  allApprovalsComplete(objectId: string): boolean {
    const chain = this.chains.get(objectId);
    if (!chain) return false;
    return chain.allApproved;
  }

  /**
   * Get next required approval
   */
  getNextRequiredApproval(objectId: string): Approval | undefined {
    const chain = this.chains.get(objectId);
    if (!chain) return undefined;

    for (const approval of chain.approvals) {
      if (approval.status === ApprovalStatusEnum.PENDING) {
        return approval;
      }
    }

    return undefined;
  }

  /**
   * Get approval statistics
   */
  getApprovalStats(): Record<string, any> {
    const total = this.approvals.size;
    const approved = Array.from(this.approvals.values()).filter(a => a.status === ApprovalStatusEnum.APPROVED).length;
    const rejected = Array.from(this.approvals.values()).filter(a => a.status === ApprovalStatusEnum.REJECTED).length;
    const pending = Array.from(this.approvals.values()).filter(a => a.status === ApprovalStatusEnum.PENDING).length;
    const conditional = Array.from(this.approvals.values()).filter(a => a.status === ApprovalStatusEnum.CONDITIONAL).length;

    const byRole: Record<ApprovalRole, number> = {} as any;
    for (const approval of this.approvals.values()) {
      byRole[approval.requiredRole] = (byRole[approval.requiredRole] || 0) + 1;
    }

    return {
      total,
      approved,
      rejected,
      pending,
      conditional,
      approvalRate: total > 0 ? (approved / total) * 100 : 0,
      byRole,
    };
  }
}

export const approvalManager = new ApprovalManager();

// ============================================================================
// DEFAULT APPROVAL CHAINS
// ============================================================================

export const DEFAULT_APPROVAL_CHAINS: Record<string, ApprovalRole[]> = {
  report: [
    ApprovalRoleEnum.ANALYST,
    ApprovalRoleEnum.PEER_ANALYST,
    ApprovalRoleEnum.QA_LEAD,
    ApprovalRoleEnum.SECURITY_OFFICER,
  ],
  ioc: [
    ApprovalRoleEnum.ANALYST,
    ApprovalRoleEnum.QA_LEAD,
  ],
  detection: [
    ApprovalRoleEnum.ANALYST,
    ApprovalRoleEnum.QA_LEAD,
    ApprovalRoleEnum.SECURITY_OFFICER,
  ],
};

/**
 * Create default approval chain for object type
 */
export function createDefaultApprovalChain(
  objectId: string,
  objectType: 'report' | 'ioc' | 'detection'
): ApprovalChain {
  const roles = DEFAULT_APPROVAL_CHAINS[objectType] || DEFAULT_APPROVAL_CHAINS.report;
  return approvalManager.createApprovalChain(objectId, objectType, roles);
}
