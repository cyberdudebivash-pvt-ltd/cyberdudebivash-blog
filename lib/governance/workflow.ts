/**
 * Governance Workflow Engine
 * State machine managing: Draft → Published → Archived lifecycle
 */

import type { WorkflowState, WorkflowTransition, IntelligenceObject, ValidationResult } from './types';
import { WorkflowState as WorkflowStateEnum } from './types';

// ============================================================================
// WORKFLOW STATE MACHINE
// ============================================================================

const VALID_TRANSITIONS: Record<WorkflowState, WorkflowState[]> = {
  [WorkflowStateEnum.DRAFT]: [
    WorkflowStateEnum.AI_GENERATED,
    WorkflowStateEnum.SCHEMA_VALIDATED,
  ],

  [WorkflowStateEnum.AI_GENERATED]: [
    WorkflowStateEnum.SCHEMA_VALIDATED,
    WorkflowStateEnum.DRAFT,
  ],

  [WorkflowStateEnum.SCHEMA_VALIDATED]: [
    WorkflowStateEnum.IOC_VALIDATED,
    WorkflowStateEnum.DETECTION_VALIDATED,
    WorkflowStateEnum.DRAFT,
  ],

  [WorkflowStateEnum.IOC_VALIDATED]: [
    WorkflowStateEnum.DETECTION_VALIDATED,
    WorkflowStateEnum.EVIDENCE_VALIDATED,
    WorkflowStateEnum.DRAFT,
  ],

  [WorkflowStateEnum.DETECTION_VALIDATED]: [
    WorkflowStateEnum.EVIDENCE_VALIDATED,
    WorkflowStateEnum.MITRE_VALIDATED,
    WorkflowStateEnum.DRAFT,
  ],

  [WorkflowStateEnum.EVIDENCE_VALIDATED]: [
    WorkflowStateEnum.MITRE_VALIDATED,
    WorkflowStateEnum.THREAT_ACTOR_VALIDATED,
    WorkflowStateEnum.DRAFT,
  ],

  [WorkflowStateEnum.MITRE_VALIDATED]: [
    WorkflowStateEnum.THREAT_ACTOR_VALIDATED,
    WorkflowStateEnum.ANALYST_REVIEW,
    WorkflowStateEnum.DRAFT,
  ],

  [WorkflowStateEnum.THREAT_ACTOR_VALIDATED]: [
    WorkflowStateEnum.ANALYST_REVIEW,
    WorkflowStateEnum.DRAFT,
  ],

  [WorkflowStateEnum.ANALYST_REVIEW]: [
    WorkflowStateEnum.PEER_REVIEW,
    WorkflowStateEnum.DRAFT,
  ],

  [WorkflowStateEnum.PEER_REVIEW]: [
    WorkflowStateEnum.QA_APPROVAL,
    WorkflowStateEnum.ANALYST_REVIEW,
    WorkflowStateEnum.DRAFT,
  ],

  [WorkflowStateEnum.QA_APPROVAL]: [
    WorkflowStateEnum.SECURITY_APPROVAL,
    WorkflowStateEnum.ANALYST_REVIEW,
    WorkflowStateEnum.DRAFT,
  ],

  [WorkflowStateEnum.SECURITY_APPROVAL]: [
    WorkflowStateEnum.PUBLISHED,
    WorkflowStateEnum.QA_APPROVAL,
    WorkflowStateEnum.DRAFT,
  ],

  [WorkflowStateEnum.PUBLISHED]: [
    WorkflowStateEnum.ARCHIVED,
    WorkflowStateEnum.RETRACTED,
  ],

  [WorkflowStateEnum.ARCHIVED]: [
    WorkflowStateEnum.RETRACTED,
  ],

  [WorkflowStateEnum.RETRACTED]: [
    WorkflowStateEnum.DRAFT,  // Can be corrected and re-published
  ],
};

// ============================================================================
// WORKFLOW ENGINE
// ============================================================================

export class WorkflowEngine {
  private transitions: Map<string, WorkflowTransition[]> = new Map();

  /**
   * Validate if a state transition is allowed
   */
  canTransition(currentState: WorkflowState, nextState: WorkflowState): boolean {
    const allowed = VALID_TRANSITIONS[currentState] || [];
    return allowed.includes(nextState);
  }

  /**
   * Get allowed transitions from current state
   */
  getAllowedTransitions(currentState: WorkflowState): WorkflowState[] {
    return VALID_TRANSITIONS[currentState] || [];
  }

  /**
   * Execute state transition
   */
  async transitionState(
    objectId: string,
    currentState: WorkflowState,
    nextState: WorkflowState,
    actor: string,
    reason?: string,
    validationResults?: ValidationResult[]
  ): Promise<WorkflowTransition> {
    if (!this.canTransition(currentState, nextState)) {
      throw new Error(
        `Invalid transition: ${currentState} → ${nextState}. ` +
        `Allowed: ${this.getAllowedTransitions(currentState).join(', ')}`
      );
    }

    const transition: WorkflowTransition = {
      from: currentState,
      to: nextState,
      timestamp: new Date(),
      actor,
      reason,
      validation_results: validationResults,
    };

    // Store transition
    const key = objectId;
    if (!this.transitions.has(key)) {
      this.transitions.set(key, []);
    }
    this.transitions.get(key)!.push(transition);

    return transition;
  }

  /**
   * Get transition history for object
   */
  getTransitionHistory(objectId: string): WorkflowTransition[] {
    return this.transitions.get(objectId) || [];
  }

  /**
   * Get current state from transition history
   */
  getCurrentState(objectId: string): WorkflowState | null {
    const history = this.getTransitionHistory(objectId);
    if (history.length === 0) return null;
    return history[history.length - 1].to;
  }

  /**
   * Get time spent in current state
   */
  getTimeInCurrentState(objectId: string): number {
    const history = this.getTransitionHistory(objectId);
    if (history.length === 0) return 0;

    const lastTransition = history[history.length - 1];
    return Date.now() - lastTransition.timestamp.getTime();
  }

  /**
   * Check if object is stale (stuck in state too long)
   */
  isStale(objectId: string, maxAgeMs: number): boolean {
    return this.getTimeInCurrentState(objectId) > maxAgeMs;
  }

  /**
   * Reset to draft (for corrections)
   */
  async resetToDraft(
    objectId: string,
    actor: string,
    reason: string
  ): Promise<WorkflowTransition> {
    const currentState = this.getCurrentState(objectId);
    if (!currentState) {
      throw new Error(`Object not found: ${objectId}`);
    }

    return this.transitionState(objectId, currentState, WorkflowStateEnum.DRAFT, actor, reason);
  }

  /**
   * Get workflow statistics
   */
  getWorkflowStats(objectIds: string[]): Record<string, any> {
    let totalObjects = objectIds.length;
    const byState: Record<WorkflowState, number> = {} as any;
    let totalTransitions = 0;
    const staleObjects: string[] = [];

    for (const objectId of objectIds) {
      const currentState = this.getCurrentState(objectId);
      if (currentState) {
        byState[currentState] = (byState[currentState] || 0) + 1;

        // Check if stale (stuck for > 7 days)
        if (this.isStale(objectId, 7 * 24 * 60 * 60 * 1000)) {
          staleObjects.push(objectId);
        }
      }

      totalTransitions += this.getTransitionHistory(objectId).length;
    }

    return {
      totalObjects,
      byState,
      averageTransitionsPerObject: totalTransitions / totalObjects,
      staleObjects,
      staleCount: staleObjects.length,
    };
  }
}

export const workflowEngine = new WorkflowEngine();

// ============================================================================
// WORKFLOW HELPERS
// ============================================================================

export function getStateDisplayName(state: WorkflowState): string {
  const displayNames: Record<WorkflowState, string> = {
    [WorkflowStateEnum.DRAFT]: 'Draft',
    [WorkflowStateEnum.AI_GENERATED]: 'AI Generated',
    [WorkflowStateEnum.SCHEMA_VALIDATED]: 'Schema Validated',
    [WorkflowStateEnum.IOC_VALIDATED]: 'IOC Validated',
    [WorkflowStateEnum.DETECTION_VALIDATED]: 'Detection Validated',
    [WorkflowStateEnum.EVIDENCE_VALIDATED]: 'Evidence Validated',
    [WorkflowStateEnum.MITRE_VALIDATED]: 'MITRE Validated',
    [WorkflowStateEnum.THREAT_ACTOR_VALIDATED]: 'Threat Actor Validated',
    [WorkflowStateEnum.ANALYST_REVIEW]: 'Analyst Review',
    [WorkflowStateEnum.PEER_REVIEW]: 'Peer Review',
    [WorkflowStateEnum.QA_APPROVAL]: 'QA Approval',
    [WorkflowStateEnum.SECURITY_APPROVAL]: 'Security Approval',
    [WorkflowStateEnum.PUBLISHED]: 'Published',
    [WorkflowStateEnum.ARCHIVED]: 'Archived',
    [WorkflowStateEnum.RETRACTED]: 'Retracted',
  };

  return displayNames[state] || state;
}

export function getStateColor(state: WorkflowState): string {
  const colors: Record<WorkflowState, string> = {
    [WorkflowStateEnum.DRAFT]: 'gray',
    [WorkflowStateEnum.AI_GENERATED]: 'blue',
    [WorkflowStateEnum.SCHEMA_VALIDATED]: 'blue',
    [WorkflowStateEnum.IOC_VALIDATED]: 'blue',
    [WorkflowStateEnum.DETECTION_VALIDATED]: 'blue',
    [WorkflowStateEnum.EVIDENCE_VALIDATED]: 'blue',
    [WorkflowStateEnum.MITRE_VALIDATED]: 'blue',
    [WorkflowStateEnum.THREAT_ACTOR_VALIDATED]: 'blue',
    [WorkflowStateEnum.ANALYST_REVIEW]: 'yellow',
    [WorkflowStateEnum.PEER_REVIEW]: 'yellow',
    [WorkflowStateEnum.QA_APPROVAL]: 'yellow',
    [WorkflowStateEnum.SECURITY_APPROVAL]: 'yellow',
    [WorkflowStateEnum.PUBLISHED]: 'green',
    [WorkflowStateEnum.ARCHIVED]: 'gray',
    [WorkflowStateEnum.RETRACTED]: 'red',
  };

  return colors[state] || 'gray';
}

export function isValidationState(state: WorkflowState): boolean {
  return [
    WorkflowStateEnum.SCHEMA_VALIDATED,
    WorkflowStateEnum.IOC_VALIDATED,
    WorkflowStateEnum.DETECTION_VALIDATED,
    WorkflowStateEnum.EVIDENCE_VALIDATED,
    WorkflowStateEnum.MITRE_VALIDATED,
    WorkflowStateEnum.THREAT_ACTOR_VALIDATED,
  ].includes(state);
}

export function isReviewState(state: WorkflowState): boolean {
  return [
    WorkflowStateEnum.ANALYST_REVIEW,
    WorkflowStateEnum.PEER_REVIEW,
    WorkflowStateEnum.QA_APPROVAL,
    WorkflowStateEnum.SECURITY_APPROVAL,
  ].includes(state);
}

export function isPublishedState(state: WorkflowState): boolean {
  return state === WorkflowStateEnum.PUBLISHED;
}

export function canPublish(state: WorkflowState): boolean {
  return state === WorkflowStateEnum.SECURITY_APPROVAL || state === WorkflowStateEnum.PUBLISHED;
}
