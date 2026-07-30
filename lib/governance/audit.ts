/**
 * Audit Trail Engine
 * Immutable audit log with comprehensive change tracking
 */

import { v4 as uuidv4 } from 'uuid';
import type { AuditEntry, AuditAction, AuditLog } from './types';
import { AuditAction as AuditActionEnum } from './types';

// ============================================================================
// AUDIT ENGINE
// ============================================================================

export class AuditEngine {
  private logs: Map<string, AuditLog> = new Map();
  private entries: Map<string, AuditEntry> = new Map();

  /**
   * Record an audit entry (immutable once created)
   */
  recordEntry(
    actor: string,
    action: AuditAction,
    objectType: 'report' | 'ioc' | 'detection' | 'approval' | 'policy',
    objectId: string,
    changes?: {
      fieldName: string;
      previousValue?: any;
      newValue?: any;
    }[],
    reason?: string,
    approver?: string,
    ipAddress?: string,
    userAgent?: string
  ): AuditEntry {
    const entry: AuditEntry = {
      auditId: uuidv4(),
      timestamp: new Date(),
      actor,
      action,
      objectType,
      objectId,
      changes,
      reason,
      approver,
      ipAddress,
      userAgent,
    };

    // Store entry
    this.entries.set(entry.auditId, entry);

    // Store in log
    if (!this.logs.has(objectId)) {
      this.logs.set(objectId, {
        objectId,
        objectType,
        entries: [],
      });
    }
    this.logs.get(objectId)!.entries.push(entry);

    return entry;
  }

  /**
   * Get audit log for object
   */
  getAuditLog(objectId: string): AuditLog | undefined {
    return this.logs.get(objectId);
  }

  /**
   * Get all entries for object
   */
  getEntries(objectId: string): AuditEntry[] {
    return this.logs.get(objectId)?.entries || [];
  }

  /**
   * Get entry by ID
   */
  getEntry(auditId: string): AuditEntry | undefined {
    return this.entries.get(auditId);
  }

  /**
   * Search entries by action
   */
  getEntriesByAction(objectId: string, action: AuditAction): AuditEntry[] {
    return this.getEntries(objectId).filter(e => e.action === action);
  }

  /**
   * Search entries by actor
   */
  getEntriesByActor(objectId: string, actor: string): AuditEntry[] {
    return this.getEntries(objectId).filter(e => e.actor === actor);
  }

  /**
   * Get entries in time range
   */
  getEntriesByTimeRange(objectId: string, startTime: Date, endTime: Date): AuditEntry[] {
    return this.getEntries(objectId).filter(
      e => e.timestamp >= startTime && e.timestamp <= endTime
    );
  }

  /**
   * Get field change history
   */
  getFieldChangeHistory(objectId: string, fieldName: string): AuditEntry[] {
    return this.getEntries(objectId).filter(
      e => e.changes && e.changes.some(c => c.fieldName === fieldName)
    );
  }

  /**
   * Get specific field changes
   */
  getFieldChanges(
    objectId: string,
    fieldName: string
  ): Array<{
    timestamp: Date;
    actor: string;
    previousValue?: any;
    newValue?: any;
    reason?: string;
  }> {
    return this.getFieldChangeHistory(objectId, fieldName)
      .map(entry => {
        const change = entry.changes?.find(c => c.fieldName === fieldName);
        return {
          timestamp: entry.timestamp,
          actor: entry.actor,
          previousValue: change?.previousValue,
          newValue: change?.newValue,
          reason: entry.reason,
        };
      });
  }

  /**
   * Get who approved this change
   */
  getApprover(auditId: string): string | undefined {
    const entry = this.entries.get(auditId);
    return entry?.approver;
  }

  /**
   * Verify audit trail integrity (check if any entries are missing or out of order)
   */
  verifyIntegrity(objectId: string): {
    isValid: boolean;
    issues: string[];
  } {
    const entries = this.getEntries(objectId);
    const issues: string[] = [];

    // Check if timestamps are ordered
    for (let i = 1; i < entries.length; i++) {
      if (entries[i].timestamp < entries[i - 1].timestamp) {
        issues.push(
          `Entry ${i} has earlier timestamp than entry ${i - 1}`
        );
      }
    }

    // Check if critical actions have reasons
    const criticalActions = [
      AuditActionEnum.REJECTED,
      AuditActionEnum.RETRACTED,
    ];
    for (const entry of entries) {
      if (
        criticalActions.includes(entry.action) &&
        !entry.reason
      ) {
        issues.push(
          `Critical action ${entry.action} at ${entry.timestamp} has no reason`
        );
      }
    }

    return {
      isValid: issues.length === 0,
      issues,
    };
  }

  /**
   * Get audit statistics
   */
  getAuditStats(): {
    totalEntries: number;
    totalObjects: number;
    byAction: Record<AuditAction, number>;
    byObjectType: Record<string, number>;
    topActors: Array<{ actor: string; count: number }>;
  } {
    const byAction: Record<AuditAction, number> = {} as any;
    const byObjectType: Record<string, number> = {};
    const actorCounts: Map<string, number> = new Map();

    for (const entry of this.entries.values()) {
      // Count by action
      byAction[entry.action] = (byAction[entry.action] || 0) + 1;

      // Count by object type
      byObjectType[entry.objectType] = (byObjectType[entry.objectType] || 0) + 1;

      // Count by actor
      actorCounts.set(entry.actor, (actorCounts.get(entry.actor) || 0) + 1);
    }

    // Get top 10 actors
    const topActors = Array.from(actorCounts.entries())
      .map(([actor, count]) => ({ actor, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return {
      totalEntries: this.entries.size,
      totalObjects: this.logs.size,
      byAction,
      byObjectType,
      topActors,
    };
  }

  /**
   * Export audit log to JSON
   */
  exportAuditLog(objectId: string): AuditLog | null {
    return this.logs.get(objectId) || null;
  }

  /**
   * Export all audit logs
   */
  exportAllAuditLogs(): AuditLog[] {
    return Array.from(this.logs.values());
  }

  /**
   * Create audit report for object
   */
  generateAuditReport(objectId: string): string {
    const log = this.logs.get(objectId);
    if (!log) return '';

    let report = `# Audit Report for ${objectId}\n\n`;
    report += `Object Type: ${log.objectType}\n`;
    report += `Total Entries: ${log.entries.length}\n\n`;

    report += '## Timeline\n\n';
    for (const entry of log.entries) {
      report += `### ${entry.timestamp.toISOString()}\n`;
      report += `**Action:** ${entry.action}\n`;
      report += `**Actor:** ${entry.actor}\n`;

      if (entry.reason) {
        report += `**Reason:** ${entry.reason}\n`;
      }

      if (entry.approver) {
        report += `**Approver:** ${entry.approver}\n`;
      }

      if (entry.changes && entry.changes.length > 0) {
        report += '**Changes:**\n';
        for (const change of entry.changes) {
          report += `- ${change.fieldName}: ${change.previousValue} → ${change.newValue}\n`;
        }
      }

      report += '\n';
    }

    return report;
  }
}

export const auditEngine = new AuditEngine();
