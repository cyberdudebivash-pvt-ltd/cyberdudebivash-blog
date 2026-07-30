/**
 * Rollback & Retraction Engine
 * Handles retractions, corrections, and recovery procedures
 */

import { v4 as uuidv4 } from 'uuid';
import type { RetractionRecord } from './types';

// ============================================================================
// ROLLBACK ENGINE
// ============================================================================

export class RollbackEngine {
  private retractions: Map<string, RetractionRecord> = new Map();
  private correctionHistory: Map<string, string[]> = new Map(); // Maps original to corrections

  /**
   * Create a retraction record
   */
  retract(
    objectId: string,
    objectType: string,
    publishedVersionId: string,
    reason: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    retractionDetails: string,
    affectedItems: string[],
    retractedBy: string
  ): RetractionRecord {
    const retractionId = uuidv4();

    const record: RetractionRecord = {
      retractionId,
      objectId,
      objectType,
      publishedVersionId,
      reason,
      severity,
      retractionDetails,
      affectedItems,
      retractedBy,
      retractedAt: new Date(),
      notificationsSent: [],
    };

    this.retractions.set(retractionId, record);

    return record;
  }

  /**
   * Get retraction record
   */
  getRetraction(retractionId: string): RetractionRecord | undefined {
    return this.retractions.get(retractionId);
  }

  /**
   * Get retractions for object
   */
  getRetractionsByObject(objectId: string): RetractionRecord[] {
    return Array.from(this.retractions.values()).filter(r => r.objectId === objectId);
  }

  /**
   * Record notification sent
   */
  recordNotificationSent(
    retractionId: string,
    channel: 'email' | 'api' | 'dashboard',
    recipients: number
  ): RetractionRecord {
    const record = this.retractions.get(retractionId);
    if (!record) {
      throw new Error(`Retraction not found: ${retractionId}`);
    }

    record.notificationsSent.push({
      channel,
      sentAt: new Date(),
      recipients,
    });

    return record;
  }

  /**
   * Mark retraction as corrected and re-published
   */
  markCorrected(retractionId: string, correctionVersionId: string): RetractionRecord {
    const record = this.retractions.get(retractionId);
    if (!record) {
      throw new Error(`Retraction not found: ${retractionId}`);
    }

    record.correctionVersion = correctionVersionId;

    // Track correction history
    if (!this.correctionHistory.has(record.objectId)) {
      this.correctionHistory.set(record.objectId, []);
    }
    this.correctionHistory.get(record.objectId)!.push(retractionId);

    return record;
  }

  /**
   * Get correction history for object
   */
  getCorrectionHistory(objectId: string): RetractionRecord[] {
    const retractionIds = this.correctionHistory.get(objectId) || [];
    return retractionIds
      .map(id => this.retractions.get(id))
      .filter((r): r is RetractionRecord => r !== undefined && r.correctionVersion !== undefined);
  }

  /**
   * Check if object has unresolved retractions
   */
  hasUnresolvedRetractions(objectId: string): boolean {
    return this.getRetractionsByObject(objectId).some(r => !r.correctionVersion);
  }

  /**
   * Get retractions by severity
   */
  getRetractionsBySeverity(
    severity: 'low' | 'medium' | 'high' | 'critical'
  ): RetractionRecord[] {
    return Array.from(this.retractions.values()).filter(r => r.severity === severity);
  }

  /**
   * Generate retraction report
   */
  generateRetractionReport(objectId: string): string {
    const retractions = this.getRetractionsByObject(objectId);
    if (retractions.length === 0) {
      return `No retractions for object: ${objectId}`;
    }

    let report = `# Retraction Report for ${objectId}\n\n`;
    report += `Total Retractions: ${retractions.length}\n\n`;

    for (const retraction of retractions) {
      report += `## Retraction ${retraction.retractionId}\n`;
      report += `**Date:** ${retraction.retractedAt.toISOString()}\n`;
      report += `**Severity:** ${retraction.severity}\n`;
      report += `**Reason:** ${retraction.reason}\n`;
      report += `**Retracted By:** ${retraction.retractedBy}\n`;
      report += `**Details:** ${retraction.retractionDetails}\n`;

      if (retraction.affectedItems.length > 0) {
        report += '**Affected Items:**\n';
        for (const item of retraction.affectedItems) {
          report += `- ${item}\n`;
        }
      }

      if (retraction.correctionVersion) {
        report += `**Corrected:** Yes (Version: ${retraction.correctionVersion})\n`;
      } else {
        report += '**Corrected:** No\n';
      }

      if (retraction.notificationsSent.length > 0) {
        report += '**Notifications Sent:**\n';
        for (const notif of retraction.notificationsSent) {
          report += `- ${notif.channel} (${notif.recipients} recipients) at ${notif.sentAt.toISOString()}\n`;
        }
      }

      report += '\n';
    }

    return report;
  }

  /**
   * Get rollback candidates (published, non-retracted versions)
   */
  getRollbackCandidates(objectId: string): string[] {
    // This would reference the versioning engine in a real implementation
    // For now, return empty array as it requires cross-engine coordination
    return [];
  }

  /**
   * Rollback statistics
   */
  getRollbackStats(): {
    totalRetractions: number;
    byObjectType: Record<string, number>;
    bySeverity: Record<string, number>;
    correctedCount: number;
    uncorrectedCount: number;
    notificationsSent: number;
  } {
    const byObjectType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    let correctedCount = 0;
    let notificationsSent = 0;

    for (const retraction of this.retractions.values()) {
      // Count by object type
      byObjectType[retraction.objectType] = (byObjectType[retraction.objectType] || 0) + 1;

      // Count by severity
      bySeverity[retraction.severity] = (bySeverity[retraction.severity] || 0) + 1;

      // Count corrections
      if (retraction.correctionVersion) {
        correctedCount++;
      }

      // Count notifications
      notificationsSent += retraction.notificationsSent.length;
    }

    return {
      totalRetractions: this.retractions.size,
      byObjectType,
      bySeverity,
      correctedCount,
      uncorrectedCount: this.retractions.size - correctedCount,
      notificationsSent,
    };
  }

  /**
   * Publish retraction notices to all destinations
   */
  async publishRetractionsNotices(destinations: string[]): Promise<void> {
    // Each unresolved retraction needs to be published to relevant destinations
    // Implementation would coordinate with publishing engine
    const unresolved = Array.from(this.retractions.values()).filter(r => !r.correctionVersion);

    for (const retraction of unresolved) {
      for (const destination of destinations) {
        // Publish notice to destination
        // This is a placeholder for actual implementation
        await this.recordNotificationSent(retraction.retractionId, destination as any, 0);
      }
    }
  }

  /**
   * Export retraction data
   */
  exportRetractions(): RetractionRecord[] {
    return Array.from(this.retractions.values());
  }

  /**
   * Export retraction timeline
   */
  exportRetractionTimeline(objectId: string): Array<{
    date: Date;
    action: string;
    severity: string;
    details: string;
  }> {
    const retractions = this.getRetractionsByObject(objectId);
    const timeline: Array<{
      date: Date;
      action: string;
      severity: string;
      details: string;
    }> = [];

    for (const retraction of retractions) {
      timeline.push({
        date: retraction.retractedAt,
        action: 'RETRACTED',
        severity: retraction.severity,
        details: retraction.reason,
      });

      if (retraction.correctionVersion) {
        timeline.push({
          date: new Date(), // Would need to track correction date
          action: 'CORRECTED',
          severity: 'info',
          details: `Published corrected version: ${retraction.correctionVersion}`,
        });
      }
    }

    return timeline.sort((a, b) => a.date.getTime() - b.date.getTime());
  }
}

export const rollbackEngine = new RollbackEngine();
