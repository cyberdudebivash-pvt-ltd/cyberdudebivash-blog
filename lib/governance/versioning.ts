/**
 * Versioning Engine
 * Version control with diffs and rollback capability
 */

import { v4 as uuidv4 } from 'uuid';
import type { IntelligenceVersion, VersionHistory, VersionDiff } from './types';

// ============================================================================
// VERSIONING ENGINE
// ============================================================================

export class VersioningEngine {
  private versions: Map<string, IntelligenceVersion> = new Map();
  private histories: Map<string, VersionHistory> = new Map();

  /**
   * Create a new version
   */
  createVersion(
    objectType: 'report' | 'ioc' | 'detection' | 'malware',
    objectId: string,
    version: number,
    content: any,
    analyst: string,
    changesSummary: string,
    diff: VersionDiff,
    previousVersionId?: string
  ): IntelligenceVersion {
    const versionId = uuidv4();

    const intelligenceVersion: IntelligenceVersion = {
      versionId,
      objectType,
      objectId,
      version,
      publishedDate: new Date(),
      analyst,
      changesSummary,
      content,
      diff,
      previousVersionId,
      isPublished: false,
      isArchived: false,
      isRetracted: false,
    };

    this.versions.set(versionId, intelligenceVersion);

    // Update or create history
    if (!this.histories.has(objectId)) {
      this.histories.set(objectId, {
        objectId,
        objectType,
        versions: [],
        currentVersion: version,
        canRollback: version > 1,
      });
    }

    const history = this.histories.get(objectId)!;
    history.versions.push(intelligenceVersion);
    history.currentVersion = version;
    history.canRollback = version > 1;

    return intelligenceVersion;
  }

  /**
   * Get version by ID
   */
  getVersion(versionId: string): IntelligenceVersion | undefined {
    return this.versions.get(versionId);
  }

  /**
   * Get version history for object
   */
  getVersionHistory(objectId: string): VersionHistory | undefined {
    return this.histories.get(objectId);
  }

  /**
   * Get specific version by number
   */
  getVersionByNumber(objectId: string, versionNumber: number): IntelligenceVersion | undefined {
    const history = this.histories.get(objectId);
    if (!history) return undefined;
    return history.versions.find(v => v.version === versionNumber);
  }

  /**
   * Get current version
   */
  getCurrentVersion(objectId: string): IntelligenceVersion | undefined {
    const history = this.histories.get(objectId);
    if (!history || history.versions.length === 0) return undefined;
    return history.versions[history.versions.length - 1];
  }

  /**
   * Publish a version
   */
  publishVersion(versionId: string, publishedBy: string): IntelligenceVersion {
    const version = this.versions.get(versionId);
    if (!version) {
      throw new Error(`Version not found: ${versionId}`);
    }

    if (version.isPublished) {
      throw new Error(`Version already published: ${versionId}`);
    }

    version.isPublished = true;
    version.publishedDate = new Date();

    return version;
  }

  /**
   * Archive a version
   */
  archiveVersion(versionId: string): IntelligenceVersion {
    const version = this.versions.get(versionId);
    if (!version) {
      throw new Error(`Version not found: ${versionId}`);
    }

    version.isArchived = true;

    return version;
  }

  /**
   * Retract a version
   */
  retractVersion(
    versionId: string,
    reason: string,
    retractedBy: string
  ): IntelligenceVersion {
    const version = this.versions.get(versionId);
    if (!version) {
      throw new Error(`Version not found: ${versionId}`);
    }

    version.isRetracted = true;
    version.retractedReason = reason;
    version.retractedBy = retractedBy;
    version.retractedAt = new Date();

    return version;
  }

  /**
   * Compare two versions
   */
  compareVersions(versionId1: string, versionId2: string): VersionDiff | null {
    const v1 = this.versions.get(versionId1);
    const v2 = this.versions.get(versionId2);

    if (!v1 || !v2) return null;

    // Combine diffs
    const combinedDiff: VersionDiff = {
      fieldChanges: [],
      iocChanges: {
        added: [],
        removed: [],
        modified: [],
      },
      detectionChanges: {
        added: [],
        removed: [],
        modified: [],
      },
      techniqueChanges: {
        added: [],
        removed: [],
      },
    };

    // Include all field changes from both versions
    if (v1.diff) {
      combinedDiff.fieldChanges.push(...v1.diff.fieldChanges);
      combinedDiff.iocChanges.added.push(...v1.diff.iocChanges.added);
      combinedDiff.iocChanges.removed.push(...v1.diff.iocChanges.removed);
      combinedDiff.iocChanges.modified.push(...v1.diff.iocChanges.modified);
      combinedDiff.detectionChanges.added.push(...v1.diff.detectionChanges.added);
      combinedDiff.detectionChanges.removed.push(...v1.diff.detectionChanges.removed);
      combinedDiff.detectionChanges.modified.push(...v1.diff.detectionChanges.modified);
      combinedDiff.techniqueChanges.added.push(...v1.diff.techniqueChanges.added);
      combinedDiff.techniqueChanges.removed.push(...v1.diff.techniqueChanges.removed);
    }

    if (v2.diff) {
      combinedDiff.fieldChanges.push(...v2.diff.fieldChanges);
      combinedDiff.iocChanges.added.push(...v2.diff.iocChanges.added);
      combinedDiff.iocChanges.removed.push(...v2.diff.iocChanges.removed);
      combinedDiff.iocChanges.modified.push(...v2.diff.iocChanges.modified);
      combinedDiff.detectionChanges.added.push(...v2.diff.detectionChanges.added);
      combinedDiff.detectionChanges.removed.push(...v2.diff.detectionChanges.removed);
      combinedDiff.detectionChanges.modified.push(...v2.diff.detectionChanges.modified);
      combinedDiff.techniqueChanges.added.push(...v2.diff.techniqueChanges.added);
      combinedDiff.techniqueChanges.removed.push(...v2.diff.techniqueChanges.removed);
    }

    return combinedDiff;
  }

  /**
   * Get version changelog (human-readable summary)
   */
  getVersionChangelog(objectId: string): Array<{
    version: number;
    date: Date;
    analyst: string;
    summary: string;
  }> {
    const history = this.histories.get(objectId);
    if (!history) return [];

    return history.versions.map(v => ({
      version: v.version,
      date: v.publishedDate,
      analyst: v.analyst,
      summary: v.changesSummary,
    }));
  }

  /**
   * Can rollback to specific version
   */
  canRollback(objectId: string, targetVersion: number): boolean {
    const history = this.histories.get(objectId);
    if (!history) return false;

    const targetVersionObj = history.versions.find(v => v.version === targetVersion);
    if (!targetVersionObj) return false;

    // Can only rollback if target version is published and not retracted
    return targetVersionObj.isPublished && !targetVersionObj.isRetracted;
  }

  /**
   * Rollback to specific version (marks current as retracted, promotes target)
   */
  rollback(objectId: string, targetVersion: number, reason: string, rolledBackBy: string): {
    previousVersion: IntelligenceVersion;
    restoredVersion: IntelligenceVersion;
  } {
    if (!this.canRollback(objectId, targetVersion)) {
      throw new Error(`Cannot rollback to version ${targetVersion}`);
    }

    const history = this.histories.get(objectId);
    if (!history) {
      throw new Error(`No version history for object: ${objectId}`);
    }

    const currentVersion = history.versions[history.versions.length - 1];
    const restoredVersion = history.versions.find(v => v.version === targetVersion);

    if (!restoredVersion) {
      throw new Error(`Target version not found: ${targetVersion}`);
    }

    // Mark current as retracted
    currentVersion.isRetracted = true;
    currentVersion.retractedReason = reason;
    currentVersion.retractedBy = rolledBackBy;
    currentVersion.retractedAt = new Date();

    // Mark target as re-published (no longer archived)
    restoredVersion.isArchived = false;

    return {
      previousVersion: currentVersion,
      restoredVersion,
    };
  }

  /**
   * Get all versions for object
   */
  getAllVersions(objectId: string): IntelligenceVersion[] {
    const history = this.histories.get(objectId);
    return history?.versions || [];
  }

  /**
   * Get published versions only
   */
  getPublishedVersions(objectId: string): IntelligenceVersion[] {
    return this.getAllVersions(objectId).filter(v => v.isPublished && !v.isRetracted);
  }

  /**
   * Get retracted versions
   */
  getRetractedVersions(objectId: string): IntelligenceVersion[] {
    return this.getAllVersions(objectId).filter(v => v.isRetracted);
  }

  /**
   * Version statistics
   */
  getVersionStats(): {
    totalVersions: number;
    totalObjects: number;
    publishedVersions: number;
    retractedVersions: number;
    averageVersionsPerObject: number;
  } {
    let publishedCount = 0;
    let retractedCount = 0;

    for (const version of this.versions.values()) {
      if (version.isPublished) publishedCount++;
      if (version.isRetracted) retractedCount++;
    }

    const avgVersions =
      this.histories.size > 0
        ? Math.round(
            Array.from(this.histories.values()).reduce(
              (sum, h) => sum + h.versions.length,
              0
            ) / this.histories.size
          )
        : 0;

    return {
      totalVersions: this.versions.size,
      totalObjects: this.histories.size,
      publishedVersions: publishedCount,
      retractedVersions: retractedCount,
      averageVersionsPerObject: avgVersions,
    };
  }
}

export const versioningEngine = new VersioningEngine();
