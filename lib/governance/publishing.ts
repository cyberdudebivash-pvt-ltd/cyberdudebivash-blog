/**
 * Publishing Engine
 * Dispatch to publication pipeline destinations
 */

import { v4 as uuidv4 } from 'uuid';
import type { PublishingRecord, PublishDestination } from './types';
import { PublishDestination as PublishDestinationEnum } from './types';

// ============================================================================
// PUBLISHING ENGINE
// ============================================================================

export class PublishingEngine {
  private records: Map<string, PublishingRecord> = new Map();
  private destinationRecords: Map<PublishDestination, PublishingRecord[]> = new Map();

  /**
   * Publish intelligence to destinations
   */
  publish(
    objectId: string,
    objectType: string,
    versionId: string,
    publishedBy: string,
    destinations: PublishDestination[],
    renderings: Array<{
      format: 'markdown' | 'html' | 'json' | 'xml';
      content: string;
    }>
  ): PublishingRecord {
    const publishingId = uuidv4();

    const record: PublishingRecord = {
      publishingId,
      objectId,
      objectType,
      versionId,
      publishedAt: new Date(),
      publishedBy,
      destinations,
      renderings: renderings.map(r => ({
        format: r.format,
        content: r.content,
        renderedAt: new Date(),
      })),
      isLive: true,
      viewCount: 0,
    };

    this.records.set(publishingId, record);

    // Index by destination
    for (const destination of destinations) {
      if (!this.destinationRecords.has(destination)) {
        this.destinationRecords.set(destination, []);
      }
      this.destinationRecords.get(destination)!.push(record);
    }

    return record;
  }

  /**
   * Get publishing record
   */
  getPublishingRecord(publishingId: string): PublishingRecord | undefined {
    return this.records.get(publishingId);
  }

  /**
   * Get publishing records for object
   */
  getPublishingRecordsByObject(objectId: string): PublishingRecord[] {
    return Array.from(this.records.values()).filter(r => r.objectId === objectId);
  }

  /**
   * Get publishing records for destination
   */
  getPublishingRecordsByDestination(destination: PublishDestination): PublishingRecord[] {
    return this.destinationRecords.get(destination) || [];
  }

  /**
   * Update view count
   */
  updateViewCount(publishingId: string, newCount: number): PublishingRecord {
    const record = this.records.get(publishingId);
    if (!record) {
      throw new Error(`Publishing record not found: ${publishingId}`);
    }

    record.viewCount = newCount;
    return record;
  }

  /**
   * Increment view count
   */
  incrementViewCount(publishingId: string): PublishingRecord {
    const record = this.records.get(publishingId);
    if (!record) {
      throw new Error(`Publishing record not found: ${publishingId}`);
    }

    record.viewCount = (record.viewCount || 0) + 1;
    return record;
  }

  /**
   * Unpublish from specific destination
   */
  unpublishFromDestination(publishingId: string, destination: PublishDestination): PublishingRecord {
    const record = this.records.get(publishingId);
    if (!record) {
      throw new Error(`Publishing record not found: ${publishingId}`);
    }

    record.destinations = record.destinations.filter(d => d !== destination);

    // Remove from destination index if no longer published
    if (record.destinations.length === 0) {
      record.isLive = false;
    }

    return record;
  }

  /**
   * Get rendering by format
   */
  getRendering(
    publishingId: string,
    format: 'markdown' | 'html' | 'json' | 'xml'
  ): string | undefined {
    const record = this.records.get(publishingId);
    if (!record) return undefined;

    const rendering = record.renderings.find(r => r.format === format);
    return rendering?.content;
  }

  /**
   * Add rendering
   */
  addRendering(
    publishingId: string,
    format: 'markdown' | 'html' | 'json' | 'xml',
    content: string
  ): PublishingRecord {
    const record = this.records.get(publishingId);
    if (!record) {
      throw new Error(`Publishing record not found: ${publishingId}`);
    }

    // Remove existing rendering if present
    record.renderings = record.renderings.filter(r => r.format !== format);

    // Add new rendering
    record.renderings.push({
      format,
      content,
      renderedAt: new Date(),
    });

    return record;
  }

  /**
   * Get most popular published objects
   */
  getMostPopular(limit: number = 10): Array<{
    objectId: string;
    objectType: string;
    viewCount: number;
    destinations: number;
  }> {
    const objectStats: Map<
      string,
      {
        objectId: string;
        objectType: string;
        viewCount: number;
        destinations: number;
      }
    > = new Map();

    for (const record of this.records.values()) {
      const key = record.objectId;
      const existing = objectStats.get(key);

      if (existing) {
        existing.viewCount += record.viewCount || 0;
        existing.destinations = new Set([
          ...Array.from({ length: existing.destinations }, () => ''),
          ...record.destinations,
        ]).size;
      } else {
        objectStats.set(key, {
          objectId: record.objectId,
          objectType: record.objectType,
          viewCount: record.viewCount || 0,
          destinations: record.destinations.length,
        });
      }
    }

    return Array.from(objectStats.values())
      .sort((a, b) => b.viewCount - a.viewCount)
      .slice(0, limit);
  }

  /**
   * Get publication statistics
   */
  getPublicationStats(): {
    totalPublications: number;
    byObjectType: Record<string, number>;
    byDestination: Record<PublishDestination, number>;
    livePublications: number;
    totalViews: number;
    averageViewsPerPublication: number;
  } {
    const byObjectType: Record<string, number> = {};
    const byDestination: Record<PublishDestination, number> = {} as any;
    let liveCount = 0;
    let totalViews = 0;

    for (const record of this.records.values()) {
      // Count by object type
      byObjectType[record.objectType] = (byObjectType[record.objectType] || 0) + 1;

      // Count by destination
      for (const dest of record.destinations) {
        byDestination[dest] = (byDestination[dest] || 0) + 1;
      }

      // Count live
      if (record.isLive) {
        liveCount++;
      }

      // Sum views
      totalViews += record.viewCount || 0;
    }

    const avgViews =
      this.records.size > 0 ? Math.round(totalViews / this.records.size) : 0;

    return {
      totalPublications: this.records.size,
      byObjectType,
      byDestination,
      livePublications: liveCount,
      totalViews,
      averageViewsPerPublication: avgViews,
    };
  }

  /**
   * Get publication timeline
   */
  getPublicationTimeline(
    limit: number = 100
  ): Array<{
    publishedAt: Date;
    objectId: string;
    objectType: string;
    destinations: number;
    publishedBy: string;
  }> {
    return Array.from(this.records.values())
      .sort((a, b) => b.publishedAt.getTime() - a.publishedAt.getTime())
      .slice(0, limit)
      .map(r => ({
        publishedAt: r.publishedAt,
        objectId: r.objectId,
        objectType: r.objectType,
        destinations: r.destinations.length,
        publishedBy: r.publishedBy,
      }));
  }

  /**
   * Export all publishing records
   */
  exportPublishingRecords(): PublishingRecord[] {
    return Array.from(this.records.values());
  }

  /**
   * Check if object is published
   */
  isPublished(objectId: string): boolean {
    return this.getPublishingRecordsByObject(objectId).some(r => r.isLive);
  }

  /**
   * Get all destinations where object is published
   */
  getPublishedDestinations(objectId: string): PublishDestination[] {
    const records = this.getPublishingRecordsByObject(objectId);
    const destinations = new Set<PublishDestination>();

    for (const record of records) {
      if (record.isLive) {
        for (const dest of record.destinations) {
          destinations.add(dest);
        }
      }
    }

    return Array.from(destinations);
  }

  /**
   * Generate publication report
   */
  generatePublicationReport(objectId: string): string {
    const records = this.getPublishingRecordsByObject(objectId);
    if (records.length === 0) {
      return `No publications for object: ${objectId}`;
    }

    let report = `# Publication Report for ${objectId}\n\n`;
    report += `Total Publications: ${records.length}\n`;
    report += `Total Views: ${records.reduce((sum, r) => sum + (r.viewCount || 0), 0)}\n\n`;

    for (const record of records) {
      report += `## Publication ${record.publishingId}\n`;
      report += `**Date:** ${record.publishedAt.toISOString()}\n`;
      report += `**Published By:** ${record.publishedBy}\n`;
      report += `**Status:** ${record.isLive ? 'Live' : 'Archived'}\n`;
      report += `**Views:** ${record.viewCount || 0}\n`;

      report += '**Destinations:**\n';
      for (const dest of record.destinations) {
        report += `- ${dest}\n`;
      }

      report += '**Formats:**\n';
      for (const rendering of record.renderings) {
        report += `- ${rendering.format} (${rendering.content.length} bytes)\n`;
      }

      report += '\n';
    }

    return report;
  }
}

export const publishingEngine = new PublishingEngine();
