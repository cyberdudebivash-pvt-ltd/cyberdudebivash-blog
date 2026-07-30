/**
 * Multidimensional Confidence Engine
 * Calculates confidence from weighted components rather than single scores
 * Stores every component, never only final score
 */

import type { ConfidenceComponent, MultidimensionalConfidence } from './types';

// ============================================================================
// CONFIDENCE ENGINE
// ============================================================================

export class ConfidenceEngine {
  private confidenceHistory: Map<string, MultidimensionalConfidence[]> = new Map();

  /**
   * Calculate multidimensional confidence from components
   */
  calculateConfidence(
    objectId: string,
    sourceReliability: ConfidenceComponent,
    observationQuality: ConfidenceComponent,
    technicalValidation: ConfidenceComponent,
    analystVerification: ConfidenceComponent,
    independentCorroboration: ConfidenceComponent,
    reasoning: string
  ): MultidimensionalConfidence {
    // Validate all components have valid scores (0-100) and weights (0-1)
    const components = [
      sourceReliability,
      observationQuality,
      technicalValidation,
      analystVerification,
      independentCorroboration,
    ];

    for (const component of components) {
      if (component.score < 0 || component.score > 100) {
        throw new Error(`Invalid score: ${component.score}. Must be 0-100.`);
      }
      if (component.weight < 0 || component.weight > 1) {
        throw new Error(`Invalid weight: ${component.weight}. Must be 0-1.`);
      }
    }

    // Calculate weighted average
    const totalWeight = components.reduce((sum, c) => sum + c.weight, 0);
    if (totalWeight === 0) {
      throw new Error('Total weight cannot be zero');
    }

    const overallConfidence = Math.round(
      components.reduce((sum, c) => sum + (c.score * c.weight), 0) / totalWeight
    );

    const confidence: MultidimensionalConfidence = {
      sourceReliability,
      observationQuality,
      technicalValidation,
      analystVerification,
      independentCorroboration,
      overallConfidence,
      reasoning,
      timestamp: new Date(),
      calculatedBy: 'system',
    };

    // Store in history
    if (!this.confidenceHistory.has(objectId)) {
      this.confidenceHistory.set(objectId, []);
    }
    this.confidenceHistory.get(objectId)!.push(confidence);

    return confidence;
  }

  /**
   * Update a single confidence component
   */
  updateComponent(
    objectId: string,
    componentName: keyof Omit<
      MultidimensionalConfidence,
      'overallConfidence' | 'reasoning' | 'timestamp' | 'calculatedBy'
    >,
    newComponent: ConfidenceComponent,
    reasoning: string
  ): MultidimensionalConfidence {
    const history = this.confidenceHistory.get(objectId);
    if (!history || history.length === 0) {
      throw new Error(`No confidence record found for object: ${objectId}`);
    }

    const previous = history[history.length - 1];

    return this.calculateConfidence(
      objectId,
      componentName === 'sourceReliability' ? newComponent : previous.sourceReliability,
      componentName === 'observationQuality' ? newComponent : previous.observationQuality,
      componentName === 'technicalValidation' ? newComponent : previous.technicalValidation,
      componentName === 'analystVerification' ? newComponent : previous.analystVerification,
      componentName === 'independentCorroboration' ? newComponent : previous.independentCorroboration,
      reasoning
    );
  }

  /**
   * Get current confidence for object
   */
  getCurrentConfidence(objectId: string): MultidimensionalConfidence | undefined {
    const history = this.confidenceHistory.get(objectId);
    return history && history.length > 0 ? history[history.length - 1] : undefined;
  }

  /**
   * Get confidence history for object
   */
  getConfidenceHistory(objectId: string): MultidimensionalConfidence[] {
    return this.confidenceHistory.get(objectId) || [];
  }

  /**
   * Analyze confidence trend (increasing/decreasing/stable)
   */
  getConfidenceTrend(objectId: string): 'increasing' | 'decreasing' | 'stable' {
    const history = this.getConfidenceHistory(objectId);
    if (history.length < 2) return 'stable';

    const recent = history.slice(-3);
    const scores = recent.map(c => c.overallConfidence);

    if (scores[scores.length - 1] > scores[0] + 5) return 'increasing';
    if (scores[scores.length - 1] < scores[0] - 5) return 'decreasing';
    return 'stable';
  }

  /**
   * Get weakest component (lowest score)
   */
  getWeakestComponent(
    objectId: string
  ): {
    component: string;
    score: number;
    basis: string;
  } | null {
    const current = this.getCurrentConfidence(objectId);
    if (!current) return null;

    const components = [
      { name: 'sourceReliability', data: current.sourceReliability },
      { name: 'observationQuality', data: current.observationQuality },
      { name: 'technicalValidation', data: current.technicalValidation },
      { name: 'analystVerification', data: current.analystVerification },
      { name: 'independentCorroboration', data: current.independentCorroboration },
    ];

    let weakest = components[0];
    for (const comp of components) {
      if (comp.data.score < weakest.data.score) {
        weakest = comp;
      }
    }

    return {
      component: weakest.name,
      score: weakest.data.score,
      basis: weakest.data.basis,
    };
  }

  /**
   * Get strongest component (highest score)
   */
  getStrongestComponent(
    objectId: string
  ): {
    component: string;
    score: number;
    basis: string;
  } | null {
    const current = this.getCurrentConfidence(objectId);
    if (!current) return null;

    const components = [
      { name: 'sourceReliability', data: current.sourceReliability },
      { name: 'observationQuality', data: current.observationQuality },
      { name: 'technicalValidation', data: current.technicalValidation },
      { name: 'analystVerification', data: current.analystVerification },
      { name: 'independentCorroboration', data: current.independentCorroboration },
    ];

    let strongest = components[0];
    for (const comp of components) {
      if (comp.data.score > strongest.data.score) {
        strongest = comp;
      }
    }

    return {
      component: strongest.name,
      score: strongest.data.score,
      basis: strongest.data.basis,
    };
  }

  /**
   * Check if confidence meets threshold
   */
  meetsThreshold(objectId: string, threshold: number): boolean {
    const current = this.getCurrentConfidence(objectId);
    return current ? current.overallConfidence >= threshold : false;
  }

  /**
   * Get confidence statistics across all objects
   */
  getConfidenceStats(): {
    totalObjects: number;
    averageConfidence: number;
    medianConfidence: number;
    byRange: Record<string, number>;
  } {
    const allScores: number[] = [];

    for (const history of this.confidenceHistory.values()) {
      if (history.length > 0) {
        allScores.push(history[history.length - 1].overallConfidence);
      }
    }

    if (allScores.length === 0) {
      return {
        totalObjects: 0,
        averageConfidence: 0,
        medianConfidence: 0,
        byRange: {},
      };
    }

    const sorted = allScores.sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    const average = Math.round(allScores.reduce((a, b) => a + b) / allScores.length);

    const byRange = {
      '0-20': allScores.filter(s => s >= 0 && s < 20).length,
      '20-40': allScores.filter(s => s >= 20 && s < 40).length,
      '40-60': allScores.filter(s => s >= 40 && s < 60).length,
      '60-80': allScores.filter(s => s >= 60 && s < 80).length,
      '80-100': allScores.filter(s => s >= 80 && s <= 100).length,
    };

    return {
      totalObjects: this.confidenceHistory.size,
      averageConfidence: average,
      medianConfidence: median,
      byRange,
    };
  }
}

export const confidenceEngine = new ConfidenceEngine();
