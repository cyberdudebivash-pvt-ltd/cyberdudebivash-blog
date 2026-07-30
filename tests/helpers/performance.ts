// Performance Helpers — Test instrumentation and SLA validation

export interface PerformanceMetrics {
  operation: string;
  duration: number; // milliseconds
  startTime: Date;
  endTime: Date;
  memoryBefore: number;
  memoryAfter: number;
  memoryDelta: number;
  passed: boolean;
  slaMet: boolean;
  slaTarget?: number;
}

export class PerformanceMonitor {
  private metrics: PerformanceMetrics[] = [];
  private startTimes: Map<string, number> = new Map();
  private startMemory: Map<string, number> = new Map();

  start(operationName: string): void {
    if (global.gc) {
      global.gc();
    }
    this.startTimes.set(operationName, Date.now());
    this.startMemory.set(operationName, process.memoryUsage().heapUsed);
  }

  end(operationName: string, slaTarget?: number): PerformanceMetrics {
    const endTime = Date.now();
    const startTime = this.startTimes.get(operationName);
    const memoryBefore = this.startMemory.get(operationName);

    if (!startTime || memoryBefore === undefined) {
      throw new Error(`No start time recorded for operation: ${operationName}`);
    }

    const duration = endTime - startTime;
    const memoryAfter = process.memoryUsage().heapUsed;
    const memoryDelta = memoryAfter - memoryBefore;

    const metric: PerformanceMetrics = {
      operation: operationName,
      duration,
      startTime: new Date(startTime),
      endTime: new Date(endTime),
      memoryBefore,
      memoryAfter,
      memoryDelta,
      passed: true,
      slaMet: !slaTarget || duration <= slaTarget,
      slaTarget,
    };

    this.metrics.push(metric);
    this.startTimes.delete(operationName);
    this.startMemory.delete(operationName);

    return metric;
  }

  async measureAsync<T>(
    operationName: string,
    operation: () => Promise<T>,
    slaTarget?: number
  ): Promise<{ result: T; metric: PerformanceMetrics }> {
    this.start(operationName);
    const result = await operation();
    const metric = this.end(operationName, slaTarget);
    return { result, metric };
  }

  measure<T>(
    operationName: string,
    operation: () => T,
    slaTarget?: number
  ): { result: T; metric: PerformanceMetrics } {
    this.start(operationName);
    const result = operation();
    const metric = this.end(operationName, slaTarget);
    return { result, metric };
  }

  getMetrics(): PerformanceMetrics[] {
    return [...this.metrics];
  }

  getMetric(operationName: string): PerformanceMetrics | undefined {
    return this.metrics.find((m) => m.operation === operationName);
  }

  getSummary(): {
    totalOperations: number;
    totalDuration: number;
    averageDuration: number;
    slaCompliance: number;
    peakMemory: number;
    averageMemoryDelta: number;
  } {
    const totalDuration = this.metrics.reduce((sum, m) => sum + m.duration, 0);
    const slaCompliance =
      this.metrics.length > 0
        ? (this.metrics.filter((m) => m.slaMet).length / this.metrics.length) * 100
        : 0;
    const peakMemory = Math.max(...this.metrics.map((m) => m.memoryAfter), 0);
    const averageMemoryDelta =
      this.metrics.length > 0
        ? this.metrics.reduce((sum, m) => sum + m.memoryDelta, 0) / this.metrics.length
        : 0;

    return {
      totalOperations: this.metrics.length,
      totalDuration,
      averageDuration: this.metrics.length > 0 ? totalDuration / this.metrics.length : 0,
      slaCompliance,
      peakMemory,
      averageMemoryDelta,
    };
  }

  reset(): void {
    this.metrics = [];
    this.startTimes.clear();
    this.startMemory.clear();
  }

  report(): string {
    const summary = this.getSummary();
    let report = `Performance Report\n`;
    report += `Total Operations: ${summary.totalOperations}\n`;
    report += `Total Duration: ${summary.totalDuration}ms\n`;
    report += `Average Duration: ${summary.averageDuration.toFixed(2)}ms\n`;
    report += `SLA Compliance: ${summary.slaCompliance.toFixed(1)}%\n`;
    report += `Peak Memory: ${(summary.peakMemory / 1024 / 1024).toFixed(2)}MB\n`;
    report += `Average Memory Delta: ${(summary.averageMemoryDelta / 1024).toFixed(2)}KB\n\n`;
    report += `Detailed Metrics:\n`;

    this.metrics.forEach((metric) => {
      report += `  ${metric.operation}: ${metric.duration}ms`;
      if (metric.slaTarget) {
        report += ` (SLA: ${metric.slaTarget}ms, ${metric.slaMet ? 'PASS' : 'FAIL'})`;
      }
      report += ` [${(metric.memoryDelta / 1024).toFixed(2)}KB]\n`;
    });

    return report;
  }
}

export const createPerformanceMonitor = (): PerformanceMonitor => new PerformanceMonitor();

export const expectPerformanceSLA = (
  duration: number,
  slaTarget: number,
  operationName?: string
): void => {
  const message = operationName ? `${operationName}: ` : '';
  expect(duration).toBeLessThanOrEqual(slaTarget);
};
