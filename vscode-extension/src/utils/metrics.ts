/**
 * Performance metrics utilities for GoSQLX extension.
 * Tracks LSP operation performance and provides insights.
 */

import * as vscode from 'vscode';

/**
 * Operation types tracked by the metrics system.
 */
export type OperationType =
    | 'lsp.startup'
    | 'lsp.shutdown'
    | 'lsp.validate'
    | 'lsp.format'
    | 'lsp.analyze'
    | 'lsp.hover'
    | 'lsp.completion'
    | 'lsp.diagnostics'
    | 'command.validate'
    | 'command.format'
    | 'command.analyze'
    | 'executable.check';

/**
 * A single performance measurement.
 */
export interface PerformanceMeasurement {
    operation: OperationType;
    duration: number;
    timestamp: number;
    success: boolean;
    metadata?: Record<string, unknown>;
}

/**
 * Aggregated statistics for an operation type.
 */
export interface OperationStats {
    count: number;
    successCount: number;
    failureCount: number;
    totalDuration: number;
    minDuration: number;
    maxDuration: number;
    avgDuration: number;
    p95Duration: number;
    lastDuration: number;
    lastTimestamp: number;
}

/**
 * Performance timer for measuring operation durations.
 */
export class PerformanceTimer {
    private startTime: number = 0;
    private running: boolean = false;

    /**
     * Starts the timer.
     */
    public start(): void {
        this.startTime = Date.now();
        this.running = true;
    }

    /**
     * Stops the timer and returns the elapsed duration in milliseconds.
     */
    public stop(): number {
        if (!this.running) {
            return 0;
        }
        this.running = false;
        return Date.now() - this.startTime;
    }

    /**
     * Gets the current elapsed time without stopping the timer.
     */
    public elapsed(): number {
        if (!this.running) {
            return 0;
        }
        return Date.now() - this.startTime;
    }

    /**
     * Checks if the timer is running.
     */
    public isRunning(): boolean {
        return this.running;
    }

    /**
     * Resets the timer.
     */
    public reset(): void {
        this.startTime = 0;
        this.running = false;
    }
}

/**
 * Collects and manages performance metrics.
 */
export class MetricsCollector {
    private static instance: MetricsCollector | undefined;
    private measurements: Map<OperationType, PerformanceMeasurement[]> = new Map();
    private maxMeasurements: number = 1000; // Per operation type
    private enabled: boolean = true;

    private constructor() { }

    /**
     * Gets the singleton instance.
     */
    public static getInstance(): MetricsCollector {
        if (!MetricsCollector.instance) {
            MetricsCollector.instance = new MetricsCollector();
        }
        return MetricsCollector.instance;
    }

    /**
     * Enables metrics collection.
     */
    public enable(): void {
        this.enabled = true;
    }

    /**
     * Disables metrics collection and clears data.
     */
    public disable(): void {
        this.enabled = false;
        this.measurements.clear();
    }

    /**
     * Records a performance measurement.
     */
    public record(
        operation: OperationType,
        duration: number,
        success: boolean = true,
        metadata?: Record<string, unknown>
    ): void {
        if (!this.enabled) {
            return;
        }

        const measurement: PerformanceMeasurement = {
            operation,
            duration,
            timestamp: Date.now(),
            success,
            metadata
        };

        if (!this.measurements.has(operation)) {
            this.measurements.set(operation, []);
        }

        const measurements = this.measurements.get(operation)!;
        measurements.push(measurement);

        // Limit stored measurements
        while (measurements.length > this.maxMeasurements) {
            measurements.shift();
        }
    }

    /**
     * Records a duration measurement with a timer.
     */
    public recordWithTimer<T>(
        operation: OperationType,
        fn: () => T,
        metadata?: Record<string, unknown>
    ): T {
        const timer = new PerformanceTimer();
        timer.start();

        try {
            const result = fn();
            this.record(operation, timer.stop(), true, metadata);
            return result;
        } catch (error) {
            this.record(operation, timer.stop(), false, metadata);
            throw error;
        }
    }

    /**
     * Records an async duration measurement with a timer.
     */
    public async recordWithTimerAsync<T>(
        operation: OperationType,
        fn: () => Promise<T>,
        metadata?: Record<string, unknown>
    ): Promise<T> {
        const timer = new PerformanceTimer();
        timer.start();

        try {
            const result = await fn();
            this.record(operation, timer.stop(), true, metadata);
            return result;
        } catch (error) {
            this.record(operation, timer.stop(), false, metadata);
            throw error;
        }
    }

    /**
     * Gets statistics for an operation type.
     */
    public getStats(operation: OperationType): OperationStats | undefined {
        const measurements = this.measurements.get(operation);
        if (!measurements || measurements.length === 0) {
            return undefined;
        }

        const durations = measurements.map(m => m.duration);
        const sortedDurations = [...durations].sort((a, b) => a - b);

        const successCount = measurements.filter(m => m.success).length;
        const totalDuration = durations.reduce((a, b) => a + b, 0);
        const p95Index = Math.floor(sortedDurations.length * 0.95);

        return {
            count: measurements.length,
            successCount,
            failureCount: measurements.length - successCount,
            totalDuration,
            minDuration: sortedDurations[0],
            maxDuration: sortedDurations[sortedDurations.length - 1],
            avgDuration: totalDuration / measurements.length,
            p95Duration: sortedDurations[p95Index] ?? sortedDurations[sortedDurations.length - 1],
            lastDuration: durations[durations.length - 1],
            lastTimestamp: measurements[measurements.length - 1].timestamp
        };
    }

    /**
     * Gets statistics for all operation types.
     */
    public getAllStats(): Map<OperationType, OperationStats> {
        const stats = new Map<OperationType, OperationStats>();

        for (const operation of this.measurements.keys()) {
            const opStats = this.getStats(operation);
            if (opStats) {
                stats.set(operation, opStats);
            }
        }

        return stats;
    }

    /**
     * Gets a summary of all metrics.
     */
    public getSummary(): string {
        const stats = this.getAllStats();
        const lines: string[] = ['=== GoSQLX Performance Metrics ===', ''];

        if (stats.size === 0) {
            lines.push('No metrics collected yet.');
            return lines.join('\n');
        }

        for (const [operation, opStats] of stats) {
            lines.push(`${operation}:`);
            lines.push(`  Count: ${opStats.count} (${opStats.successCount} success, ${opStats.failureCount} failed)`);
            lines.push(`  Duration: avg=${opStats.avgDuration.toFixed(1)}ms, min=${opStats.minDuration}ms, max=${opStats.maxDuration}ms, p95=${opStats.p95Duration.toFixed(1)}ms`);
            lines.push('');
        }

        return lines.join('\n');
    }

    /**
     * Gets recent measurements for an operation.
     */
    public getRecentMeasurements(operation: OperationType, count: number = 10): PerformanceMeasurement[] {
        const measurements = this.measurements.get(operation);
        if (!measurements) {
            return [];
        }
        return measurements.slice(-count);
    }

    /**
     * Gets the success rate for an operation.
     */
    public getSuccessRate(operation: OperationType): number | undefined {
        const stats = this.getStats(operation);
        if (!stats || stats.count === 0) {
            return undefined;
        }
        return stats.successCount / stats.count;
    }

    /**
     * Checks if an operation is performing slowly.
     */
    public isSlowOperation(operation: OperationType, thresholdMs: number = 1000): boolean {
        const stats = this.getStats(operation);
        if (!stats) {
            return false;
        }
        return stats.avgDuration > thresholdMs;
    }

    /**
     * Clears all collected metrics.
     */
    public clear(): void {
        this.measurements.clear();
    }

    /**
     * Clears metrics for a specific operation.
     */
    public clearOperation(operation: OperationType): void {
        this.measurements.delete(operation);
    }

    /**
     * Disposes the metrics collector.
     */
    public dispose(): void {
        this.measurements.clear();
        MetricsCollector.instance = undefined;
    }
}

/**
 * Shows performance metrics in a new document.
 */
export async function showMetricsReport(): Promise<void> {
    const collector = MetricsCollector.getInstance();
    const summary = collector.getSummary();

    const document = await vscode.workspace.openTextDocument({
        content: summary,
        language: 'markdown'
    });

    await vscode.window.showTextDocument(document, { preview: true });
}

/**
 * Creates a status bar item for performance monitoring.
 */
export function createPerformanceStatusBarItem(): vscode.StatusBarItem {
    const item = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        50
    );
    item.name = 'GoSQLX Performance';
    item.command = 'gosqlx.showMetrics';
    return item;
}

/**
 * Updates the performance status bar item.
 */
export function updatePerformanceStatusBar(
    item: vscode.StatusBarItem,
    collector: MetricsCollector
): void {
    const lspStats = collector.getStats('lsp.diagnostics');
    const validateStats = collector.getStats('command.validate');

    if (!lspStats && !validateStats) {
        item.hide();
        return;
    }

    const avgLatency = lspStats?.avgDuration ?? validateStats?.avgDuration ?? 0;
    const successRate = lspStats
        ? collector.getSuccessRate('lsp.diagnostics') ?? 1
        : collector.getSuccessRate('command.validate') ?? 1;

    // Choose icon based on performance
    let icon: string;
    let status: string;

    if (successRate < 0.8) {
        icon = '$(warning)';
        status = 'Issues detected';
    } else if (avgLatency > 500) {
        icon = '$(clock)';
        status = 'Slow';
    } else if (avgLatency > 100) {
        icon = '$(pulse)';
        status = 'Normal';
    } else {
        icon = '$(zap)';
        status = 'Fast';
    }

    item.text = `${icon} ${avgLatency.toFixed(0)}ms`;
    item.tooltip = `GoSQLX Performance: ${status}\n` +
        `Avg latency: ${avgLatency.toFixed(1)}ms\n` +
        `Success rate: ${(successRate * 100).toFixed(1)}%\n` +
        `Click to see detailed metrics`;
    item.show();
}
