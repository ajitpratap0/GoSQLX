/**
 * Telemetry utilities for GoSQLX extension.
 * All telemetry is opt-in and respects user privacy.
 * No SQL content or file paths are ever collected.
 */

import * as vscode from 'vscode';
import * as os from 'os';
import { extractFileExtension } from './validation';

/**
 * Telemetry event types.
 */
export type TelemetryEventType =
    | 'extension.activated'
    | 'extension.deactivated'
    | 'command.validate'
    | 'command.format'
    | 'command.analyze'
    | 'command.restartServer'
    | 'lsp.started'
    | 'lsp.stopped'
    | 'lsp.error'
    | 'lsp.retry'
    | 'config.changed'
    | 'error.occurred';

/**
 * Telemetry event data (sanitized).
 */
export interface TelemetryEvent {
    type: TelemetryEventType;
    timestamp: number;
    sessionId: string;
    properties?: Record<string, string | number | boolean>;
}

/**
 * Sanitized telemetry data - never contains sensitive information.
 */
export interface SanitizedTelemetryData {
    // Extension info
    extensionVersion: string;
    vscodeVersion: string;

    // Platform info (generic, non-identifying)
    platform: string;
    platformVersion: string;
    arch: string;

    // Configuration (non-sensitive)
    dialect?: string;
    indentSize?: number;
    uppercaseKeywords?: boolean;

    // Usage metrics (aggregated)
    fileExtension?: string;
    operationDuration?: number;
    success?: boolean;
    errorCode?: string;
}

/**
 * Manages telemetry collection with user consent.
 */
export class TelemetryManager {
    private static instance: TelemetryManager | undefined;
    private enabled: boolean = false;
    private sessionId: string;
    private events: TelemetryEvent[] = [];
    private extensionVersion: string;
    private maxEvents: number = 100; // Buffer limit

    private constructor(extensionVersion: string) {
        this.extensionVersion = extensionVersion;
        this.sessionId = this.generateSessionId();
        this.loadEnabledState();
    }

    /**
     * Gets the singleton instance.
     */
    public static getInstance(extensionVersion: string = '0.0.0'): TelemetryManager {
        if (!TelemetryManager.instance) {
            TelemetryManager.instance = new TelemetryManager(extensionVersion);
        }
        return TelemetryManager.instance;
    }

    /**
     * Checks if telemetry is enabled.
     */
    public isEnabled(): boolean {
        return this.enabled && this.isVscodeTelemetryEnabled();
    }

    /**
     * Enables telemetry collection.
     */
    public enable(): void {
        this.enabled = true;
        this.saveEnabledState();
    }

    /**
     * Disables telemetry collection and clears buffered events.
     */
    public disable(): void {
        this.enabled = false;
        this.events = [];
        this.saveEnabledState();
    }

    /**
     * Records a telemetry event if telemetry is enabled.
     */
    public recordEvent(
        type: TelemetryEventType,
        properties?: Record<string, string | number | boolean>
    ): void {
        if (!this.isEnabled()) {
            return;
        }

        const event: TelemetryEvent = {
            type,
            timestamp: Date.now(),
            sessionId: this.sessionId,
            properties: properties ? this.sanitizeProperties(properties) : undefined
        };

        this.events.push(event);

        // Limit buffer size
        if (this.events.length > this.maxEvents) {
            this.events.shift();
        }
    }

    /**
     * Records a command execution.
     */
    public recordCommand(
        command: string,
        duration: number,
        success: boolean,
        errorCode?: string
    ): void {
        this.recordEvent(`command.${command}` as TelemetryEventType, {
            duration,
            success,
            ...(errorCode && { errorCode })
        });
    }

    /**
     * Records an LSP operation.
     */
    public recordLspOperation(
        operation: 'started' | 'stopped' | 'error' | 'retry',
        details?: Record<string, string | number | boolean>
    ): void {
        this.recordEvent(`lsp.${operation}` as TelemetryEventType, details);
    }

    /**
     * Records an error occurrence.
     */
    public recordError(errorCode: string, component: string): void {
        this.recordEvent('error.occurred', {
            errorCode,
            component
        });
    }

    /**
     * Gets sanitized environment data for telemetry.
     */
    public getSanitizedEnvironment(): SanitizedTelemetryData {
        return {
            extensionVersion: this.extensionVersion,
            vscodeVersion: vscode.version,
            platform: os.platform(),
            platformVersion: os.release(),
            arch: os.arch()
        };
    }

    /**
     * Sanitizes file path to only extract extension.
     * Never includes the actual path.
     */
    public sanitizeFilePath(filePath: string): { fileExtension: string } {
        return {
            fileExtension: extractFileExtension(filePath) || 'unknown'
        };
    }

    /**
     * Gets buffered events for potential submission.
     * Events are cleared after retrieval.
     */
    public getAndClearEvents(): TelemetryEvent[] {
        if (!this.isEnabled()) {
            return [];
        }
        const events = [...this.events];
        this.events = [];
        return events;
    }

    /**
     * Gets aggregated statistics (for potential future use).
     */
    public getStats(): {
        totalEvents: number;
        eventsByType: Record<string, number>;
    } {
        const eventsByType: Record<string, number> = {};

        for (const event of this.events) {
            eventsByType[event.type] = (eventsByType[event.type] || 0) + 1;
        }

        return {
            totalEvents: this.events.length,
            eventsByType
        };
    }

    /**
     * Disposes the telemetry manager.
     */
    public dispose(): void {
        this.events = [];
        TelemetryManager.instance = undefined;
    }

    /**
     * Generates a random session ID (not tied to user identity).
     */
    private generateSessionId(): string {
        const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < 16; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    /**
     * Checks if VS Code's global telemetry setting is enabled.
     */
    private isVscodeTelemetryEnabled(): boolean {
        const telemetryConfig = vscode.workspace.getConfiguration('telemetry');
        const level = telemetryConfig.get<string>('telemetryLevel', 'all');
        return level !== 'off';
    }

    /**
     * Loads the enabled state from configuration.
     */
    private loadEnabledState(): void {
        const config = vscode.workspace.getConfiguration('gosqlx');
        this.enabled = config.get<boolean>('telemetry.enable', false);
    }

    /**
     * Saves the enabled state to configuration.
     */
    private saveEnabledState(): void {
        const config = vscode.workspace.getConfiguration('gosqlx');
        config.update('telemetry.enable', this.enabled, vscode.ConfigurationTarget.Global);
    }

    /**
     * Sanitizes properties to ensure no sensitive data is included.
     */
    private sanitizeProperties(
        properties: Record<string, string | number | boolean>
    ): Record<string, string | number | boolean> {
        const sanitized: Record<string, string | number | boolean> = {};

        // Whitelist of allowed property names
        const allowedKeys = new Set([
            'duration',
            'success',
            'errorCode',
            'dialect',
            'indentSize',
            'uppercaseKeywords',
            'fileExtension',
            'attempt',
            'maxAttempts',
            'retryDelay'
        ]);

        for (const [key, value] of Object.entries(properties)) {
            if (allowedKeys.has(key)) {
                // Ensure values are not too long (potential PII)
                if (typeof value === 'string' && value.length > 50) {
                    sanitized[key] = value.substring(0, 50);
                } else {
                    sanitized[key] = value;
                }
            }
        }

        return sanitized;
    }
}

/**
 * Prompts user to opt-in to telemetry.
 */
export async function promptTelemetryOptIn(): Promise<boolean> {
    const message = 'Would you like to help improve GoSQLX by sharing anonymous usage data? ' +
        'No SQL content or file paths are ever collected.';

    const learnMore = 'Learn More';
    const yes = 'Yes, help improve';
    const no = 'No thanks';

    const choice = await vscode.window.showInformationMessage(
        message,
        learnMore,
        yes,
        no
    );

    if (choice === learnMore) {
        vscode.env.openExternal(
            vscode.Uri.parse('https://github.com/ajitpratap0/GoSQLX/blob/main/PRIVACY.md')
        );
        // Re-prompt after they've had a chance to read
        return promptTelemetryOptIn();
    }

    return choice === yes;
}

/**
 * Creates a telemetry event wrapper that measures duration.
 */
export function withTelemetry<T>(
    telemetry: TelemetryManager,
    eventType: TelemetryEventType,
    operation: () => Promise<T>
): Promise<T> {
    const startTime = Date.now();

    return operation()
        .then((result) => {
            telemetry.recordEvent(eventType, {
                duration: Date.now() - startTime,
                success: true
            });
            return result;
        })
        .catch((error) => {
            telemetry.recordEvent(eventType, {
                duration: Date.now() - startTime,
                success: false,
                errorCode: error?.code || 'UNKNOWN'
            });
            throw error;
        });
}
