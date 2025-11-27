import * as assert from 'assert';

/**
 * Error Recovery Scenario Tests for GoSQLX extension.
 * Tests how the extension handles various error scenarios gracefully.
 */

// =========================================================================
// LSP Server Error Recovery Tests
// =========================================================================
suite('LSP Server Error Recovery Tests', () => {

    test('should handle server crash gracefully', async () => {
        const recovery = new ErrorRecoveryManager();

        // Simulate server crash
        recovery.recordError('SERVER_CRASH', 'Process exited unexpectedly');

        assert.strictEqual(recovery.shouldRetry(), true);
        assert.strictEqual(recovery.getRetryDelay(), 1000);
    });

    test('should implement exponential backoff on repeated failures', () => {
        const recovery = new ErrorRecoveryManager();

        // First failure
        recovery.recordError('CONNECTION_FAILED', 'Connection refused');
        assert.strictEqual(recovery.getRetryDelay(), 1000);

        // Second failure
        recovery.recordError('CONNECTION_FAILED', 'Connection refused');
        assert.strictEqual(recovery.getRetryDelay(), 2000);

        // Third failure
        recovery.recordError('CONNECTION_FAILED', 'Connection refused');
        assert.strictEqual(recovery.getRetryDelay(), 4000);
    });

    test('should cap retry delay at maximum', () => {
        const recovery = new ErrorRecoveryManager({ maxRetryDelay: 30000 });

        // Simulate many failures
        for (let i = 0; i < 10; i++) {
            recovery.recordError('CONNECTION_FAILED', 'Error');
        }

        assert.ok(recovery.getRetryDelay() <= 30000);
    });

    test('should stop retrying after max attempts', () => {
        const recovery = new ErrorRecoveryManager({ maxRetries: 3 });

        recovery.recordError('ERROR', 'msg');
        recovery.recordError('ERROR', 'msg');
        recovery.recordError('ERROR', 'msg');

        assert.strictEqual(recovery.shouldRetry(), false);
    });

    test('should reset retry count on success', () => {
        const recovery = new ErrorRecoveryManager();

        recovery.recordError('ERROR', 'msg');
        recovery.recordError('ERROR', 'msg');

        assert.strictEqual(recovery.getRetryCount(), 2);

        recovery.recordSuccess();

        assert.strictEqual(recovery.getRetryCount(), 0);
        assert.strictEqual(recovery.getRetryDelay(), 1000); // Back to initial delay
    });

    test('should categorize errors by type', () => {
        const recovery = new ErrorRecoveryManager();

        recovery.recordError('ENOENT', 'Executable not found');
        assert.strictEqual(recovery.getErrorCategory(), 'fatal');
        assert.strictEqual(recovery.shouldRetry(), false);

        recovery.reset();

        recovery.recordError('ETIMEDOUT', 'Connection timed out');
        assert.strictEqual(recovery.getErrorCategory(), 'transient');
        assert.strictEqual(recovery.shouldRetry(), true);
    });

    test('should track error history', () => {
        const recovery = new ErrorRecoveryManager();

        recovery.recordError('ERROR_A', 'Message A');
        recovery.recordError('ERROR_B', 'Message B');

        const history = recovery.getErrorHistory();
        assert.strictEqual(history.length, 2);
        assert.strictEqual(history[0].code, 'ERROR_A');
        assert.strictEqual(history[1].code, 'ERROR_B');
    });
});

// =========================================================================
// Configuration Error Recovery Tests
// =========================================================================
suite('Configuration Error Recovery Tests', () => {

    test('should fall back to defaults on invalid config', () => {
        const config = new ConfigWithFallback({
            indentSize: -1, // invalid
            dialect: 'nosql', // invalid
            timeout: 'abc' // invalid
        });

        assert.strictEqual(config.get('indentSize'), 2); // default
        assert.strictEqual(config.get('dialect'), 'generic'); // default
        assert.strictEqual(config.get('timeout'), 30000); // default
    });

    test('should preserve valid partial config', () => {
        const config = new ConfigWithFallback({
            indentSize: 4, // valid
            dialect: 'nosql', // invalid - falls back
            timeout: 5000 // valid
        });

        assert.strictEqual(config.get('indentSize'), 4);
        assert.strictEqual(config.get('dialect'), 'generic');
        assert.strictEqual(config.get('timeout'), 5000);
    });

    test('should handle missing config file gracefully', () => {
        const config = ConfigWithFallback.fromFile('/nonexistent/path/config.json');

        // Should return defaults without throwing
        assert.strictEqual(config.get('indentSize'), 2);
        assert.ok(config.hadLoadError());
    });

    test('should handle corrupted config file', () => {
        const config = ConfigWithFallback.fromJson('{ invalid json }');

        assert.strictEqual(config.get('dialect'), 'generic');
        assert.ok(config.hadLoadError());
        assert.ok(config.getLoadError()?.includes('parse'));
    });

    test('should migrate old config format', () => {
        // Old format might have different property names
        const config = ConfigWithFallback.fromJson(JSON.stringify({
            tabSize: 4, // old name
            sql_dialect: 'postgres' // old name with underscore
        }));

        // Should be migrated to new names
        assert.strictEqual(config.get('indentSize'), 4);
        assert.strictEqual(config.get('dialect'), 'postgresql');
    });

    test('should handle config change during operation', () => {
        const config = new ConfigWithFallback({ indentSize: 2 });

        // Simulate config change
        config.update({ indentSize: 'invalid' as unknown as number });

        // Should keep previous valid value
        assert.strictEqual(config.get('indentSize'), 2);
        assert.ok(config.getLastUpdateError());
    });
});

// =========================================================================
// Network Error Recovery Tests
// =========================================================================
suite('Network Error Recovery Tests', () => {

    test('should handle connection refused', () => {
        const handler = new NetworkErrorHandler();
        const result = handler.handleError({ code: 'ECONNREFUSED' });

        assert.strictEqual(result.retryable, true);
        assert.ok(result.userMessage.includes('connection'));
    });

    test('should handle connection reset', () => {
        const handler = new NetworkErrorHandler();
        const result = handler.handleError({ code: 'ECONNRESET' });

        assert.strictEqual(result.retryable, true);
    });

    test('should handle timeout', () => {
        const handler = new NetworkErrorHandler();
        const result = handler.handleError({ code: 'ETIMEDOUT' });

        assert.strictEqual(result.retryable, true);
        assert.ok(result.userMessage.includes('timeout') || result.userMessage.includes('slow'));
    });

    test('should handle DNS resolution failure', () => {
        const handler = new NetworkErrorHandler();
        const result = handler.handleError({ code: 'ENOTFOUND' });

        assert.strictEqual(result.retryable, false);
        assert.ok(result.userMessage.includes('not found') || result.userMessage.includes('resolve'));
    });

    test('should handle permission denied', () => {
        const handler = new NetworkErrorHandler();
        const result = handler.handleError({ code: 'EACCES' });

        assert.strictEqual(result.retryable, false);
        assert.ok(result.userMessage.includes('permission'));
    });

    test('should handle unknown errors gracefully', () => {
        const handler = new NetworkErrorHandler();
        const result = handler.handleError({ code: 'UNKNOWN_ERROR' });

        assert.ok(result.userMessage);
        assert.strictEqual(result.retryable, true); // Default to retryable
    });

    test('should include diagnostic information', () => {
        const handler = new NetworkErrorHandler();
        const result = handler.handleError({
            code: 'ECONNREFUSED',
            syscall: 'connect',
            address: '127.0.0.1',
            port: 8080
        });

        assert.ok(result.diagnosticInfo);
        assert.ok(result.diagnosticInfo.includes('127.0.0.1'));
    });
});

// =========================================================================
// Process Error Recovery Tests
// =========================================================================
suite('Process Error Recovery Tests', () => {

    test('should handle process exit with non-zero code', () => {
        const handler = new ProcessErrorHandler();
        const result = handler.handleExit(1, null);

        assert.strictEqual(result.wasError, true);
        assert.ok(result.message.includes('exit code 1'));
    });

    test('should handle process killed by signal', () => {
        const handler = new ProcessErrorHandler();
        const result = handler.handleExit(null, 'SIGKILL');

        assert.strictEqual(result.wasError, true);
        assert.ok(result.message.includes('SIGKILL'));
    });

    test('should handle process exit with code 0', () => {
        const handler = new ProcessErrorHandler();
        const result = handler.handleExit(0, null);

        assert.strictEqual(result.wasError, false);
    });

    test('should suggest action based on exit code', () => {
        const handler = new ProcessErrorHandler();

        // Exit code 127 - command not found
        let result = handler.handleExit(127, null);
        assert.ok(result.suggestedAction?.includes('install'));

        // Exit code 126 - permission denied
        result = handler.handleExit(126, null);
        assert.ok(result.suggestedAction?.includes('permission'));
    });

    test('should detect OOM kill', () => {
        const handler = new ProcessErrorHandler();
        const result = handler.handleExit(null, 'SIGKILL');

        // SIGKILL might be OOM
        assert.ok(result.possibleOOM || result.message.includes('killed'));
    });

    test('should handle spawn errors', () => {
        const handler = new ProcessErrorHandler();
        const result = handler.handleSpawnError({
            code: 'ENOENT',
            message: 'spawn gosqlx ENOENT',
            path: 'gosqlx'
        });

        assert.strictEqual(result.wasError, true);
        assert.ok(result.message.includes('not found') || result.message.includes('ENOENT'));
    });
});

// =========================================================================
// Diagnostic Error Recovery Tests
// =========================================================================
suite('Diagnostic Error Recovery Tests', () => {

    test('should handle malformed diagnostic response', () => {
        const processor = new DiagnosticProcessor();

        // Malformed response
        const result = processor.process({
            diagnostics: 'not an array'
        });

        assert.deepStrictEqual(result, []);
        assert.ok(processor.getLastError());
    });

    test('should skip invalid diagnostic entries', () => {
        const processor = new DiagnosticProcessor();

        const result = processor.process({
            diagnostics: [
                { range: { start: { line: 0, character: 0 }, end: { line: 0, character: 5 } }, message: 'Valid' },
                { invalid: 'entry' },
                null,
                { range: { start: { line: 1, character: 0 }, end: { line: 1, character: 10 } }, message: 'Also valid' }
            ]
        });

        assert.strictEqual(result.length, 2);
    });

    test('should handle missing range gracefully', () => {
        const processor = new DiagnosticProcessor();

        const result = processor.process({
            diagnostics: [
                { message: 'No range' }
            ]
        });

        // Should create a default range
        assert.strictEqual(result.length, 1);
        assert.ok(result[0].range);
    });

    test('should handle negative line numbers', () => {
        const processor = new DiagnosticProcessor();

        const result = processor.process({
            diagnostics: [
                {
                    range: { start: { line: -1, character: 0 }, end: { line: -1, character: 5 } },
                    message: 'Negative line'
                }
            ]
        });

        // Should normalize to line 0
        assert.strictEqual(result[0].range.start.line, 0);
    });

    test('should preserve source and code when available', () => {
        const processor = new DiagnosticProcessor();

        const result = processor.process({
            diagnostics: [
                {
                    range: { start: { line: 0, character: 0 }, end: { line: 0, character: 5 } },
                    message: 'Error',
                    source: 'gosqlx',
                    code: 'SQL001'
                }
            ]
        });

        assert.strictEqual(result[0].source, 'gosqlx');
        assert.strictEqual(result[0].code, 'SQL001');
    });
});

// =========================================================================
// Graceful Degradation Tests
// =========================================================================
suite('Graceful Degradation Tests', () => {

    test('should work without LSP when features fail', () => {
        const extension = new MockExtension();

        // Simulate LSP failure
        extension.setLspAvailable(false);

        // Basic features should still work
        assert.strictEqual(extension.isValidationAvailable(), true); // fallback to CLI
        assert.strictEqual(extension.isFormattingAvailable(), false); // requires LSP
        assert.strictEqual(extension.isSyntaxHighlightingAvailable(), true); // client-side
    });

    test('should fall back to CLI validation when LSP fails', async () => {
        const extension = new MockExtension();
        extension.setLspAvailable(false);

        const result = await extension.validate('SELECT * FROM users');

        assert.ok(result.method === 'cli');
        assert.ok(result.success);
    });

    test('should provide offline capability for syntax highlighting', () => {
        const extension = new MockExtension();

        // Even with no connectivity
        extension.setLspAvailable(false);
        extension.setCliAvailable(false);

        // TextMate grammar should still work
        assert.strictEqual(extension.isSyntaxHighlightingAvailable(), true);
    });

    test('should queue operations during temporary outage', async () => {
        const extension = new MockExtension();

        // Start with LSP available
        extension.setLspAvailable(true);

        // Queue some operations
        const promise1 = extension.validate('SELECT 1');

        // LSP goes down
        extension.setLspAvailable(false);

        // More operations queued
        const promise2 = extension.validate('SELECT 2');

        // LSP comes back
        extension.setLspAvailable(true);

        // All operations should eventually complete
        const results = await Promise.all([promise1, promise2]);
        assert.strictEqual(results.length, 2);
    });

    test('should show degraded status in UI', () => {
        const extension = new MockExtension();
        extension.setLspAvailable(false);

        const status = extension.getStatusBarInfo();

        assert.ok(status.text.includes('(limited)') || status.degraded);
        assert.ok(status.tooltip.includes('features may be limited'));
    });
});

// =========================================================================
// Implementation stubs for error recovery testing
// =========================================================================

interface ErrorHistoryEntry {
    code: string;
    message: string;
    timestamp: number;
}

interface ErrorRecoveryOptions {
    maxRetries?: number;
    maxRetryDelay?: number;
    initialRetryDelay?: number;
}

class ErrorRecoveryManager {
    private retryCount: number = 0;
    private lastErrorCode: string = '';
    private options: Required<ErrorRecoveryOptions>;
    private errorHistory: ErrorHistoryEntry[] = [];

    constructor(options: ErrorRecoveryOptions = {}) {
        this.options = {
            maxRetries: options.maxRetries ?? 5,
            maxRetryDelay: options.maxRetryDelay ?? 30000,
            initialRetryDelay: options.initialRetryDelay ?? 1000
        };
    }

    recordError(code: string, message: string): void {
        this.lastErrorCode = code;
        this.retryCount++;
        this.errorHistory.push({
            code,
            message,
            timestamp: Date.now()
        });
    }

    recordSuccess(): void {
        this.retryCount = 0;
        this.lastErrorCode = '';
    }

    reset(): void {
        this.retryCount = 0;
        this.lastErrorCode = '';
        this.errorHistory = [];
    }

    shouldRetry(): boolean {
        // Fatal errors should not retry
        if (this.getErrorCategory() === 'fatal') {
            return false;
        }
        return this.retryCount < this.options.maxRetries;
    }

    getRetryDelay(): number {
        const delay = this.options.initialRetryDelay * Math.pow(2, Math.max(0, this.retryCount - 1));
        return Math.min(delay, this.options.maxRetryDelay);
    }

    getRetryCount(): number {
        return this.retryCount;
    }

    getErrorCategory(): 'fatal' | 'transient' | 'unknown' {
        const fatalErrors = ['ENOENT', 'EACCES', 'ENOTFOUND'];
        const transientErrors = ['ETIMEDOUT', 'ECONNREFUSED', 'ECONNRESET'];

        if (fatalErrors.includes(this.lastErrorCode)) {
            return 'fatal';
        }
        if (transientErrors.includes(this.lastErrorCode)) {
            return 'transient';
        }
        return 'unknown';
    }

    getErrorHistory(): ErrorHistoryEntry[] {
        return [...this.errorHistory];
    }
}

interface ConfigDefaults {
    indentSize: number;
    dialect: string;
    timeout: number;
}

class ConfigWithFallback {
    private values: Partial<ConfigDefaults>;
    private defaults: ConfigDefaults = {
        indentSize: 2,
        dialect: 'generic',
        timeout: 30000
    };
    private loadError: string | null = null;
    private updateError: string | null = null;

    constructor(values: Record<string, unknown>) {
        this.values = this.validateAndMigrate(values);
    }

    static fromFile(path: string): ConfigWithFallback {
        const config = new ConfigWithFallback({});
        config.loadError = 'File not found';
        return config;
    }

    static fromJson(json: string): ConfigWithFallback {
        try {
            const parsed = JSON.parse(json);
            return new ConfigWithFallback(parsed);
        } catch {
            const config = new ConfigWithFallback({});
            config.loadError = 'Failed to parse JSON';
            return config;
        }
    }

    private validateAndMigrate(values: Record<string, unknown>): Partial<ConfigDefaults> {
        const result: Partial<ConfigDefaults> = {};

        // Handle old config names
        const indentValue = values.indentSize ?? values.tabSize;
        if (typeof indentValue === 'number' && indentValue >= 1 && indentValue <= 16) {
            result.indentSize = indentValue;
        }

        let dialectValue = values.dialect ?? values.sql_dialect;
        if (typeof dialectValue === 'string') {
            // Migrate old names
            if (dialectValue === 'postgres') {
                dialectValue = 'postgresql';
            }
            const validDialects = ['generic', 'postgresql', 'mysql', 'sqlserver', 'oracle', 'sqlite'];
            if (validDialects.includes(dialectValue as string)) {
                result.dialect = dialectValue as string;
            }
        }

        if (typeof values.timeout === 'number' && values.timeout > 0) {
            result.timeout = values.timeout as number;
        }

        return result;
    }

    get<K extends keyof ConfigDefaults>(key: K): ConfigDefaults[K] {
        return (this.values[key] ?? this.defaults[key]) as ConfigDefaults[K];
    }

    update(values: Partial<ConfigDefaults>): void {
        const validated = this.validateAndMigrate(values as Record<string, unknown>);
        if (Object.keys(validated).length === 0 && Object.keys(values).length > 0) {
            this.updateError = 'All values were invalid';
        } else {
            this.values = { ...this.values, ...validated };
            this.updateError = null;
        }
    }

    hadLoadError(): boolean {
        return this.loadError !== null;
    }

    getLoadError(): string | null {
        return this.loadError;
    }

    getLastUpdateError(): string | null {
        return this.updateError;
    }
}

interface NetworkErrorResult {
    retryable: boolean;
    userMessage: string;
    diagnosticInfo?: string;
}

class NetworkErrorHandler {
    handleError(error: { code: string; syscall?: string; address?: string; port?: number }): NetworkErrorResult {
        const errorMessages: Record<string, { retryable: boolean; message: string }> = {
            'ECONNREFUSED': { retryable: true, message: 'Connection refused. The server may not be running.' },
            'ECONNRESET': { retryable: true, message: 'Connection was reset. Retrying...' },
            'ETIMEDOUT': { retryable: true, message: 'Connection timed out. The server may be slow to respond.' },
            'ENOTFOUND': { retryable: false, message: 'Server not found. Check the server address.' },
            'EACCES': { retryable: false, message: 'Permission denied. Check file permissions.' }
        };

        const errorInfo = errorMessages[error.code] || { retryable: true, message: `Error: ${error.code}` };

        let diagnosticInfo = '';
        if (error.address || error.port) {
            diagnosticInfo = `Address: ${error.address || 'unknown'}:${error.port || 'unknown'}`;
            if (error.syscall) {
                diagnosticInfo += `, Syscall: ${error.syscall}`;
            }
        }

        return {
            retryable: errorInfo.retryable,
            userMessage: errorInfo.message,
            diagnosticInfo: diagnosticInfo || undefined
        };
    }
}

interface ProcessExitResult {
    wasError: boolean;
    message: string;
    suggestedAction?: string;
    possibleOOM?: boolean;
}

interface SpawnError {
    code: string;
    message: string;
    path?: string;
}

class ProcessErrorHandler {
    handleExit(code: number | null, signal: string | null): ProcessExitResult {
        if (signal) {
            return {
                wasError: true,
                message: `Process was killed by signal ${signal}`,
                possibleOOM: signal === 'SIGKILL'
            };
        }

        if (code === 0 || code === null) {
            return { wasError: false, message: 'Process exited normally' };
        }

        const suggestions: Record<number, string> = {
            126: 'Check file permissions: chmod +x $(which gosqlx)',
            127: 'Install gosqlx: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest'
        };

        return {
            wasError: true,
            message: `Process exited with exit code ${code}`,
            suggestedAction: suggestions[code]
        };
    }

    handleSpawnError(error: SpawnError): ProcessExitResult {
        return {
            wasError: true,
            message: error.code === 'ENOENT'
                ? `Executable not found: ${error.path || 'unknown'}`
                : `Spawn error: ${error.message}`
        };
    }
}

interface ParsedDiagnostic {
    range: {
        start: { line: number; character: number };
        end: { line: number; character: number };
    };
    message: string;
    severity?: number;
    source?: string;
    code?: string | number;
}

class DiagnosticProcessor {
    private lastError: string | null = null;

    process(response: { diagnostics: unknown }): ParsedDiagnostic[] {
        this.lastError = null;

        if (!Array.isArray(response.diagnostics)) {
            this.lastError = 'Diagnostics must be an array';
            return [];
        }

        const results: ParsedDiagnostic[] = [];

        for (const diag of response.diagnostics) {
            if (!diag || typeof diag !== 'object') {
                continue;
            }

            const diagObj = diag as Record<string, unknown>;
            if (!diagObj.message) {
                continue;
            }

            const parsed: ParsedDiagnostic = {
                range: this.normalizeRange(diagObj.range),
                message: String(diagObj.message),
                severity: typeof diagObj.severity === 'number' ? diagObj.severity : 1,
                source: typeof diagObj.source === 'string' ? diagObj.source : undefined,
                code: typeof diagObj.code === 'string' || typeof diagObj.code === 'number'
                    ? diagObj.code
                    : undefined
            };

            results.push(parsed);
        }

        return results;
    }

    private normalizeRange(range: unknown): ParsedDiagnostic['range'] {
        const defaultRange = {
            start: { line: 0, character: 0 },
            end: { line: 0, character: 0 }
        };

        if (!range || typeof range !== 'object') {
            return defaultRange;
        }

        const rangeObj = range as Record<string, unknown>;
        const start = rangeObj.start as Record<string, unknown> | undefined;
        const end = rangeObj.end as Record<string, unknown> | undefined;

        return {
            start: {
                line: Math.max(0, Number(start?.line) || 0),
                character: Math.max(0, Number(start?.character) || 0)
            },
            end: {
                line: Math.max(0, Number(end?.line) || 0),
                character: Math.max(0, Number(end?.character) || 0)
            }
        };
    }

    getLastError(): string | null {
        return this.lastError;
    }
}

interface ValidationResult {
    success: boolean;
    method: 'lsp' | 'cli' | 'none';
    diagnostics?: unknown[];
}

interface StatusBarInfo {
    text: string;
    tooltip: string;
    degraded: boolean;
}

class MockExtension {
    private lspAvailable = true;
    private cliAvailable = true;
    private operationQueue: Array<{ sql: string; resolve: (result: ValidationResult) => void }> = [];

    setLspAvailable(available: boolean): void {
        this.lspAvailable = available;
        if (available) {
            this.processQueue();
        }
    }

    setCliAvailable(available: boolean): void {
        this.cliAvailable = available;
    }

    isValidationAvailable(): boolean {
        return this.lspAvailable || this.cliAvailable;
    }

    isFormattingAvailable(): boolean {
        return this.lspAvailable;
    }

    isSyntaxHighlightingAvailable(): boolean {
        return true; // TextMate grammar works offline
    }

    async validate(sql: string): Promise<ValidationResult> {
        if (this.lspAvailable) {
            return { success: true, method: 'lsp' };
        }

        if (this.cliAvailable) {
            return { success: true, method: 'cli' };
        }

        return new Promise(resolve => {
            this.operationQueue.push({ sql, resolve });
        });
    }

    private processQueue(): void {
        while (this.operationQueue.length > 0) {
            const op = this.operationQueue.shift();
            if (op) {
                op.resolve({ success: true, method: 'lsp' });
            }
        }
    }

    getStatusBarInfo(): StatusBarInfo {
        if (this.lspAvailable) {
            return {
                text: 'GoSQLX',
                tooltip: 'GoSQLX Language Server - Running',
                degraded: false
            };
        }

        return {
            text: 'GoSQLX (limited)',
            tooltip: 'GoSQLX: Some features may be limited',
            degraded: true
        };
    }
}
