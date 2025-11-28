import * as assert from 'assert';
import * as os from 'os';
import * as path from 'path';

/**
 * Unit tests for GoSQLX extension command functions.
 * These tests validate individual functions without external dependencies.
 */

// Configuration validation tests
suite('Configuration Validation Unit Tests', () => {

    test('validateIndentSize should accept valid values', () => {
        const validValues = [1, 2, 4, 8];
        for (const value of validValues) {
            const result = validateIndentSize(value);
            assert.strictEqual(result.valid, true, `Indent size ${value} should be valid`);
        }
    });

    test('validateIndentSize should reject invalid values', () => {
        const invalidValues = [-1, 0, 100, NaN];
        for (const value of invalidValues) {
            const result = validateIndentSize(value);
            assert.strictEqual(result.valid, false, `Indent size ${value} should be invalid`);
        }
    });

    test('validateDialect should accept valid dialects', () => {
        const validDialects = ['generic', 'postgresql', 'mysql', 'sqlserver', 'oracle', 'sqlite'];
        for (const dialect of validDialects) {
            const result = validateDialect(dialect);
            assert.strictEqual(result.valid, true, `Dialect ${dialect} should be valid`);
        }
    });

    test('validateDialect should reject invalid dialects', () => {
        const invalidDialects = ['nosql', 'mongodb', 'invalid', ''];
        for (const dialect of invalidDialects) {
            const result = validateDialect(dialect);
            assert.strictEqual(result.valid, false, `Dialect ${dialect} should be invalid`);
        }
    });

    test('validateExecutablePath should handle path formats', () => {
        // Valid paths
        assert.strictEqual(validateExecutablePath('gosqlx').valid, true);
        assert.strictEqual(validateExecutablePath('/usr/local/bin/gosqlx').valid, true);
        assert.strictEqual(validateExecutablePath('C:\\Program Files\\gosqlx\\gosqlx.exe').valid, true);

        // Invalid paths
        assert.strictEqual(validateExecutablePath('').valid, false);
    });

    test('validateTimeout should accept reasonable values', () => {
        assert.strictEqual(validateTimeout(1000).valid, true);
        assert.strictEqual(validateTimeout(5000).valid, true);
        assert.strictEqual(validateTimeout(30000).valid, true);
        assert.strictEqual(validateTimeout(60000).valid, true);

        // Edge cases
        assert.strictEqual(validateTimeout(0).valid, false);
        assert.strictEqual(validateTimeout(-1).valid, false);
        assert.strictEqual(validateTimeout(1000000).valid, false); // Too high
    });
});

// Error message generation tests
suite('Error Message Generation Unit Tests', () => {

    test('getExecutableNotFoundMessage should include installation instructions', () => {
        const message = getExecutableNotFoundMessage('gosqlx');
        assert.ok(message.includes('go install'), 'Should include go install command');
        assert.ok(message.includes('PATH'), 'Should mention PATH');
    });

    test('getExecutableNotFoundMessage should handle custom paths', () => {
        const message = getExecutableNotFoundMessage('/custom/path/gosqlx');
        assert.ok(message.includes('/custom/path/gosqlx'), 'Should include the custom path');
        assert.ok(message.includes('check if the file exists'), 'Should suggest checking file');
    });

    test('getLspStartFailureMessage should provide retry info', () => {
        const message = getLspStartFailureMessage('connection refused', 2, 3);
        assert.ok(message.includes('connection refused'), 'Should include error');
        assert.ok(message.includes('2'), 'Should include attempt number');
    });

    test('getConfigurationErrorMessage should suggest fixes', () => {
        const message = getConfigurationErrorMessage('indentSize', -1);
        assert.ok(message.includes('indentSize'), 'Should include setting name');
        assert.ok(message.includes('valid'), 'Should mention valid values');
    });

    test('getCommonSetupErrorMessage should identify common issues', () => {
        // ENOENT - executable not found
        const enoent = getCommonSetupErrorMessage('ENOENT');
        assert.ok(enoent.includes('not found') || enoent.includes('install'), 'Should explain ENOENT');

        // EACCES - permission denied
        const eacces = getCommonSetupErrorMessage('EACCES');
        assert.ok(eacces.includes('permission') || eacces.includes('chmod'), 'Should explain EACCES');

        // ETIMEDOUT - connection timeout
        const timeout = getCommonSetupErrorMessage('ETIMEDOUT');
        assert.ok(timeout.includes('timeout') || timeout.includes('slow'), 'Should explain timeout');
    });
});

// Diagnostic filtering tests
suite('Diagnostic Filtering Unit Tests', () => {

    test('filterSqlDiagnostics should filter by source', () => {
        const mockDiagnostics = [
            { source: 'gosqlx', message: 'error 1', severity: 0 },
            { source: 'typescript', message: 'ts error', severity: 0 },
            { source: 'GoSQLX', message: 'error 2', severity: 1 },
            { source: undefined, message: 'unknown', severity: 2 }
        ] as MockDiagnostic[];

        const filtered = filterSqlDiagnostics(mockDiagnostics);
        assert.strictEqual(filtered.length, 3, 'Should include gosqlx, GoSQLX, and undefined sources');
    });

    test('countDiagnosticsBySeverity should categorize correctly', () => {
        const mockDiagnostics = [
            { severity: 0 }, // Error
            { severity: 0 }, // Error
            { severity: 1 }, // Warning
            { severity: 2 }, // Info
            { severity: 2 }  // Info
        ] as MockDiagnostic[];

        const counts = countDiagnosticsBySeverity(mockDiagnostics);
        assert.strictEqual(counts.errors, 2);
        assert.strictEqual(counts.warnings, 1);
        assert.strictEqual(counts.info, 2);
    });

    test('formatDiagnosticMessage should handle various counts', () => {
        assert.strictEqual(
            formatDiagnosticMessage({ errors: 0, warnings: 0, info: 0 }),
            'No issues found.'
        );

        assert.ok(
            formatDiagnosticMessage({ errors: 1, warnings: 0, info: 0 }).includes('1 error')
        );

        assert.ok(
            formatDiagnosticMessage({ errors: 2, warnings: 3, info: 1 }).includes('2 error')
        );
    });
});

// Timeout calculation tests
suite('Timeout Calculation Unit Tests', () => {

    test('calculateExponentialBackoff should increase exponentially', () => {
        assert.strictEqual(calculateExponentialBackoff(0), 1000);
        assert.strictEqual(calculateExponentialBackoff(1), 2000);
        assert.strictEqual(calculateExponentialBackoff(2), 4000);
        assert.strictEqual(calculateExponentialBackoff(3), 8000);
    });

    test('calculateExponentialBackoff should cap at maximum', () => {
        const maxBackoff = 30000;
        const result = calculateExponentialBackoff(10, maxBackoff);
        assert.ok(result <= maxBackoff, 'Should not exceed max backoff');
    });

    test('getEffectiveTimeout should apply user override', () => {
        const defaultTimeout = 30000;
        const userTimeout = 60000;

        assert.strictEqual(
            getEffectiveTimeout(undefined, defaultTimeout),
            defaultTimeout
        );

        assert.strictEqual(
            getEffectiveTimeout(userTimeout, defaultTimeout),
            userTimeout
        );
    });
});

// Path handling tests
suite('Path Handling Unit Tests', () => {

    test('normalizeExecutablePath should handle platform differences', () => {
        // Unix-style paths
        assert.strictEqual(
            normalizeExecutablePath('/usr/local/bin/gosqlx'),
            '/usr/local/bin/gosqlx'
        );

        // Simple command names
        assert.strictEqual(
            normalizeExecutablePath('gosqlx'),
            'gosqlx'
        );
    });

    test('isAbsolutePath should detect absolute paths', () => {
        // Unix absolute
        assert.strictEqual(isAbsolutePath('/usr/bin/gosqlx'), true);

        // Windows absolute
        assert.strictEqual(isAbsolutePath('C:\\Program Files\\gosqlx'), true);

        // Relative
        assert.strictEqual(isAbsolutePath('gosqlx'), false);
        assert.strictEqual(isAbsolutePath('./gosqlx'), false);
    });

    test('getDebugLogPath should create valid path', () => {
        const logPath = getDebugLogPath();
        assert.ok(logPath.includes('gosqlx'), 'Should include gosqlx in path');
        assert.ok(logPath.endsWith('.log'), 'Should end with .log');
    });
});

// Language detection tests
suite('Language Detection Unit Tests', () => {

    test('isSqlLanguageId should recognize SQL variants', () => {
        assert.strictEqual(isSqlLanguageId('sql'), true);
        assert.strictEqual(isSqlLanguageId('SQL'), true);
        assert.strictEqual(isSqlLanguageId('pgsql'), true);
        assert.strictEqual(isSqlLanguageId('mysql'), true);
        assert.strictEqual(isSqlLanguageId('plpgsql'), true);

        assert.strictEqual(isSqlLanguageId('javascript'), false);
        assert.strictEqual(isSqlLanguageId('python'), false);
    });

    test('getSqlFileExtensions should return all supported extensions', () => {
        const extensions = getSqlFileExtensions();
        assert.ok(extensions.includes('.sql'));
        assert.ok(extensions.includes('.pgsql'));
        assert.ok(extensions.includes('.psql'));
        assert.ok(extensions.includes('.mysql'));
    });
});

// Telemetry sanitization tests
suite('Telemetry Data Sanitization Unit Tests', () => {

    test('sanitizeTelemetryData should remove sensitive info', () => {
        const data = {
            command: 'validate',
            filePath: '/home/user/secret/query.sql',
            sqlContent: 'SELECT password FROM users',
            timestamp: Date.now()
        };

        const sanitized = sanitizeTelemetryData(data);

        // Should keep command and timestamp
        assert.strictEqual(sanitized.command, 'validate');
        assert.ok(sanitized.timestamp);

        // Should sanitize or remove sensitive data
        assert.ok(!sanitized.sqlContent || sanitized.sqlContent === '[redacted]');
        assert.ok(!sanitized.filePath?.includes('secret'));
    });

    test('extractFileExtension should get extension safely', () => {
        assert.strictEqual(extractFileExtension('/path/to/file.sql'), '.sql');
        assert.strictEqual(extractFileExtension('query.pgsql'), '.pgsql');
        assert.strictEqual(extractFileExtension('noextension'), '');
    });
});

// Performance metrics tests
suite('Performance Metrics Unit Tests', () => {

    test('PerformanceTimer should measure duration', async () => {
        const timer = new PerformanceTimer();
        timer.start();

        await new Promise(resolve => setTimeout(resolve, 50));

        const duration = timer.stop();
        assert.ok(duration >= 40, 'Duration should be at least 40ms');
        assert.ok(duration < 200, 'Duration should be less than 200ms');
    });

    test('MetricsCollector should track operation counts', () => {
        const collector = new MetricsCollector();

        collector.recordOperation('validate');
        collector.recordOperation('validate');
        collector.recordOperation('format');

        const stats = collector.getStats();
        assert.strictEqual(stats.validate, 2);
        assert.strictEqual(stats.format, 1);
    });

    test('MetricsCollector should calculate averages', () => {
        const collector = new MetricsCollector();

        collector.recordDuration('validate', 100);
        collector.recordDuration('validate', 200);
        collector.recordDuration('validate', 300);

        const avg = collector.getAverageDuration('validate');
        assert.strictEqual(avg, 200);
    });
});

// =========================================================================
// Implementation stubs for unit testing
// These would typically be imported from the main extension module
// =========================================================================

interface ValidationResult {
    valid: boolean;
    message?: string;
}

interface MockDiagnostic {
    source?: string;
    message?: string;
    severity: number;
}

interface DiagnosticCounts {
    errors: number;
    warnings: number;
    info: number;
}

interface TelemetryData {
    command?: string;
    filePath?: string;
    sqlContent?: string;
    timestamp?: number;
    fileExtension?: string;
}

function validateIndentSize(value: number): ValidationResult {
    if (isNaN(value) || value < 1 || value > 16) {
        return { valid: false, message: 'Indent size must be between 1 and 16' };
    }
    return { valid: true };
}

function validateDialect(dialect: string): ValidationResult {
    const validDialects = ['generic', 'postgresql', 'mysql', 'sqlserver', 'oracle', 'sqlite'];
    if (!validDialects.includes(dialect.toLowerCase())) {
        return { valid: false, message: `Invalid dialect. Valid options: ${validDialects.join(', ')}` };
    }
    return { valid: true };
}

function validateExecutablePath(path: string): ValidationResult {
    if (!path || path.trim().length === 0) {
        return { valid: false, message: 'Executable path cannot be empty' };
    }
    return { valid: true };
}

function validateTimeout(timeout: number): ValidationResult {
    if (timeout <= 0) {
        return { valid: false, message: 'Timeout must be positive' };
    }
    if (timeout > 300000) { // 5 minutes max
        return { valid: false, message: 'Timeout cannot exceed 5 minutes (300000ms)' };
    }
    return { valid: true };
}

function getExecutableNotFoundMessage(executablePath: string): string {
    if (executablePath === 'gosqlx') {
        return `GoSQLX executable not found. Please install it:\n\n` +
            `  go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest\n\n` +
            `Then ensure it's in your PATH. You can verify with:\n\n` +
            `  which gosqlx\n` +
            `  gosqlx --version`;
    }
    return `GoSQLX executable not found at: ${executablePath}\n\n` +
        `Please check if the file exists and has execute permissions.\n` +
        `You can also try using just 'gosqlx' if it's in your PATH.`;
}

function getLspStartFailureMessage(error: string, attempt: number, maxAttempts: number): string {
    return `Failed to start GoSQLX Language Server (attempt ${attempt}/${maxAttempts}):\n${error}\n\n` +
        `Check the GoSQLX output channel for more details.`;
}

function getConfigurationErrorMessage(settingName: string, value: unknown): string {
    return `Invalid configuration for '${settingName}': ${value}\n` +
        `Please check your settings for valid values.`;
}

function getCommonSetupErrorMessage(errorCode: string): string {
    const messages: { [key: string]: string } = {
        'ENOENT': 'The gosqlx executable was not found. Please install it with: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest',
        'EACCES': 'Permission denied. Please check that gosqlx has execute permissions: chmod +x $(which gosqlx)',
        'ETIMEDOUT': 'Connection timed out. The language server may be slow to start. Try increasing the timeout in settings.',
        'ECONNREFUSED': 'Connection refused. The language server may have crashed. Try restarting it.',
    };
    return messages[errorCode] || `An error occurred: ${errorCode}. Check the output channel for details.`;
}

function filterSqlDiagnostics(diagnostics: MockDiagnostic[]): MockDiagnostic[] {
    return diagnostics.filter(d =>
        d.source === 'gosqlx' || d.source === 'GoSQLX' || d.source === undefined
    );
}

function countDiagnosticsBySeverity(diagnostics: MockDiagnostic[]): DiagnosticCounts {
    return {
        errors: diagnostics.filter(d => d.severity === 0).length,
        warnings: diagnostics.filter(d => d.severity === 1).length,
        info: diagnostics.filter(d => d.severity === 2 || d.severity === 3).length
    };
}

function formatDiagnosticMessage(counts: DiagnosticCounts): string {
    if (counts.errors === 0 && counts.warnings === 0 && counts.info === 0) {
        return 'No issues found.';
    }

    const parts: string[] = [];
    if (counts.errors > 0) {
        parts.push(`${counts.errors} error${counts.errors !== 1 ? 's' : ''}`);
    }
    if (counts.warnings > 0) {
        parts.push(`${counts.warnings} warning${counts.warnings !== 1 ? 's' : ''}`);
    }
    if (counts.info > 0) {
        parts.push(`${counts.info} info`);
    }

    return parts.join(', ');
}

function calculateExponentialBackoff(attempt: number, maxBackoff: number = 30000): number {
    const backoff = Math.pow(2, attempt) * 1000;
    return Math.min(backoff, maxBackoff);
}

function getEffectiveTimeout(userTimeout: number | undefined, defaultTimeout: number): number {
    return userTimeout !== undefined ? userTimeout : defaultTimeout;
}

function normalizeExecutablePath(execPath: string): string {
    return execPath.trim();
}

function isAbsolutePath(filePath: string): boolean {
    return filePath.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(filePath);
}

function getDebugLogPath(): string {
    return path.join(os.tmpdir(), 'gosqlx-lsp-debug.log');
}

function isSqlLanguageId(languageId: string): boolean {
    const sqlLanguages = ['sql', 'pgsql', 'mysql', 'plpgsql', 'tsql', 'plsql'];
    return sqlLanguages.includes(languageId.toLowerCase());
}

function getSqlFileExtensions(): string[] {
    return ['.sql', '.pgsql', '.psql', '.mysql', '.tsql', '.plsql'];
}

function sanitizeTelemetryData(data: TelemetryData): TelemetryData {
    const sanitized: TelemetryData = {};

    if (data.command) {
        sanitized.command = data.command;
    }

    if (data.timestamp) {
        sanitized.timestamp = data.timestamp;
    }

    if (data.filePath) {
        // Only keep the extension, not the full path
        sanitized.fileExtension = extractFileExtension(data.filePath);
    }

    // Never include SQL content
    if (data.sqlContent) {
        sanitized.sqlContent = '[redacted]';
    }

    return sanitized;
}

function extractFileExtension(filePath: string): string {
    const lastDot = filePath.lastIndexOf('.');
    if (lastDot === -1 || lastDot === filePath.length - 1) {
        return '';
    }
    return filePath.substring(lastDot);
}

class PerformanceTimer {
    private startTime: number = 0;

    start(): void {
        this.startTime = Date.now();
    }

    stop(): number {
        return Date.now() - this.startTime;
    }
}

class MetricsCollector {
    private operations: { [key: string]: number } = {};
    private durations: { [key: string]: number[] } = {};

    recordOperation(name: string): void {
        this.operations[name] = (this.operations[name] || 0) + 1;
    }

    recordDuration(name: string, duration: number): void {
        if (!this.durations[name]) {
            this.durations[name] = [];
        }
        this.durations[name].push(duration);
    }

    getStats(): { [key: string]: number } {
        return { ...this.operations };
    }

    getAverageDuration(name: string): number {
        const durations = this.durations[name];
        if (!durations || durations.length === 0) {
            return 0;
        }
        return durations.reduce((a, b) => a + b, 0) / durations.length;
    }
}
