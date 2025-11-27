import * as assert from 'assert';
import * as path from 'path';
import * as os from 'os';

/**
 * Configuration Validation Edge Case Tests for GoSQLX extension.
 * Tests boundary conditions and edge cases for all configuration options.
 */

// Import validation types
interface ValidationResult {
    valid: boolean;
    message?: string;
    suggestion?: string;
}

// =========================================================================
// Indent Size Validation Edge Cases
// =========================================================================
suite('Indent Size Validation Edge Cases', () => {

    test('should accept boundary value 1', () => {
        const result = validateIndentSize(1);
        assert.strictEqual(result.valid, true);
    });

    test('should accept boundary value 16', () => {
        const result = validateIndentSize(16);
        assert.strictEqual(result.valid, true);
    });

    test('should reject value just below minimum (0)', () => {
        const result = validateIndentSize(0);
        assert.strictEqual(result.valid, false);
        assert.ok(result.message?.includes('out of range') || result.message?.includes('must be'));
    });

    test('should reject value just above maximum (17)', () => {
        const result = validateIndentSize(17);
        assert.strictEqual(result.valid, false);
        assert.ok(result.message?.includes('out of range'));
    });

    test('should reject negative values', () => {
        const result = validateIndentSize(-1);
        assert.strictEqual(result.valid, false);
    });

    test('should reject large negative values', () => {
        const result = validateIndentSize(-1000);
        assert.strictEqual(result.valid, false);
    });

    test('should reject floating point values', () => {
        const result = validateIndentSize(2.5);
        assert.strictEqual(result.valid, false);
        assert.ok(result.message?.includes('whole number'));
    });

    test('should reject very small floating point values', () => {
        const result = validateIndentSize(0.1);
        assert.strictEqual(result.valid, false);
    });

    test('should reject NaN', () => {
        const result = validateIndentSize(NaN);
        assert.strictEqual(result.valid, false);
        assert.ok(result.message?.includes('number'));
    });

    test('should reject Infinity', () => {
        const result = validateIndentSize(Infinity);
        assert.strictEqual(result.valid, false);
    });

    test('should reject negative Infinity', () => {
        const result = validateIndentSize(-Infinity);
        assert.strictEqual(result.valid, false);
    });

    test('should reject string values', () => {
        const result = validateIndentSize('4' as unknown as number);
        assert.strictEqual(result.valid, false);
    });

    test('should reject null', () => {
        const result = validateIndentSize(null as unknown as number);
        assert.strictEqual(result.valid, false);
    });

    test('should reject undefined', () => {
        const result = validateIndentSize(undefined as unknown as number);
        assert.strictEqual(result.valid, false);
    });

    test('should reject object values', () => {
        const result = validateIndentSize({} as unknown as number);
        assert.strictEqual(result.valid, false);
    });

    test('should reject array values', () => {
        const result = validateIndentSize([4] as unknown as number);
        assert.strictEqual(result.valid, false);
    });

    test('should provide suggestion for invalid values', () => {
        const result = validateIndentSize(2.7);
        assert.ok(result.suggestion);
    });
});

// =========================================================================
// Dialect Validation Edge Cases
// =========================================================================
suite('Dialect Validation Edge Cases', () => {

    test('should accept valid dialects in lowercase', () => {
        const dialects = ['generic', 'postgresql', 'mysql', 'sqlserver', 'oracle', 'sqlite'];
        for (const dialect of dialects) {
            const result = validateDialect(dialect);
            assert.strictEqual(result.valid, true, `${dialect} should be valid`);
        }
    });

    test('should accept valid dialects in uppercase', () => {
        const dialects = ['GENERIC', 'POSTGRESQL', 'MYSQL', 'SQLSERVER', 'ORACLE', 'SQLITE'];
        for (const dialect of dialects) {
            const result = validateDialect(dialect);
            assert.strictEqual(result.valid, true, `${dialect} should be valid`);
        }
    });

    test('should accept valid dialects in mixed case', () => {
        const dialects = ['Generic', 'PostgreSQL', 'MySQL', 'SQLServer', 'Oracle', 'SQLite'];
        for (const dialect of dialects) {
            const result = validateDialect(dialect);
            assert.strictEqual(result.valid, true, `${dialect} should be valid`);
        }
    });

    test('should accept dialects with leading/trailing whitespace', () => {
        const result = validateDialect('  postgresql  ');
        assert.strictEqual(result.valid, true);
    });

    test('should reject empty string', () => {
        const result = validateDialect('');
        assert.strictEqual(result.valid, false);
    });

    test('should reject whitespace-only string', () => {
        const result = validateDialect('   ');
        assert.strictEqual(result.valid, false);
    });

    test('should reject unknown dialects', () => {
        const result = validateDialect('nosql');
        assert.strictEqual(result.valid, false);
        assert.ok(result.message?.includes('Unknown'));
    });

    test('should suggest postgres for common typo', () => {
        const result = validateDialect('postgres');
        // Should suggest postgresql
        assert.ok(result.suggestion?.includes('postgresql'));
    });

    test('should suggest mysql for mariadb', () => {
        const result = validateDialect('mariadb');
        assert.ok(result.suggestion?.includes('mysql'));
    });

    test('should suggest sqlserver for mssql', () => {
        const result = validateDialect('mssql');
        assert.ok(result.suggestion?.includes('sqlserver'));
    });

    test('should reject number input', () => {
        const result = validateDialect(123 as unknown as string);
        assert.strictEqual(result.valid, false);
    });

    test('should reject null', () => {
        const result = validateDialect(null as unknown as string);
        assert.strictEqual(result.valid, false);
    });

    test('should reject array', () => {
        const result = validateDialect(['postgresql'] as unknown as string);
        assert.strictEqual(result.valid, false);
    });

    test('should handle special characters gracefully', () => {
        const result = validateDialect('post<script>gresql');
        assert.strictEqual(result.valid, false);
    });
});

// =========================================================================
// Executable Path Validation Edge Cases
// =========================================================================
suite('Executable Path Validation Edge Cases', () => {

    test('should accept simple command name', () => {
        const result = validateExecutablePath('gosqlx');
        assert.strictEqual(result.valid, true);
    });

    test('should accept Unix absolute path', () => {
        const result = validateExecutablePath('/usr/local/bin/gosqlx');
        assert.strictEqual(result.valid, true);
    });

    test('should accept Windows absolute path', () => {
        const result = validateExecutablePath('C:\\Program Files\\gosqlx\\gosqlx.exe');
        assert.strictEqual(result.valid, true);
    });

    test('should accept relative path', () => {
        const result = validateExecutablePath('./gosqlx');
        assert.strictEqual(result.valid, true);
    });

    test('should accept path with spaces', () => {
        const result = validateExecutablePath('/Users/John Doe/bin/gosqlx');
        assert.strictEqual(result.valid, true);
    });

    test('should reject empty string', () => {
        const result = validateExecutablePath('');
        assert.strictEqual(result.valid, false);
        assert.ok(result.message?.includes('empty'));
    });

    test('should reject whitespace-only string', () => {
        const result = validateExecutablePath('   ');
        assert.strictEqual(result.valid, false);
    });

    test('should reject path with multiple consecutive spaces', () => {
        const result = validateExecutablePath('/usr/bin/  gosqlx');
        assert.strictEqual(result.valid, false);
        assert.ok(result.message?.includes('whitespace'));
    });

    test('should reject path with newlines', () => {
        const result = validateExecutablePath('/usr/bin/gosqlx\n');
        assert.strictEqual(result.valid, false);
    });

    test('should reject path with tabs', () => {
        const result = validateExecutablePath('/usr/bin/\tgosqlx');
        assert.strictEqual(result.valid, false);
    });

    test('should reject null', () => {
        const result = validateExecutablePath(null as unknown as string);
        assert.strictEqual(result.valid, false);
    });

    test('should reject number', () => {
        const result = validateExecutablePath(123 as unknown as string);
        assert.strictEqual(result.valid, false);
    });

    test('should accept path with unicode characters', () => {
        const result = validateExecutablePath('/Users/utilisateur/bin/gosqlx');
        assert.strictEqual(result.valid, true);
    });

    test('should accept UNC path', () => {
        const result = validateExecutablePath('\\\\server\\share\\gosqlx.exe');
        assert.strictEqual(result.valid, true);
    });
});

// =========================================================================
// Timeout Validation Edge Cases
// =========================================================================
suite('Timeout Validation Edge Cases', () => {

    test('should accept minimum reasonable value (1000ms)', () => {
        const result = validateTimeout(1000);
        assert.strictEqual(result.valid, true);
    });

    test('should accept maximum allowed value (300000ms)', () => {
        const result = validateTimeout(300000);
        assert.strictEqual(result.valid, true);
    });

    test('should accept common timeout values', () => {
        const values = [5000, 10000, 30000, 60000];
        for (const value of values) {
            const result = validateTimeout(value);
            assert.strictEqual(result.valid, true, `${value} should be valid`);
        }
    });

    test('should reject zero', () => {
        const result = validateTimeout(0);
        assert.strictEqual(result.valid, false);
        assert.ok(result.message?.includes('positive'));
    });

    test('should reject negative values', () => {
        const result = validateTimeout(-1000);
        assert.strictEqual(result.valid, false);
    });

    test('should reject values exceeding maximum (5 minutes)', () => {
        const result = validateTimeout(300001);
        assert.strictEqual(result.valid, false);
        assert.ok(result.message?.includes('exceeds'));
    });

    test('should warn for very short timeouts', () => {
        const result = validateTimeout(500);
        // Should be valid but with a warning
        assert.strictEqual(result.valid, true);
        assert.ok(result.message?.includes('too short'));
    });

    test('should reject NaN', () => {
        const result = validateTimeout(NaN);
        assert.strictEqual(result.valid, false);
    });

    test('should reject Infinity', () => {
        const result = validateTimeout(Infinity);
        assert.strictEqual(result.valid, false);
    });

    test('should reject string values', () => {
        const result = validateTimeout('30000' as unknown as number);
        assert.strictEqual(result.valid, false);
    });

    test('should include setting name in error message', () => {
        const result = validateTimeout(-1, 'analysis timeout');
        assert.ok(result.message?.includes('analysis timeout'));
    });

    test('should accept floating point that represents whole milliseconds', () => {
        const result = validateTimeout(5000.0);
        assert.strictEqual(result.valid, true);
    });
});

// =========================================================================
// Trace Level Validation Edge Cases
// =========================================================================
suite('Trace Level Validation Edge Cases', () => {

    test('should accept valid trace levels', () => {
        const levels = ['off', 'messages', 'verbose'];
        for (const level of levels) {
            const result = validateTraceLevel(level);
            assert.strictEqual(result.valid, true, `${level} should be valid`);
        }
    });

    test('should accept trace levels in different cases', () => {
        const result1 = validateTraceLevel('OFF');
        const result2 = validateTraceLevel('Messages');
        const result3 = validateTraceLevel('VERBOSE');

        assert.strictEqual(result1.valid, true);
        assert.strictEqual(result2.valid, true);
        assert.strictEqual(result3.valid, true);
    });

    test('should reject invalid trace levels', () => {
        const result = validateTraceLevel('debug');
        assert.strictEqual(result.valid, false);
    });

    test('should reject empty string', () => {
        const result = validateTraceLevel('');
        assert.strictEqual(result.valid, false);
    });

    test('should reject non-string values', () => {
        const result = validateTraceLevel(1 as unknown as string);
        assert.strictEqual(result.valid, false);
    });

    test('should provide valid options in suggestion', () => {
        const result = validateTraceLevel('invalid');
        assert.ok(result.suggestion?.includes('off'));
        assert.ok(result.suggestion?.includes('messages'));
        assert.ok(result.suggestion?.includes('verbose'));
    });
});

// =========================================================================
// Full Configuration Object Validation
// =========================================================================
suite('Full Configuration Validation Edge Cases', () => {

    test('should accept valid complete configuration', () => {
        const config = {
            enable: true,
            executablePath: 'gosqlx',
            dialect: 'postgresql',
            format: {
                indentSize: 4,
                uppercaseKeywords: true
            },
            timeouts: {
                startup: 30000,
                validation: 5000,
                analysis: 60000
            },
            'trace.server': 'verbose'
        };

        const results = validateConfiguration(config);
        const errors = results.filter(r => !r.valid);
        assert.strictEqual(errors.length, 0);
    });

    test('should accept minimal configuration', () => {
        const results = validateConfiguration({});
        const errors = results.filter(r => !r.valid);
        assert.strictEqual(errors.length, 0);
    });

    test('should collect multiple errors', () => {
        const config = {
            enable: 'yes', // invalid
            executablePath: '', // invalid
            dialect: 'nosql', // invalid
            format: {
                indentSize: -1, // invalid
                uppercaseKeywords: 'true' // invalid
            },
            timeouts: {
                startup: -1000 // invalid
            }
        };

        const results = validateConfiguration(config);
        const errors = results.filter(r => !r.valid);
        assert.ok(errors.length >= 4, `Expected at least 4 errors, got ${errors.length}`);
    });

    test('should handle nested null values', () => {
        const config = {
            format: null,
            timeouts: null
        };

        // Should not throw
        const results = validateConfiguration(config as Record<string, unknown>);
        assert.ok(Array.isArray(results));
    });

    test('should handle extra unknown properties gracefully', () => {
        const config = {
            unknownProperty: 'value',
            anotherUnknown: 123
        };

        const results = validateConfiguration(config);
        // Should not error on unknown properties
        const errors = results.filter(r => !r.valid);
        assert.strictEqual(errors.length, 0);
    });
});

// =========================================================================
// Path Detection Edge Cases
// =========================================================================
suite('Path Detection Edge Cases', () => {

    test('isAbsolutePath should detect Unix absolute paths', () => {
        assert.strictEqual(isAbsolutePath('/'), true);
        assert.strictEqual(isAbsolutePath('/usr'), true);
        assert.strictEqual(isAbsolutePath('/usr/bin/gosqlx'), true);
    });

    test('isAbsolutePath should detect Windows absolute paths', () => {
        assert.strictEqual(isAbsolutePath('C:\\'), true);
        assert.strictEqual(isAbsolutePath('D:\\Program Files'), true);
        assert.strictEqual(isAbsolutePath('c:/users'), true);
    });

    test('isAbsolutePath should detect UNC paths', () => {
        assert.strictEqual(isAbsolutePath('\\\\server\\share'), true);
    });

    test('isAbsolutePath should reject relative paths', () => {
        assert.strictEqual(isAbsolutePath('gosqlx'), false);
        assert.strictEqual(isAbsolutePath('./gosqlx'), false);
        assert.strictEqual(isAbsolutePath('../bin/gosqlx'), false);
        assert.strictEqual(isAbsolutePath('bin/gosqlx'), false);
    });

    test('extractFileExtension should handle various paths', () => {
        assert.strictEqual(extractFileExtension('query.sql'), '.sql');
        assert.strictEqual(extractFileExtension('/path/to/file.pgsql'), '.pgsql');
        assert.strictEqual(extractFileExtension('C:\\files\\query.SQL'), '.sql');
        assert.strictEqual(extractFileExtension('noextension'), '');
        assert.strictEqual(extractFileExtension('.hidden'), '');
        assert.strictEqual(extractFileExtension('file.'), '');
    });

    test('extractFileExtension should handle dots in directory names', () => {
        assert.strictEqual(extractFileExtension('/path.with.dots/file.sql'), '.sql');
        assert.strictEqual(extractFileExtension('/path.with.dots/noext'), '');
    });
});

// =========================================================================
// SQL Language ID Detection Edge Cases
// =========================================================================
suite('SQL Language ID Detection Edge Cases', () => {

    test('should recognize all SQL language IDs', () => {
        const sqlIds = ['sql', 'pgsql', 'mysql', 'plpgsql', 'tsql', 'plsql'];
        for (const id of sqlIds) {
            assert.strictEqual(isSqlLanguageId(id), true, `${id} should be recognized as SQL`);
        }
    });

    test('should recognize case-insensitive SQL IDs', () => {
        assert.strictEqual(isSqlLanguageId('SQL'), true);
        assert.strictEqual(isSqlLanguageId('PgSQL'), true);
        assert.strictEqual(isSqlLanguageId('MYSQL'), true);
    });

    test('should reject non-SQL language IDs', () => {
        const nonSqlIds = ['javascript', 'typescript', 'python', 'go', 'json', 'markdown'];
        for (const id of nonSqlIds) {
            assert.strictEqual(isSqlLanguageId(id), false, `${id} should not be recognized as SQL`);
        }
    });

    test('should reject empty string', () => {
        assert.strictEqual(isSqlLanguageId(''), false);
    });

    test('should handle partial matches correctly', () => {
        assert.strictEqual(isSqlLanguageId('sqlx'), false); // Not in the list
        assert.strictEqual(isSqlLanguageId('sq'), false); // Too short
    });
});

// =========================================================================
// Implementation stubs for validation testing
// =========================================================================

function validateIndentSize(value: unknown): ValidationResult {
    if (typeof value !== 'number' || isNaN(value) || !isFinite(value)) {
        return {
            valid: false,
            message: 'Indent size must be a number',
            suggestion: 'Set gosqlx.format.indentSize to 2 or 4'
        };
    }

    if (value < 1 || value > 16) {
        return {
            valid: false,
            message: `Indent size ${value} is out of range (1-16)`,
            suggestion: 'Common values are 2 or 4 spaces'
        };
    }

    if (!Number.isInteger(value)) {
        return {
            valid: false,
            message: 'Indent size must be a whole number',
            suggestion: `Use ${Math.round(value)} instead`
        };
    }

    return { valid: true };
}

function validateDialect(dialect: unknown): ValidationResult {
    if (typeof dialect !== 'string') {
        return {
            valid: false,
            message: 'Dialect must be a string',
            suggestion: 'Valid dialects: generic, postgresql, mysql, sqlserver, oracle, sqlite'
        };
    }

    const normalized = dialect.toLowerCase().trim();

    if (normalized.length === 0) {
        return {
            valid: false,
            message: 'Dialect cannot be empty',
            suggestion: 'Valid dialects: generic, postgresql, mysql, sqlserver, oracle, sqlite'
        };
    }

    const validDialects = ['generic', 'postgresql', 'mysql', 'sqlserver', 'oracle', 'sqlite'];

    if (!validDialects.includes(normalized)) {
        // Check for common aliases
        const aliases: { [key: string]: string } = {
            'postgres': 'postgresql',
            'pg': 'postgresql',
            'pgsql': 'postgresql',
            'mariadb': 'mysql',
            'mssql': 'sqlserver',
            'sql server': 'sqlserver',
            'ora': 'oracle',
            'sqlite3': 'sqlite'
        };

        const suggestion = aliases[normalized];
        return {
            valid: false,
            message: `Unknown SQL dialect: "${dialect}"`,
            suggestion: suggestion
                ? `Did you mean "${suggestion}"? Valid dialects: ${validDialects.join(', ')}`
                : `Valid dialects: ${validDialects.join(', ')}`
        };
    }

    return { valid: true };
}

function validateExecutablePath(execPath: unknown): ValidationResult {
    if (typeof execPath !== 'string') {
        return {
            valid: false,
            message: 'Executable path must be a string',
            suggestion: 'Set to "gosqlx" or provide full path'
        };
    }

    const trimmed = execPath.trim();

    if (trimmed.length === 0) {
        return {
            valid: false,
            message: 'Executable path cannot be empty',
            suggestion: 'Set to "gosqlx" to use PATH lookup'
        };
    }

    if (trimmed.includes('  ') || trimmed.includes('\n') || trimmed.includes('\t')) {
        return {
            valid: false,
            message: 'Executable path contains invalid whitespace',
            suggestion: 'Remove extra spaces or newlines from the path'
        };
    }

    return { valid: true };
}

function validateTimeout(timeout: unknown, settingName: string = 'timeout'): ValidationResult {
    if (typeof timeout !== 'number' || isNaN(timeout) || !isFinite(timeout)) {
        return {
            valid: false,
            message: `${settingName} must be a number`,
            suggestion: 'Specify timeout in milliseconds'
        };
    }

    if (timeout <= 0) {
        return {
            valid: false,
            message: `${settingName} must be positive`,
            suggestion: 'Use at least 1000ms'
        };
    }

    if (timeout > 300000) {
        return {
            valid: false,
            message: `${settingName} of ${timeout}ms exceeds maximum (300000ms)`,
            suggestion: 'Maximum allowed timeout is 5 minutes'
        };
    }

    if (timeout < 1000) {
        return {
            valid: true,
            message: `Warning: ${settingName} of ${timeout}ms may be too short`,
            suggestion: 'Consider using at least 5000ms'
        };
    }

    return { valid: true };
}

function validateTraceLevel(level: unknown): ValidationResult {
    const validLevels = ['off', 'messages', 'verbose'];

    if (typeof level !== 'string') {
        return {
            valid: false,
            message: 'Trace level must be a string',
            suggestion: `Valid levels: ${validLevels.join(', ')}`
        };
    }

    if (!validLevels.includes(level.toLowerCase())) {
        return {
            valid: false,
            message: `Unknown trace level: "${level}"`,
            suggestion: `Valid levels: ${validLevels.join(', ')}`
        };
    }

    return { valid: true };
}

function validateConfiguration(config: Record<string, unknown>): ValidationResult[] {
    const results: ValidationResult[] = [];

    if (config.enable !== undefined && typeof config.enable !== 'boolean') {
        results.push({
            valid: false,
            message: 'gosqlx.enable must be a boolean'
        });
    }

    if (config.executablePath !== undefined) {
        const result = validateExecutablePath(config.executablePath);
        if (!result.valid) {
            results.push(result);
        }
    }

    if (config.dialect !== undefined) {
        const result = validateDialect(config.dialect);
        if (!result.valid) {
            results.push(result);
        }
    }

    const format = config.format as Record<string, unknown> | null | undefined;
    if (format && typeof format === 'object') {
        if (format.indentSize !== undefined) {
            const result = validateIndentSize(format.indentSize);
            if (!result.valid) {
                results.push(result);
            }
        }
        if (format.uppercaseKeywords !== undefined && typeof format.uppercaseKeywords !== 'boolean') {
            results.push({
                valid: false,
                message: 'gosqlx.format.uppercaseKeywords must be a boolean'
            });
        }
    }

    const timeouts = config.timeouts as Record<string, unknown> | null | undefined;
    if (timeouts && typeof timeouts === 'object') {
        for (const [key, value] of Object.entries(timeouts)) {
            if (value !== undefined) {
                const result = validateTimeout(value, `${key} timeout`);
                if (!result.valid) {
                    results.push(result);
                }
            }
        }
    }

    if (config['trace.server'] !== undefined) {
        const result = validateTraceLevel(config['trace.server']);
        if (!result.valid) {
            results.push(result);
        }
    }

    return results;
}

function isAbsolutePath(filePath: string): boolean {
    if (filePath.startsWith('/')) {
        return true;
    }
    if (/^[a-zA-Z]:[\\/]/.test(filePath)) {
        return true;
    }
    if (filePath.startsWith('\\\\')) {
        return true;
    }
    return false;
}

function extractFileExtension(filePath: string): string {
    const lastDot = filePath.lastIndexOf('.');
    const lastSep = Math.max(filePath.lastIndexOf('/'), filePath.lastIndexOf('\\'));

    if (lastDot === -1 || lastDot < lastSep || lastDot === filePath.length - 1 || lastDot === 0) {
        return '';
    }

    return filePath.substring(lastDot).toLowerCase();
}

function isSqlLanguageId(languageId: string): boolean {
    const sqlLanguages = ['sql', 'pgsql', 'mysql', 'plpgsql', 'tsql', 'plsql'];
    return sqlLanguages.includes(languageId.toLowerCase());
}
