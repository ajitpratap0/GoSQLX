/**
 * Configuration validation utilities for GoSQLX extension.
 * Provides validation functions and helpful error messages for all settings.
 */

export interface ValidationResult {
    valid: boolean;
    message?: string;
    suggestion?: string;
}

export const VALID_DIALECTS = ['generic', 'postgresql', 'mysql', 'sqlserver', 'oracle', 'sqlite'] as const;
export type SqlDialect = typeof VALID_DIALECTS[number];

export const SQL_LANGUAGE_IDS = ['sql', 'pgsql', 'mysql', 'plpgsql', 'tsql', 'plsql', 'gosqlx'] as const;
export const SQL_FILE_EXTENSIONS = ['.sql', '.pgsql', '.psql', '.mysql', '.tsql', '.plsql'] as const;

/**
 * Validates the indent size configuration value.
 */
export function validateIndentSize(value: unknown): ValidationResult {
    if (typeof value !== 'number' || isNaN(value)) {
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

/**
 * Validates the SQL dialect configuration value.
 */
export function validateDialect(dialect: unknown): ValidationResult {
    if (typeof dialect !== 'string') {
        return {
            valid: false,
            message: 'Dialect must be a string',
            suggestion: `Valid dialects: ${VALID_DIALECTS.join(', ')}`
        };
    }

    const normalized = dialect.toLowerCase().trim();

    if (!VALID_DIALECTS.includes(normalized as SqlDialect)) {
        // Try to suggest the closest match
        const suggestions = findClosestDialect(normalized);
        return {
            valid: false,
            message: `Unknown SQL dialect: "${dialect}"`,
            suggestion: suggestions
                ? `Did you mean "${suggestions}"? Valid dialects: ${VALID_DIALECTS.join(', ')}`
                : `Valid dialects: ${VALID_DIALECTS.join(', ')}`
        };
    }

    return { valid: true };
}

/**
 * Validates the executable path configuration value.
 */
export function validateExecutablePath(execPath: unknown): ValidationResult {
    if (typeof execPath !== 'string') {
        return {
            valid: false,
            message: 'Executable path must be a string',
            suggestion: 'Set to "gosqlx" or provide full path like "/usr/local/bin/gosqlx"'
        };
    }

    const trimmed = execPath.trim();

    if (trimmed.length === 0) {
        return {
            valid: false,
            message: 'Executable path cannot be empty',
            suggestion: 'Set to "gosqlx" to use PATH lookup, or provide full path'
        };
    }

    // Check for suspicious characters that might indicate a typo
    if (trimmed.includes('  ') || trimmed.includes('\n') || trimmed.includes('\t')) {
        return {
            valid: false,
            message: 'Executable path contains invalid whitespace',
            suggestion: 'Remove extra spaces or newlines from the path'
        };
    }

    return { valid: true };
}

/**
 * Validates timeout configuration values.
 */
export function validateTimeout(timeout: unknown, settingName: string = 'timeout'): ValidationResult {
    if (typeof timeout !== 'number' || isNaN(timeout)) {
        return {
            valid: false,
            message: `${settingName} must be a number`,
            suggestion: 'Specify timeout in milliseconds (e.g., 30000 for 30 seconds)'
        };
    }

    if (timeout <= 0) {
        return {
            valid: false,
            message: `${settingName} must be positive`,
            suggestion: 'Use at least 1000ms (1 second)'
        };
    }

    if (timeout > 300000) { // 5 minutes
        return {
            valid: false,
            message: `${settingName} of ${timeout}ms exceeds maximum (300000ms)`,
            suggestion: 'Maximum allowed timeout is 5 minutes (300000ms)'
        };
    }

    if (timeout < 1000) {
        return {
            valid: true,
            message: `Warning: ${settingName} of ${timeout}ms may be too short`,
            suggestion: 'Consider using at least 5000ms for reliable operation'
        };
    }

    return { valid: true };
}

/**
 * Validates trace level configuration.
 */
export function validateTraceLevel(level: unknown): ValidationResult {
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

/**
 * Validates the complete gosqlx configuration object.
 */
export function validateConfiguration(config: Record<string, unknown>): ValidationResult[] {
    const results: ValidationResult[] = [];

    if (config.enable !== undefined && typeof config.enable !== 'boolean') {
        results.push({
            valid: false,
            message: 'gosqlx.enable must be a boolean',
            suggestion: 'Set to true or false'
        });
    }

    if (config.executablePath !== undefined) {
        const execResult = validateExecutablePath(config.executablePath);
        if (!execResult.valid) {
            results.push(execResult);
        }
    }

    if (config.dialect !== undefined) {
        const dialectResult = validateDialect(config.dialect);
        if (!dialectResult.valid) {
            results.push(dialectResult);
        }
    }

    // Validate format options
    const format = config.format as Record<string, unknown> | undefined;
    if (format) {
        if (format.indentSize !== undefined) {
            const indentResult = validateIndentSize(format.indentSize);
            if (!indentResult.valid) {
                results.push(indentResult);
            }
        }

        if (format.uppercaseKeywords !== undefined && typeof format.uppercaseKeywords !== 'boolean') {
            results.push({
                valid: false,
                message: 'gosqlx.format.uppercaseKeywords must be a boolean',
                suggestion: 'Set to true or false'
            });
        }
    }

    // Validate timeouts
    const timeouts = config.timeouts as Record<string, unknown> | undefined;
    if (timeouts) {
        if (timeouts.validation !== undefined) {
            const result = validateTimeout(timeouts.validation, 'validation timeout');
            if (!result.valid) {
                results.push(result);
            }
        }
        if (timeouts.analysis !== undefined) {
            const result = validateTimeout(timeouts.analysis, 'analysis timeout');
            if (!result.valid) {
                results.push(result);
            }
        }
        if (timeouts.startup !== undefined) {
            const result = validateTimeout(timeouts.startup, 'startup timeout');
            if (!result.valid) {
                results.push(result);
            }
        }
    }

    if (config['trace.server'] !== undefined) {
        const traceResult = validateTraceLevel(config['trace.server']);
        if (!traceResult.valid) {
            results.push(traceResult);
        }
    }

    return results;
}

/**
 * Checks if a language ID represents SQL.
 */
export function isSqlLanguageId(languageId: string): boolean {
    return SQL_LANGUAGE_IDS.includes(languageId.toLowerCase() as typeof SQL_LANGUAGE_IDS[number]);
}

/**
 * Gets all supported SQL file extensions.
 */
export function getSqlFileExtensions(): readonly string[] {
    return SQL_FILE_EXTENSIONS;
}

/**
 * Extracts file extension from a path.
 */
export function extractFileExtension(filePath: string): string {
    const lastDot = filePath.lastIndexOf('.');
    const lastSep = Math.max(filePath.lastIndexOf('/'), filePath.lastIndexOf('\\'));

    if (lastDot === -1 || lastDot < lastSep || lastDot === filePath.length - 1) {
        return '';
    }

    return filePath.substring(lastDot).toLowerCase();
}

/**
 * Checks if a path is absolute.
 */
export function isAbsolutePath(filePath: string): boolean {
    // Unix absolute paths
    if (filePath.startsWith('/')) {
        return true;
    }
    // Windows absolute paths (C:\, D:\, etc.)
    if (/^[a-zA-Z]:[\\/]/.test(filePath)) {
        return true;
    }
    // UNC paths (\\server\share)
    if (filePath.startsWith('\\\\')) {
        return true;
    }
    return false;
}

/**
 * Normalizes an executable path for the current platform.
 */
export function normalizeExecutablePath(execPath: string): string {
    return execPath.trim();
}

/**
 * Finds the closest matching dialect for typo correction.
 */
function findClosestDialect(input: string): string | undefined {
    const lowercaseInput = input.toLowerCase();

    // Common aliases and typos
    const aliases: { [key: string]: SqlDialect } = {
        'postgres': 'postgresql',
        'pg': 'postgresql',
        'pgsql': 'postgresql',
        'mariadb': 'mysql',
        'mssql': 'sqlserver',
        'sql server': 'sqlserver',
        'microsoftsql': 'sqlserver',
        'ora': 'oracle',
        'sqlite3': 'sqlite',
        'lite': 'sqlite'
    };

    if (aliases[lowercaseInput]) {
        return aliases[lowercaseInput];
    }

    // Simple Levenshtein-like matching for close typos
    for (const dialect of VALID_DIALECTS) {
        if (dialect.startsWith(lowercaseInput) || lowercaseInput.startsWith(dialect)) {
            return dialect;
        }
    }

    return undefined;
}
