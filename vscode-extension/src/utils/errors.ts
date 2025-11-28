/**
 * Error messaging utilities for GoSQLX extension.
 * Provides detailed, actionable error messages for common issues.
 */

import * as os from 'os';

export interface ErrorContext {
    code?: string;
    message?: string;
    executablePath?: string;
    attempt?: number;
    maxAttempts?: number;
    platform?: NodeJS.Platform;
}

/**
 * Common error codes and their meanings.
 */
export const ERROR_CODES = {
    ENOENT: 'File or command not found',
    EACCES: 'Permission denied',
    ETIMEDOUT: 'Operation timed out',
    ECONNREFUSED: 'Connection refused',
    ECONNRESET: 'Connection reset',
    EPERM: 'Operation not permitted',
    ENOTFOUND: 'DNS lookup failed',
    EADDRINUSE: 'Address already in use'
} as const;

/**
 * Gets a detailed, actionable error message for executable not found.
 */
export function getExecutableNotFoundMessage(executablePath: string, platform: NodeJS.Platform = os.platform()): string {
    const isDefaultPath = executablePath === 'gosqlx';
    const isWindows = platform === 'win32';

    let message = `GoSQLX executable not found: "${executablePath}"\n\n`;

    if (isDefaultPath) {
        message += `The 'gosqlx' command was not found in your system PATH.\n\n`;
        message += `To fix this, install GoSQLX:\n\n`;
        message += `  go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest\n\n`;

        if (isWindows) {
            message += `Then verify installation:\n`;
            message += `  where gosqlx\n`;
            message += `  gosqlx --version\n\n`;
            message += `If 'go install' succeeded but 'where gosqlx' fails:\n`;
            message += `  1. Ensure %GOPATH%\\bin is in your PATH\n`;
            message += `  2. Default GOPATH is %USERPROFILE%\\go\n`;
            message += `  3. Restart VS Code after modifying PATH\n`;
        } else {
            message += `Then verify installation:\n`;
            message += `  which gosqlx\n`;
            message += `  gosqlx --version\n\n`;
            message += `If 'go install' succeeded but 'which gosqlx' fails:\n`;
            message += `  1. Ensure $GOPATH/bin is in your PATH\n`;
            message += `  2. Add to ~/.bashrc or ~/.zshrc:\n`;
            message += `     export PATH="$PATH:$(go env GOPATH)/bin"\n`;
            message += `  3. Restart your terminal and VS Code\n`;
        }
    } else {
        message += `The specified path does not exist or is not executable.\n\n`;
        message += `To fix this:\n`;
        message += `  1. Check if the file exists:\n`;
        message += isWindows
            ? `     dir "${executablePath}"\n`
            : `     ls -la "${executablePath}"\n`;
        message += `  2. If it doesn't exist, either:\n`;
        message += `     - Install gosqlx and update the path in settings\n`;
        message += `     - Remove the custom path to use PATH lookup\n\n`;

        if (!isWindows) {
            message += `  3. Ensure execute permissions:\n`;
            message += `     chmod +x "${executablePath}"\n`;
        }
    }

    return message;
}

/**
 * Gets a detailed error message for LSP startup failure.
 */
export function getLspStartFailureMessage(
    error: string,
    attempt: number,
    maxAttempts: number,
    executablePath: string
): string {
    let message = `Failed to start GoSQLX Language Server`;

    if (maxAttempts > 1) {
        message += ` (attempt ${attempt}/${maxAttempts})`;
    }

    message += `:\n\n${error}\n\n`;

    // Provide specific guidance based on error content
    if (error.includes('ENOENT') || error.includes('not found')) {
        message += `The gosqlx executable was not found.\n`;
        message += `Run: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest\n`;
    } else if (error.includes('EACCES') || error.includes('permission')) {
        message += `Permission denied when trying to execute gosqlx.\n`;
        message += `Run: chmod +x "${executablePath}"\n`;
    } else if (error.includes('timeout') || error.includes('ETIMEDOUT')) {
        message += `The language server took too long to start.\n`;
        message += `Try increasing the startup timeout in settings.\n`;
    } else if (error.includes('JSON') || error.includes('parse')) {
        message += `The language server returned invalid data.\n`;
        message += `This may indicate a version mismatch. Try reinstalling:\n`;
        message += `  go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest\n`;
    } else if (error.includes('port') || error.includes('EADDRINUSE')) {
        message += `A port conflict was detected.\n`;
        message += `Another instance may be running. Try restarting VS Code.\n`;
    } else {
        message += `Troubleshooting steps:\n`;
        message += `  1. Check the GoSQLX output channel for details\n`;
        message += `  2. Verify gosqlx works: gosqlx --version\n`;
        message += `  3. Try restarting the language server\n`;
    }

    return message;
}

/**
 * Gets a detailed error message for common setup issues.
 */
export function getCommonSetupErrorMessage(errorCode: string, context?: ErrorContext): string {
    const platform = context?.platform ?? os.platform();
    const isWindows = platform === 'win32';

    switch (errorCode) {
        case 'ENOENT':
            return getExecutableNotFoundMessage(
                context?.executablePath ?? 'gosqlx',
                platform
            );

        case 'EACCES':
        case 'EPERM':
            if (isWindows) {
                return `Permission denied when accessing GoSQLX.\n\n` +
                    `To fix this:\n` +
                    `  1. Run VS Code as Administrator\n` +
                    `  2. Check Windows Defender or antivirus settings\n` +
                    `  3. Verify the executable is not blocked`;
            }
            return `Permission denied when executing gosqlx.\n\n` +
                `To fix this:\n` +
                `  1. Check file permissions: ls -la $(which gosqlx)\n` +
                `  2. Add execute permission: chmod +x $(which gosqlx)\n` +
                `  3. Check if the directory is mounted with noexec`;

        case 'ETIMEDOUT':
            return `Connection timed out while starting the language server.\n\n` +
                `Possible causes:\n` +
                `  - System is under heavy load\n` +
                `  - Very large SQL files being processed\n` +
                `  - Antivirus scanning the process\n\n` +
                `To fix this:\n` +
                `  1. Increase timeout in settings: gosqlx.timeouts.startup\n` +
                `  2. Try closing other resource-intensive applications\n` +
                `  3. Temporarily disable antivirus and test`;

        case 'ECONNREFUSED':
            return `Connection refused by the language server.\n\n` +
                `This usually means the server crashed or failed to start.\n\n` +
                `To fix this:\n` +
                `  1. Check the GoSQLX output channel for error details\n` +
                `  2. Try restarting the language server\n` +
                `  3. Reinstall: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest`;

        case 'ECONNRESET':
            return `Connection to the language server was reset.\n\n` +
                `This may happen if:\n` +
                `  - The server crashed unexpectedly\n` +
                `  - System went to sleep and woke up\n` +
                `  - Network issues on remote development\n\n` +
                `To fix this: Try restarting the language server.`;

        case 'EADDRINUSE':
            return `The required port is already in use.\n\n` +
                `Another instance of the language server may be running.\n\n` +
                `To fix this:\n` +
                `  1. Close other VS Code windows using GoSQLX\n` +
                `  2. Restart VS Code\n` +
                `  3. Check for zombie processes: ps aux | grep gosqlx`;

        default:
            return `An error occurred: ${errorCode}\n\n` +
                (context?.message ? `Details: ${context.message}\n\n` : '') +
                `General troubleshooting:\n` +
                `  1. Check the GoSQLX output channel for details\n` +
                `  2. Verify gosqlx is installed: gosqlx --version\n` +
                `  3. Try restarting VS Code\n` +
                `  4. Reinstall: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest`;
    }
}

/**
 * Gets an error message for configuration issues.
 */
export function getConfigurationErrorMessage(
    settingName: string,
    value: unknown,
    suggestion?: string
): string {
    let message = `Invalid configuration for "gosqlx.${settingName}"\n\n`;
    message += `Current value: ${JSON.stringify(value)}\n\n`;

    if (suggestion) {
        message += `${suggestion}\n\n`;
    }

    message += `To fix this:\n`;
    message += `  1. Open Settings (Ctrl+,)\n`;
    message += `  2. Search for "gosqlx.${settingName}"\n`;
    message += `  3. Update to a valid value\n`;

    return message;
}

/**
 * Gets an error message for validation failures.
 */
export function getValidationErrorMessage(documentUri: string, error: string): string {
    return `Failed to validate SQL file:\n\n` +
        `File: ${documentUri}\n` +
        `Error: ${error}\n\n` +
        `The file may contain syntax that GoSQLX doesn't recognize.\n` +
        `Check the Problems panel for specific error locations.`;
}

/**
 * Gets an error message for format failures.
 */
export function getFormatErrorMessage(documentUri: string, error: string): string {
    let message = `Failed to format SQL file:\n\n`;
    message += `File: ${documentUri}\n`;
    message += `Error: ${error}\n\n`;

    if (error.includes('parse') || error.includes('syntax')) {
        message += `The file contains syntax errors that prevent formatting.\n`;
        message += `Fix the syntax errors first, then try formatting again.`;
    } else {
        message += `Try the following:\n`;
        message += `  1. Check for syntax errors in the file\n`;
        message += `  2. Restart the language server\n`;
        message += `  3. Check the GoSQLX output channel for details`;
    }

    return message;
}

/**
 * Gets an error message for analysis failures.
 */
export function getAnalysisErrorMessage(error: string): string {
    let message = `Failed to analyze SQL:\n\n${error}\n\n`;

    if (error.includes('timeout')) {
        message += `The analysis took too long.\n`;
        message += `Try with a smaller SQL query or increase the timeout.`;
    } else if (error.includes('empty') || error.includes('no content')) {
        message += `No SQL content to analyze.\n`;
        message += `Make sure the file contains valid SQL statements.`;
    } else {
        message += `Troubleshooting:\n`;
        message += `  1. Check that the SQL syntax is valid\n`;
        message += `  2. Try with a simpler query first\n`;
        message += `  3. Check the GoSQLX output channel`;
    }

    return message;
}

/**
 * Extracts an error code from an error object or string.
 */
export function extractErrorCode(error: unknown): string | undefined {
    if (error && typeof error === 'object') {
        const err = error as { code?: string; errno?: string };
        return err.code ?? err.errno;
    }
    if (typeof error === 'string') {
        // Try to extract error code from string
        const match = error.match(/\b(E[A-Z]+)\b/);
        return match?.[1];
    }
    return undefined;
}

/**
 * Creates a user-friendly error message from any error type.
 */
export function formatError(error: unknown): string {
    if (error instanceof Error) {
        return error.message;
    }
    if (typeof error === 'string') {
        return error;
    }
    if (error && typeof error === 'object') {
        const err = error as { message?: string; toString?: () => string };
        return err.message ?? err.toString?.() ?? 'Unknown error';
    }
    return 'An unknown error occurred';
}
