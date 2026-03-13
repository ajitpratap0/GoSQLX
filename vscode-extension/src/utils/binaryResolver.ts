/**
 * Binary resolution logic for locating the gosqlx executable.
 *
 * Resolves via a three-step fallback chain:
 *   1. User-configured explicit path (gosqlx.executablePath setting)
 *   2. Bundled binary at <extensionPath>/bin/gosqlx[.exe]
 *   3. PATH lookup ("gosqlx")
 *
 * Dependencies are injected so the logic is testable without VS Code or the filesystem.
 */

import * as path from 'path';
import * as fs from 'fs';

/**
 * Dependencies that can be injected for testing.
 */
export interface BinaryResolverDeps {
    /** The extension install path, or undefined if not available. */
    extensionPath: string | undefined;
    /** The OS platform string (e.g. 'win32', 'darwin', 'linux'). */
    platform: string;
    /** Reads a configuration value by key, returning defaultValue when absent. */
    getConfig: (key: string, defaultValue: string) => string;
    /** Checks file access; rejects when the file is missing or the mode check fails. */
    checkAccess: (filePath: string, mode: number) => Promise<void>;
}

/**
 * Resolves the gosqlx binary path using a fallback chain.
 *
 * @param deps  Injected dependencies (defaults use real VS Code / Node APIs in production).
 * @returns     The resolved binary path.
 */
export async function getBinaryPath(deps: BinaryResolverDeps): Promise<string> {
    // 1. Explicit user setting (non-empty means user override)
    const userPath = deps.getConfig('executablePath', '');
    if (userPath) {
        return userPath;
    }

    // 2. Bundled binary
    if (deps.extensionPath) {
        const binaryName = deps.platform === 'win32' ? 'gosqlx.exe' : 'gosqlx';
        const bundledPath = path.join(deps.extensionPath, 'bin', binaryName);
        try {
            const mode = deps.platform === 'win32' ? fs.constants.F_OK : fs.constants.X_OK;
            await deps.checkAccess(bundledPath, mode);
            return bundledPath;
        } catch {
            // Bundled binary not found or not executable, fall through
        }
    }

    // 3. Fall back to PATH lookup
    return 'gosqlx';
}
