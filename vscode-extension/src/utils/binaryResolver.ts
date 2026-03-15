/**
 * Binary resolution logic for locating the gosqlx executable.
 *
 * Resolves via a four-step fallback chain:
 *   1. User-configured explicit path (gosqlx.executablePath setting)
 *   2. Bundled binary at <extensionPath>/bin/gosqlx[.exe] (with optional checksum verification)
 *   3. PATH lookup ("gosqlx") - can be forced via gosqlx.forcePathLookup setting
 *   4. 'gosqlx' as last resort
 *
 * Dependencies are injected so the logic is testable without VS Code or the filesystem.
 */

import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';

/** Which resolution method was used. */
export type BinaryResolutionSource = 'user-setting' | 'bundled' | 'path-lookup';

/** Result of binary resolution, including the source for telemetry. */
export interface BinaryResolutionResult {
    /** The resolved binary path. */
    binaryPath: string;
    /** Which resolution method was used. */
    source: BinaryResolutionSource;
    /** Whether checksum validation passed (undefined if not checked). */
    checksumValid?: boolean;
}

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
    /** Reads a boolean configuration value by key. */
    getBoolConfig: (key: string, defaultValue: boolean) => boolean;
    /** Checks file access; rejects when the file is missing or the mode check fails. */
    checkAccess: (filePath: string, mode: number) => Promise<void>;
    /** Reads a file and returns its contents as a Buffer. */
    readFile: (filePath: string) => Promise<Buffer>;
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

let cachedResult: BinaryResolutionResult | undefined;

/**
 * Clears the cached binary path. Call when configuration changes or
 * when the user explicitly restarts the server.
 */
export function clearBinaryPathCache(): void {
    cachedResult = undefined;
}

// ---------------------------------------------------------------------------
// Checksum verification
// ---------------------------------------------------------------------------

/**
 * Verifies the SHA-256 checksum of a binary against a .sha256 sidecar file.
 *
 * The sidecar file is expected at `<binaryPath>.sha256` and should contain
 * the hex-encoded SHA-256 hash (optionally followed by whitespace/filename).
 *
 * @returns true if checksum matches, false if mismatch or sidecar missing.
 */
async function verifyChecksum(
    binaryPath: string,
    readFile: (filePath: string) => Promise<Buffer>
): Promise<boolean> {
    const checksumPath = binaryPath + '.sha256';
    try {
        const [binaryContent, checksumContent] = await Promise.all([
            readFile(binaryPath),
            readFile(checksumPath)
        ]);

        const expectedHash = checksumContent.toString('utf8').trim().split(/\s+/)[0].toLowerCase();
        const actualHash = crypto.createHash('sha256').update(binaryContent).digest('hex').toLowerCase();

        return expectedHash === actualHash;
    } catch {
        // Sidecar file missing or unreadable - skip verification
        return true;
    }
}

// ---------------------------------------------------------------------------
// Main resolver
// ---------------------------------------------------------------------------

/**
 * Resolves the gosqlx binary path using a fallback chain, with caching.
 *
 * @param deps  Injected dependencies.
 * @returns     The resolved binary path (from cache on subsequent calls).
 */
export async function getBinaryPath(deps: BinaryResolverDeps): Promise<string> {
    if (cachedResult) {
        return cachedResult.binaryPath;
    }

    const result = await resolveBinaryPath(deps);
    cachedResult = result;
    return result.binaryPath;
}

/**
 * Resolves the gosqlx binary path and returns the full result with source info.
 * Does NOT use the cache - always performs fresh resolution.
 *
 * @param deps  Injected dependencies.
 * @returns     Resolution result with path, source, and checksum status.
 */
export async function resolveBinaryPath(deps: BinaryResolverDeps): Promise<BinaryResolutionResult> {
    // 0. Force PATH lookup if setting is enabled (for development)
    const forcePathLookup = deps.getBoolConfig('forcePathLookup', false);
    if (forcePathLookup) {
        return { binaryPath: 'gosqlx', source: 'path-lookup' };
    }

    // 1. Explicit user setting (non-empty means user override)
    const userPath = deps.getConfig('executablePath', '')?.trim();
    if (userPath) {
        return { binaryPath: userPath, source: 'user-setting' };
    }

    // 2. Bundled binary
    if (deps.extensionPath) {
        const binaryName = deps.platform === 'win32' ? 'gosqlx.exe' : 'gosqlx';
        const bundledPath = path.join(deps.extensionPath, 'bin', binaryName);
        try {
            const mode = deps.platform === 'win32' ? fs.constants.F_OK : fs.constants.X_OK;
            await deps.checkAccess(bundledPath, mode);

            // Verify checksum if sidecar exists
            const checksumValid = await verifyChecksum(bundledPath, deps.readFile);

            return { binaryPath: bundledPath, source: 'bundled', checksumValid };
        } catch {
            // Bundled binary not found or not executable, fall through
        }
    }

    // 3. Fall back to PATH lookup
    return { binaryPath: 'gosqlx', source: 'path-lookup' };
}
