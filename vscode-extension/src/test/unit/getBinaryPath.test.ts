import * as assert from 'assert';
import * as path from 'path';
import * as fs from 'fs';
import { getBinaryPath, resolveBinaryPath, BinaryResolverDeps, clearBinaryPathCache } from '../../utils/binaryResolver';

/**
 * Unit tests for getBinaryPath() binary resolution logic.
 *
 * The function resolves the gosqlx executable via a three-step fallback:
 *   1. User-configured explicit path (gosqlx.executablePath)
 *   2. Bundled binary at <extensionPath>/bin/gosqlx[.exe]
 *   3. PATH lookup ("gosqlx")
 */

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Builds a BinaryResolverDeps with sensible defaults that can be overridden. */
function makeDeps(overrides: Partial<BinaryResolverDeps> = {}): BinaryResolverDeps {
    return {
        extensionPath: '/mock/extension',
        platform: 'linux',
        getConfig: (_key: string, defaultValue: string) => defaultValue,
        getBoolConfig: (_key: string, defaultValue: boolean) => defaultValue,
        checkAccess: () => Promise.reject(new Error('ENOENT')),
        readFile: () => Promise.reject(new Error('ENOENT')),
        ...overrides,
    };
}

/** Clear cache before each test suite to avoid cross-test pollution. */
setup(() => {
    clearBinaryPathCache();
});

// ---------------------------------------------------------------------------
// 1. User-configured path
// ---------------------------------------------------------------------------

suite('getBinaryPath — user-configured path', () => {

    test('returns user-configured path when setting is non-empty', async () => {
        const deps = makeDeps({
            getConfig: (key: string, defaultValue: string) =>
                key === 'executablePath' ? '/usr/local/bin/gosqlx-custom' : defaultValue,
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, '/usr/local/bin/gosqlx-custom');
    });

    test('skips user path when setting is empty string', async () => {
        const deps = makeDeps({
            getConfig: (key: string, defaultValue: string) =>
                key === 'executablePath' ? '' : defaultValue,
        });
        // With no bundled binary and empty user path, should fall back to 'gosqlx'
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, 'gosqlx');
    });

    test('returns user path even when bundled binary exists', async () => {
        const deps = makeDeps({
            getConfig: (key: string, defaultValue: string) =>
                key === 'executablePath' ? '/custom/gosqlx' : defaultValue,
            // Bundled binary would succeed, but user path takes priority
            checkAccess: () => Promise.resolve(),
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, '/custom/gosqlx');
    });
});

// ---------------------------------------------------------------------------
// 2. Bundled binary detection
// ---------------------------------------------------------------------------

suite('getBinaryPath — bundled binary', () => {

    test('returns bundled binary path when it exists and is executable', async () => {
        const deps = makeDeps({
            extensionPath: '/home/user/.vscode/extensions/gosqlx-1.0.0',
            platform: 'linux',
            checkAccess: () => Promise.resolve(),
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(
            result,
            path.join('/home/user/.vscode/extensions/gosqlx-1.0.0', 'bin', 'gosqlx')
        );
    });

    test('falls back to PATH when bundled binary does not exist', async () => {
        const deps = makeDeps({
            extensionPath: '/ext',
            checkAccess: () => Promise.reject(new Error('ENOENT')),
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, 'gosqlx');
    });

    test('falls back to PATH when extensionPath is undefined', async () => {
        const deps = makeDeps({
            extensionPath: undefined,
            checkAccess: () => Promise.resolve(), // would succeed, but path is undefined
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, 'gosqlx');
    });

    test('checks correct bundled path using extensionPath + bin + binaryName', async () => {
        let checkedPath = '';
        const deps = makeDeps({
            extensionPath: '/my/ext',
            platform: 'darwin',
            checkAccess: (filePath: string) => {
                checkedPath = filePath;
                return Promise.resolve();
            },
        });
        await getBinaryPath(deps);
        assert.strictEqual(checkedPath, path.join('/my/ext', 'bin', 'gosqlx'));
    });
});

// ---------------------------------------------------------------------------
// 3. PATH fallback
// ---------------------------------------------------------------------------

suite('getBinaryPath — PATH fallback', () => {

    test('returns "gosqlx" when no user path and no bundled binary', async () => {
        const deps = makeDeps({
            extensionPath: '/ext',
            getConfig: () => '',
            checkAccess: () => Promise.reject(new Error('ENOENT')),
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, 'gosqlx');
    });

    test('returns "gosqlx" when extensionPath is undefined and no user path', async () => {
        const deps = makeDeps({
            extensionPath: undefined,
            getConfig: () => '',
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, 'gosqlx');
    });
});

// ---------------------------------------------------------------------------
// 4. Windows-specific behavior
// ---------------------------------------------------------------------------

suite('getBinaryPath — Windows platform handling', () => {

    test('appends .exe on win32 platform', async () => {
        let checkedPath = '';
        const deps = makeDeps({
            extensionPath: '/ext',
            platform: 'win32',
            checkAccess: (filePath: string) => {
                checkedPath = filePath;
                return Promise.resolve();
            },
        });
        const result = await getBinaryPath(deps);
        assert.ok(
            checkedPath.endsWith('gosqlx.exe'),
            `Expected path to end with gosqlx.exe, got: ${checkedPath}`
        );
        assert.strictEqual(result, path.join('/ext', 'bin', 'gosqlx.exe'));
    });

    test('does not append .exe on non-win32 platform', async () => {
        let checkedPath = '';
        const deps = makeDeps({
            extensionPath: '/ext',
            platform: 'darwin',
            checkAccess: (filePath: string) => {
                checkedPath = filePath;
                return Promise.resolve();
            },
        });
        await getBinaryPath(deps);
        assert.ok(
            checkedPath.endsWith('gosqlx') && !checkedPath.endsWith('gosqlx.exe'),
            `Expected path to end with gosqlx (no .exe), got: ${checkedPath}`
        );
    });

    test('uses F_OK access mode on Windows', async () => {
        let usedMode: number | undefined;
        const deps = makeDeps({
            extensionPath: '/ext',
            platform: 'win32',
            checkAccess: (_filePath: string, mode: number) => {
                usedMode = mode;
                return Promise.resolve();
            },
        });
        await getBinaryPath(deps);
        assert.strictEqual(usedMode, fs.constants.F_OK);
    });

    test('uses X_OK access mode on non-Windows platforms', async () => {
        let usedMode: number | undefined;
        const deps = makeDeps({
            extensionPath: '/ext',
            platform: 'linux',
            checkAccess: (_filePath: string, mode: number) => {
                usedMode = mode;
                return Promise.resolve();
            },
        });
        await getBinaryPath(deps);
        assert.strictEqual(usedMode, fs.constants.X_OK);
    });

    test('uses X_OK access mode on macOS (darwin)', async () => {
        let usedMode: number | undefined;
        const deps = makeDeps({
            extensionPath: '/ext',
            platform: 'darwin',
            checkAccess: (_filePath: string, mode: number) => {
                usedMode = mode;
                return Promise.resolve();
            },
        });
        await getBinaryPath(deps);
        assert.strictEqual(usedMode, fs.constants.X_OK);
    });
});

// ---------------------------------------------------------------------------
// 5. Priority / precedence
// ---------------------------------------------------------------------------

suite('getBinaryPath — fallback chain precedence', () => {

    test('user setting > bundled binary > PATH (full chain)', async () => {
        // All three options available — user setting wins
        const deps = makeDeps({
            extensionPath: '/ext',
            getConfig: (key: string, defaultValue: string) =>
                key === 'executablePath' ? '/user/bin/gosqlx' : defaultValue,
            checkAccess: () => Promise.resolve(),
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, '/user/bin/gosqlx');
    });

    test('bundled binary > PATH when user setting is empty', async () => {
        const deps = makeDeps({
            extensionPath: '/ext',
            getConfig: () => '',
            checkAccess: () => Promise.resolve(),
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, path.join('/ext', 'bin', 'gosqlx'));
    });

    test('PATH is last resort', async () => {
        const deps = makeDeps({
            extensionPath: '/ext',
            getConfig: () => '',
            checkAccess: () => Promise.reject(new Error('ENOENT')),
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, 'gosqlx');
    });
});

// ---------------------------------------------------------------------------
// 6. Caching
// ---------------------------------------------------------------------------

suite('getBinaryPath — caching', () => {

    test('returns cached result on subsequent calls', async () => {
        let callCount = 0;
        const deps = makeDeps({
            checkAccess: () => {
                callCount++;
                return Promise.resolve();
            },
        });
        await getBinaryPath(deps);
        await getBinaryPath(deps);
        await getBinaryPath(deps);
        assert.strictEqual(callCount, 1, 'checkAccess should only be called once');
    });

    test('clearBinaryPathCache forces re-resolution', async () => {
        let callCount = 0;
        const deps = makeDeps({
            checkAccess: () => {
                callCount++;
                return Promise.resolve();
            },
        });
        await getBinaryPath(deps);
        clearBinaryPathCache();
        await getBinaryPath(deps);
        assert.strictEqual(callCount, 2, 'checkAccess should be called twice after cache clear');
    });
});

// ---------------------------------------------------------------------------
// 7. Force PATH lookup
// ---------------------------------------------------------------------------

suite('getBinaryPath — forcePathLookup setting', () => {

    test('returns gosqlx when forcePathLookup is true', async () => {
        const deps = makeDeps({
            extensionPath: '/ext',
            getBoolConfig: (key: string, defaultValue: boolean) =>
                key === 'forcePathLookup' ? true : defaultValue,
            checkAccess: () => Promise.resolve(), // bundled exists but should be skipped
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, 'gosqlx');
    });

    test('uses bundled binary when forcePathLookup is false', async () => {
        const deps = makeDeps({
            extensionPath: '/ext',
            getBoolConfig: (key: string, defaultValue: boolean) =>
                key === 'forcePathLookup' ? false : defaultValue,
            checkAccess: () => Promise.resolve(),
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, path.join('/ext', 'bin', 'gosqlx'));
    });

    test('forcePathLookup takes precedence over user setting', async () => {
        const deps = makeDeps({
            getBoolConfig: (key: string, defaultValue: boolean) =>
                key === 'forcePathLookup' ? true : defaultValue,
            getConfig: (key: string, defaultValue: string) =>
                key === 'executablePath' ? '/custom/path' : defaultValue,
        });
        const result = await getBinaryPath(deps);
        assert.strictEqual(result, 'gosqlx');
    });
});

// ---------------------------------------------------------------------------
// 8. Resolution source tracking
// ---------------------------------------------------------------------------

suite('resolveBinaryPath — resolution source', () => {

    test('reports user-setting source', async () => {
        const deps = makeDeps({
            getConfig: (key: string, defaultValue: string) =>
                key === 'executablePath' ? '/custom/gosqlx' : defaultValue,
        });
        const result = await resolveBinaryPath(deps);
        assert.strictEqual(result.source, 'user-setting');
        assert.strictEqual(result.binaryPath, '/custom/gosqlx');
    });

    test('reports bundled source', async () => {
        const deps = makeDeps({
            extensionPath: '/ext',
            checkAccess: () => Promise.resolve(),
        });
        const result = await resolveBinaryPath(deps);
        assert.strictEqual(result.source, 'bundled');
    });

    test('reports path-lookup source on fallback', async () => {
        const deps = makeDeps({
            extensionPath: '/ext',
            checkAccess: () => Promise.reject(new Error('ENOENT')),
        });
        const result = await resolveBinaryPath(deps);
        assert.strictEqual(result.source, 'path-lookup');
    });

    test('reports path-lookup source when forcePathLookup is true', async () => {
        const deps = makeDeps({
            getBoolConfig: (key: string, defaultValue: boolean) =>
                key === 'forcePathLookup' ? true : defaultValue,
        });
        const result = await resolveBinaryPath(deps);
        assert.strictEqual(result.source, 'path-lookup');
    });
});

// ---------------------------------------------------------------------------
// 9. Checksum verification
// ---------------------------------------------------------------------------

suite('resolveBinaryPath — checksum verification', () => {

    test('checksumValid is true when sidecar matches', async () => {
        const binaryContent = Buffer.from('fake binary content');
        const crypto = require('crypto');
        const expectedHash = crypto.createHash('sha256').update(binaryContent).digest('hex');

        const deps = makeDeps({
            extensionPath: '/ext',
            checkAccess: () => Promise.resolve(),
            readFile: (filePath: string) => {
                if (filePath.endsWith('.sha256')) {
                    return Promise.resolve(Buffer.from(expectedHash));
                }
                return Promise.resolve(binaryContent);
            },
        });
        const result = await resolveBinaryPath(deps);
        assert.strictEqual(result.source, 'bundled');
        assert.strictEqual(result.checksumValid, true);
    });

    test('checksumValid is false when sidecar mismatches', async () => {
        const deps = makeDeps({
            extensionPath: '/ext',
            checkAccess: () => Promise.resolve(),
            readFile: (filePath: string) => {
                if (filePath.endsWith('.sha256')) {
                    return Promise.resolve(Buffer.from('deadbeef'));
                }
                return Promise.resolve(Buffer.from('binary content'));
            },
        });
        const result = await resolveBinaryPath(deps);
        assert.strictEqual(result.source, 'bundled');
        assert.strictEqual(result.checksumValid, false);
    });

    test('checksumValid is true when sidecar file is missing (skip verification)', async () => {
        const deps = makeDeps({
            extensionPath: '/ext',
            checkAccess: () => Promise.resolve(),
            readFile: () => Promise.reject(new Error('ENOENT')),
        });
        const result = await resolveBinaryPath(deps);
        assert.strictEqual(result.source, 'bundled');
        assert.strictEqual(result.checksumValid, true);
    });

    test('checksum not checked for user-setting source', async () => {
        const deps = makeDeps({
            getConfig: (key: string, defaultValue: string) =>
                key === 'executablePath' ? '/custom/gosqlx' : defaultValue,
        });
        const result = await resolveBinaryPath(deps);
        assert.strictEqual(result.checksumValid, undefined);
    });

    test('checksum not checked for path-lookup source', async () => {
        const deps = makeDeps({
            checkAccess: () => Promise.reject(new Error('ENOENT')),
        });
        const result = await resolveBinaryPath(deps);
        assert.strictEqual(result.checksumValid, undefined);
    });
});
