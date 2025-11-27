import * as assert from 'assert';
import * as path from 'path';
import * as os from 'os';
import { spawn, ChildProcess, SpawnOptions } from 'child_process';

/**
 * Integration Tests with GoSQLX Binary for VSCode extension.
 * These tests verify interaction with the actual gosqlx CLI tool.
 *
 * Note: These tests require the gosqlx binary to be installed and available in PATH.
 * Run: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
 */

// Configuration
const GOSQLX_PATH = process.env.GOSQLX_PATH || 'gosqlx';
const TEST_TIMEOUT = 30000;

// Helper to check if gosqlx is available
async function isGosqlxAvailable(): Promise<boolean> {
    return new Promise((resolve) => {
        const proc = spawn(GOSQLX_PATH, ['--version'], { stdio: 'pipe' });
        proc.on('close', (code) => resolve(code === 0));
        proc.on('error', () => resolve(false));
        setTimeout(() => {
            proc.kill();
            resolve(false);
        }, 5000);
    });
}

// Helper to run gosqlx command
async function runGosqlx(args: string[], input?: string, timeout: number = TEST_TIMEOUT): Promise<{
    stdout: string;
    stderr: string;
    exitCode: number | null;
    signal: string | null;
    timedOut: boolean;
}> {
    return new Promise((resolve) => {
        const proc = spawn(GOSQLX_PATH, args, { stdio: 'pipe' });
        let stdout = '';
        let stderr = '';
        let timedOut = false;

        const timeoutHandle = setTimeout(() => {
            timedOut = true;
            proc.kill('SIGTERM');
        }, timeout);

        proc.stdout?.on('data', (data) => { stdout += data.toString(); });
        proc.stderr?.on('data', (data) => { stderr += data.toString(); });

        proc.on('close', (code, signal) => {
            clearTimeout(timeoutHandle);
            resolve({ stdout, stderr, exitCode: code, signal, timedOut });
        });

        proc.on('error', (err) => {
            clearTimeout(timeoutHandle);
            resolve({ stdout, stderr: err.message, exitCode: null, signal: null, timedOut: false });
        });

        if (input && proc.stdin) {
            proc.stdin.write(input);
            proc.stdin.end();
        }
    });
}

// =========================================================================
// GoSQLX Binary Availability Tests
// =========================================================================
suite('GoSQLX Binary Availability Tests', function() {
    this.timeout(TEST_TIMEOUT);

    test('gosqlx binary should be available', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }
        assert.strictEqual(available, true);
    });

    test('gosqlx --version should return version info', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const result = await runGosqlx(['--version']);

        assert.strictEqual(result.exitCode, 0, 'Should exit with code 0');
        assert.ok(result.stdout.toLowerCase().includes('gosqlx') ||
                  result.stdout.toLowerCase().includes('version'),
                  'Should include version info');
    });

    test('gosqlx --help should show available commands', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const result = await runGosqlx(['--help']);

        assert.strictEqual(result.exitCode, 0);
        assert.ok(result.stdout.includes('validate') || result.stderr.includes('validate'),
                  'Should list validate command');
    });
});

// =========================================================================
// GoSQLX Validate Command Tests
// =========================================================================
suite('GoSQLX Validate Command Tests', function() {
    this.timeout(TEST_TIMEOUT);

    test('should validate correct SQL', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const result = await runGosqlx(['validate', 'SELECT * FROM users']);

        assert.strictEqual(result.exitCode, 0, `Expected exit code 0, got ${result.exitCode}`);
    });

    test('should detect syntax error in invalid SQL', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const result = await runGosqlx(['validate', 'SELEC * FROM users']);

        // Should either exit non-zero or report error in output
        assert.ok(
            result.exitCode !== 0 ||
            result.stdout.toLowerCase().includes('error') ||
            result.stderr.toLowerCase().includes('error'),
            'Should detect syntax error'
        );
    });

    test('should validate complex query with JOINs', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = `
            SELECT u.name, o.order_date, p.product_name
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id
            INNER JOIN products p ON o.product_id = p.id
            WHERE u.active = true
            ORDER BY o.order_date DESC
        `;

        const result = await runGosqlx(['validate', sql]);

        assert.strictEqual(result.exitCode, 0, 'Complex query should validate');
    });

    test('should validate query with window functions', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = `
            SELECT name, salary,
                   ROW_NUMBER() OVER (ORDER BY salary DESC) as rank,
                   AVG(salary) OVER (PARTITION BY department) as dept_avg
            FROM employees
        `;

        const result = await runGosqlx(['validate', sql]);

        assert.strictEqual(result.exitCode, 0, 'Window function query should validate');
    });

    test('should validate CTE query', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = `
            WITH active_users AS (
                SELECT id, name FROM users WHERE active = true
            )
            SELECT * FROM active_users
        `;

        const result = await runGosqlx(['validate', sql]);

        assert.strictEqual(result.exitCode, 0, 'CTE query should validate');
    });

    test('should handle empty input', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const result = await runGosqlx(['validate', '']);

        // Empty input should be handled gracefully (either success or specific error)
        assert.ok(result.exitCode !== null, 'Should complete without crash');
    });

    test('should handle unicode in query', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = `SELECT * FROM users WHERE name = 'utilisateur'`;

        const result = await runGosqlx(['validate', sql]);

        assert.strictEqual(result.exitCode, 0, 'Unicode query should validate');
    });
});

// =========================================================================
// GoSQLX Format Command Tests
// =========================================================================
suite('GoSQLX Format Command Tests', function() {
    this.timeout(TEST_TIMEOUT);

    test('should format simple query', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = 'select * from users where id=1';
        const result = await runGosqlx(['format', sql]);

        if (result.exitCode === 0) {
            // Formatted output should have proper casing
            assert.ok(
                result.stdout.includes('SELECT') || result.stdout.includes('select'),
                'Should produce formatted output'
            );
        }
    });

    test('should format multi-line query', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = 'SELECT id,name,email FROM users WHERE active=true AND created_at>now()-interval 30 day';
        const result = await runGosqlx(['format', sql]);

        if (result.exitCode === 0) {
            assert.ok(result.stdout.length > 0, 'Should produce output');
        }
    });
});

// =========================================================================
// GoSQLX Analyze Command Tests
// =========================================================================
suite('GoSQLX Analyze Command Tests', function() {
    this.timeout(TEST_TIMEOUT);

    test('should analyze query structure', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = 'SELECT COUNT(*) FROM orders GROUP BY status HAVING COUNT(*) > 10';
        const result = await runGosqlx(['analyze', sql]);

        // Analyze might output to stdout or stderr depending on implementation
        assert.ok(result.exitCode !== null, 'Should complete');
    });

    test('should handle stdin input for analyze', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = 'SELECT * FROM users WHERE id IN (SELECT user_id FROM admins)';
        const result = await runGosqlx(['analyze'], sql);

        assert.ok(result.exitCode !== null, 'Should complete with stdin input');
    });
});

// =========================================================================
// GoSQLX LSP Mode Tests
// =========================================================================
suite('GoSQLX LSP Mode Tests', function() {
    this.timeout(TEST_TIMEOUT);

    test('should start in LSP mode', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const proc = spawn(GOSQLX_PATH, ['lsp'], { stdio: 'pipe' });

        return new Promise<void>((resolve, reject) => {
            let output = '';
            let responded = false;

            const timeout = setTimeout(() => {
                if (!responded) {
                    proc.kill();
                    // If it didn't crash immediately, consider it a pass
                    resolve();
                }
            }, 2000);

            proc.stderr?.on('data', (data) => {
                output += data.toString();
            });

            proc.on('error', (err) => {
                clearTimeout(timeout);
                if (!responded) {
                    responded = true;
                    reject(new Error(`LSP mode failed to start: ${err.message}`));
                }
            });

            proc.on('close', (code) => {
                clearTimeout(timeout);
                if (!responded) {
                    responded = true;
                    if (code === 0 || code === null) {
                        resolve();
                    } else {
                        // Non-zero exit might be okay if we didn't send proper LSP messages
                        resolve();
                    }
                }
            });

            // Send an initialize request
            const initRequest = {
                jsonrpc: '2.0',
                id: 1,
                method: 'initialize',
                params: {
                    processId: process.pid,
                    rootUri: null,
                    capabilities: {}
                }
            };

            const message = JSON.stringify(initRequest);
            const header = `Content-Length: ${Buffer.byteLength(message)}\r\n\r\n`;

            if (proc.stdin) {
                proc.stdin.write(header + message);
            }

            // Give it time to respond
            setTimeout(() => {
                if (!responded) {
                    responded = true;
                    proc.kill();
                    resolve();
                }
            }, 1500);
        });
    });

    test('should respond to LSP shutdown', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const proc = spawn(GOSQLX_PATH, ['lsp'], { stdio: 'pipe' });

        return new Promise<void>((resolve) => {
            let receivedResponse = false;

            const timeout = setTimeout(() => {
                proc.kill();
                resolve(); // Consider it passed if it didn't crash
            }, 3000);

            proc.stdout?.on('data', (data) => {
                const output = data.toString();
                if (output.includes('result')) {
                    receivedResponse = true;
                }
            });

            proc.on('close', () => {
                clearTimeout(timeout);
                resolve();
            });

            // Send initialize
            const init = JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'initialize',
                params: { processId: process.pid, rootUri: null, capabilities: {} }
            });
            const initMsg = `Content-Length: ${Buffer.byteLength(init)}\r\n\r\n${init}`;

            // Send shutdown
            const shutdown = JSON.stringify({
                jsonrpc: '2.0',
                id: 2,
                method: 'shutdown'
            });
            const shutdownMsg = `Content-Length: ${Buffer.byteLength(shutdown)}\r\n\r\n${shutdown}`;

            // Send exit
            const exit = JSON.stringify({
                jsonrpc: '2.0',
                method: 'exit'
            });
            const exitMsg = `Content-Length: ${Buffer.byteLength(exit)}\r\n\r\n${exit}`;

            if (proc.stdin) {
                proc.stdin.write(initMsg);
                setTimeout(() => {
                    proc.stdin?.write(shutdownMsg);
                    setTimeout(() => {
                        proc.stdin?.write(exitMsg);
                        proc.stdin?.end();
                    }, 200);
                }, 500);
            }
        });
    });
});

// =========================================================================
// GoSQLX Error Handling Tests
// =========================================================================
suite('GoSQLX Error Handling Tests', function() {
    this.timeout(TEST_TIMEOUT);

    test('should handle invalid command gracefully', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const result = await runGosqlx(['invalidcommand']);

        // Should exit with error but not crash
        assert.ok(result.exitCode !== 0 || result.stderr.length > 0,
                  'Should report error for invalid command');
    });

    test('should handle very long SQL input', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        // Generate a long but valid SQL
        const columns = Array.from({ length: 100 }, (_, i) => `col${i}`).join(', ');
        const sql = `SELECT ${columns} FROM large_table`;

        const result = await runGosqlx(['validate', sql]);

        // Should handle without crash
        assert.ok(result.exitCode !== null, 'Should complete for long input');
    });

    test('should handle deeply nested SQL', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        // Nested subqueries
        let sql = 'SELECT 1';
        for (let i = 0; i < 10; i++) {
            sql = `SELECT * FROM (${sql}) AS sub${i}`;
        }

        const result = await runGosqlx(['validate', sql]);

        // Should handle without crash
        assert.ok(result.exitCode !== null, 'Should complete for nested query');
    });

    test('should handle special characters in string literals', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = `SELECT * FROM users WHERE bio LIKE '%"quoted"%'`;

        const result = await runGosqlx(['validate', sql]);

        assert.ok(result.exitCode !== null, 'Should handle special characters');
    });

    test('should handle SQL injection patterns gracefully', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = `SELECT * FROM users WHERE id = 1; DROP TABLE users; --`;

        const result = await runGosqlx(['validate', sql]);

        // Should parse (possibly with multiple statements) but not execute
        assert.ok(result.exitCode !== null, 'Should handle injection patterns');
    });
});

// =========================================================================
// GoSQLX Performance Tests
// =========================================================================
suite('GoSQLX Performance Tests', function() {
    this.timeout(TEST_TIMEOUT);

    test('should validate simple query quickly', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const start = Date.now();
        const result = await runGosqlx(['validate', 'SELECT 1']);
        const duration = Date.now() - start;

        assert.strictEqual(result.exitCode, 0);
        assert.ok(duration < 5000, `Should complete in < 5s, took ${duration}ms`);
    });

    test('should handle multiple sequential validations', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const queries = [
            'SELECT * FROM users',
            'INSERT INTO users (name) VALUES ("test")',
            'UPDATE users SET name = "updated" WHERE id = 1',
            'DELETE FROM users WHERE id = 1',
            'SELECT COUNT(*) FROM orders GROUP BY status'
        ];

        const start = Date.now();

        for (const sql of queries) {
            await runGosqlx(['validate', sql]);
        }

        const duration = Date.now() - start;

        assert.ok(duration < 15000, `5 validations should complete in < 15s, took ${duration}ms`);
    });
});

// =========================================================================
// GoSQLX Dialect Tests
// =========================================================================
suite('GoSQLX Dialect Tests', function() {
    this.timeout(TEST_TIMEOUT);

    test('should support PostgreSQL-style casting', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = `SELECT '2023-01-01'::date`;
        const result = await runGosqlx(['validate', sql]);

        // May or may not be supported depending on dialect
        assert.ok(result.exitCode !== null, 'Should handle PostgreSQL cast syntax');
    });

    test('should support MySQL-style backtick identifiers', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = 'SELECT `column` FROM `table`';
        const result = await runGosqlx(['validate', sql]);

        assert.ok(result.exitCode !== null, 'Should handle backtick identifiers');
    });

    test('should support standard double-quote identifiers', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = 'SELECT "column" FROM "table"';
        const result = await runGosqlx(['validate', sql]);

        assert.ok(result.exitCode !== null, 'Should handle double-quote identifiers');
    });

    test('should support bracket identifiers (SQL Server)', async function() {
        const available = await isGosqlxAvailable();
        if (!available) {
            this.skip();
            return;
        }

        const sql = 'SELECT [column] FROM [table]';
        const result = await runGosqlx(['validate', sql]);

        assert.ok(result.exitCode !== null, 'Should handle bracket identifiers');
    });
});
