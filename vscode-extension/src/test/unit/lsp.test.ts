import * as assert from 'assert';
import * as path from 'path';
import * as os from 'os';

/**
 * LSP Communication Tests for GoSQLX extension.
 * Tests the Language Server Protocol communication scenarios.
 */

// Mock types for LSP testing
interface MockMessage {
    jsonrpc: string;
    id?: number;
    method?: string;
    params?: unknown;
    result?: unknown;
    error?: LspError;
}

interface LspError {
    code: number;
    message: string;
    data?: unknown;
}

interface MockDiagnostic {
    range: {
        start: { line: number; character: number };
        end: { line: number; character: number };
    };
    message: string;
    severity: number;
    source?: string;
    code?: string | number;
}

interface MockServerCapabilities {
    textDocumentSync?: number;
    completionProvider?: { triggerCharacters?: string[] };
    hoverProvider?: boolean;
    documentFormattingProvider?: boolean;
    diagnosticProvider?: { interFileDependencies: boolean; workspaceDiagnostics: boolean };
}

// LSP Message Validation Tests
suite('LSP Message Validation Tests', () => {

    test('validateJsonRpcMessage should accept valid request', () => {
        const message: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: {}
        };

        const result = validateJsonRpcMessage(message);
        assert.strictEqual(result.valid, true);
    });

    test('validateJsonRpcMessage should accept valid notification', () => {
        const message: MockMessage = {
            jsonrpc: '2.0',
            method: 'textDocument/didOpen',
            params: {}
        };

        const result = validateJsonRpcMessage(message);
        assert.strictEqual(result.valid, true);
    });

    test('validateJsonRpcMessage should accept valid response', () => {
        const message: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: { capabilities: {} }
        };

        const result = validateJsonRpcMessage(message);
        assert.strictEqual(result.valid, true);
    });

    test('validateJsonRpcMessage should reject invalid version', () => {
        const message: MockMessage = {
            jsonrpc: '1.0',
            id: 1,
            method: 'initialize'
        };

        const result = validateJsonRpcMessage(message);
        assert.strictEqual(result.valid, false);
        assert.ok(result.error?.includes('jsonrpc'));
    });

    test('validateJsonRpcMessage should reject message without method or result', () => {
        const message: MockMessage = {
            jsonrpc: '2.0',
            id: 1
        };

        const result = validateJsonRpcMessage(message);
        assert.strictEqual(result.valid, false);
    });
});

// LSP Initialize Request Tests
suite('LSP Initialize Request Tests', () => {

    test('createInitializeRequest should include required fields', () => {
        const request = createInitializeRequest(1, '/workspace/project', {
            dialect: 'postgresql',
            indentSize: 4
        });

        assert.strictEqual(request.jsonrpc, '2.0');
        assert.strictEqual(request.id, 1);
        assert.strictEqual(request.method, 'initialize');
        assert.ok(request.params);
        assert.ok(request.params.processId);
        assert.strictEqual(request.params.rootUri, 'file:///workspace/project');
    });

    test('createInitializeRequest should include client capabilities', () => {
        const request = createInitializeRequest(1, '/workspace', {});

        assert.ok(request.params.capabilities);
        assert.ok(request.params.capabilities.textDocument);
        assert.ok(request.params.capabilities.workspace);
    });

    test('createInitializeRequest should include initialization options', () => {
        const request = createInitializeRequest(1, '/workspace', {
            dialect: 'mysql',
            indentSize: 2,
            uppercaseKeywords: true
        });

        assert.deepStrictEqual(request.params.initializationOptions, {
            dialect: 'mysql',
            indentSize: 2,
            uppercaseKeywords: true
        });
    });

    test('createInitializeRequest should handle null root path', () => {
        const request = createInitializeRequest(1, null, {});

        assert.strictEqual(request.params.rootUri, null);
        assert.strictEqual(request.params.rootPath, null);
    });
});

// LSP Response Parsing Tests
suite('LSP Response Parsing Tests', () => {

    test('parseInitializeResponse should extract capabilities', () => {
        const response: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: {
                capabilities: {
                    textDocumentSync: 1,
                    completionProvider: { triggerCharacters: ['.', ' '] },
                    hoverProvider: true,
                    documentFormattingProvider: true
                }
            }
        };

        const capabilities = parseInitializeResponse(response);
        assert.strictEqual(capabilities.textDocumentSync, 1);
        assert.strictEqual(capabilities.hoverProvider, true);
        assert.strictEqual(capabilities.documentFormattingProvider, true);
        assert.deepStrictEqual(capabilities.completionProvider?.triggerCharacters, ['.', ' ']);
    });

    test('parseInitializeResponse should handle missing capabilities gracefully', () => {
        const response: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: {
                capabilities: {}
            }
        };

        const capabilities = parseInitializeResponse(response);
        assert.strictEqual(capabilities.textDocumentSync, undefined);
        assert.strictEqual(capabilities.hoverProvider, undefined);
    });

    test('parseInitializeResponse should throw on error response', () => {
        const response: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            error: {
                code: -32600,
                message: 'Invalid Request'
            }
        };

        assert.throws(() => parseInitializeResponse(response), /Invalid Request/);
    });
});

// LSP Diagnostic Tests
suite('LSP Diagnostic Parsing Tests', () => {

    test('parseDiagnostics should convert LSP diagnostics to VS Code format', () => {
        const lspDiagnostics: MockDiagnostic[] = [
            {
                range: {
                    start: { line: 0, character: 0 },
                    end: { line: 0, character: 10 }
                },
                message: 'Syntax error near SELECT',
                severity: 1,
                source: 'gosqlx',
                code: 'E001'
            }
        ];

        const parsed = parseDiagnostics(lspDiagnostics);
        assert.strictEqual(parsed.length, 1);
        assert.strictEqual(parsed[0].message, 'Syntax error near SELECT');
        assert.strictEqual(parsed[0].severity, 0); // VSCode Error
        assert.strictEqual(parsed[0].source, 'gosqlx');
    });

    test('parseDiagnostics should map severity levels correctly', () => {
        const diagnostics: MockDiagnostic[] = [
            { range: { start: { line: 0, character: 0 }, end: { line: 0, character: 1 } }, message: 'Error', severity: 1 },
            { range: { start: { line: 1, character: 0 }, end: { line: 1, character: 1 } }, message: 'Warning', severity: 2 },
            { range: { start: { line: 2, character: 0 }, end: { line: 2, character: 1 } }, message: 'Info', severity: 3 },
            { range: { start: { line: 3, character: 0 }, end: { line: 3, character: 1 } }, message: 'Hint', severity: 4 }
        ];

        const parsed = parseDiagnostics(diagnostics);
        assert.strictEqual(parsed[0].severity, 0); // Error
        assert.strictEqual(parsed[1].severity, 1); // Warning
        assert.strictEqual(parsed[2].severity, 2); // Information
        assert.strictEqual(parsed[3].severity, 3); // Hint
    });

    test('parseDiagnostics should handle empty array', () => {
        const parsed = parseDiagnostics([]);
        assert.strictEqual(parsed.length, 0);
    });

    test('parseDiagnostics should preserve diagnostic codes', () => {
        const diagnostics: MockDiagnostic[] = [
            {
                range: { start: { line: 0, character: 0 }, end: { line: 0, character: 1 } },
                message: 'Error',
                severity: 1,
                code: 'SQL001'
            },
            {
                range: { start: { line: 1, character: 0 }, end: { line: 1, character: 1 } },
                message: 'Error 2',
                severity: 1,
                code: 42
            }
        ];

        const parsed = parseDiagnostics(diagnostics);
        assert.strictEqual(parsed[0].code, 'SQL001');
        assert.strictEqual(parsed[1].code, 42);
    });
});

// LSP Document Sync Tests
suite('LSP Document Sync Tests', () => {

    test('createDidOpenNotification should include document details', () => {
        const notification = createDidOpenNotification(
            'file:///workspace/query.sql',
            'sql',
            1,
            'SELECT * FROM users;'
        );

        assert.strictEqual(notification.method, 'textDocument/didOpen');
        assert.strictEqual(notification.params.textDocument.uri, 'file:///workspace/query.sql');
        assert.strictEqual(notification.params.textDocument.languageId, 'sql');
        assert.strictEqual(notification.params.textDocument.version, 1);
        assert.strictEqual(notification.params.textDocument.text, 'SELECT * FROM users;');
    });

    test('createDidChangeNotification should include content changes', () => {
        const notification = createDidChangeNotification(
            'file:///workspace/query.sql',
            2,
            [{ text: 'SELECT id FROM users;' }]
        );

        assert.strictEqual(notification.method, 'textDocument/didChange');
        assert.strictEqual(notification.params.textDocument.version, 2);
        assert.strictEqual(notification.params.contentChanges[0].text, 'SELECT id FROM users;');
    });

    test('createDidCloseNotification should include document URI', () => {
        const notification = createDidCloseNotification('file:///workspace/query.sql');

        assert.strictEqual(notification.method, 'textDocument/didClose');
        assert.strictEqual(notification.params.textDocument.uri, 'file:///workspace/query.sql');
    });

    test('createDidSaveNotification should optionally include text', () => {
        const withText = createDidSaveNotification('file:///test.sql', 'SELECT 1;');
        const withoutText = createDidSaveNotification('file:///test.sql');

        assert.strictEqual(withText.params.text, 'SELECT 1;');
        assert.strictEqual(withoutText.params.text, undefined);
    });
});

// LSP Completion Tests
suite('LSP Completion Tests', () => {

    test('createCompletionRequest should include position', () => {
        const request = createCompletionRequest(1, 'file:///query.sql', 5, 10);

        assert.strictEqual(request.method, 'textDocument/completion');
        assert.strictEqual(request.params.textDocument.uri, 'file:///query.sql');
        assert.strictEqual(request.params.position.line, 5);
        assert.strictEqual(request.params.position.character, 10);
    });

    test('parseCompletionResponse should handle array result', () => {
        const response: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: [
                { label: 'SELECT', kind: 14 },
                { label: 'FROM', kind: 14 }
            ]
        };

        const items = parseCompletionResponse(response);
        assert.strictEqual(items.length, 2);
        assert.strictEqual(items[0].label, 'SELECT');
    });

    test('parseCompletionResponse should handle CompletionList result', () => {
        const response: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: {
                isIncomplete: false,
                items: [
                    { label: 'INSERT', kind: 14 }
                ]
            }
        };

        const items = parseCompletionResponse(response);
        assert.strictEqual(items.length, 1);
        assert.strictEqual(items[0].label, 'INSERT');
    });

    test('parseCompletionResponse should return empty array for null result', () => {
        const response: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: null
        };

        const items = parseCompletionResponse(response);
        assert.strictEqual(items.length, 0);
    });
});

// LSP Hover Tests
suite('LSP Hover Tests', () => {

    test('createHoverRequest should include position', () => {
        const request = createHoverRequest(1, 'file:///query.sql', 3, 7);

        assert.strictEqual(request.method, 'textDocument/hover');
        assert.strictEqual(request.params.position.line, 3);
        assert.strictEqual(request.params.position.character, 7);
    });

    test('parseHoverResponse should extract markdown content', () => {
        const response: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: {
                contents: {
                    kind: 'markdown',
                    value: '**SELECT** - Retrieves data from a table'
                }
            }
        };

        const hover = parseHoverResponse(response);
        assert.ok(hover);
        assert.ok(hover.contents.includes('SELECT'));
    });

    test('parseHoverResponse should handle string contents', () => {
        const response: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: {
                contents: 'Simple hover text'
            }
        };

        const hover = parseHoverResponse(response);
        assert.ok(hover);
        assert.strictEqual(hover.contents, 'Simple hover text');
    });

    test('parseHoverResponse should return null for null result', () => {
        const response: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: null
        };

        const hover = parseHoverResponse(response);
        assert.strictEqual(hover, null);
    });
});

// LSP Format Tests
suite('LSP Format Tests', () => {

    test('createFormatRequest should include formatting options', () => {
        const request = createFormatRequest(1, 'file:///query.sql', {
            tabSize: 4,
            insertSpaces: true
        });

        assert.strictEqual(request.method, 'textDocument/formatting');
        assert.strictEqual(request.params.options.tabSize, 4);
        assert.strictEqual(request.params.options.insertSpaces, true);
    });

    test('parseFormatResponse should return text edits', () => {
        const response: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: [
                {
                    range: { start: { line: 0, character: 0 }, end: { line: 5, character: 0 } },
                    newText: 'SELECT\n  id,\n  name\nFROM\n  users;\n'
                }
            ]
        };

        const edits = parseFormatResponse(response);
        assert.strictEqual(edits.length, 1);
        assert.ok(edits[0].newText.includes('SELECT'));
    });

    test('parseFormatResponse should return empty array for null result', () => {
        const response: MockMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: null
        };

        const edits = parseFormatResponse(response);
        assert.strictEqual(edits.length, 0);
    });
});

// LSP Connection State Tests
suite('LSP Connection State Tests', () => {

    test('LspConnectionState should track connection lifecycle', () => {
        const state = new LspConnectionState();

        assert.strictEqual(state.getState(), 'disconnected');

        state.connecting();
        assert.strictEqual(state.getState(), 'connecting');

        state.connected();
        assert.strictEqual(state.getState(), 'connected');

        state.disconnected();
        assert.strictEqual(state.getState(), 'disconnected');
    });

    test('LspConnectionState should track error state', () => {
        const state = new LspConnectionState();

        state.error('Connection refused');
        assert.strictEqual(state.getState(), 'error');
        assert.strictEqual(state.getLastError(), 'Connection refused');
    });

    test('LspConnectionState should track retry attempts', () => {
        const state = new LspConnectionState();

        state.retry(1, 3);
        assert.strictEqual(state.getState(), 'retrying');
        assert.strictEqual(state.getRetryAttempt(), 1);
        assert.strictEqual(state.getMaxRetries(), 3);
    });

    test('LspConnectionState should report isConnected correctly', () => {
        const state = new LspConnectionState();

        assert.strictEqual(state.isConnected(), false);

        state.connected();
        assert.strictEqual(state.isConnected(), true);

        state.disconnected();
        assert.strictEqual(state.isConnected(), false);
    });
});

// =========================================================================
// Implementation stubs for LSP testing
// =========================================================================

interface ValidationResponse {
    valid: boolean;
    error?: string;
}

interface InitializeParams {
    processId: number | null;
    rootUri: string | null;
    rootPath: string | null;
    capabilities: {
        textDocument: Record<string, unknown>;
        workspace: Record<string, unknown>;
    };
    initializationOptions: Record<string, unknown>;
}

interface TextDocumentItem {
    uri: string;
    languageId: string;
    version: number;
    text: string;
}

interface CompletionItem {
    label: string;
    kind?: number;
}

interface HoverResult {
    contents: string;
    range?: unknown;
}

interface TextEdit {
    range: unknown;
    newText: string;
}

function validateJsonRpcMessage(message: MockMessage): ValidationResponse {
    if (message.jsonrpc !== '2.0') {
        return { valid: false, error: 'Invalid jsonrpc version' };
    }

    // Must have method (request/notification) or result/error (response)
    if (!message.method && message.result === undefined && !message.error) {
        return { valid: false, error: 'Message must have method, result, or error' };
    }

    return { valid: true };
}

function createInitializeRequest(id: number, rootPath: string | null, options: Record<string, unknown>): {
    jsonrpc: string;
    id: number;
    method: string;
    params: InitializeParams;
} {
    return {
        jsonrpc: '2.0',
        id,
        method: 'initialize',
        params: {
            processId: process.pid,
            rootUri: rootPath ? `file://${rootPath}` : null,
            rootPath: rootPath,
            capabilities: {
                textDocument: {
                    synchronization: { dynamicRegistration: true },
                    completion: { dynamicRegistration: true },
                    hover: { dynamicRegistration: true },
                    formatting: { dynamicRegistration: true }
                },
                workspace: {
                    configuration: true,
                    workspaceFolders: true
                }
            },
            initializationOptions: options
        }
    };
}

function parseInitializeResponse(response: MockMessage): MockServerCapabilities {
    if (response.error) {
        throw new Error(response.error.message);
    }

    const result = response.result as { capabilities: MockServerCapabilities } | undefined;
    return result?.capabilities || {};
}

function parseDiagnostics(diagnostics: MockDiagnostic[]): Array<{
    message: string;
    severity: number;
    source?: string;
    code?: string | number;
}> {
    return diagnostics.map(d => ({
        message: d.message,
        severity: d.severity - 1, // LSP severity 1-4 maps to VS Code 0-3
        source: d.source,
        code: d.code
    }));
}

function createDidOpenNotification(uri: string, languageId: string, version: number, text: string): {
    jsonrpc: string;
    method: string;
    params: { textDocument: TextDocumentItem };
} {
    return {
        jsonrpc: '2.0',
        method: 'textDocument/didOpen',
        params: {
            textDocument: { uri, languageId, version, text }
        }
    };
}

function createDidChangeNotification(uri: string, version: number, changes: Array<{ text: string }>): {
    jsonrpc: string;
    method: string;
    params: {
        textDocument: { uri: string; version: number };
        contentChanges: Array<{ text: string }>;
    };
} {
    return {
        jsonrpc: '2.0',
        method: 'textDocument/didChange',
        params: {
            textDocument: { uri, version },
            contentChanges: changes
        }
    };
}

function createDidCloseNotification(uri: string): {
    jsonrpc: string;
    method: string;
    params: { textDocument: { uri: string } };
} {
    return {
        jsonrpc: '2.0',
        method: 'textDocument/didClose',
        params: {
            textDocument: { uri }
        }
    };
}

function createDidSaveNotification(uri: string, text?: string): {
    jsonrpc: string;
    method: string;
    params: { textDocument: { uri: string }; text?: string };
} {
    return {
        jsonrpc: '2.0',
        method: 'textDocument/didSave',
        params: {
            textDocument: { uri },
            text
        }
    };
}

function createCompletionRequest(id: number, uri: string, line: number, character: number): {
    jsonrpc: string;
    id: number;
    method: string;
    params: {
        textDocument: { uri: string };
        position: { line: number; character: number };
    };
} {
    return {
        jsonrpc: '2.0',
        id,
        method: 'textDocument/completion',
        params: {
            textDocument: { uri },
            position: { line, character }
        }
    };
}

function parseCompletionResponse(response: MockMessage): CompletionItem[] {
    if (!response.result) {
        return [];
    }

    if (Array.isArray(response.result)) {
        return response.result as CompletionItem[];
    }

    const listResult = response.result as { items?: CompletionItem[] };
    return listResult.items || [];
}

function createHoverRequest(id: number, uri: string, line: number, character: number): {
    jsonrpc: string;
    id: number;
    method: string;
    params: {
        textDocument: { uri: string };
        position: { line: number; character: number };
    };
} {
    return {
        jsonrpc: '2.0',
        id,
        method: 'textDocument/hover',
        params: {
            textDocument: { uri },
            position: { line, character }
        }
    };
}

function parseHoverResponse(response: MockMessage): HoverResult | null {
    if (!response.result) {
        return null;
    }

    const result = response.result as { contents: unknown };
    if (typeof result.contents === 'string') {
        return { contents: result.contents };
    }

    const markupContent = result.contents as { value?: string };
    return { contents: markupContent.value || '' };
}

function createFormatRequest(id: number, uri: string, options: { tabSize: number; insertSpaces: boolean }): {
    jsonrpc: string;
    id: number;
    method: string;
    params: {
        textDocument: { uri: string };
        options: { tabSize: number; insertSpaces: boolean };
    };
} {
    return {
        jsonrpc: '2.0',
        id,
        method: 'textDocument/formatting',
        params: {
            textDocument: { uri },
            options
        }
    };
}

function parseFormatResponse(response: MockMessage): TextEdit[] {
    if (!response.result) {
        return [];
    }
    return response.result as TextEdit[];
}

class LspConnectionState {
    private state: 'disconnected' | 'connecting' | 'connected' | 'error' | 'retrying' = 'disconnected';
    private lastError: string = '';
    private retryAttempt: number = 0;
    private maxRetries: number = 0;

    getState(): string {
        return this.state;
    }

    getLastError(): string {
        return this.lastError;
    }

    getRetryAttempt(): number {
        return this.retryAttempt;
    }

    getMaxRetries(): number {
        return this.maxRetries;
    }

    isConnected(): boolean {
        return this.state === 'connected';
    }

    connecting(): void {
        this.state = 'connecting';
    }

    connected(): void {
        this.state = 'connected';
        this.lastError = '';
        this.retryAttempt = 0;
    }

    disconnected(): void {
        this.state = 'disconnected';
    }

    error(message: string): void {
        this.state = 'error';
        this.lastError = message;
    }

    retry(attempt: number, maxRetries: number): void {
        this.state = 'retrying';
        this.retryAttempt = attempt;
        this.maxRetries = maxRetries;
    }
}
