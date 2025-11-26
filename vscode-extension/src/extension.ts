import * as vscode from 'vscode';
import * as path from 'path';
import * as os from 'os';
import { spawn } from 'child_process';
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;
let extensionContext: vscode.ExtensionContext | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    // Store context for restart functionality
    extensionContext = context;

    outputChannel = vscode.window.createOutputChannel('GoSQLX');
    context.subscriptions.push(outputChannel);

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = '$(database) GoSQLX';
    statusBarItem.tooltip = 'GoSQLX Language Server';
    statusBarItem.command = 'gosqlx.showOutput';
    context.subscriptions.push(statusBarItem);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('gosqlx.validate', validateCommand),
        vscode.commands.registerCommand('gosqlx.format', formatCommand),
        vscode.commands.registerCommand('gosqlx.analyze', analyzeCommand),
        vscode.commands.registerCommand('gosqlx.restartServer', restartServerCommand),
        vscode.commands.registerCommand('gosqlx.showOutput', () => outputChannel.show())
    );

    // Start the language server
    const config = vscode.workspace.getConfiguration('gosqlx');
    if (config.get<boolean>('enable', true)) {
        await startLanguageServer(context);
    }

    // Watch for configuration changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(async (e) => {
            if (e.affectsConfiguration('gosqlx')) {
                const newConfig = vscode.workspace.getConfiguration('gosqlx');
                if (newConfig.get<boolean>('enable', true)) {
                    if (!client) {
                        await startLanguageServer(context);
                    }
                } else {
                    await stopLanguageServer();
                }
            }
        })
    );

    outputChannel.appendLine('GoSQLX extension activated');
}

// Validate that the gosqlx executable exists and is runnable
async function validateExecutable(executablePath: string): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
        const child = spawn(executablePath, ['--version'], { stdio: 'pipe' });
        const timeout = setTimeout(() => {
            child.kill();
            resolve(false);
        }, 5000); // 5 second timeout

        child.on('close', (code) => {
            clearTimeout(timeout);
            resolve(code === 0);
        });

        child.on('error', () => {
            clearTimeout(timeout);
            resolve(false);
        });
    });
}

async function startLanguageServer(context: vscode.ExtensionContext, retryCount: number = 0): Promise<void> {
    const config = vscode.workspace.getConfiguration('gosqlx');
    const executablePath = config.get<string>('executablePath', 'gosqlx');
    const maxRetries = 3;

    // Validate executable before starting
    const isValid = await validateExecutable(executablePath);
    if (!isValid) {
        const message = `GoSQLX executable not found or not working: ${executablePath}`;
        outputChannel.appendLine(message);
        vscode.window.showErrorMessage(
            `${message}. Please install gosqlx: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest`
        );
        statusBarItem.text = '$(error) GoSQLX';
        statusBarItem.tooltip = 'GoSQLX: Executable not found';
        statusBarItem.show();
        return;
    }

    // Server options - spawn the gosqlx lsp command
    // Use cross-platform temp directory for debug logs
    const debugLogPath = path.join(os.tmpdir(), 'gosqlx-lsp-debug.log');

    const serverOptions: ServerOptions = {
        run: {
            command: executablePath,
            args: ['lsp'],
            transport: TransportKind.stdio
        },
        debug: {
            command: executablePath,
            args: ['lsp', '--log', debugLogPath],
            transport: TransportKind.stdio
        }
    };

    // Client options
    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'sql' },
            { scheme: 'untitled', language: 'sql' }
        ],
        synchronize: {
            fileEvents: vscode.workspace.createFileSystemWatcher('**/*.sql')
        },
        outputChannel: outputChannel,
        traceOutputChannel: outputChannel,
        initializationOptions: {
            dialect: config.get<string>('dialect', 'generic'),
            format: {
                indentSize: config.get<number>('format.indentSize', 2),
                uppercaseKeywords: config.get<boolean>('format.uppercaseKeywords', true)
            }
        }
    };

    // Create and start the client
    client = new LanguageClient(
        'gosqlx',
        'GoSQLX Language Server',
        serverOptions,
        clientOptions
    );

    try {
        await client.start();
        statusBarItem.text = '$(database) GoSQLX';
        statusBarItem.tooltip = 'GoSQLX Language Server - Running';
        statusBarItem.show();
        outputChannel.appendLine('GoSQLX Language Server started successfully');
        vscode.window.showInformationMessage('GoSQLX Language Server started');
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        outputChannel.appendLine(`Failed to start GoSQLX Language Server: ${message}`);

        // Retry logic
        if (retryCount < maxRetries) {
            const retryDelay = Math.pow(2, retryCount) * 1000; // Exponential backoff
            outputChannel.appendLine(`Retrying in ${retryDelay / 1000} seconds... (attempt ${retryCount + 1}/${maxRetries})`);
            statusBarItem.text = '$(sync~spin) GoSQLX';
            statusBarItem.tooltip = `GoSQLX: Retrying... (${retryCount + 1}/${maxRetries})`;
            statusBarItem.show();

            await new Promise(resolve => setTimeout(resolve, retryDelay));
            return startLanguageServer(context, retryCount + 1);
        }

        vscode.window.showErrorMessage(
            `Failed to start GoSQLX Language Server after ${maxRetries} attempts: ${message}. ` +
            'Make sure gosqlx is installed and in your PATH.'
        );
        statusBarItem.text = '$(error) GoSQLX';
        statusBarItem.tooltip = 'GoSQLX: Failed to start';
        statusBarItem.show();
    }
}

async function stopLanguageServer(): Promise<void> {
    if (client) {
        await client.stop();
        client = undefined;
        statusBarItem.hide();
        outputChannel.appendLine('GoSQLX Language Server stopped');
    }
}

async function restartServerCommand(): Promise<void> {
    outputChannel.appendLine('Restarting GoSQLX Language Server...');
    await stopLanguageServer();

    const context = getExtensionContext();
    if (context) {
        await startLanguageServer(context);
    }
}

function getExtensionContext(): vscode.ExtensionContext | undefined {
    return extensionContext;
}

async function validateCommand(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.languageId !== 'sql') {
        vscode.window.showWarningMessage('No SQL file is open');
        return;
    }

    if (!client) {
        vscode.window.showErrorMessage('GoSQLX Language Server is not running');
        return;
    }

    const uri = editor.document.uri;
    outputChannel.appendLine(`Validating: ${uri.fsPath}`);

    try {
        // Force document sync by saving if dirty, or touch the document
        if (editor.document.isDirty) {
            // If document has unsaved changes, the LSP should already have diagnostics
            // Just wait a moment for any pending diagnostics
            await new Promise(resolve => setTimeout(resolve, 200));
        }

        // Get current diagnostics for the document
        const diagnostics = vscode.languages.getDiagnostics(uri);
        const sqlDiagnostics = diagnostics.filter(d =>
            d.source === 'gosqlx' || d.source === 'GoSQLX' || d.source === undefined
        );

        if (sqlDiagnostics.length === 0) {
            vscode.window.showInformationMessage('SQL validation complete. No issues found.');
        } else {
            const errorCount = sqlDiagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length;
            const warningCount = sqlDiagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length;
            const infoCount = sqlDiagnostics.length - errorCount - warningCount;

            let message = 'SQL validation complete: ';
            const parts: string[] = [];
            if (errorCount > 0) { parts.push(`${errorCount} error(s)`); }
            if (warningCount > 0) { parts.push(`${warningCount} warning(s)`); }
            if (infoCount > 0) { parts.push(`${infoCount} info`); }

            if (parts.length === 0) {
                vscode.window.showInformationMessage('SQL validation complete. No issues found.');
            } else if (errorCount > 0) {
                vscode.window.showErrorMessage(`${message}${parts.join(', ')}. Check the Problems panel.`);
            } else {
                vscode.window.showWarningMessage(`${message}${parts.join(', ')}. Check the Problems panel.`);
            }
        }

        // Focus the Problems panel if there are issues
        if (sqlDiagnostics.length > 0) {
            await vscode.commands.executeCommand('workbench.actions.view.problems');
        }
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        outputChannel.appendLine(`Validation error: ${message}`);
        vscode.window.showInformationMessage('SQL validation triggered. Check the Problems panel for any issues.');
    }
}

async function formatCommand(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.languageId !== 'sql') {
        vscode.window.showWarningMessage('No SQL file is open');
        return;
    }

    if (!client) {
        vscode.window.showErrorMessage('GoSQLX Language Server is not running');
        return;
    }

    try {
        // Use VS Code's built-in format command which will use our LSP server
        await vscode.commands.executeCommand('editor.action.formatDocument');
        outputChannel.appendLine(`Formatted: ${editor.document.uri.fsPath}`);
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        vscode.window.showErrorMessage(`Format failed: ${message}`);
    }
}

async function analyzeCommand(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.languageId !== 'sql') {
        vscode.window.showWarningMessage('No SQL file is open');
        return;
    }

    const text = editor.document.getText();
    const config = vscode.workspace.getConfiguration('gosqlx');
    const executablePath = config.get<string>('executablePath', 'gosqlx');

    // Show progress indicator
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Analyzing SQL...',
        cancellable: false
    }, async () => {
        try {
            // Use stdin to send SQL content - safer than command line arguments
            const result = await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
                const child = spawn(executablePath, ['analyze'], {
                    stdio: ['pipe', 'pipe', 'pipe']
                });

                let stdout = '';
                let stderr = '';
                let outputSize = 0;
                const maxSize = 5 * 1024 * 1024; // 5MB limit for large analysis results

                // Set a timeout to prevent hanging
                const timeout = setTimeout(() => {
                    child.kill();
                    reject(new Error('Analysis timed out after 30 seconds'));
                }, 30000);

                if (child.stdout) {
                    child.stdout.on('data', (data: Buffer) => {
                        outputSize += data.length;
                        if (outputSize < maxSize) {
                            stdout += data.toString();
                        }
                    });
                }

                if (child.stderr) {
                    child.stderr.on('data', (data: Buffer) => {
                        stderr += data.toString();
                    });
                }

                child.on('close', (code: number | null) => {
                    clearTimeout(timeout);
                    if (code === 0 || code === null) {
                        resolve({ stdout, stderr });
                    } else {
                        reject(new Error(`Process exited with code ${code}: ${stderr || 'Unknown error'}`));
                    }
                });

                child.on('error', (err: Error) => {
                    clearTimeout(timeout);
                    reject(err);
                });

                // Send SQL content via stdin - avoids command line length limits and injection risks
                if (child.stdin) {
                    child.stdin.write(text);
                    child.stdin.end();
                }
            });

            if (result.stderr) {
                outputChannel.appendLine(`Analysis stderr: ${result.stderr}`);
            }

            // Show analysis results in a new document
            const doc = await vscode.workspace.openTextDocument({
                content: result.stdout || 'No analysis output',
                language: 'markdown'
            });
            await vscode.window.showTextDocument(doc, { preview: true });

            outputChannel.appendLine(`Analyzed: ${editor.document.uri.fsPath}`);
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            vscode.window.showErrorMessage(`Analysis failed: ${message}`);
            outputChannel.appendLine(`Analysis error: ${message}`);
        }
    });
}

export async function deactivate(): Promise<void> {
    await stopLanguageServer();
}
