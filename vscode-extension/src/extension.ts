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

import {
    validateConfiguration,
    isSqlLanguageId,
    getExecutableNotFoundMessage,
    getLspStartFailureMessage,
    getAnalysisErrorMessage,
    extractErrorCode,
    formatError,
    TelemetryManager,
    MetricsCollector,
    PerformanceTimer,
    showMetricsReport,
    createPerformanceStatusBarItem,
    updatePerformanceStatusBar
} from './utils';

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;
let performanceStatusBarItem: vscode.StatusBarItem | undefined;
let extensionContext: vscode.ExtensionContext | undefined;
let telemetry: TelemetryManager;
let metrics: MetricsCollector;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    // Store context for restart functionality
    extensionContext = context;

    // Initialize utilities
    const packageJson = context.extension.packageJSON;
    telemetry = TelemetryManager.getInstance(packageJson.version || '0.1.0');
    metrics = MetricsCollector.getInstance();

    outputChannel = vscode.window.createOutputChannel('GoSQLX');
    context.subscriptions.push(outputChannel);

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = '$(database) GoSQLX';
    statusBarItem.tooltip = 'GoSQLX Language Server';
    statusBarItem.command = 'gosqlx.showOutput';
    context.subscriptions.push(statusBarItem);

    // Create performance status bar item if enabled
    const config = vscode.workspace.getConfiguration('gosqlx');
    if (config.get<boolean>('performance.showStatusBar', false)) {
        performanceStatusBarItem = createPerformanceStatusBarItem();
        context.subscriptions.push(performanceStatusBarItem);
    }

    // Validate configuration on startup
    await validateAndWarnConfiguration();

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('gosqlx.validate', validateCommand),
        vscode.commands.registerCommand('gosqlx.format', formatCommand),
        vscode.commands.registerCommand('gosqlx.analyze', analyzeCommand),
        vscode.commands.registerCommand('gosqlx.restartServer', restartServerCommand),
        vscode.commands.registerCommand('gosqlx.showOutput', () => outputChannel.show()),
        vscode.commands.registerCommand('gosqlx.showMetrics', showMetricsCommand),
        vscode.commands.registerCommand('gosqlx.validateConfiguration', validateConfigurationCommand)
    );

    // Start the language server
    if (config.get<boolean>('enable', true)) {
        await startLanguageServer(context);
    }

    // Watch for configuration changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(async (e) => {
            if (e.affectsConfiguration('gosqlx')) {
                telemetry.recordEvent('config.changed');

                // Re-validate configuration
                await validateAndWarnConfiguration();

                const newConfig = vscode.workspace.getConfiguration('gosqlx');

                // Handle enable/disable
                if (newConfig.get<boolean>('enable', true)) {
                    if (!client) {
                        await startLanguageServer(context);
                    }
                } else {
                    await stopLanguageServer();
                }

                // Handle performance status bar toggle
                if (e.affectsConfiguration('gosqlx.performance.showStatusBar')) {
                    if (newConfig.get<boolean>('performance.showStatusBar', false)) {
                        if (!performanceStatusBarItem) {
                            performanceStatusBarItem = createPerformanceStatusBarItem();
                            context.subscriptions.push(performanceStatusBarItem);
                        }
                        updatePerformanceStatusBar(performanceStatusBarItem, metrics);
                    } else {
                        performanceStatusBarItem?.hide();
                    }
                }
            }
        })
    );

    // Record activation
    telemetry.recordEvent('extension.activated');
    outputChannel.appendLine('GoSQLX extension activated');
}

/**
 * Validates configuration and shows warnings for invalid settings.
 */
async function validateAndWarnConfiguration(): Promise<void> {
    const config = vscode.workspace.getConfiguration('gosqlx');

    // Build config object for validation
    const configObj: Record<string, unknown> = {
        enable: config.get('enable'),
        executablePath: config.get('executablePath'),
        dialect: config.get('dialect'),
        format: {
            indentSize: config.get('format.indentSize'),
            uppercaseKeywords: config.get('format.uppercaseKeywords')
        },
        timeouts: {
            startup: config.get('timeouts.startup'),
            validation: config.get('timeouts.validation'),
            analysis: config.get('timeouts.analysis')
        },
        'trace.server': config.get('trace.server')
    };

    const results = validateConfiguration(configObj);
    const errors = results.filter(r => !r.valid);

    if (errors.length > 0) {
        outputChannel.appendLine('Configuration validation warnings:');
        for (const error of errors) {
            outputChannel.appendLine(`  - ${error.message}`);
            if (error.suggestion) {
                outputChannel.appendLine(`    Suggestion: ${error.suggestion}`);
            }
        }

        const action = await vscode.window.showWarningMessage(
            `GoSQLX: ${errors.length} configuration issue(s) detected`,
            'Show Details',
            'Open Settings'
        );

        if (action === 'Show Details') {
            outputChannel.show();
        } else if (action === 'Open Settings') {
            vscode.commands.executeCommand('workbench.action.openSettings', 'gosqlx');
        }
    }
}

/**
 * Validates that the gosqlx executable exists and is runnable.
 */
async function validateExecutable(executablePath: string): Promise<boolean> {
    const config = vscode.workspace.getConfiguration('gosqlx');
    const timeout = config.get<number>('timeouts.validation', 5000);

    const timer = new PerformanceTimer();
    timer.start();

    return new Promise<boolean>((resolve) => {
        const child = spawn(executablePath, ['--version'], { stdio: 'pipe' });
        const timeoutHandle = setTimeout(() => {
            child.kill();
            metrics.record('executable.check', timer.stop(), false, { reason: 'timeout' });
            resolve(false);
        }, timeout);

        child.on('close', (code) => {
            clearTimeout(timeoutHandle);
            const success = code === 0;
            metrics.record('executable.check', timer.stop(), success, { exitCode: code ?? -1 });
            resolve(success);
        });

        child.on('error', (err: NodeJS.ErrnoException) => {
            clearTimeout(timeoutHandle);
            metrics.record('executable.check', timer.stop(), false, { error: err.code || 'unknown' });
            resolve(false);
        });
    });
}

async function startLanguageServer(context: vscode.ExtensionContext, retryCount: number = 0): Promise<void> {
    const config = vscode.workspace.getConfiguration('gosqlx');
    const executablePath = config.get<string>('executablePath', 'gosqlx');
    const maxRetries = 3;

    const timer = new PerformanceTimer();
    timer.start();

    // Validate executable before starting
    const isValid = await validateExecutable(executablePath);
    if (!isValid) {
        const message = getExecutableNotFoundMessage(executablePath, os.platform());
        outputChannel.appendLine(message);

        telemetry.recordError('ENOENT', 'lsp.startup');

        const action = await vscode.window.showErrorMessage(
            `GoSQLX executable not found or not working: ${executablePath}`,
            'Show Details',
            'Install Guide',
            'Open Settings'
        );

        if (action === 'Show Details') {
            outputChannel.show();
        } else if (action === 'Install Guide') {
            vscode.env.openExternal(
                vscode.Uri.parse('https://github.com/ajitpratap0/GoSQLX#installation')
            );
        } else if (action === 'Open Settings') {
            vscode.commands.executeCommand('workbench.action.openSettings', 'gosqlx.executablePath');
        }

        statusBarItem.text = '$(error) GoSQLX';
        statusBarItem.tooltip = 'GoSQLX: Executable not found - Click for details';
        statusBarItem.show();
        return;
    }

    // Server options - spawn the gosqlx lsp command
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
        const duration = timer.stop();

        metrics.record('lsp.startup', duration, true);
        telemetry.recordLspOperation('started', { duration });

        statusBarItem.text = '$(database) GoSQLX';
        statusBarItem.tooltip = 'GoSQLX Language Server - Running';
        statusBarItem.show();

        if (performanceStatusBarItem) {
            updatePerformanceStatusBar(performanceStatusBarItem, metrics);
        }

        outputChannel.appendLine(`GoSQLX Language Server started successfully (${duration}ms)`);
        vscode.window.showInformationMessage('GoSQLX Language Server started');
    } catch (error) {
        const duration = timer.stop();
        const errorMessage = formatError(error);
        const errorCode = extractErrorCode(error);

        metrics.record('lsp.startup', duration, false, { error: errorCode || 'unknown' });
        telemetry.recordLspOperation('error', { errorCode: errorCode || 'unknown', attempt: retryCount });

        outputChannel.appendLine(`Failed to start GoSQLX Language Server: ${errorMessage}`);

        // Retry logic
        if (retryCount < maxRetries) {
            const retryDelay = Math.pow(2, retryCount) * 1000; // Exponential backoff

            telemetry.recordLspOperation('retry', { attempt: retryCount + 1, retryDelay });
            outputChannel.appendLine(`Retrying in ${retryDelay / 1000} seconds... (attempt ${retryCount + 1}/${maxRetries})`);

            statusBarItem.text = '$(sync~spin) GoSQLX';
            statusBarItem.tooltip = `GoSQLX: Retrying... (${retryCount + 1}/${maxRetries})`;
            statusBarItem.show();

            await new Promise(resolve => setTimeout(resolve, retryDelay));
            return startLanguageServer(context, retryCount + 1);
        }

        const detailedMessage = getLspStartFailureMessage(
            errorMessage,
            maxRetries,
            maxRetries,
            executablePath
        );
        outputChannel.appendLine(detailedMessage);

        const action = await vscode.window.showErrorMessage(
            `Failed to start GoSQLX Language Server after ${maxRetries} attempts`,
            'Show Details',
            'Restart',
            'Open Settings'
        );

        if (action === 'Show Details') {
            outputChannel.show();
        } else if (action === 'Restart') {
            await restartServerCommand();
        } else if (action === 'Open Settings') {
            vscode.commands.executeCommand('workbench.action.openSettings', 'gosqlx');
        }

        statusBarItem.text = '$(error) GoSQLX';
        statusBarItem.tooltip = 'GoSQLX: Failed to start - Click for details';
        statusBarItem.show();
    }
}

async function stopLanguageServer(): Promise<void> {
    if (client) {
        const timer = new PerformanceTimer();
        timer.start();

        await client.stop();
        client = undefined;

        metrics.record('lsp.shutdown', timer.stop(), true);
        telemetry.recordLspOperation('stopped');

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
    const timer = new PerformanceTimer();
    timer.start();

    const editor = vscode.window.activeTextEditor;
    if (!editor || !isSqlLanguageId(editor.document.languageId)) {
        vscode.window.showWarningMessage(
            'No SQL file is open. Open a .sql file to validate.',
            'Open File'
        ).then(action => {
            if (action === 'Open File') {
                vscode.commands.executeCommand('workbench.action.files.openFile');
            }
        });
        return;
    }

    if (!client) {
        const action = await vscode.window.showErrorMessage(
            'GoSQLX Language Server is not running',
            'Start Server',
            'Show Output'
        );

        if (action === 'Start Server') {
            await restartServerCommand();
        } else if (action === 'Show Output') {
            outputChannel.show();
        }
        return;
    }

    const uri = editor.document.uri;
    outputChannel.appendLine(`Validating: ${uri.fsPath}`);

    try {
        // Force document sync by waiting for diagnostics
        if (editor.document.isDirty) {
            await new Promise(resolve => setTimeout(resolve, 200));
        }

        // Get current diagnostics for the document
        const diagnostics = vscode.languages.getDiagnostics(uri);
        const sqlDiagnostics = diagnostics.filter(d =>
            d.source === 'gosqlx' || d.source === 'GoSQLX' || d.source === undefined
        );

        const duration = timer.stop();
        metrics.record('command.validate', duration, true, { diagnosticCount: sqlDiagnostics.length });
        telemetry.recordCommand('validate', duration, true);

        if (sqlDiagnostics.length === 0) {
            vscode.window.showInformationMessage('SQL validation complete. No issues found.');
        } else {
            const errorCount = sqlDiagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length;
            const warningCount = sqlDiagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length;
            const infoCount = sqlDiagnostics.length - errorCount - warningCount;

            const message = 'SQL validation complete: ';
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

        if (performanceStatusBarItem) {
            updatePerformanceStatusBar(performanceStatusBarItem, metrics);
        }
    } catch (error) {
        const duration = timer.stop();
        const errorMessage = formatError(error);

        metrics.record('command.validate', duration, false);
        telemetry.recordCommand('validate', duration, false, extractErrorCode(error));

        outputChannel.appendLine(`Validation error: ${errorMessage}`);
        vscode.window.showInformationMessage('SQL validation triggered. Check the Problems panel for any issues.');
    }
}

async function formatCommand(): Promise<void> {
    const timer = new PerformanceTimer();
    timer.start();

    const editor = vscode.window.activeTextEditor;
    if (!editor || !isSqlLanguageId(editor.document.languageId)) {
        vscode.window.showWarningMessage(
            'No SQL file is open. Open a .sql file to format.',
            'Open File'
        ).then(action => {
            if (action === 'Open File') {
                vscode.commands.executeCommand('workbench.action.files.openFile');
            }
        });
        return;
    }

    if (!client) {
        const action = await vscode.window.showErrorMessage(
            'GoSQLX Language Server is not running',
            'Start Server',
            'Show Output'
        );

        if (action === 'Start Server') {
            await restartServerCommand();
        } else if (action === 'Show Output') {
            outputChannel.show();
        }
        return;
    }

    try {
        // Use VS Code's built-in format command which will use our LSP server
        await vscode.commands.executeCommand('editor.action.formatDocument');

        const duration = timer.stop();
        metrics.record('command.format', duration, true);
        telemetry.recordCommand('format', duration, true);

        outputChannel.appendLine(`Formatted: ${editor.document.uri.fsPath} (${duration}ms)`);

        if (performanceStatusBarItem) {
            updatePerformanceStatusBar(performanceStatusBarItem, metrics);
        }
    } catch (error) {
        const duration = timer.stop();
        const errorMessage = formatError(error);

        metrics.record('command.format', duration, false);
        telemetry.recordCommand('format', duration, false, extractErrorCode(error));

        vscode.window.showErrorMessage(`Format failed: ${errorMessage}`);
    }
}

async function analyzeCommand(): Promise<void> {
    const timer = new PerformanceTimer();
    timer.start();

    const editor = vscode.window.activeTextEditor;
    if (!editor || !isSqlLanguageId(editor.document.languageId)) {
        vscode.window.showWarningMessage(
            'No SQL file is open. Open a .sql file to analyze.',
            'Open File'
        ).then(action => {
            if (action === 'Open File') {
                vscode.commands.executeCommand('workbench.action.files.openFile');
            }
        });
        return;
    }

    const text = editor.document.getText();
    const config = vscode.workspace.getConfiguration('gosqlx');
    const executablePath = config.get<string>('executablePath', 'gosqlx');
    const analysisTimeout = config.get<number>('timeouts.analysis', 30000);

    // Show progress indicator
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Analyzing SQL...',
        cancellable: true
    }, async (progress, cancellationToken) => {
        try {
            const result = await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
                const child = spawn(executablePath, ['analyze'], {
                    stdio: ['pipe', 'pipe', 'pipe']
                });

                let stdout = '';
                let stderr = '';
                let outputSize = 0;
                const maxSize = 5 * 1024 * 1024; // 5MB limit

                // Set a timeout using configured value
                const timeout = setTimeout(() => {
                    child.kill();
                    reject(new Error(`Analysis timed out after ${analysisTimeout / 1000} seconds. Try increasing gosqlx.timeouts.analysis in settings.`));
                }, analysisTimeout);

                // Handle cancellation
                cancellationToken.onCancellationRequested(() => {
                    child.kill();
                    clearTimeout(timeout);
                    reject(new Error('Analysis cancelled by user'));
                });

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

                // Send SQL content via stdin
                if (child.stdin) {
                    child.stdin.write(text);
                    child.stdin.end();
                }
            });

            const duration = timer.stop();
            metrics.record('command.analyze', duration, true, { outputSize: result.stdout.length });
            telemetry.recordCommand('analyze', duration, true);

            if (result.stderr) {
                outputChannel.appendLine(`Analysis stderr: ${result.stderr}`);
            }

            // Show analysis results in a new document
            const doc = await vscode.workspace.openTextDocument({
                content: result.stdout || 'No analysis output',
                language: 'markdown'
            });
            await vscode.window.showTextDocument(doc, { preview: true });

            outputChannel.appendLine(`Analyzed: ${editor.document.uri.fsPath} (${duration}ms)`);

            if (performanceStatusBarItem) {
                updatePerformanceStatusBar(performanceStatusBarItem, metrics);
            }
        } catch (error) {
            const duration = timer.stop();
            const errorMessage = formatError(error);
            const errorCode = extractErrorCode(error);

            metrics.record('command.analyze', duration, false, { error: errorCode || 'unknown' });
            telemetry.recordCommand('analyze', duration, false, errorCode);

            const detailedMessage = getAnalysisErrorMessage(errorMessage);
            outputChannel.appendLine(detailedMessage);

            vscode.window.showErrorMessage(
                `Analysis failed: ${errorMessage}`,
                'Show Details'
            ).then(action => {
                if (action === 'Show Details') {
                    outputChannel.show();
                }
            });
        }
    });
}

async function showMetricsCommand(): Promise<void> {
    await showMetricsReport();
}

async function validateConfigurationCommand(): Promise<void> {
    await validateAndWarnConfiguration();
    outputChannel.show();
    vscode.window.showInformationMessage('Configuration validation complete. Check the output channel for details.');
}

export async function deactivate(): Promise<void> {
    telemetry.recordEvent('extension.deactivated');

    // Get final metrics summary
    const summary = metrics.getSummary();
    outputChannel.appendLine('\n' + summary);

    // Cleanup
    await stopLanguageServer();
    telemetry.dispose();
    metrics.dispose();
}
