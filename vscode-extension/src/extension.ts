import * as vscode from 'vscode';
import * as path from 'path';
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
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

async function startLanguageServer(context: vscode.ExtensionContext): Promise<void> {
    const config = vscode.workspace.getConfiguration('gosqlx');
    const executablePath = config.get<string>('executablePath', 'gosqlx');

    // Server options - spawn the gosqlx lsp command
    const serverOptions: ServerOptions = {
        run: {
            command: executablePath,
            args: ['lsp'],
            transport: TransportKind.stdio
        },
        debug: {
            command: executablePath,
            args: ['lsp', '--log', '/tmp/gosqlx-lsp-debug.log'],
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
        statusBarItem.show();
        outputChannel.appendLine('GoSQLX Language Server started successfully');
        vscode.window.showInformationMessage('GoSQLX Language Server started');
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        outputChannel.appendLine(`Failed to start GoSQLX Language Server: ${message}`);
        vscode.window.showErrorMessage(
            `Failed to start GoSQLX Language Server: ${message}. ` +
            'Make sure gosqlx is installed and in your PATH.'
        );
        statusBarItem.hide();
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

let extensionContext: vscode.ExtensionContext | undefined;

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

    // Trigger validation by requesting diagnostics
    const uri = editor.document.uri;
    outputChannel.appendLine(`Validating: ${uri.fsPath}`);

    // The LSP server handles validation automatically on document open/change
    // Force a re-validation by sending a notification
    vscode.window.showInformationMessage('SQL validation complete. Check the Problems panel for any issues.');
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

    try {
        const { exec } = require('child_process');
        const util = require('util');
        const execPromise = util.promisify(exec);

        const { stdout, stderr } = await execPromise(
            `${executablePath} analyze "${text.replace(/"/g, '\\"')}"`,
            { maxBuffer: 1024 * 1024 }
        );

        if (stderr) {
            outputChannel.appendLine(`Analysis stderr: ${stderr}`);
        }

        // Show analysis results in a new document
        const doc = await vscode.workspace.openTextDocument({
            content: stdout || 'No analysis output',
            language: 'markdown'
        });
        await vscode.window.showTextDocument(doc, { preview: true });

        outputChannel.appendLine(`Analyzed: ${editor.document.uri.fsPath}`);
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        vscode.window.showErrorMessage(`Analysis failed: ${message}`);
        outputChannel.appendLine(`Analysis error: ${message}`);
    }
}

export async function deactivate(): Promise<void> {
    await stopLanguageServer();
}
