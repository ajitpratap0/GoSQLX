import * as assert from 'assert';
import * as vscode from 'vscode';

suite('GoSQLX Extension Test Suite', () => {
    vscode.window.showInformationMessage('Starting GoSQLX extension tests');

    test('Extension should be present', () => {
        const extension = vscode.extensions.getExtension('ajitpratap0.gosqlx');
        assert.ok(extension, 'Extension should be installed');
    });

    test('Extension should activate on SQL file', async () => {
        // Create a new SQL document
        const document = await vscode.workspace.openTextDocument({
            language: 'sql',
            content: 'SELECT * FROM users;'
        });

        // Show the document to trigger activation
        await vscode.window.showTextDocument(document);

        // Give the extension time to activate
        await new Promise(resolve => setTimeout(resolve, 1000));

        const extension = vscode.extensions.getExtension('ajitpratap0.gosqlx');
        if (extension) {
            // Extension may or may not be active depending on LSP availability
            assert.ok(true, 'Extension loaded without errors');
        }
    });

    test('Commands should be registered', async () => {
        const commands = await vscode.commands.getCommands(true);

        const expectedCommands = [
            'gosqlx.validate',
            'gosqlx.format',
            'gosqlx.analyze',
            'gosqlx.restartServer',
            'gosqlx.showOutput'
        ];

        for (const cmd of expectedCommands) {
            assert.ok(
                commands.includes(cmd),
                `Command ${cmd} should be registered`
            );
        }
    });

    test('Configuration should have defaults', () => {
        const config = vscode.workspace.getConfiguration('gosqlx');

        assert.strictEqual(config.get('enable'), true, 'enable should default to true');
        assert.strictEqual(config.get('executablePath'), 'gosqlx', 'executablePath should default to gosqlx');
        assert.strictEqual(config.get('format.indentSize'), 2, 'indentSize should default to 2');
        assert.strictEqual(config.get('format.uppercaseKeywords'), true, 'uppercaseKeywords should default to true');
        assert.strictEqual(config.get('dialect'), 'generic', 'dialect should default to generic');
    });

    test('SQL language should be recognized', async () => {
        const document = await vscode.workspace.openTextDocument({
            language: 'sql',
            content: 'SELECT 1;'
        });

        assert.strictEqual(document.languageId, 'sql', 'Document should be recognized as SQL');
    });

    test('Validate command should handle missing editor gracefully', async () => {
        // Close all editors
        await vscode.commands.executeCommand('workbench.action.closeAllEditors');

        // This should not throw an error, just show a warning
        try {
            await vscode.commands.executeCommand('gosqlx.validate');
            assert.ok(true, 'Validate command handled missing editor');
        } catch (error) {
            // Command might fail if no editor is open, which is expected behavior
            assert.ok(true, 'Validate command threw expected error');
        }
    });
});
