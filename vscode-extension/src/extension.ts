import * as vscode from 'vscode';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CygnusClient } from './client';
import { ImportScanner } from './scanner';
import { StatusBarManager } from './statusbar';
import { InlineDecorator } from './decorator';

let client: CygnusClient;
let scanner: ImportScanner;
let statusBar: StatusBarManager;
let decorator: InlineDecorator;

/**
 * Resolve the API key with the same precedence chain as the `cygnus` CLI:
 *   1. VS Code setting `cygnus.apiKey` (explicit override)
 *   2. `CYGNUS_API_KEY` environment variable
 *   3. `~/.cygnus/config.json` `api_key` field — written by `cygnus auth login`
 *   4. empty (free-tier mode)
 *
 * Returning the same key the CLI uses lets a user run `cygnus auth login`
 * once and the extension picks up the session automatically — no manual
 * paste into VS Code settings required. Exported for the e2e test suite.
 */
export function resolveApiKey(): string {
    const fromSetting = vscode.workspace
        .getConfiguration('cygnus')
        .get<string>('apiKey');
    if (fromSetting) {
        return fromSetting;
    }
    const fromEnv = process.env.CYGNUS_API_KEY;
    if (fromEnv) {
        return fromEnv;
    }
    try {
        const cygnusHome = process.env.CYGNUS_HOME
            ? process.env.CYGNUS_HOME
            : path.join(os.homedir(), '.cygnus');
        const configPath = path.join(cygnusHome, 'config.json');
        if (fs.existsSync(configPath)) {
            const raw = fs.readFileSync(configPath, 'utf8');
            const config = JSON.parse(raw) as { api_key?: string };
            if (config.api_key) {
                return config.api_key;
            }
        }
    } catch {
        // Swallow — fall through to free-tier mode.
    }
    return '';
}

export function activate(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('cygnus');
    const apiKey = resolveApiKey();
    const registryUrl = config.get<string>('registryUrl') || 'https://cygnus.blackswan-software.ai';

    client = new CygnusClient(registryUrl, apiKey);
    scanner = new ImportScanner();
    statusBar = new StatusBarManager();
    decorator = new InlineDecorator();

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('cygnus.verify', () => verifyCurrentFile()),
        vscode.commands.registerCommand('cygnus.verifyLibrary', () => verifyLibraryPrompt()),
        vscode.commands.registerCommand('cygnus.request', () => requestVerification()),
    );

    // Auto-verify on file open/save
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && config.get<boolean>('showInlineStatus')) {
                verifyCurrentFile();
            }
        }),
        vscode.workspace.onDidSaveTextDocument(doc => {
            if (config.get<boolean>('showInlineStatus')) {
                verifyCurrentFile();
            }
        }),
    );

    // Initial verification
    if (vscode.window.activeTextEditor) {
        verifyCurrentFile();
    }

    statusBar.show(context);
}

async function verifyCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const doc = editor.document;
    const ecosystem = scanner.detectEcosystem(doc.languageId);
    if (!ecosystem) return;

    const imports = scanner.extractImports(doc.getText(), ecosystem);
    if (imports.length === 0) return;

    // Batch lookup
    const results = await client.batchVerify(ecosystem, imports);

    // Update decorations
    decorator.update(editor, doc, imports, results);

    // Update status bar
    const verified = results.filter(r => r.confidence === 'FULLY_VERIFIED').length;
    const total = results.length;
    statusBar.update(verified, total);
}

async function verifyLibraryPrompt() {
    const input = await vscode.window.showInputBox({
        prompt: 'Library name to verify',
        placeHolder: 'e.g. requests, lodash, gin',
    });
    if (!input) return;

    const ecosystem = await vscode.window.showQuickPick(
        ['python', 'node', 'go', 'rust', 'java', 'csharp', 'ruby', 'php', 'kotlin', 'scala', 'swift', 'dart', 'elixir', 'cpp'],
        { placeHolder: 'Select ecosystem' }
    );
    if (!ecosystem) return;

    const result = await client.verify(ecosystem, input);
    if (result.confidence === 'FULLY_VERIFIED') {
        vscode.window.showInformationMessage(
            `✓ ${input}: FULLY_VERIFIED (${result.tokenCount} functions verified)`
        );
    } else if (result.confidence) {
        vscode.window.showWarningMessage(
            `⚠ ${input}: ${result.confidence}`
        );
    } else {
        vscode.window.showErrorMessage(`✗ ${input}: not in Cygnus registry`);
    }
}

async function requestVerification() {
    const input = await vscode.window.showInputBox({
        prompt: 'Library name to request verification for',
        placeHolder: 'e.g. requests, lodash, gin',
    });
    if (!input) return;

    const ecosystem = await vscode.window.showQuickPick(
        ['python', 'node', 'go', 'rust', 'java', 'csharp', 'ruby', 'php', 'kotlin', 'scala', 'swift', 'dart', 'elixir', 'cpp'],
        { placeHolder: 'Select ecosystem' }
    );
    if (!ecosystem) return;

    const result = await client.verify(ecosystem, input);
    if (result.confidence === 'FULLY_VERIFIED') {
        vscode.window.showInformationMessage(
            `✓ ${input}: already FULLY_VERIFIED`
        );
    } else {
        vscode.window.showInformationMessage(
            `⟳ ${input}: verification requested — typically completes within hours`
        );
    }
}

export function deactivate() {
    statusBar.dispose();
}
