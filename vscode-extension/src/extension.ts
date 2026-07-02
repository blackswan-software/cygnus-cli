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
        vscode.commands.registerCommand('cygnus.showTokens', () => showTokens()),
        vscode.commands.registerCommand('cygnus.compose', () => composeTokens()),
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
            `✓ ${input}: FULLY_VERIFIED (${result.tokenCount} tokens)`
        );
    } else if (result.confidence) {
        vscode.window.showWarningMessage(
            `⚠ ${input}: ${result.confidence} (${result.tokenCount} tokens)`
        );
    } else {
        vscode.window.showErrorMessage(`✗ ${input}: not in Cygnus registry`);
    }
}

async function showTokens() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const word = editor.document.getText(editor.selection).trim();
    if (!word) {
        vscode.window.showInformationMessage('Select a function name first');
        return;
    }

    const ecosystem = scanner.detectEcosystem(editor.document.languageId);
    if (!ecosystem) return;

    // Extract library from the word context
    const tokens = await client.lookupFunction(ecosystem, word);
    if (tokens) {
        const panel = vscode.window.createWebviewPanel(
            'cygnusTokens', `Cygnus: ${word}`,
            vscode.ViewColumn.Beside, {}
        );
        panel.webview.html = formatTokenHtml(tokens);
    }
}

async function composeTokens() {
    const task = await vscode.window.showInputBox({
        prompt: 'Describe what you want to build',
        placeHolder: 'e.g. flask API with auth and PostgreSQL',
    });
    if (!task) return;

    const result = await client.compose(task);
    const panel = vscode.window.createWebviewPanel(
        'cygnusCompose', `Cygnus: ${task}`,
        vscode.ViewColumn.Beside, {}
    );
    panel.webview.html = formatComposeHtml(result);
}

function formatTokenHtml(token: any): string {
    return `<html><body style="font-family:monospace;padding:16px;background:#1e1e1e;color:#d4d4d4">
        <h2 style="color:#4ec9b0">${token.function}</h2>
        <p><strong>Signature:</strong> ${token.signature}</p>
        <p><strong>Confidence:</strong> <span style="color:#4ade80">${token.confidence}</span></p>
        <p><strong>Docstring:</strong> ${token.docstring || 'none'}</p>
    </body></html>`;
}

function formatComposeHtml(result: any): string {
    const libs = (result.libraries || []).map((l: any) =>
        `<div style="margin:8px 0;padding:8px;border-left:3px solid #4ec9b0">
            <strong>${l.library}</strong> (${l.ecosystem}) — ${l.available_tokens} tokens
            <div style="color:#888;font-size:12px">${(l.matched_functions || []).join(', ')}</div>
        </div>`
    ).join('');
    return `<html><body style="font-family:monospace;padding:16px;background:#1e1e1e;color:#d4d4d4">
        <h2 style="color:#4ec9b0">Token Composition</h2>
        <p style="color:#888">Task: ${result.task}</p>
        ${libs}
    </body></html>`;
}

export function deactivate() {
    statusBar.dispose();
}
