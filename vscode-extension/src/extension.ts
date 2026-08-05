import * as vscode from 'vscode';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CygnusClient, VerifyResult } from './client';
import { ImportScanner } from './scanner';
import { StatusBarManager } from './statusbar';
import { InlineDecorator } from './decorator';

let client: CygnusClient;
let scanner: ImportScanner;
let statusBar: StatusBarManager;
let decorator: InlineDecorator;
let diagnosticCollection: vscode.DiagnosticCollection;

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
    diagnosticCollection = vscode.languages.createDiagnosticCollection('cygnus');

    context.subscriptions.push(
        diagnosticCollection,
        vscode.commands.registerCommand('cygnus.verify', () => verifyCurrentFile()),
        vscode.commands.registerCommand('cygnus.verifyLibrary', () => verifyLibraryPrompt()),
        vscode.commands.registerCommand('cygnus.request', () => requestVerification()),
    );

    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && config.get<boolean>('showInlineStatus')) {
                verifyCurrentFile();
            }
        }),
        vscode.workspace.onDidSaveTextDocument(() => {
            if (config.get<boolean>('showInlineStatus')) {
                verifyCurrentFile();
            }
        }),
        vscode.workspace.onDidCloseTextDocument(doc => {
            diagnosticCollection.delete(doc.uri);
        }),
    );

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
    if (!ecosystem) {
        diagnosticCollection.delete(doc.uri);
        return;
    }

    const imports = scanner.extractImports(doc.getText(), ecosystem);
    if (imports.length === 0) {
        diagnosticCollection.delete(doc.uri);
        return;
    }

    const results = await client.batchVerify(ecosystem, imports);

    decorator.update(editor, doc, imports, results);
    updateDiagnostics(doc, results);

    const verified = results.filter(r => r.confidence === 'FULLY_VERIFIED').length;
    const total = results.length;
    const cveCount = results.reduce((sum, r) => sum + r.cves.count, 0);
    statusBar.update(verified, total, cveCount);
}

function updateDiagnostics(doc: vscode.TextDocument, results: VerifyResult[]) {
    const diagnostics: vscode.Diagnostic[] = [];
    const lines = doc.getText().split('\n');

    for (const result of results) {
        const lineIdx = decorator.findImportLine(lines, result.library, doc.languageId);
        if (lineIdx < 0) continue;

        const line = doc.lineAt(lineIdx);

        if (result.cves.count > 0) {
            const cveList = result.cves.advisories.slice(0, 3).join(', ');
            const extra = result.cves.count > 3 ? ` (+${result.cves.count - 3} more)` : '';
            const diag = new vscode.Diagnostic(
                line.range,
                `${result.library}@${result.version}: ${result.cves.count} CVE${result.cves.count !== 1 ? 's' : ''} — ${cveList}${extra}`,
                result.cves.count >= 5
                    ? vscode.DiagnosticSeverity.Error
                    : vscode.DiagnosticSeverity.Warning,
            );
            diag.source = 'Cygnus';
            diag.code = 'cve';
            diagnostics.push(diag);
        }

        if (!result.confidence) {
            const diag = new vscode.Diagnostic(
                line.range,
                `${result.library}: not in Cygnus registry — verification queued`,
                vscode.DiagnosticSeverity.Information,
            );
            diag.source = 'Cygnus';
            diag.code = 'unverified';
            diagnostics.push(diag);
        }

        if (result.grade === 'D' || result.grade === 'F' || result.grade === 'BLOCKED') {
            const diag = new vscode.Diagnostic(
                line.range,
                `${result.library}@${result.version}: Grade ${result.grade} — low verification confidence`,
                vscode.DiagnosticSeverity.Warning,
            );
            diag.source = 'Cygnus';
            diag.code = 'low-grade';
            diagnostics.push(diag);
        }
    }

    diagnosticCollection.set(doc.uri, diagnostics);
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
        const cveNote = result.cves.count > 0
            ? ` · ⚠ ${result.cves.count} CVEs`
            : ' · 0 CVEs';
        vscode.window.showInformationMessage(
            `✓ ${input}: Grade ${result.grade} — ${result.functionCount} functions verified${cveNote}`
        );
    } else if (result.confidence) {
        vscode.window.showWarningMessage(
            `⚠ ${input}: ${result.confidence} (Grade ${result.grade})`
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
