import * as vscode from 'vscode';
import { VerifyResult } from './client';

const VERIFIED_DECORATION = vscode.window.createTextEditorDecorationType({
    after: {
        contentText: ' ✓ verified',
        color: '#4ade80',
        fontStyle: 'italic',
        fontWeight: 'normal',
        margin: '0 0 0 12px',
    },
});

const PARTIAL_DECORATION = vscode.window.createTextEditorDecorationType({
    after: {
        contentText: ' ⚠ partial',
        color: '#fb923c',
        fontStyle: 'italic',
        fontWeight: 'normal',
        margin: '0 0 0 12px',
    },
});

const MISSING_DECORATION = vscode.window.createTextEditorDecorationType({
    after: {
        contentText: ' ✗ unverified — queuing...',
        color: '#f87171',
        fontStyle: 'italic',
        fontWeight: 'normal',
        margin: '0 0 0 12px',
    },
});

export class InlineDecorator {
    update(
        editor: vscode.TextEditor,
        doc: vscode.TextDocument,
        imports: string[],
        results: VerifyResult[],
    ) {
        const verified: vscode.DecorationOptions[] = [];
        const partial: vscode.DecorationOptions[] = [];
        const missing: vscode.DecorationOptions[] = [];

        const text = doc.getText();
        const lines = text.split('\n');

        for (const result of results) {
            // Find the line containing this import
            const lineIdx = this.findImportLine(lines, result.library, doc.languageId);
            if (lineIdx < 0) continue;

            const line = doc.lineAt(lineIdx);
            const range = new vscode.Range(line.range.end, line.range.end);
            const hoverMsg = this.buildHover(result);

            const decoration: vscode.DecorationOptions = {
                range,
                hoverMessage: hoverMsg,
            };

            if (result.confidence === 'FULLY_VERIFIED') {
                verified.push({
                    ...decoration,
                    renderOptions: {
                        after: {
                            contentText: ` ✓ ${result.tokenCount} tokens`,
                        },
                    },
                });
            } else if (result.confidence === 'TESTS_PASS' || result.confidence === 'VERIFIED_PARTIAL') {
                partial.push(decoration);
            } else if (!result.confidence) {
                missing.push(decoration);
            }
        }

        editor.setDecorations(VERIFIED_DECORATION, verified);
        editor.setDecorations(PARTIAL_DECORATION, partial);
        editor.setDecorations(MISSING_DECORATION, missing);
    }

    private findImportLine(lines: string[], library: string, languageId: string): number {
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].toLowerCase();
            if (line.includes(library.toLowerCase()) &&
                (line.includes('import') || line.includes('require') || line.includes('using') || line.includes('use '))) {
                return i;
            }
        }
        return -1;
    }

    private buildHover(result: VerifyResult): vscode.MarkdownString {
        const md = new vscode.MarkdownString();
        md.isTrusted = true;

        if (result.confidence === 'FULLY_VERIFIED') {
            md.appendMarkdown(`**Cygnus: ✓ FULLY_VERIFIED**\n\n`);
            md.appendMarkdown(`- Library: \`${result.library}@${result.version}\`\n`);
            md.appendMarkdown(`- Tokens: ${result.tokenCount} verified functions\n`);
            md.appendMarkdown(`- Signed: ${result.signed ? 'Ed25519 ✓' : 'unsigned'}\n`);
            md.appendMarkdown(`\n[View on Cygnus](https://cygnus.blackswan-software.ai/verify/python/${result.library})`);
        } else if (!result.confidence) {
            md.appendMarkdown(`**Cygnus: ✗ Not verified**\n\n`);
            md.appendMarkdown(`\`${result.library}\` is not in the Cygnus registry.\n\n`);
            md.appendMarkdown(`[Trigger compilation](command:cygnus.verifyLibrary) — takes ~5 minutes.`);
        } else {
            md.appendMarkdown(`**Cygnus: ⚠ ${result.confidence}**\n\n`);
            md.appendMarkdown(`- Library: \`${result.library}@${result.version}\`\n`);
            md.appendMarkdown(`- Tokens: ${result.tokenCount} functions\n`);
            md.appendMarkdown(`- Not all functions verified yet.`);
        }

        return md;
    }
}
