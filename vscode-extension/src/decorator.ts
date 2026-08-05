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

const CVE_DECORATION = vscode.window.createTextEditorDecorationType({
    after: {
        contentText: ' ⚠ CVEs found',
        color: '#f87171',
        fontStyle: 'italic',
        fontWeight: 'bold',
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
        const cveWarnings: vscode.DecorationOptions[] = [];

        const lines = doc.getText().split('\n');

        for (const result of results) {
            const lineIdx = this.findImportLine(lines, result.library, doc.languageId);
            if (lineIdx < 0) continue;

            const line = doc.lineAt(lineIdx);
            const range = new vscode.Range(line.range.end, line.range.end);
            const hoverMsg = this.buildHover(result);

            const decoration: vscode.DecorationOptions = {
                range,
                hoverMessage: hoverMsg,
            };

            if (!result.confidence) {
                missing.push(decoration);
            } else if (result.cves.count > 0) {
                cveWarnings.push({
                    ...decoration,
                    renderOptions: {
                        after: {
                            contentText: ` ⚠ ${result.grade || '?'} · ${result.cves.count} CVE${result.cves.count !== 1 ? 's' : ''}`,
                            color: '#f87171',
                            fontStyle: 'italic',
                            fontWeight: 'bold',
                            margin: '0 0 0 12px',
                        },
                    },
                });
            } else if (result.confidence === 'FULLY_VERIFIED') {
                verified.push({
                    ...decoration,
                    renderOptions: {
                        after: {
                            contentText: ` ✓ ${result.grade || 'A'} · ${result.functionCount} functions`,
                            color: '#4ade80',
                            fontStyle: 'italic',
                            margin: '0 0 0 12px',
                        },
                    },
                });
            } else if (result.confidence === 'TESTS_PASS' || result.confidence === 'VERIFIED_PARTIAL') {
                partial.push(decoration);
            }
        }

        editor.setDecorations(VERIFIED_DECORATION, verified);
        editor.setDecorations(PARTIAL_DECORATION, partial);
        editor.setDecorations(MISSING_DECORATION, missing);
        editor.setDecorations(CVE_DECORATION, cveWarnings);
    }

    findImportLine(lines: string[], library: string, languageId: string): number {
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

        if (!result.confidence) {
            md.appendMarkdown(`**Cygnus: ✗ Not verified**\n\n`);
            md.appendMarkdown(`\`${result.library}\` is not in the Cygnus registry.\n\n`);
            md.appendMarkdown(`[Request verification](command:cygnus.request) — typically completes within hours.`);
            return md;
        }

        const icon = this.gradeIcon(result.grade);
        md.appendMarkdown(`**Cygnus: ${icon} Grade ${result.grade} — ${result.confidence}**\n\n`);
        md.appendMarkdown(`- Library: \`${result.library}@${result.version}\`\n`);
        md.appendMarkdown(`- Functions: ${result.functionCount} verified\n`);

        if (result.signed) {
            md.appendMarkdown(`- Signed: ${result.signatureAlgorithm || 'Ed25519'} ✓\n`);
        } else {
            md.appendMarkdown(`- Signed: unsigned\n`);
        }

        if (result.license) {
            md.appendMarkdown(`- License: ${result.license}\n`);
        }

        if (result.cves.count > 0) {
            md.appendMarkdown(`\n---\n\n`);
            md.appendMarkdown(`**⚠ ${result.cves.count} CVE${result.cves.count !== 1 ? 's' : ''} found:**\n\n`);
            for (const cve of result.cves.advisories.slice(0, 5)) {
                md.appendMarkdown(`- \`${cve}\`\n`);
            }
            if (result.cves.advisories.length > 5) {
                md.appendMarkdown(`- _...and ${result.cves.advisories.length - 5} more_\n`);
            }
            if (result.cves.riskFlags.length > 0) {
                md.appendMarkdown(`\nRisk: ${result.cves.riskFlags.join(', ')}\n`);
            }
            if (result.cves.depsDevUrl) {
                md.appendMarkdown(`\n[View on deps.dev](${result.cves.depsDevUrl})\n`);
            }
        } else {
            md.appendMarkdown(`- CVEs: 0 known ✓\n`);
        }

        return md;
    }

    private gradeIcon(grade: string): string {
        switch (grade) {
            case 'A': return '✓';
            case 'B': return '✓';
            case 'C': return '⚠';
            case 'D': return '⚠';
            case 'F': return '✗';
            case 'BLOCKED': return '🚫';
            default: return '?';
        }
    }
}
