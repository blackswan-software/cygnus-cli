import * as vscode from 'vscode';

export class StatusBarManager {
    private item: vscode.StatusBarItem;

    constructor() {
        this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
        this.item.command = 'cygnus.verify';
    }

    show(context: vscode.ExtensionContext) {
        this.item.text = '$(shield) Cygnus';
        this.item.tooltip = 'Click to verify dependencies';
        this.item.show();
        context.subscriptions.push(this.item);
    }

    update(verified: number, total: number, cveCount: number = 0) {
        if (total === 0) {
            this.item.text = '$(shield) Cygnus';
            this.item.tooltip = 'No imports detected';
            this.item.backgroundColor = undefined;
            return;
        }

        if (cveCount > 0) {
            this.item.text = `$(shield) Cygnus: ${verified}/${total} · $(warning) ${cveCount} CVE${cveCount !== 1 ? 's' : ''}`;
            this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            this.item.tooltip = `${verified}/${total} verified · ${cveCount} CVE${cveCount !== 1 ? 's' : ''} found — click to verify`;
        } else if (verified === total) {
            this.item.text = `$(shield) Cygnus: ${verified}/${total} ✓`;
            this.item.backgroundColor = undefined;
            this.item.tooltip = `All ${total} dependencies verified · 0 CVEs`;
        } else {
            const missing = total - verified;
            this.item.text = `$(shield) Cygnus: ${verified}/${total}`;
            this.item.tooltip = `${missing} unverified — click to trigger compilation`;
            const pct = Math.round(verified / total * 100);
            if (pct < 70) {
                this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            } else {
                this.item.backgroundColor = undefined;
            }
        }
    }

    dispose() {
        this.item.dispose();
    }
}
