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

    update(verified: number, total: number) {
        if (total === 0) {
            this.item.text = '$(shield) Cygnus';
            this.item.tooltip = 'No imports detected';
            return;
        }

        const pct = Math.round(verified / total * 100);
        if (verified === total) {
            this.item.text = `$(shield) Cygnus: ${verified}/${total} ✓`;
            this.item.backgroundColor = undefined;
            this.item.tooltip = `All ${total} dependencies verified`;
        } else {
            const missing = total - verified;
            this.item.text = `$(shield) Cygnus: ${verified}/${total}`;
            this.item.tooltip = `${missing} unverified — click to trigger compilation`;
            if (pct < 70) {
                this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            }
        }
    }

    dispose() {
        this.item.dispose();
    }
}
