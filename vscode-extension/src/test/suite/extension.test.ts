/**
 * E2E tests for the Cygnus VS Code extension.
 *
 * These run inside an isolated VS Code Extension Host launched by
 * @vscode/test-electron. The four tests below pin the public contract
 * the extension promises:
 *
 *   1. Extension activates without errors
 *   2. Three `cygnus.*` commands are registered with VS Code
 *   3. Configuration properties (apiKey, registryUrl, etc.) exist on the
 *      `cygnus` namespace
 *   4. The auth-key resolver picks up `~/.cygnus/config.json` `api_key`
 *      when neither the VS Code setting nor `CYGNUS_API_KEY` is set —
 *      the seamless-CLI-handoff promise to users
 */
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';

import { resolveApiKey } from '../../extension';

const EXTENSION_ID = 'blackswan-software.cygnus';
const EXPECTED_COMMANDS = [
    'cygnus.verify',
    'cygnus.verifyLibrary',
    'cygnus.request',
];

suite('cygnus extension — e2e', () => {
    test('Extension activates without throwing', async () => {
        const ext = vscode.extensions.getExtension(EXTENSION_ID);
        assert.ok(ext, `extension ${EXTENSION_ID} not found in VS Code`);
        await ext.activate();
        assert.strictEqual(ext.isActive, true, 'extension failed to activate');
    });

    test('All three cygnus.* commands are registered', async () => {
        const ext = vscode.extensions.getExtension(EXTENSION_ID);
        assert.ok(ext);
        await ext.activate();
        const allCommands = await vscode.commands.getCommands(true);
        for (const cmd of EXPECTED_COMMANDS) {
            assert.ok(
                allCommands.includes(cmd),
                `expected command ${cmd} to be registered (have ${allCommands
                    .filter((c) => c.startsWith('cygnus.'))
                    .join(', ')})`,
            );
        }
    });

    test('Configuration namespace `cygnus` exposes apiKey/registryUrl/showInlineStatus', async () => {
        const config = vscode.workspace.getConfiguration('cygnus');
        // `inspect` returns undefined if the key isn't contributed at all.
        for (const key of ['apiKey', 'registryUrl', 'showInlineStatus', 'showStatusBar']) {
            const info = config.inspect(key);
            assert.ok(
                info,
                `cygnus.${key} not contributed by package.json (extension would silently lose user-facing controls)`,
            );
        }
        // registryUrl must default to the production registry — the seamless
        // free-tier promise depends on the default landing on a real host.
        const defaultUrl = config.inspect<string>('registryUrl')?.defaultValue;
        assert.ok(
            defaultUrl && defaultUrl.startsWith('https://'),
            `cygnus.registryUrl default must be an HTTPS URL; got ${defaultUrl}`,
        );
    });

    test('resolveApiKey() falls through to ~/.cygnus/config.json when settings + env are empty', () => {
        // Build an isolated cygnus home so we don't touch the user's real
        // config during the test.
        const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'cygnus-e2e-'));
        const configPath = path.join(tmpHome, 'config.json');
        fs.writeFileSync(
            configPath,
            JSON.stringify({ api_key: 'cyg_test_e2e_marker_token' }),
            { mode: 0o600 },
        );

        const origHome = process.env.CYGNUS_HOME;
        const origKey = process.env.CYGNUS_API_KEY;
        process.env.CYGNUS_HOME = tmpHome;
        delete process.env.CYGNUS_API_KEY;
        try {
            const resolved = resolveApiKey();
            assert.strictEqual(
                resolved,
                'cyg_test_e2e_marker_token',
                'resolveApiKey() must read api_key from $CYGNUS_HOME/config.json — that is how users on cygnus auth login get seamless extension auth',
            );
        } finally {
            // Restore env so later tests aren't surprised.
            if (origHome === undefined) {
                delete process.env.CYGNUS_HOME;
            } else {
                process.env.CYGNUS_HOME = origHome;
            }
            if (origKey !== undefined) {
                process.env.CYGNUS_API_KEY = origKey;
            }
            fs.rmSync(tmpHome, { recursive: true, force: true });
        }
    });
});
