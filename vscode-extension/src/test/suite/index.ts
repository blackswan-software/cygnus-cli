/**
 * Mocha entry that @vscode/test-electron invokes inside the Extension Host.
 * Discovers *.test.js files in this directory and runs them.
 */
import * as path from 'path';
import Mocha from 'mocha';
import { glob } from 'glob';

export function run(): Promise<void> {
    const mocha = new Mocha({
        ui: 'tdd',
        color: true,
        timeout: 60_000,
    });
    const testsRoot = path.resolve(__dirname);
    return new Promise((resolve, reject) => {
        glob('**/*.test.js', { cwd: testsRoot })
            .then((files) => {
                files.forEach((f) => mocha.addFile(path.resolve(testsRoot, f)));
                try {
                    mocha.run((failures) => {
                        if (failures > 0) {
                            reject(new Error(`${failures} test(s) failed.`));
                        } else {
                            resolve();
                        }
                    });
                } catch (err) {
                    reject(err);
                }
            })
            .catch((err) => reject(err));
    });
}
