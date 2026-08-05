import * as https from 'https';
import * as http from 'http';

export interface VerifyResult {
    library: string;
    version: string;
    confidence: string;
    tokenCount: number;
    signed: boolean;
}

export class CygnusClient {
    private baseUrl: string;
    private apiKey: string;

    constructor(baseUrl: string, apiKey: string) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.apiKey = apiKey;
    }

    async verify(ecosystem: string, library: string): Promise<VerifyResult> {
        const data = await this.get(`/versions/${ecosystem}/${library}/latest`);
        if (!data || !data.version) {
            this.triggerCompilation(ecosystem, library);
            return { library, version: '', confidence: '', tokenCount: 0, signed: false };
        }

        return {
            library,
            version: data.version,
            confidence: data.confidence || 'COMPILED',
            tokenCount: data.function_count || 0,
            signed: data.signed || false,
        };
    }

    /**
     * Auto-trigger compilation for missing libraries.
     * When 23/25 deps are verified and 2 are missing, we don't just show
     * "not found" — we fix it by queuing compilation immediately.
     */
    private async triggerCompilation(ecosystem: string, library: string) {
        // Queue via compiler endpoint (priority=1 for on-demand)
        await this.post('/compile/queue', {
            ecosystem,
            library,
            version: 'latest',
            priority: 1,
            source: 'ide-auto',
        });
    }

    async batchVerify(ecosystem: string, libraries: string[]): Promise<VerifyResult[]> {
        // TODO: use batch endpoint when available
        // For now, parallel individual lookups (limited to 10 concurrent)
        const results: VerifyResult[] = [];
        const chunks = [];
        for (let i = 0; i < libraries.length; i += 10) {
            chunks.push(libraries.slice(i, i + 10));
        }
        for (const chunk of chunks) {
            const batch = await Promise.all(
                chunk.map(lib => this.verify(ecosystem, lib))
            );
            results.push(...batch);
        }
        return results;
    }

    private async get(path: string): Promise<any> {
        return this.request('GET', path);
    }

    private async post(path: string, body: any): Promise<any> {
        return this.request('POST', path, body);
    }

    private request(method: string, path: string, body?: any): Promise<any> {
        return new Promise((resolve) => {
            const url = new URL(path, this.baseUrl);
            const isHttps = url.protocol === 'https:';
            const options = {
                hostname: url.hostname,
                port: url.port || (isHttps ? 443 : 80),
                path: url.pathname + url.search,
                method,
                headers: {
                    'X-Api-Key': this.apiKey,
                    'Content-Type': 'application/json',
                },
                timeout: 8000,
            };

            const req = (isHttps ? https : http).request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch {
                        resolve(null);
                    }
                });
            });

            req.on('error', () => resolve(null));
            req.on('timeout', () => { req.destroy(); resolve(null); });

            if (body) {
                req.write(JSON.stringify(body));
            }
            req.end();
        });
    }
}
