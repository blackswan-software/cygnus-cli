import * as https from 'https';
import * as http from 'http';

export interface CveInfo {
    count: number;
    advisories: string[];
    riskFlags: string[];
    depsDevUrl: string;
}

export interface VerifyResult {
    library: string;
    version: string;
    ecosystem: string;
    confidence: string;
    grade: string;
    functionCount: number;
    signed: boolean;
    signatureAlgorithm: string;
    license: string;
    cves: CveInfo;
    sbomUrl: string;
    verifyUrl: string;
}

const EMPTY_CVES: CveInfo = { count: 0, advisories: [], riskFlags: [], depsDevUrl: '' };

export class CygnusClient {
    private baseUrl: string;
    private apiKey: string;

    constructor(baseUrl: string, apiKey: string) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.apiKey = apiKey;
    }

    async verify(ecosystem: string, library: string): Promise<VerifyResult> {
        const data = await this.get(`/lookup/${ecosystem}/${library}`);
        if (!data || !data.version || data.detail) {
            this.triggerCompilation(ecosystem, library);
            return {
                library, version: '', ecosystem, confidence: '', grade: '',
                functionCount: 0, signed: false, signatureAlgorithm: '',
                license: '', cves: { ...EMPTY_CVES }, sbomUrl: '', verifyUrl: '',
            };
        }

        return {
            library,
            version: data.version,
            ecosystem: data.ecosystem || ecosystem,
            confidence: data.confidence || 'COMPILED',
            grade: data.grade || '',
            functionCount: data.tokens || 0,
            signed: data.signed || false,
            signatureAlgorithm: data.signature?.algorithm || '',
            license: data.license || '',
            cves: {
                count: data.cves?.cve_count || 0,
                advisories: data.cves?.advisories || [],
                riskFlags: data.cves?.risk_flags || [],
                depsDevUrl: data.cves?.deps_dev_url || '',
            },
            sbomUrl: data.sbom_url || '',
            verifyUrl: data.verify_url || '',
        };
    }

    private async triggerCompilation(ecosystem: string, library: string) {
        await this.post('/compile/queue', {
            ecosystem,
            library,
            version: 'latest',
            priority: 1,
            source: 'ide-auto',
        });
    }

    async batchVerify(ecosystem: string, libraries: string[]): Promise<VerifyResult[]> {
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
