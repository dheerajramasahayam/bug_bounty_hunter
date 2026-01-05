
import axios from 'axios';
import * as cheerio from 'cheerio';
import { logger } from '../core/logger.js';
import { ffuf } from '../tools/ffuf.js';

export interface ParameterResult {
    url: string;
    method: string;
    params: string[];
    source: 'reflection' | 'wordlist' | 'js_analysis';
}

class ParameterScanner {

    // Common parameter names that often lead to XSS, SQLi, SSRF
    private commonParams = [
        'id', 'user', 'user_id', 'userid', 'token', 'auth', 'key', 'q', 'query', 'search',
        'redirect', 'url', 'file', 'path', 'page', 'cmd', 'exec', 'command', 'dir',
        'debug', 'test', 'admin', 'role'
    ];

    async scanEndpoint(url: string): Promise<ParameterResult[]> {
        const results: ParameterResult[] = [];
        logger.info(`Scanning for hidden parameters on ${url}`);

        // 1. Passive JS Analysis
        // (This would ideally use AST parsing, but for now regex is a quick win)
        try {
            const httpsAgent = new (await import('https')).Agent({ rejectUnauthorized: false });
            const response = await axios.get(url, {
                httpsAgent,
                timeout: 10000,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Connection': 'close'
                }
            });
            const html = response.data;
            const $ = cheerio.load(html);

            // Extract from scripts
            $('script').each((i, el) => {
                const scriptContent = $(el).html();
                if (scriptContent) {
                    const jsParams = this.extractParamsFromJs(scriptContent);
                    if (jsParams.length > 0) {
                        results.push({
                            url,
                            method: 'GET',
                            params: jsParams,
                            source: 'js_analysis'
                        });
                    }
                }
            });
        } catch (e) {
            // Only warn for significant errors, ignore simple timeouts/404s to reduce noise
            const err = e as any;
            if (err.response && err.response.status !== 404) {
                logger.debug(`Failed to fetch ${url} for parameter scan: ${err.message}`);
            }
        }

        // 2. Active Brute-forcing (if ffuf is available)
        // We construct a fuzzing URL: https://example.com/page?FUZZ=1
        if (await ffuf.isAvailable()) {
            // We need a custom wordlist for parameters. 
            // For now, we'll assume we have a 'burp-parameter-names.txt' or similar standard list.
            // If not, we can fail gracefully or use the commonParams list to generate a temp file.

            // TODO: In a real scenario, implementing a full ffuf run for params is heavy. 
            // We might want to use a lighter specialized tool or just check the top 20 manually.

            // Checking top 20 manually for now (Lightweight Active Mode)
            const foundParams = await this.checkCommonParams(url);
            if (foundParams.length > 0) {
                results.push({
                    url,
                    method: 'GET',
                    params: foundParams,
                    source: 'wordlist'
                });
            }
        }

        return results;
    }

    private extractParamsFromJs(js: string): string[] {
        const params = new Set<string>();
        // Regex to find "key": "value" or key: "value" or URLSearchParams('key')
        const regexes = [
            /['"]?([a-zA-Z0-9_]+)['"]?\s*:\s*['"][^'"]*['"]/g, // JSON-like object keys
            /URLSearchParams\(['"]([a-zA-Z0-9_]+)['"]\)/g,    // URLSearchParams
            /[?&]([a-zA-Z0-9_]+)=/g,                            // Query strings in code
        ];

        for (const regex of regexes) {
            let match;
            while ((match = regex.exec(js)) !== null) {
                if (match[1] && match[1].length > 1 && !this.isReservedWord(match[1])) {
                    params.add(match[1]);
                }
            }
        }
        return Array.from(params);
    }

    private isReservedWord(word: string): boolean {
        const reserved = ['var', 'let', 'const', 'function', 'return', 'if', 'else', 'true', 'false', 'null', 'undefined'];
        return reserved.includes(word);
    }

    private async checkCommonParams(url: string): Promise<string[]> {
        const found: string[] = [];

        // Simple 'refelction' check - does changing the param change the page?
        // This is naive but a start.
        // Ideally we compare content length or hash.

        try {
            const httpsAgent = new (await import('https')).Agent({ rejectUnauthorized: false });
            const axiosConfig = {
                httpsAgent,
                timeout: 5000,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
            };

            const original = await axios.get(url, axiosConfig);
            const originalLen = JSON.stringify(original.data).length;

            for (const param of this.commonParams) {
                try {
                    // Inject a random value
                    const testVal = 'BugHunter' + Math.floor(Math.random() * 1000);
                    const separator = url.includes('?') ? '&' : '?';
                    const testUrl = `${url}${separator}${param}=${testVal}`;

                    const res = await axios.get(testUrl, axiosConfig);
                    const resLen = JSON.stringify(res.data).length;

                    // If length matches exactly, it's likely ignored.
                    // If diff, it might be reflected or processed.
                    // We also check if the value 'BugHunter' is reflected in text.

                    if (JSON.stringify(res.data).includes(testVal)) {
                        logger.success(`Parameter reflected: ${param} at ${url}`);
                        found.push(param);
                    } else if (Math.abs(resLen - originalLen) > 50) {
                        // Significant length difference (heuristic)
                        logger.info(`Parameter affects response: ${param} at ${url}`);
                        found.push(param);
                    }

                } catch {
                    // Ignore request errors
                }
            }
        } catch {
            // Ignore original fetch error
        }

        return found;
    }
}

export const parameterScanner = new ParameterScanner();
