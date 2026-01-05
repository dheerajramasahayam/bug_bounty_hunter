import { externalTools } from './external.js';
import { logger } from '../core/logger.js';

export interface GauResult {
    url: string;
    source: string;
}

export interface WaybackResult {
    url: string;
}

class UrlGatherer {
    async isGauAvailable(): Promise<boolean> {
        return externalTools.isToolAvailable('gau');
    }

    async isWaybackAvailable(): Promise<boolean> {
        return externalTools.isToolAvailable('waybackurls');
    }

    async runGau(domain: string, options: {
        providers?: string[];
        blacklist?: string[];
        timeout?: number;
    } = {}): Promise<GauResult[]> {
        if (!await this.isGauAvailable()) {
            logger.warn('gau not available');
            return [];
        }

        const args: string[] = [
            '--subs',
            '--json',
        ];

        if (options.providers && options.providers.length > 0) {
            args.push('--providers', options.providers.join(','));
        }

        if (options.blacklist && options.blacklist.length > 0) {
            args.push('--blacklist', options.blacklist.join(','));
        }

        args.push(domain);

        logger.info(`Running gau for ${domain}...`);

        try {
            const { stdout } = await externalTools.runCommand('gau', args, {
                timeout: options.timeout || 300000,
            });

            const results: GauResult[] = [];
            const lines = stdout.split('\n').filter(line => line.trim());

            for (const line of lines) {
                try {
                    const json = JSON.parse(line);
                    results.push({
                        url: json.url || line,
                        source: json.source || 'gau',
                    });
                } catch {
                    if (line.startsWith('http')) {
                        results.push({ url: line, source: 'gau' });
                    }
                }
            }

            logger.success(`gau found ${results.length} URLs`);
            return results;
        } catch (error) {
            logger.error('gau failed', { error: String(error) });
            return [];
        }
    }

    async runWaybackurls(domain: string, options: {
        noSubs?: boolean;
        timeout?: number;
    } = {}): Promise<WaybackResult[]> {
        if (!await this.isWaybackAvailable()) {
            logger.warn('waybackurls not available');
            return [];
        }

        const args: string[] = [];

        if (options.noSubs) {
            args.push('-no-subs');
        }

        args.push(domain);

        logger.info(`Running waybackurls for ${domain}...`);

        try {
            const { stdout } = await externalTools.runCommand('waybackurls', args, {
                timeout: options.timeout || 300000,
            });

            const results: WaybackResult[] = [];
            const lines = stdout.split('\n').filter(line => line.trim());

            for (const line of lines) {
                if (line.startsWith('http')) {
                    results.push({ url: line });
                }
            }

            logger.success(`waybackurls found ${results.length} URLs`);
            return results;
        } catch (error) {
            logger.error('waybackurls failed', { error: String(error) });
            return [];
        }
    }

    async gatherAllUrls(domain: string): Promise<string[]> {
        const allUrls = new Set<string>();

        // Run both tools in parallel
        const [gauResults, waybackResults] = await Promise.all([
            this.runGau(domain).catch(() => []),
            this.runWaybackurls(domain).catch(() => []),
        ]);

        for (const result of gauResults) {
            allUrls.add(result.url);
        }

        for (const result of waybackResults) {
            allUrls.add(result.url);
        }

        logger.success(`Total unique URLs gathered: ${allUrls.size}`);
        return Array.from(allUrls);
    }

    // Extract interesting patterns from URLs
    extractInterestingUrls(urls: string[]): {
        jsFiles: string[];
        apiEndpoints: string[];
        adminPanels: string[];
        sensitiveFiles: string[];
        parameters: Map<string, Set<string>>;
    } {
        const jsFiles: string[] = [];
        const apiEndpoints: string[] = [];
        const adminPanels: string[] = [];
        const sensitiveFiles: string[] = [];
        const parameters = new Map<string, Set<string>>();

        const sensitivePatterns = [
            /\.env$/i,
            /\.git/i,
            /config\.(json|yml|yaml|xml)/i,
            /backup/i,
            /\.sql$/i,
            /\.bak$/i,
            /\.log$/i,
            /phpinfo/i,
            /web\.config/i,
        ];

        const adminPatterns = [
            /admin/i,
            /dashboard/i,
            /manager/i,
            /login/i,
            /wp-admin/i,
            /cpanel/i,
        ];

        for (const url of urls) {
            try {
                const parsed = new URL(url);

                // JS files
                if (url.endsWith('.js') || url.includes('.js?')) {
                    jsFiles.push(url);
                }

                // API endpoints
                if (/\/api\//i.test(url) || /\/v\d+\//i.test(url) || /\.json/i.test(url)) {
                    apiEndpoints.push(url);
                }

                // Admin panels
                if (adminPatterns.some(p => p.test(url))) {
                    adminPanels.push(url);
                }

                // Sensitive files
                if (sensitivePatterns.some(p => p.test(url))) {
                    sensitiveFiles.push(url);
                }

                // Extract parameters
                parsed.searchParams.forEach((_, key) => {
                    if (!parameters.has(parsed.pathname)) {
                        parameters.set(parsed.pathname, new Set());
                    }
                    parameters.get(parsed.pathname)!.add(key);
                });
            } catch {
                // Invalid URL, skip
            }
        }

        return { jsFiles, apiEndpoints, adminPanels, sensitiveFiles, parameters };
    }
}

export const urlGatherer = new UrlGatherer();
