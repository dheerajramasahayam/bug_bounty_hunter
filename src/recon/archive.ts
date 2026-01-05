import axios from 'axios';
import { logger } from '../core/logger.js';
import { getConfig } from '../config/settings.js';

export interface ArchiveResult {
    url: string;
    timestamp: string;
    statusCode?: number;
    mimeType?: string;
}

export interface ArchiveCrawlResult {
    domain: string;
    urls: ArchiveResult[];
    jsFiles: string[];
    apiEndpoints: string[];
    parameters: Map<string, Set<string>>;
}

class ArchiveCrawler {
    private get config() { return getConfig(); }

    async crawl(domain: string, limit: number = 1000): Promise<ArchiveCrawlResult> {
        logger.info(`Crawling Wayback Machine for: ${domain}`);

        const results: ArchiveResult[] = [];
        const jsFiles = new Set<string>();
        const apiEndpoints = new Set<string>();
        const parameters = new Map<string, Set<string>>();

        try {
            // Query Wayback Machine CDX API
            const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=${limit}`;

            const response = await axios.get(cdxUrl, {
                timeout: 60000,
                headers: { 'User-Agent': this.config.scanner.userAgent },
            });

            if (Array.isArray(response.data) && response.data.length > 1) {
                // First row is header
                const rows = response.data.slice(1) as string[][];

                for (const [url, timestamp, statusCode, mimeType] of rows) {
                    const archiveResult: ArchiveResult = {
                        url,
                        timestamp,
                        statusCode: parseInt(statusCode) || undefined,
                        mimeType,
                    };
                    results.push(archiveResult);

                    // Extract interesting patterns
                    this.extractPatterns(url, jsFiles, apiEndpoints, parameters);
                }
            }

            logger.success(`Found ${results.length} archived URLs for ${domain}`);
        } catch (error) {
            logger.error('Wayback Machine query failed', { error: String(error) });
        }

        return {
            domain,
            urls: results,
            jsFiles: Array.from(jsFiles),
            apiEndpoints: Array.from(apiEndpoints),
            parameters,
        };
    }

    private extractPatterns(
        url: string,
        jsFiles: Set<string>,
        apiEndpoints: Set<string>,
        parameters: Map<string, Set<string>>
    ): void {
        try {
            const parsed = new URL(url);

            // Extract JavaScript files
            if (url.endsWith('.js') || url.includes('.js?')) {
                jsFiles.add(parsed.pathname);
            }

            // Detect API endpoints
            const apiPatterns = [
                /\/api\//i,
                /\/v[0-9]+\//i,
                /\/rest\//i,
                /\/graphql/i,
                /\/json/i,
                /\.json(\?|$)/i,
                /\/ajax\//i,
                /\/rpc\//i,
            ];

            if (apiPatterns.some(p => p.test(url))) {
                apiEndpoints.add(parsed.pathname);
            }

            // Extract parameters
            parsed.searchParams.forEach((_value, key) => {
                if (!parameters.has(parsed.pathname)) {
                    parameters.set(parsed.pathname, new Set());
                }
                parameters.get(parsed.pathname)!.add(key);
            });
        } catch {
            // Invalid URL, skip
        }
    }

    async fetchArchivedVersion(url: string, timestamp?: string): Promise<string | null> {
        try {
            const archiveUrl = timestamp
                ? `https://web.archive.org/web/${timestamp}/${url}`
                : `https://web.archive.org/web/${url}`;

            const response = await axios.get(archiveUrl, {
                timeout: 30000,
                headers: { 'User-Agent': this.config.scanner.userAgent },
                maxRedirects: 5,
            });

            return typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        } catch (error) {
            logger.warn(`Failed to fetch archived version of ${url}`, { error: String(error) });
            return null;
        }
    }

    async findSensitiveFiles(domain: string): Promise<string[]> {
        const sensitivePatterns = [
            '.env',
            '.git/config',
            'config.json',
            'config.yml',
            'secrets.json',
            '.aws/credentials',
            'backup.sql',
            'database.sql',
            'phpinfo.php',
            '.htpasswd',
            'web.config',
            'crossdomain.xml',
            'clientaccesspolicy.xml',
            'package.json',
            'composer.json',
            '.npmrc',
            '.dockerenv',
            'Dockerfile',
            'docker-compose.yml',
            '.travis.yml',
            'jenkins.xml',
            'wp-config.php.bak',
            'settings.py',
        ];

        const found: string[] = [];

        for (const pattern of sensitivePatterns) {
            try {
                const checkUrl = `https://${domain}/${pattern}`;
                const response = await axios.head(checkUrl, {
                    timeout: 5000,
                    validateStatus: (status) => status < 400,
                    maxRedirects: 3,
                });

                if (response.status === 200) {
                    found.push(checkUrl);
                    logger.vulnerability('Sensitive File Exposed', 'high', checkUrl);
                }
            } catch {
                // Not found or error, continue
            }

            // Rate limiting
            await new Promise(resolve => setTimeout(resolve, this.config.scanner.requestDelayMs));
        }

        return found;
    }
}

export const archiveCrawler = new ArchiveCrawler();
