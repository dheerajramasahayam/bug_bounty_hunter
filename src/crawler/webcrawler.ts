import axios, { AxiosResponse } from 'axios';
import * as cheerio from 'cheerio';
import { URL } from 'url';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../core/logger.js';
import { getConfig } from '../config/settings.js';
import { db, CrawledUrl } from '../core/database.js';

export interface CrawlRequest {
    url: string;
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
    headers?: Record<string, string>;
    body?: string;
    parameters: {
        name: string;
        value: string;
        type: 'query' | 'body' | 'path' | 'header';
    }[];
}

export interface CrawlResponse {
    request: CrawlRequest;
    statusCode: number;
    headers: Record<string, string>;
    body: string;
    contentType: string;
    responseTime: number;
}

export interface CrawlResult {
    responses: CrawlResponse[];
    forms: FormData[];
    links: string[];
    jsFiles: string[];
    apiEndpoints: string[];
}

export interface FormData {
    action: string;
    method: string;
    inputs: {
        name: string;
        type: string;
        value?: string;
    }[];
}

class WebCrawler {
    private get config() { return getConfig(); }
    private visited = new Set<string>();
    private queue: string[] = [];
    private baseUrl = '';
    private scope: string[] = [];

    async crawl(
        startUrl: string,
        options: {
            maxDepth?: number;
            maxPages?: number;
            scope?: string[];
            sessionId: string;
            targetId: string;
        }
    ): Promise<CrawlResult> {
        const maxDepth = options.maxDepth ?? this.config.scanner.maxCrawlDepth;
        const maxPages = options.maxPages ?? 500;
        this.scope = options.scope ?? [];

        const parsedUrl = new URL(startUrl);
        this.baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;

        logger.info(`Starting web crawl from: ${startUrl}`);
        logger.info(`Max depth: ${maxDepth}, Max pages: ${maxPages}`);

        const responses: CrawlResponse[] = [];
        const forms: FormData[] = [];
        const links = new Set<string>();
        const jsFiles = new Set<string>();
        const apiEndpoints = new Set<string>();

        this.queue = [startUrl];
        this.visited.clear();

        let depth = 0;
        let pagesProcessed = 0;

        while (this.queue.length > 0 && depth < maxDepth && pagesProcessed < maxPages) {
            const currentBatch = [...this.queue];
            this.queue = [];

            const batchPromises = currentBatch
                .filter(url => !this.visited.has(url) && this.isInScope(url))
                .slice(0, this.config.scanner.maxConcurrentRequests)
                .map(async (url) => {
                    this.visited.add(url);
                    pagesProcessed++;

                    try {
                        const response = await this.fetchPage(url);
                        if (response) {
                            responses.push(response);

                            // Save to database
                            const crawledUrl: CrawledUrl = {
                                id: uuidv4(),
                                targetId: options.targetId,
                                sessionId: options.sessionId,
                                url,
                                method: 'GET',
                                statusCode: response.statusCode,
                                contentType: response.contentType,
                                responseSize: response.body.length,
                                parameters: JSON.stringify(response.request.parameters),
                                crawledAt: new Date().toISOString(),
                            };
                            db.saveCrawledUrl(crawledUrl);

                            // Parse HTML responses
                            if (response.contentType.includes('text/html')) {
                                const extracted = this.extractFromHtml(url, response.body);
                                extracted.links.forEach(l => {
                                    links.add(l);
                                    if (!this.visited.has(l)) {
                                        this.queue.push(l);
                                    }
                                });
                                extracted.forms.forEach(f => forms.push(f));
                                extracted.jsFiles.forEach(js => jsFiles.add(js));
                            }

                            // Detect API endpoints
                            this.detectApiEndpoints(url, response).forEach(ep => apiEndpoints.add(ep));
                        }
                    } catch (error) {
                        logger.debug(`Failed to crawl ${url}`, { error: String(error) });
                    }
                });

            await Promise.all(batchPromises);

            logger.progress(pagesProcessed, maxPages, 'Crawling pages');
            depth++;

            // Rate limiting between batches
            await new Promise(resolve => setTimeout(resolve, this.config.scanner.requestDelayMs));
        }

        logger.success(`Crawl complete: ${pagesProcessed} pages, ${forms.length} forms, ${jsFiles.size} JS files`);

        return {
            responses,
            forms,
            links: Array.from(links),
            jsFiles: Array.from(jsFiles),
            apiEndpoints: Array.from(apiEndpoints),
        };
    }

    private isInScope(url: string): boolean {
        try {
            const parsed = new URL(url);

            // Must be same origin or in scope list
            if (url.startsWith(this.baseUrl)) {
                return true;
            }

            // Check scope patterns
            for (const pattern of this.scope) {
                if (pattern.startsWith('*.')) {
                    const domain = pattern.slice(2);
                    if (parsed.host.endsWith(domain)) return true;
                } else if (parsed.host === pattern || url.includes(pattern)) {
                    return true;
                }
            }

            return false;
        } catch {
            return false;
        }
    }

    private async fetchPage(url: string): Promise<CrawlResponse | null> {
        const startTime = Date.now();

        try {
            const response: AxiosResponse = await axios.get(url, {
                timeout: this.config.scanner.timeout,
                headers: {
                    'User-Agent': this.config.scanner.userAgent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                },
                maxRedirects: 5,
                validateStatus: () => true,
            });

            const responseTime = Date.now() - startTime;
            const parsedUrl = new URL(url);

            // Extract query parameters
            const parameters: CrawlRequest['parameters'] = [];
            parsedUrl.searchParams.forEach((value, name) => {
                parameters.push({ name, value, type: 'query' });
            });

            return {
                request: {
                    url,
                    method: 'GET',
                    parameters,
                },
                statusCode: response.status,
                headers: this.normalizeHeaders(response.headers),
                body: typeof response.data === 'string' ? response.data : JSON.stringify(response.data),
                contentType: response.headers['content-type'] || '',
                responseTime,
            };
        } catch (error) {
            logger.debug(`Request failed for ${url}`, { error: String(error) });
            return null;
        }
    }

    private normalizeHeaders(headers: Record<string, unknown>): Record<string, string> {
        const normalized: Record<string, string> = {};
        for (const [key, value] of Object.entries(headers)) {
            normalized[key.toLowerCase()] = String(value);
        }
        return normalized;
    }

    private extractFromHtml(baseUrl: string, html: string): {
        links: string[];
        forms: FormData[];
        jsFiles: string[];
    } {
        const $ = cheerio.load(html);
        const links: string[] = [];
        const forms: FormData[] = [];
        const jsFiles: string[] = [];

        // Extract links
        $('a[href]').each((_, el) => {
            const href = $(el).attr('href');
            if (href) {
                const absoluteUrl = this.resolveUrl(baseUrl, href);
                if (absoluteUrl) links.push(absoluteUrl);
            }
        });

        // Extract forms
        $('form').each((_, el) => {
            const $form = $(el);
            const action = this.resolveUrl(baseUrl, $form.attr('action') || '') || baseUrl;
            const method = ($form.attr('method') || 'GET').toUpperCase();

            const inputs: FormData['inputs'] = [];
            $form.find('input, select, textarea').each((_, input) => {
                const $input = $(input);
                inputs.push({
                    name: $input.attr('name') || '',
                    type: $input.attr('type') || 'text',
                    value: $input.attr('value'),
                });
            });

            if (inputs.length > 0) {
                forms.push({ action, method, inputs });
            }
        });

        // Extract JavaScript files
        $('script[src]').each((_, el) => {
            const src = $(el).attr('src');
            if (src) {
                const absoluteUrl = this.resolveUrl(baseUrl, src);
                if (absoluteUrl) jsFiles.push(absoluteUrl);
            }
        });

        return { links, forms, jsFiles };
    }

    private resolveUrl(base: string, relative: string): string | null {
        try {
            // Skip non-HTTP URLs
            if (relative.startsWith('javascript:') ||
                relative.startsWith('mailto:') ||
                relative.startsWith('tel:') ||
                relative.startsWith('data:') ||
                relative.startsWith('#')) {
                return null;
            }

            const resolved = new URL(relative, base);

            // Only HTTP(S) URLs
            if (!resolved.protocol.startsWith('http')) {
                return null;
            }

            // Remove fragments
            resolved.hash = '';

            return resolved.toString();
        } catch {
            return null;
        }
    }

    private detectApiEndpoints(url: string, response: CrawlResponse): string[] {
        const endpoints: string[] = [];

        // Check content type
        if (response.contentType.includes('application/json')) {
            endpoints.push(url);
        }

        // Look for API patterns in URL
        const apiPatterns = [
            /\/api\//i,
            /\/v[0-9]+\//i,
            /\/rest\//i,
            /\/graphql/i,
        ];

        if (apiPatterns.some(p => p.test(url))) {
            endpoints.push(url);
        }

        // Search response body for API references
        const apiUrlPattern = /["'](\/api\/[^"']+|https?:\/\/[^"']*\/api\/[^"']+)["']/gi;
        let match;
        while ((match = apiUrlPattern.exec(response.body)) !== null) {
            const apiUrl = this.resolveUrl(url, match[1]);
            if (apiUrl) endpoints.push(apiUrl);
        }

        return [...new Set(endpoints)];
    }
}

export const webCrawler = new WebCrawler();
