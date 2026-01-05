import axios from 'axios';
import * as cheerio from 'cheerio';
import { logger } from '../core/logger.js';
import { getConfig } from '../config/settings.js';

export interface TechFingerprint {
    name: string;
    version?: string;
    category: string;
    confidence: number;
}

export interface TechDetectionResult {
    url: string;
    technologies: TechFingerprint[];
    headers: Record<string, string>;
    meta: {
        title?: string;
        generator?: string;
        poweredBy?: string;
    };
    serverInfo: {
        server?: string;
        xPoweredBy?: string;
        aspNetVersion?: string;
        phpVersion?: string;
    };
    securityHeaders: {
        contentSecurityPolicy?: string;
        xFrameOptions?: string;
        xXssProtection?: string;
        strictTransportSecurity?: string;
        xContentTypeOptions?: string;
        referrerPolicy?: string;
    };
    cookies: {
        name: string;
        secure: boolean;
        httpOnly: boolean;
        sameSite?: string;
    }[];
}

// Technology signatures for detection
const TECH_SIGNATURES: {
    name: string;
    category: string;
    patterns: {
        type: 'header' | 'body' | 'cookie' | 'script' | 'meta';
        key?: string;
        pattern: RegExp;
        version?: RegExp;
    }[];
}[] = [
        {
            name: 'WordPress',
            category: 'CMS',
            patterns: [
                { type: 'body', pattern: /wp-content|wp-includes/i },
                { type: 'meta', key: 'generator', pattern: /wordpress/i, version: /wordpress\s*([\d.]+)/i },
                { type: 'cookie', key: 'wordpress', pattern: /wordpress/i },
            ],
        },
        {
            name: 'React',
            category: 'JavaScript Framework',
            patterns: [
                { type: 'body', pattern: /_reactRootContainer|data-reactroot|__NEXT_DATA__/i },
                { type: 'script', pattern: /react\.production\.min\.js|react-dom/i },
            ],
        },
        {
            name: 'Vue.js',
            category: 'JavaScript Framework',
            patterns: [
                { type: 'body', pattern: /data-v-[a-f0-9]|__vue__|vue-app/i },
                { type: 'script', pattern: /vue\.min\.js|vue\.runtime/i },
            ],
        },
        {
            name: 'Angular',
            category: 'JavaScript Framework',
            patterns: [
                { type: 'body', pattern: /ng-version|ng-app|\[ng-[a-z]+\]/i },
                { type: 'script', pattern: /angular\.min\.js|zone\.js/i },
            ],
        },
        {
            name: 'jQuery',
            category: 'JavaScript Library',
            patterns: [
                { type: 'script', pattern: /jquery[-.]?([\d.]+)?\.min\.js/i, version: /jquery[-.]?([\d.]+)/i },
                { type: 'body', pattern: /jquery/i },
            ],
        },
        {
            name: 'Bootstrap',
            category: 'CSS Framework',
            patterns: [
                { type: 'body', pattern: /class="[^"]*\b(container|row|col-|btn-|nav-)/i },
                { type: 'script', pattern: /bootstrap\.min\.js/i },
            ],
        },
        {
            name: 'nginx',
            category: 'Web Server',
            patterns: [
                { type: 'header', key: 'server', pattern: /nginx/i, version: /nginx\/([\d.]+)/i },
            ],
        },
        {
            name: 'Apache',
            category: 'Web Server',
            patterns: [
                { type: 'header', key: 'server', pattern: /apache/i, version: /apache\/([\d.]+)/i },
            ],
        },
        {
            name: 'PHP',
            category: 'Programming Language',
            patterns: [
                { type: 'header', key: 'x-powered-by', pattern: /php/i, version: /php\/([\d.]+)/i },
                { type: 'cookie', key: 'phpsessid', pattern: /phpsessid/i },
            ],
        },
        {
            name: 'ASP.NET',
            category: 'Framework',
            patterns: [
                { type: 'header', key: 'x-aspnet-version', pattern: /.+/ },
                { type: 'header', key: 'x-powered-by', pattern: /asp\.net/i },
                { type: 'cookie', key: 'asp.net_sessionid', pattern: /asp\.net/i },
            ],
        },
        {
            name: 'Express.js',
            category: 'Framework',
            patterns: [
                { type: 'header', key: 'x-powered-by', pattern: /express/i },
            ],
        },
        {
            name: 'Django',
            category: 'Framework',
            patterns: [
                { type: 'cookie', key: 'csrftoken', pattern: /csrftoken/ },
                { type: 'body', pattern: /csrf_token|csrfmiddlewaretoken/i },
            ],
        },
        {
            name: 'Ruby on Rails',
            category: 'Framework',
            patterns: [
                { type: 'header', key: 'x-powered-by', pattern: /phusion passenger/i },
                { type: 'cookie', key: '_session_id', pattern: /_session_id/ },
            ],
        },
        {
            name: 'Cloudflare',
            category: 'CDN/Security',
            patterns: [
                { type: 'header', key: 'cf-ray', pattern: /.+/ },
                { type: 'header', key: 'server', pattern: /cloudflare/i },
            ],
        },
        {
            name: 'AWS',
            category: 'Cloud',
            patterns: [
                { type: 'header', key: 'x-amz-', pattern: /.+/ },
                { type: 'header', key: 'server', pattern: /AmazonS3|awselb/i },
            ],
        },
        {
            name: 'Google Cloud',
            category: 'Cloud',
            patterns: [
                { type: 'header', key: 'via', pattern: /google/i },
                { type: 'header', key: 'server', pattern: /gws|Google Frontend/i },
            ],
        },
    ];

class TechDetector {
    private get config() { return getConfig(); }

    async detect(url: string): Promise<TechDetectionResult> {
        logger.info(`Detecting technologies for: ${url}`);

        try {
            const response = await axios.get(url, {
                timeout: this.config.scanner.timeout,
                headers: {
                    'User-Agent': this.config.scanner.userAgent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                },
                maxRedirects: 5,
                validateStatus: () => true,
            });

            const headers = this.normalizeHeaders(response.headers);
            const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
            const $ = cheerio.load(body);

            const technologies = this.detectTechnologies(headers, body, $);
            const cookies = this.parseCookies(response.headers['set-cookie']);
            const meta = this.extractMeta($);
            const serverInfo = this.extractServerInfo(headers);
            const securityHeaders = this.extractSecurityHeaders(headers);

            logger.success(`Detected ${technologies.length} technologies on ${url}`);

            return {
                url,
                technologies,
                headers,
                meta,
                serverInfo,
                securityHeaders,
                cookies,
            };
        } catch (error) {
            logger.error(`Failed to detect technologies for ${url}`, { error: String(error) });
            return {
                url,
                technologies: [],
                headers: {},
                meta: {},
                serverInfo: {},
                securityHeaders: {},
                cookies: [],
            };
        }
    }

    private normalizeHeaders(headers: Record<string, unknown>): Record<string, string> {
        const normalized: Record<string, string> = {};
        for (const [key, value] of Object.entries(headers)) {
            normalized[key.toLowerCase()] = String(value);
        }
        return normalized;
    }

    private detectTechnologies(
        headers: Record<string, string>,
        body: string,
        $: cheerio.CheerioAPI
    ): TechFingerprint[] {
        const detected: TechFingerprint[] = [];

        for (const tech of TECH_SIGNATURES) {
            let matched = false;
            let version: string | undefined;
            let confidence = 0;

            for (const pattern of tech.patterns) {
                let target = '';

                switch (pattern.type) {
                    case 'header':
                        target = pattern.key ? headers[pattern.key] || '' : JSON.stringify(headers);
                        break;
                    case 'body':
                        target = body;
                        break;
                    case 'cookie':
                        target = headers['set-cookie'] || '';
                        break;
                    case 'script':
                        target = $('script[src]').map((_, el) => $(el).attr('src')).get().join(' ');
                        break;
                    case 'meta':
                        target = pattern.key ? $(`meta[name="${pattern.key}"]`).attr('content') || '' : '';
                        break;
                }

                if (pattern.pattern.test(target)) {
                    matched = true;
                    confidence += 1 / tech.patterns.length;

                    if (pattern.version) {
                        const versionMatch = target.match(pattern.version);
                        if (versionMatch?.[1]) {
                            version = versionMatch[1];
                        }
                    }
                }
            }

            if (matched) {
                detected.push({
                    name: tech.name,
                    version,
                    category: tech.category,
                    confidence: Math.min(confidence, 1),
                });
            }
        }

        return detected;
    }

    private parseCookies(setCookieHeader: string | string[] | undefined): TechDetectionResult['cookies'] {
        if (!setCookieHeader) return [];

        const cookies: TechDetectionResult['cookies'] = [];
        const cookieArray = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];

        for (const cookie of cookieArray) {
            const parts = cookie.split(';');
            const [nameValue] = parts;
            const [name] = nameValue?.split('=') || [];

            if (name) {
                const attributes = parts.slice(1).map(p => p.trim().toLowerCase());
                cookies.push({
                    name,
                    secure: attributes.some(a => a === 'secure'),
                    httpOnly: attributes.some(a => a === 'httponly'),
                    sameSite: attributes.find(a => a.startsWith('samesite='))?.split('=')[1],
                });
            }
        }

        return cookies;
    }

    private extractMeta($: cheerio.CheerioAPI): TechDetectionResult['meta'] {
        return {
            title: $('title').text() || undefined,
            generator: $('meta[name="generator"]').attr('content'),
            poweredBy: $('meta[name="powered-by"]').attr('content'),
        };
    }

    private extractServerInfo(headers: Record<string, string>): TechDetectionResult['serverInfo'] {
        return {
            server: headers['server'],
            xPoweredBy: headers['x-powered-by'],
            aspNetVersion: headers['x-aspnet-version'],
            phpVersion: headers['x-powered-by']?.match(/PHP\/([\d.]+)/)?.[1],
        };
    }

    private extractSecurityHeaders(headers: Record<string, string>): TechDetectionResult['securityHeaders'] {
        return {
            contentSecurityPolicy: headers['content-security-policy'],
            xFrameOptions: headers['x-frame-options'],
            xXssProtection: headers['x-xss-protection'],
            strictTransportSecurity: headers['strict-transport-security'],
            xContentTypeOptions: headers['x-content-type-options'],
            referrerPolicy: headers['referrer-policy'],
        };
    }

    analyzeSecurityPosture(result: TechDetectionResult): {
        score: number;
        issues: { severity: string; message: string }[];
    } {
        const issues: { severity: string; message: string }[] = [];
        let score = 100;

        // Check security headers
        if (!result.securityHeaders.contentSecurityPolicy) {
            issues.push({ severity: 'medium', message: 'Missing Content-Security-Policy header' });
            score -= 10;
        }
        if (!result.securityHeaders.xFrameOptions) {
            issues.push({ severity: 'medium', message: 'Missing X-Frame-Options header (Clickjacking risk)' });
            score -= 10;
        }
        if (!result.securityHeaders.strictTransportSecurity) {
            issues.push({ severity: 'high', message: 'Missing Strict-Transport-Security header (HSTS)' });
            score -= 15;
        }
        if (!result.securityHeaders.xContentTypeOptions) {
            issues.push({ severity: 'low', message: 'Missing X-Content-Type-Options header' });
            score -= 5;
        }

        // Check cookies
        for (const cookie of result.cookies) {
            if (!cookie.secure) {
                issues.push({ severity: 'medium', message: `Cookie "${cookie.name}" missing Secure flag` });
                score -= 5;
            }
            if (!cookie.httpOnly && cookie.name.toLowerCase().includes('session')) {
                issues.push({ severity: 'high', message: `Session cookie "${cookie.name}" missing HttpOnly flag` });
                score -= 10;
            }
        }

        // Check for information disclosure
        if (result.serverInfo.server) {
            issues.push({ severity: 'info', message: `Server version disclosed: ${result.serverInfo.server}` });
            score -= 3;
        }
        if (result.serverInfo.xPoweredBy) {
            issues.push({ severity: 'low', message: `X-Powered-By header disclosed: ${result.serverInfo.xPoweredBy}` });
            score -= 5;
        }

        return { score: Math.max(score, 0), issues };
    }
}

export const techDetector = new TechDetector();
