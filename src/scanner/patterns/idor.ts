import { CrawlResponse } from '../../crawler/webcrawler.js';
import { PatternMatch } from './sqli.js';

// Patterns indicating potential IDOR vulnerabilities
const IDOR_PATTERNS = [
    // Numeric IDs in URL path
    /\/users?\/(\d+)/i,
    /\/accounts?\/(\d+)/i,
    /\/profiles?\/(\d+)/i,
    /\/orders?\/(\d+)/i,
    /\/invoices?\/(\d+)/i,
    /\/documents?\/(\d+)/i,
    /\/files?\/(\d+)/i,
    /\/records?\/(\d+)/i,
    /\/items?\/(\d+)/i,
    /\/messages?\/(\d+)/i,
    /\/comments?\/(\d+)/i,
    /\/posts?\/(\d+)/i,
    /\/articles?\/(\d+)/i,
    /\/transactions?\/(\d+)/i,
    /\/payments?\/(\d+)/i,

    // Common ID parameter patterns
    /[?&]id=(\d+)/i,
    /[?&]user_?id=(\d+)/i,
    /[?&]account_?id=(\d+)/i,
    /[?&]order_?id=(\d+)/i,
    /[?&]doc_?id=(\d+)/i,
    /[?&]file_?id=(\d+)/i,
    /[?&]ref=(\d+)/i,
    /[?&]reference=(\d+)/i,
];

// Sequential ID patterns (higher IDOR risk)
const SEQUENTIAL_ID_PATTERNS = [
    /\/\d{1,6}(\/|$|\?)/,  // Short numeric IDs (likely sequential)
    /[?&]\w*id=\d{1,6}(&|$)/i,
];

// UUID patterns (lower IDOR risk but still worth noting)
const UUID_PATTERN = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

// Sensitive data patterns that indicate IDOR impact
const SENSITIVE_DATA_PATTERNS = [
    /email["']?\s*[=:]\s*["']?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i,
    /password["']?\s*[=:]/i,
    /credit.?card/i,
    /ssn|social.?security/i,
    /phone["']?\s*[=:]\s*["']?\+?[\d\s()-]+/i,
    /address["']?\s*[=:]/i,
    /bank.?account/i,
    /routing.?number/i,
    /api.?key/i,
    /secret/i,
    /token["']?\s*[=:]/i,
    /private/i,
    /salary|income|payment/i,
    /medical|health/i,
    /date.?of.?birth|dob|birthday/i,
];

export function detectIdor(response: CrawlResponse): PatternMatch[] {
    const matches: PatternMatch[] = [];
    const url = response.request.url;
    const body = response.body;

    // Check URL for IDOR-prone patterns
    for (const pattern of IDOR_PATTERNS) {
        const match = url.match(pattern);
        if (match) {
            const isSequential = SEQUENTIAL_ID_PATTERNS.some(p => p.test(url));

            matches.push({
                type: 'idor',
                severity: isSequential ? 'high' : 'medium',
                pattern: pattern.source,
                match: match[0],
                context: `Numeric ID found in ${url.includes('?') ? 'query parameter' : 'URL path'}${isSequential ? ' (appears sequential)' : ''}`,
                confidence: isSequential ? 0.7 : 0.5,
            });
        }
    }

    // Check for sensitive data in response (increases IDOR severity)
    if (matches.length > 0) {
        const sensitiveDataFound: string[] = [];

        for (const pattern of SENSITIVE_DATA_PATTERNS) {
            if (pattern.test(body)) {
                sensitiveDataFound.push(pattern.source);
            }
        }

        if (sensitiveDataFound.length > 0) {
            matches[0].severity = 'high';
            matches[0].confidence = Math.min(matches[0].confidence + 0.2, 0.95);
            matches[0].context += ` - Response contains sensitive data: ${sensitiveDataFound.slice(0, 3).join(', ')}`;
        }
    }

    // Check for UUID-based IDs (lower risk but still worth noting)
    if (UUID_PATTERN.test(url)) {
        matches.push({
            type: 'idor',
            severity: 'info',
            pattern: 'UUID in URL',
            match: url.match(UUID_PATTERN)?.[0] || '',
            context: 'UUID-based identifier found (harder to guess but may still be vulnerable)',
            confidence: 0.3,
        });
    }

    // Check for direct object access via parameters
    for (const param of response.request.parameters) {
        if (/^(id|user_?id|account_?id|doc_?id|file_?id|ref)$/i.test(param.name)) {
            if (/^\d+$/.test(param.value)) {
                matches.push({
                    type: 'idor',
                    severity: 'medium',
                    pattern: 'Numeric ID parameter',
                    match: `${param.name}=${param.value}`,
                    context: `Parameter "${param.name}" uses numeric ID - test for IDOR by changing value`,
                    confidence: 0.6,
                });
            }
        }
    }

    return matches;
}

// IDOR test strategy
export const IDOR_TESTS = [
    { description: 'Increment ID by 1', transform: (id: string) => String(parseInt(id) + 1) },
    { description: 'Decrement ID by 1', transform: (id: string) => String(parseInt(id) - 1) },
    { description: 'Use ID 1 (first user)', transform: () => '1' },
    { description: 'Use ID 0', transform: () => '0' },
    { description: 'Use negative ID', transform: () => '-1' },
    { description: 'Use large ID', transform: () => '999999999' },
    { description: 'Add array notation', transform: (id: string) => `[${id}]` },
    { description: 'Use different user ID (if known)', transform: (_id: string, targetId?: string) => targetId || '2' },
];
