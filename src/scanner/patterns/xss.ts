import { CrawlResponse } from '../../crawler/webcrawler.js';
import { PatternMatch } from './sqli.js';

// XSS test payloads for reflection testing
export const XSS_PAYLOADS = [
    // Basic reflection tests
    { payload: '<script>alert(1)</script>', purpose: 'Basic script tag' },
    { payload: '<img src=x onerror=alert(1)>', purpose: 'Image error handler' },
    { payload: '<svg onload=alert(1)>', purpose: 'SVG onload' },
    { payload: '"><script>alert(1)</script>', purpose: 'Attribute breakout' },
    { payload: "'-alert(1)-'", purpose: 'JavaScript context breakout' },
    { payload: '</script><script>alert(1)</script>', purpose: 'Script tag breakout' },
    { payload: '{{7*7}}', purpose: 'Template injection test' },
    { payload: '${7*7}', purpose: 'Template literal test' },

    // Event handlers
    { payload: '" onmouseover="alert(1)', purpose: 'Event handler injection' },
    { payload: "' onfocus='alert(1)' autofocus='", purpose: 'Focus event' },
    { payload: '<body onload=alert(1)>', purpose: 'Body onload' },
    { payload: '<input onfocus=alert(1) autofocus>', purpose: 'Input autofocus' },

    // Protocol handlers
    { payload: 'javascript:alert(1)', purpose: 'JavaScript protocol' },
    { payload: 'data:text/html,<script>alert(1)</script>', purpose: 'Data URL' },

    // Encoding bypasses
    { payload: '<scr<script>ipt>alert(1)</script>', purpose: 'Filter bypass - nested tags' },
    { payload: '<SCRIPT>alert(1)</SCRIPT>', purpose: 'Case variation' },
    { payload: '<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>', purpose: 'HTML entity encoding' },
    { payload: '<img src=x onerror="\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29">', purpose: 'Hex encoding' },

    // DOM-based XSS indicators
    { payload: '#<img src=x onerror=alert(1)>', purpose: 'Fragment-based XSS' },
];

// Patterns that indicate potential XSS in response
// XSS reflection patterns for future use
// /<script[^>]*>.*?<\/script>/gi,
// /on\w+\s*=\s*["'][^"']*["']/gi,
// /javascript\s*:/gi,
// /data\s*:\s*text\/html/gi,

// DOM sinks that could lead to DOM-based XSS
const DOM_SINKS = [
    'document.write',
    'document.writeln',
    '.innerHTML',
    '.outerHTML',
    '.insertAdjacentHTML',
    'eval(',
    'setTimeout(',
    'setInterval(',
    'Function(',
    '.src',
    '.href',
    'location',
    'location.href',
    'location.hash',
    'location.search',
];

// DOM sources that attackers can control
const DOM_SOURCES = [
    'location.hash',
    'location.search',
    'location.href',
    'document.URL',
    'document.documentURI',
    'document.referrer',
    'window.name',
    'document.cookie',
];

export function detectXss(response: CrawlResponse): PatternMatch[] {
    const matches: PatternMatch[] = [];
    const body = response.body;

    // Check if any request parameter values are reflected in the response
    for (const param of response.request.parameters) {
        if (!param.value || param.value.length < 3) continue;

        // Check for direct reflection
        if (body.includes(param.value)) {
            // Check if reflection is in a dangerous context
            const reflectionContext = getReflectionContext(body, param.value);

            if (reflectionContext.isDangerous) {
                matches.push({
                    type: 'xss',
                    severity: reflectionContext.severity,
                    pattern: 'Parameter reflection',
                    match: param.value,
                    context: `Parameter "${param.name}" reflected in ${reflectionContext.context}`,
                    confidence: reflectionContext.confidence,
                });
            }
        }

        // Check for encoded reflection
        const encodedValue = encodeURIComponent(param.value);
        if (encodedValue !== param.value && body.includes(encodedValue)) {
            matches.push({
                type: 'xss',
                severity: 'medium',
                pattern: 'URL-encoded reflection',
                match: encodedValue,
                context: `Parameter "${param.name}" reflected with URL encoding`,
                confidence: 0.5,
            });
        }
    }

    // Check for dangerous patterns in JavaScript
    if (response.contentType.includes('javascript') || body.includes('<script')) {
        for (const sink of DOM_SINKS) {
            if (body.includes(sink)) {
                // Check if a source is used with the sink
                for (const source of DOM_SOURCES) {
                    const regex = new RegExp(`${escapeRegex(sink)}[^;]*${escapeRegex(source)}`, 'gi');
                    if (regex.test(body)) {
                        matches.push({
                            type: 'xss',
                            severity: 'high',
                            pattern: 'DOM-based XSS',
                            match: `${sink} with ${source}`,
                            context: `Potential DOM-based XSS: user-controlled source flows to dangerous sink`,
                            confidence: 0.7,
                        });
                    }
                }
            }
        }
    }

    return matches;
}

function getReflectionContext(body: string, value: string): {
    isDangerous: boolean;
    context: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    confidence: number;
} {
    const index = body.indexOf(value);
    const before = body.substring(Math.max(0, index - 100), index);
    const _after = body.substring(index + value.length, index + value.length + 100);

    // Check if inside a script tag
    if (/<script[^>]*>(?:(?!<\/script>).)*$/i.test(before)) {
        return {
            isDangerous: true,
            context: 'JavaScript context',
            severity: 'high',
            confidence: 0.85,
        };
    }

    // Check if inside an attribute
    const attrMatch = before.match(/(\w+)\s*=\s*["']?[^"']*$/);
    if (attrMatch) {
        const attrName = attrMatch[1].toLowerCase();

        // Event handler attributes are most dangerous
        if (attrName.startsWith('on')) {
            return {
                isDangerous: true,
                context: `Event handler attribute (${attrName})`,
                severity: 'high',
                confidence: 0.9,
            };
        }

        // href/src can lead to XSS
        if (['href', 'src', 'action', 'formaction'].includes(attrName)) {
            return {
                isDangerous: true,
                context: `URL attribute (${attrName})`,
                severity: 'medium',
                confidence: 0.7,
            };
        }

        // Regular attributes still interesting
        return {
            isDangerous: true,
            context: `HTML attribute (${attrName})`,
            severity: 'medium',
            confidence: 0.6,
        };
    }

    // Check if inside a style tag/attribute
    if (/<style[^>]*>(?:(?!<\/style>).)*$/i.test(before) || /style\s*=\s*["']?[^"']*$/i.test(before)) {
        return {
            isDangerous: true,
            context: 'CSS context',
            severity: 'medium',
            confidence: 0.6,
        };
    }

    // Plain HTML context
    if (/<[^>]*$/.test(before)) {
        return {
            isDangerous: true,
            context: 'HTML tag context',
            severity: 'medium',
            confidence: 0.7,
        };
    }

    // Generic HTML body
    return {
        isDangerous: false,
        context: 'HTML body',
        severity: 'low',
        confidence: 0.3,
    };
}

function escapeRegex(string: string): string {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export { DOM_SINKS, DOM_SOURCES };
