import { CrawlResponse } from '../../crawler/webcrawler.js';
import { PatternMatch } from './sqli.js';
import { ApiEndpoint } from '../../crawler/apicrawler.js';

// API Security issue patterns
export interface ApiSecurityIssue {
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    description: string;
    recommendation: string;
}

// Authentication and authorization patterns
const AUTH_ISSUES = [
    {
        pattern: /["']?(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)["']?\s*[=:]/gi,
        type: 'Hardcoded API Key',
        severity: 'high' as const,
        description: 'API key or token appears to be hardcoded in the response',
        recommendation: 'Remove hardcoded credentials. Use environment variables or secure secret management.',
    },
    {
        pattern: /bearer\s+[a-zA-Z0-9._-]+/gi,
        type: 'Exposed Bearer Token',
        severity: 'high' as const,
        description: 'Bearer token found in response body',
        recommendation: 'Ensure tokens are not leaked in responses. Check for token exposure in error messages.',
    },
    {
        pattern: /password["']?\s*[=:]\s*["'][^"']+["']/gi,
        type: 'Password Exposure',
        severity: 'critical' as const,
        description: 'Password appears in API response',
        recommendation: 'Never return passwords in API responses. Use one-way hashing.',
    },
];

// Data exposure patterns
const DATA_EXPOSURE_PATTERNS = [
    {
        pattern: /"(ssn|social_security|tax_id|national_id)":\s*"[^"]+"/gi,
        type: 'SSN/Tax ID Exposure',
        severity: 'critical' as const,
    },
    {
        pattern: /"(credit_card|card_number|cvv|ccv)":\s*"?\d+/gi,
        type: 'Credit Card Data Exposure',
        severity: 'critical' as const,
    },
    {
        pattern: /"(internal_id|admin_flag|is_admin|role)":\s*/gi,
        type: 'Internal Field Exposure',
        severity: 'medium' as const,
    },
    {
        pattern: /"(secret|private_key|signing_key)":\s*"[^"]+"/gi,
        type: 'Secret Key Exposure',
        severity: 'critical' as const,
    },
];

// Rate limiting and enumeration patterns
const ENUMERATION_INDICATORS = [
    /user.*not.*found/i,
    /invalid.*username/i,
    /account.*does.*not.*exist/i,
    /email.*not.*registered/i,
    /no.*user.*with.*this.*email/i,
];

export function analyzeApiSecurity(response: CrawlResponse): PatternMatch[] {
    const matches: PatternMatch[] = [];
    const body = response.body;
    const headers = response.headers;

    // Check for authentication issues
    for (const issue of AUTH_ISSUES) {
        const match = body.match(issue.pattern);
        if (match) {
            matches.push({
                type: 'info_disclosure',
                severity: issue.severity,
                pattern: issue.type,
                match: match[0].substring(0, 50) + '...',
                context: issue.description,
                confidence: 0.9,
            });
        }
    }

    // Check for data exposure
    for (const exposure of DATA_EXPOSURE_PATTERNS) {
        if (exposure.pattern.test(body)) {
            matches.push({
                type: 'info_disclosure',
                severity: exposure.severity,
                pattern: exposure.type,
                match: 'Sensitive data field found',
                context: `API response contains ${exposure.type}`,
                confidence: 0.85,
            });
        }
    }

    // Check security headers
    const missingHeaders: string[] = [];

    if (!headers['content-type']?.includes('application/json')) {
        // For APIs, this might indicate misconfiguration
    }

    if (!headers['x-content-type-options']) {
        missingHeaders.push('X-Content-Type-Options');
    }

    if (!headers['cache-control']?.includes('no-store')) {
        missingHeaders.push('Cache-Control: no-store');
    }

    if (missingHeaders.length > 0) {
        matches.push({
            type: 'info_disclosure',
            severity: 'low',
            pattern: 'Missing Security Headers',
            match: missingHeaders.join(', '),
            context: 'API response missing recommended security headers',
            confidence: 0.7,
        });
    }

    // Check for user enumeration
    for (const pattern of ENUMERATION_INDICATORS) {
        if (pattern.test(body)) {
            matches.push({
                type: 'info_disclosure',
                severity: 'medium',
                pattern: 'User Enumeration',
                match: 'Account existence disclosure',
                context: 'API response reveals whether user exists - enables enumeration attacks',
                confidence: 0.75,
            });
            break;
        }
    }

    // Check for verbose errors
    const errorPatterns = [
        /stack\s*trace/i,
        /exception.*at.*line/i,
        /traceback.*most.*recent/i,
        /file.*line.*in/i,
        /internal.*server.*error.*details/i,
    ];

    for (const pattern of errorPatterns) {
        if (pattern.test(body)) {
            matches.push({
                type: 'info_disclosure',
                severity: 'medium',
                pattern: 'Verbose Error',
                match: 'Stack trace or debug info exposed',
                context: 'API returns detailed error information that could aid attackers',
                confidence: 0.8,
            });
            break;
        }
    }

    // Check for CORS misconfiguration
    const corsOrigin = headers['access-control-allow-origin'];
    const corsCredentials = headers['access-control-allow-credentials'];

    if (corsOrigin === '*' && corsCredentials === 'true') {
        matches.push({
            type: 'info_disclosure',
            severity: 'high',
            pattern: 'CORS Misconfiguration',
            match: 'Origin: *, Credentials: true',
            context: 'Dangerous CORS configuration allows any origin with credentials',
            confidence: 0.95,
        });
    } else if (corsOrigin === '*') {
        matches.push({
            type: 'info_disclosure',
            severity: 'low',
            pattern: 'Permissive CORS',
            match: 'Access-Control-Allow-Origin: *',
            context: 'API allows requests from any origin',
            confidence: 0.6,
        });
    }

    return matches;
}

export function analyzeApiEndpoint(endpoint: ApiEndpoint): ApiSecurityIssue[] {
    const issues: ApiSecurityIssue[] = [];

    // Check for mass assignment vulnerability potential
    const sensitiveParams = ['role', 'admin', 'is_admin', 'permissions', 'price', 'balance', 'credits'];
    const bodyParams = endpoint.parameters.filter((p: ApiEndpoint['parameters'][0]) => p.location === 'body');

    for (const param of bodyParams) {
        if (sensitiveParams.includes(param.name.toLowerCase())) {
            issues.push({
                type: 'Mass Assignment',
                severity: 'high',
                description: `Sensitive parameter "${param.name}" accepted in request body`,
                recommendation: 'Whitelist allowed parameters. Reject or ignore unexpected fields.',
            });
        }
    }

    // Check for authentication on sensitive endpoints
    const sensitiveEndpoints = ['/admin', '/user', '/account', '/settings', '/profile', '/payment'];
    const requiresAuth = sensitiveEndpoints.some(ep => endpoint.url.includes(ep));

    if (requiresAuth && !endpoint.authentication) {
        issues.push({
            type: 'Missing Authentication',
            severity: 'high',
            description: 'Sensitive endpoint may lack authentication',
            recommendation: 'Implement proper authentication for all sensitive endpoints.',
        });
    }

    // Check for proper HTTP methods
    if (endpoint.method === 'GET' && endpoint.url.includes('delete')) {
        issues.push({
            type: 'Unsafe HTTP Method',
            severity: 'medium',
            description: 'DELETE operation using GET method - vulnerable to CSRF',
            recommendation: 'Use proper HTTP methods (DELETE for deletion, POST for state changes).',
        });
    }

    // Check for file upload endpoints
    if (endpoint.url.includes('upload') || endpoint.url.includes('file')) {
        issues.push({
            type: 'File Upload Endpoint',
            severity: 'info',
            description: 'File upload functionality detected - requires careful testing',
            recommendation: 'Test for unrestricted file upload, path traversal, and file type bypass.',
        });
    }

    return issues;
}
