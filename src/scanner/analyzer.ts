import { v4 as uuidv4 } from 'uuid';
import { CrawlResponse } from '../crawler/webcrawler.js';
import { ApiEndpoint } from '../crawler/apicrawler.js';
import { gemini, VulnerabilityAnalysis } from '../core/gemini.js';
import { db, Finding } from '../core/database.js';
import { logger } from '../core/logger.js';
import { detectSqlInjection, PatternMatch } from './patterns/sqli.js';
import { detectXss } from './patterns/xss.js';
import { detectIdor } from './patterns/idor.js';
import { analyzeApiSecurity, analyzeApiEndpoint } from './patterns/api.js';
import { secretsScanner } from './secrets.js';

export interface ScanResult {
    url: string;
    patternMatches: PatternMatch[];
    aiAnalysis?: VulnerabilityAnalysis;
    findings: Finding[];
}

export interface ScanOptions {
    targetId: string;
    sessionId: string;
    useAi: boolean;
    aiConfidenceThreshold: number;
    skipPatternMatching: boolean;
}

class VulnerabilityAnalyzer {
    private processedUrls = new Set<string>();

    async analyzeResponse(
        response: CrawlResponse,
        options: ScanOptions
    ): Promise<ScanResult> {
        const url = response.request.url;

        // Avoid duplicate analysis
        if (this.processedUrls.has(url)) {
            return { url, patternMatches: [], findings: [] };
        }
        this.processedUrls.add(url);

        const patternMatches: PatternMatch[] = [];
        const findings: Finding[] = [];

        // Phase 1: Pattern-based detection (fast, pre-filter)
        if (!options.skipPatternMatching) {
            patternMatches.push(...detectSqlInjection(response));
            patternMatches.push(...detectXss(response));
            patternMatches.push(...detectIdor(response));
            patternMatches.push(...analyzeApiSecurity(response));

            // Secrets Detection
            const secrets = await secretsScanner.scanText(response.body, url);
            for (const secret of secrets) {
                patternMatches.push({
                    type: 'secret_leak',
                    severity: 'critical',
                    pattern: secret.type,
                    match: secret.value,
                    context: `Likely ${secret.type} found in response body`,
                    confidence: secret.confidence === 'high' ? 0.95 : 0.6,
                });
            }
        }

        // Log pattern matches
        for (const match of patternMatches) {
            if (match.confidence >= 0.5) {
                logger.vulnerability(match.type.toUpperCase(), match.severity, url);
            }
        }

        // Phase 2: AI-powered analysis for high-confidence or complex cases
        let aiAnalysis: VulnerabilityAnalysis | undefined;

        if (options.useAi) {
            // Use AI for:
            // 1. Pattern matches that need confirmation
            // 2. Complex responses that might have subtle vulnerabilities
            const shouldUseAi =
                patternMatches.some(m => m.confidence >= 0.5 && m.confidence < 0.9) ||
                (response.contentType.includes('json') && response.body.length > 100) ||
                response.statusCode >= 400;

            if (shouldUseAi) {
                try {
                    aiAnalysis = await gemini.analyzeHttpResponse(
                        url,
                        response.request.method,
                        response.request.headers || {},
                        response.request.body || null,
                        response.statusCode,
                        response.headers,
                        response.body,
                        response.request.parameters.map(p => `${p.name}=${p.value}`)
                    );

                    if (aiAnalysis.isVulnerable && aiAnalysis.confidence >= options.aiConfidenceThreshold) {
                        logger.vulnerability(
                            aiAnalysis.vulnerabilityType,
                            aiAnalysis.severity,
                            url
                        );
                    }
                } catch (error) {
                    logger.warn('AI analysis failed', { url, error: String(error) });
                }
            }
        }

        // Phase 3: Create findings from confirmed vulnerabilities
        findings.push(...this.createFindings(url, patternMatches, aiAnalysis, options));

        // Save findings to database
        for (const finding of findings) {
            db.createFinding(finding);
        }

        return { url, patternMatches, aiAnalysis, findings };
    }

    async analyzeApiEndpoints(
        endpoints: ApiEndpoint[],
        options: ScanOptions
    ): Promise<ScanResult[]> {
        const results: ScanResult[] = [];

        for (const endpoint of endpoints) {
            logger.debug(`Analyzing API endpoint: ${endpoint.method} ${endpoint.url}`);

            const patternMatches: PatternMatch[] = [];
            const findings: Finding[] = [];

            // Pattern-based analysis
            const apiIssues = analyzeApiEndpoint(endpoint);

            for (const issue of apiIssues) {
                patternMatches.push({
                    type: issue.type.toLowerCase().includes('auth') ? 'idor' : 'info_disclosure',
                    severity: issue.severity,
                    pattern: issue.type,
                    match: issue.description,
                    context: issue.recommendation,
                    confidence: 0.6,
                });
            }

            // AI analysis for API endpoints
            let aiAnalysis: VulnerabilityAnalysis | undefined;

            if (options.useAi && endpoint.sampleResponse) {
                try {
                    const analysis = await gemini.analyzeApiEndpoint(
                        endpoint.url,
                        endpoint.method,
                        { parameters: endpoint.parameters },
                        null,
                        endpoint.sampleResponse,
                        endpoint.authentication || 'unknown'
                    );

                    if (analysis.issues.length > 0) {
                        for (const issue of analysis.issues) {
                            patternMatches.push({
                                type: 'info_disclosure',
                                severity: issue.severity,
                                pattern: issue.type,
                                match: issue.description,
                                context: issue.recommendation,
                                confidence: 0.8,
                            });
                        }
                    }
                } catch (error) {
                    logger.warn('AI API analysis failed', { url: endpoint.url, error: String(error) });
                }
            }

            // Create findings
            findings.push(...this.createFindings(endpoint.url, patternMatches, aiAnalysis, options));

            for (const finding of findings) {
                db.createFinding(finding);
            }

            results.push({ url: endpoint.url, patternMatches, aiAnalysis, findings });
        }

        return results;
    }

    async analyzeJavaScript(
        jsUrl: string,
        jsCode: string,
        options: ScanOptions
    ): Promise<ScanResult> {
        const patternMatches: PatternMatch[] = [];
        const findings: Finding[] = [];

        // Use AI for JavaScript analysis
        if (options.useAi) {
            try {
                const analysis = await gemini.analyzeJavaScript(jsCode, jsUrl);

                for (const finding of analysis.findings) {
                    patternMatches.push({
                        type: finding.type.toLowerCase().includes('xss') ? 'xss' : 'info_disclosure',
                        severity: finding.severity as PatternMatch['severity'],
                        pattern: finding.type,
                        match: finding.line,
                        context: finding.description,
                        confidence: 0.75,
                    });
                }

                // Sensitive data findings
                for (const data of analysis.sensitiveData) {
                    patternMatches.push({
                        type: 'info_disclosure',
                        severity: 'high',
                        pattern: 'Hardcoded Secret',
                        match: data.substring(0, 20) + '...',
                        context: 'Sensitive data found in JavaScript file',
                        confidence: 0.9,
                    });
                }

                // Log discovered API endpoints
                if (analysis.apiEndpoints.length > 0) {
                    logger.info(`Found ${analysis.apiEndpoints.length} API endpoints in ${jsUrl}`);
                }
            } catch (error) {
                logger.warn('AI JavaScript analysis failed', { url: jsUrl, error: String(error) });
            }
        }

        // Secrets Detection in JS
        const secrets = await secretsScanner.scanText(jsCode, jsUrl);
        for (const secret of secrets) {
            patternMatches.push({
                type: 'secret_leak',
                severity: 'critical',
                pattern: secret.type,
                match: secret.value,
                context: `Hardcoded ${secret.type} found in JavaScript file`,
                confidence: secret.confidence === 'high' ? 0.95 : 0.6,
            });
        }

        findings.push(...this.createFindings(jsUrl, patternMatches, undefined, options));

        for (const finding of findings) {
            db.createFinding(finding);
        }

        return { url: jsUrl, patternMatches, findings };
    }

    private createFindings(
        url: string,
        patternMatches: PatternMatch[],
        aiAnalysis: VulnerabilityAnalysis | undefined,
        options: ScanOptions
    ): Finding[] {
        const findings: Finding[] = [];
        const addedTypes = new Set<string>();

        // Create findings from pattern matches
        for (const match of patternMatches) {
            if (match.confidence < 0.5) continue;

            // Avoid duplicate findings of same type for same URL
            const key = `${match.type}-${match.pattern}`;
            if (addedTypes.has(key)) continue;
            addedTypes.add(key);

            findings.push({
                id: uuidv4(),
                targetId: options.targetId,
                type: this.normalizeVulnType(match.type),
                severity: match.severity,
                url,
                evidence: match.match,
                description: match.context,
                confidence: match.confidence,
                status: match.confidence >= 0.8 ? 'verified' : 'new',
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
            });
        }

        // Create finding from AI analysis if confident
        if (aiAnalysis?.isVulnerable && aiAnalysis.confidence >= options.aiConfidenceThreshold) {
            const typeKey = aiAnalysis.vulnerabilityType.toLowerCase();
            if (!addedTypes.has(typeKey)) {
                findings.push({
                    id: uuidv4(),
                    targetId: options.targetId,
                    type: aiAnalysis.vulnerabilityType,
                    severity: aiAnalysis.severity,
                    url,
                    evidence: aiAnalysis.evidence.join('\n'),
                    description: aiAnalysis.description,
                    aiAnalysis: JSON.stringify({
                        exploitability: aiAnalysis.exploitability,
                        impact: aiAnalysis.impact,
                        remediation: aiAnalysis.remediation,
                        cweId: aiAnalysis.cweId,
                        cvssScore: aiAnalysis.cvssScore,
                    }),
                    confidence: aiAnalysis.confidence,
                    status: aiAnalysis.confidence >= 0.85 ? 'verified' : 'new',
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString(),
                });
            }
        }

        return findings;
    }

    private normalizeVulnType(type: string): string {
        const typeMap: Record<string, string> = {
            'sqli': 'SQL Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'idor': 'Insecure Direct Object Reference (IDOR)',
            'info_disclosure': 'Information Disclosure',
            'ssrf': 'Server-Side Request Forgery (SSRF)',
            'cmd_injection': 'Command Injection',
            'secret_leak': 'Hardcoded Secret / Credential Leak',
        };
        return typeMap[type] || type;
    }

    clearCache(): void {
        this.processedUrls.clear();
    }
}

export const vulnerabilityAnalyzer = new VulnerabilityAnalyzer();
