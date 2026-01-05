import { v4 as uuidv4 } from 'uuid';
import { nuclei, NucleiResult } from '../tools/nuclei.js';
import { httpx } from '../tools/httpx.js';
import { nmap } from '../tools/nmap.js';
import { urlGatherer } from '../tools/urlgatherer.js';
import { subfinder } from '../tools/subfinder.js';
import { externalTools } from '../tools/external.js';
import { db, Finding } from '../core/database.js';
import { gemini } from '../core/gemini.js';
import { logger } from '../core/logger.js';
import { ffuf } from '../tools/ffuf.js';
import { parameterScanner } from './parameters.js';
export interface EnhancedScanOptions {
    targetId: string;
    sessionId: string;
    useNuclei: boolean;
    useAi: boolean;
    nucleiSeverity?: ('critical' | 'high' | 'medium' | 'low' | 'info')[];
    nucleiTags?: string[];
    skipPortScan?: boolean;
    skipUrlGathering?: boolean;
    aggressive?: boolean;
}

export interface EnhancedScanResult {
    domain: string;
    subdomains: string[];
    liveHosts: string[];
    openPorts: { host: string; port: number; service: string }[];
    urls: string[];
    nucleiFindings: NucleiResult[];
    findings: Finding[];
    summary: {
        totalSubdomains: number;
        totalLiveHosts: number;
        totalUrls: number;
        totalVulnerabilities: number;
        bySeverity: Record<string, number>;
    };
}

class EnhancedScanner {
    async checkToolsAvailability(): Promise<Record<string, boolean>> {
        const status = await externalTools.checkTools();
        const availability: Record<string, boolean> = {};

        for (const [tool, config] of Object.entries(status)) {
            availability[tool] = config.available;
        }

        logger.info('External tools availability:');
        for (const [tool, available] of Object.entries(availability)) {
            if (available) {
                logger.success(`  ✓ ${tool}`);
            } else {
                logger.warn(`  ✗ ${tool} (not installed)`);
            }
        }

        return availability;
    }

    async runFullScan(domain: string, options: EnhancedScanOptions): Promise<EnhancedScanResult> {
        logger.banner('Enhanced Security Scan');
        logger.info(`Target: ${domain}`);

        const result: EnhancedScanResult = {
            domain,
            subdomains: [],
            liveHosts: [],
            openPorts: [],
            urls: [],
            nucleiFindings: [],
            findings: [],
            summary: {
                totalSubdomains: 0,
                totalLiveHosts: 0,
                totalUrls: 0,
                totalVulnerabilities: 0,
                bySeverity: {},
            },
        };

        // Check tools
        await this.checkToolsAvailability();

        // Phase 1: Subdomain Enumeration
        logger.info('\n📡 Phase 1: Subdomain Enumeration');
        if (await subfinder.isAvailable()) {
            const subfinderResults = await subfinder.run({ domain, recursive: true });
            result.subdomains = subfinderResults.map(r => r.subdomain);
        }
        result.summary.totalSubdomains = result.subdomains.length;
        logger.success(`Found ${result.subdomains.length} subdomains`);

        // Phase 2: HTTP Probing
        logger.info('\n🌐 Phase 2: HTTP Probing');
        if (await httpx.isAvailable() && result.subdomains.length > 0) {
            const targets = result.subdomains.map(s => `https://${s}`);
            targets.push(...result.subdomains.map(s => `http://${s}`));

            const httpxResults = await httpx.probeUrls(targets);
            result.liveHosts = httpxResults
                .filter(r => !r.failed && r.statusCode > 0)
                .map(r => r.url);
        } else {
            // Fallback: use the domain itself
            result.liveHosts = [`https://${domain}`];
        }
        result.summary.totalLiveHosts = result.liveHosts.length;
        logger.success(`Found ${result.liveHosts.length} live hosts`);

        // Phase 3: Port Scanning (optional)
        if (!options.skipPortScan) {
            logger.info('\n🔌 Phase 3: Port Scanning');
            if (await nmap.isAvailable()) {
                const nmapTargets = result.subdomains.slice(0, 20); // Limit to first 20
                const nmapResults = await nmap.webScan(nmapTargets);

                for (const host of nmapResults) {
                    for (const port of host.ports) {
                        if (port.state === 'open') {
                            result.openPorts.push({
                                host: host.ip || host.hostname,
                                port: port.port,
                                service: port.service || 'unknown',
                            });
                        }
                    }
                }
                logger.success(`Found ${result.openPorts.length} open ports`);
            } else {
                logger.warn('Nmap not available, skipping port scan');
            }
        }

        // Phase 4: URL Gathering
        if (!options.skipUrlGathering) {
            logger.info('\n📜 Phase 4: URL Gathering');
            if (await urlGatherer.isGauAvailable() || await urlGatherer.isWaybackAvailable()) {
                result.urls = await urlGatherer.gatherAllUrls(domain);

                // Extract interesting URLs
                const interesting = urlGatherer.extractInterestingUrls(result.urls);
                logger.info(`  JS Files: ${interesting.jsFiles.length}`);
                logger.info(`  API Endpoints: ${interesting.apiEndpoints.length}`);
                logger.info(`  Admin Panels: ${interesting.adminPanels.length}`);
                logger.info(`  Sensitive Files: ${interesting.sensitiveFiles.length}`);
            }
            result.summary.totalUrls = result.urls.length;
        }

        // Phase 5: Nuclei Vulnerability Scanning
        if (options.useNuclei) {
            logger.info('\n🔥 Phase 5: Nuclei Vulnerability Scanning');
            if (await nuclei.isAvailable()) {
                const severity = options.nucleiSeverity || ['critical', 'high', 'medium'];

                result.nucleiFindings = await nuclei.run({
                    targets: result.liveHosts,
                    severity,
                    tags: options.nucleiTags,
                    rateLimit: 150,
                    concurrency: 25,
                });

                // Convert Nuclei findings to our Finding format
                for (const nf of result.nucleiFindings) {
                    const finding: Finding = {
                        id: uuidv4(),
                        targetId: options.targetId,
                        type: nf.info.name,
                        severity: nf.info.severity === 'unknown' ? 'info' : nf.info.severity,
                        url: nf.host,
                        evidence: nf.matched || nf.curl || '',
                        description: nf.info.description || `Detected by Nuclei template: ${nf.templateId}`,
                        aiAnalysis: JSON.stringify({
                            templateId: nf.templateId,
                            tags: nf.info.tags,
                            references: nf.info.reference,
                            author: nf.info.author,
                        }),
                        confidence: 0.9, // Nuclei templates are highly reliable
                        status: 'new',
                        createdAt: new Date().toISOString(),
                        updatedAt: new Date().toISOString(),
                    };

                    result.findings.push(finding);
                    db.createFinding(finding);

                    // Update severity count
                    result.summary.bySeverity[finding.severity] =
                        (result.summary.bySeverity[finding.severity] || 0) + 1;
                }

                logger.success(`Nuclei found ${result.nucleiFindings.length} vulnerabilities`);
            } else {
                logger.warn('Nuclei not available, skipping vulnerability scan');
            }
        }

        // Phase 6: AI Analysis (optional)
        if (options.useAi && result.nucleiFindings.length > 0) {
            logger.info('\n🤖 Phase 6: AI-Powered Analysis');

            // Use AI to validate and enrich high-severity findings
            const highSeverity = result.findings.filter(f =>
                f.severity === 'critical' || f.severity === 'high'
            );

            for (const finding of highSeverity.slice(0, 10)) { // Limit to 10 for cost
                try {
                    const classification = await gemini.classifyVulnerability({
                        url: finding.url,
                        indicator: finding.type,
                        context: `${finding.evidence}\n${finding.description}`,
                    });

                    if (!classification.isFalsePositive) {
                        finding.confidence = classification.confidence;
                        finding.aiAnalysis = JSON.stringify({
                            ...JSON.parse(finding.aiAnalysis || '{}'),
                            aiClassification: classification,
                        });

                        if (classification.confidence >= 0.85) {
                            finding.status = 'verified';
                        }

                        // Update status in database
                        db.updateFindingStatus(finding.id, finding.status);
                    }
                } catch (error) {
                    logger.warn(`AI analysis failed for finding ${finding.id}`, { error: String(error) });
                }
            }
        }

        // Phase 7: Active Fuzzing (Aggressive Mode)
        if (options.aggressive) {
            logger.info('\n🧨 Phase 7: Active Fuzzing & Discovery');

            if (await ffuf.isAvailable()) {
                // Directory Fuzzing on main domain
                logger.info('  Running directory fuzzing on live hosts...');
                const fuzzTargets = result.liveHosts.slice(0, 5); // Limit to top 5 hosts to save time

                for (const target of fuzzTargets) {
                    const paths = await ffuf.discoverDirectories(target);
                    for (const path of paths) {
                        const url = path.url;
                        if (!result.urls.includes(url)) {
                            result.urls.push(url);
                            logger.info(`  Found hidden path: ${url}`);

                            // Check for backup files on interesting paths (config, admin, etc)
                            if (url.includes('admin') || url.includes('config') || url.includes('api')) {
                                const backups = await ffuf.scanBackupFiles(url);
                                for (const backup of backups) {
                                    const backupUrl = backup.url;
                                    logger.vulnerability('Sensitive File Exposure', 'high', backupUrl);

                                    const finding: Finding = {
                                        id: uuidv4(),
                                        targetId: options.targetId,
                                        type: 'Sensitive File Exposure',
                                        severity: 'high',
                                        url: backupUrl,
                                        evidence: `Found hidden backup file: ${backupUrl} (Status: ${backup.status})`,
                                        description: 'A backup file (likely containing source code or secrets) was discovered via fuzzing.',
                                        confidence: 0.9,
                                        status: 'new',
                                        createdAt: new Date().toISOString(),
                                        updatedAt: new Date().toISOString(),
                                    };
                                    result.findings.push(finding);
                                    db.createFinding(finding);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Phase 8: Parameter Discovery
        if (options.aggressive) {
            logger.info('\n🔍 Phase 8: Parameter Discovery');

            // Scan interesting URLs for hidden parameters
            const targetsToScan = result.urls.filter(u => u.includes('?') || u.includes('.php') || u.includes('.aspx') || u.includes('api')).slice(0, 10);

            for (const url of targetsToScan) {
                const params = await parameterScanner.scanEndpoint(url);
                if (params.length > 0) {
                    for (const p of params) {
                        for (const paramName of p.params) {
                            const finding: Finding = {
                                id: uuidv4(),
                                targetId: options.targetId,
                                type: 'Hidden Parameter Discovered',
                                severity: 'info',
                                url: p.url,
                                parameter: paramName,
                                evidence: `Parameter '${paramName}' discovered via ${p.source}`,
                                description: `A hidden or undocumented parameter '${paramName}' was discovered. This could be a vector for XSS, SQLi, or IDOR.`,
                                confidence: 0.7,
                                status: 'new',
                                createdAt: new Date().toISOString(),
                                updatedAt: new Date().toISOString(),
                            };
                            result.findings.push(finding);
                            db.createFinding(finding);
                        }
                    }
                }
            }
        }

        // Summary
        result.summary.totalVulnerabilities = result.findings.length;

        logger.banner('Scan Complete');
        logger.info(`📊 Summary for ${domain}:`);
        logger.info(`   Subdomains: ${result.summary.totalSubdomains}`);
        logger.info(`   Live Hosts: ${result.summary.totalLiveHosts}`);
        logger.info(`   URLs Found: ${result.summary.totalUrls}`);
        logger.info(`   Vulnerabilities: ${result.summary.totalVulnerabilities}`);

        if (Object.keys(result.summary.bySeverity).length > 0) {
            logger.info('\n   By Severity:');
            for (const [sev, count] of Object.entries(result.summary.bySeverity)) {
                logger.info(`     ${sev}: ${count}`);
            }
        }

        return result;
    }

    // Quick scan with just Nuclei on critical/high
    async quickScan(targets: string[], options: EnhancedScanOptions): Promise<NucleiResult[]> {
        logger.info(`Quick scan on ${targets.length} targets...`);

        if (!await nuclei.isAvailable()) {
            logger.error('Nuclei is required for quick scan');
            return [];
        }

        return nuclei.scanCriticalHigh(targets);
    }

    // CVE-focused scan
    async cveScan(targets: string[], options: EnhancedScanOptions): Promise<NucleiResult[]> {
        logger.info(`CVE scan on ${targets.length} targets...`);

        if (!await nuclei.isAvailable()) {
            logger.error('Nuclei is required for CVE scan');
            return [];
        }

        return nuclei.scanCves(targets);
    }

    // Subdomain takeover scan
    async takeoverScan(domain: string): Promise<NucleiResult[]> {
        logger.info(`Subdomain takeover scan for ${domain}...`);

        if (!await nuclei.isAvailable() || !await subfinder.isAvailable()) {
            logger.error('Nuclei and Subfinder are required for takeover scan');
            return [];
        }

        // Get subdomains
        const subdomains = await subfinder.run({ domain });
        const targets = subdomains.map(s => `https://${s.subdomain}`);

        return nuclei.scanTakeovers(targets);
    }
}

export const enhancedScanner = new EnhancedScanner();
