import fs from 'fs';
import path from 'path';
import { subfinder } from '../tools/subfinder.js';
import { httpx } from '../tools/httpx.js';
import { nmap } from '../tools/nmap.js';
import { nuclei } from '../tools/nuclei.js';
import { externalTools } from '../tools/external.js';
import { logger } from '../core/logger.js';
import { db } from '../core/database.js';
import { v4 as uuidv4 } from 'uuid';
import { ffuf } from '../tools/ffuf.js';
import { parameterScanner } from '../scanner/parameters.js';
import { advancedJsAnalyzer } from '../scanner/ast-analyzer.js';

export interface MonitorConfig {
    targets: string[];
    outputDir: string;
    notifications: {
        enabled: boolean;
        discordWebhook?: string;
        slackWebhook?: string;
        email?: string;
    };
    scanning: {
        enabled: boolean;
        nmapTopPorts: number;
        fullScanPorts: number[];
        nucleiSeverity: ('critical' | 'high' | 'medium' | 'low' | 'info')[];
        aggressive?: boolean;
    };
    screenshots: {
        enabled: boolean;
    };
}

export interface MonitorResult {
    domain: string;
    timestamp: string;
    newSubdomains: string[];
    removedSubdomains: string[];
    totalSubdomains: number;
    liveHosts: string[];
    openPorts: { host: string; port: number; service: string }[];
    vulnerabilities: { host: string; name: string; severity: string }[];
    screenshotsPath?: string;
}

class SubdomainMonitor {
    private dataDir: string;

    constructor() {
        this.dataDir = path.join(process.cwd(), 'data', 'monitoring');
        if (!fs.existsSync(this.dataDir)) {
            fs.mkdirSync(this.dataDir, { recursive: true });
        }
    }

    private getSubdomainFile(domain: string): string {
        return path.join(this.dataDir, `${domain.replace(/\./g, '_')}_subdomains.json`);
    }

    private getHistoryFile(domain: string): string {
        return path.join(this.dataDir, `${domain.replace(/\./g, '_')}_history.json`);
    }

    private loadPreviousSubdomains(domain: string): Set<string> {
        const file = this.getSubdomainFile(domain);
        if (fs.existsSync(file)) {
            try {
                const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
                return new Set(data.subdomains || []);
            } catch {
                return new Set();
            }
        }
        return new Set();
    }

    private saveSubdomains(domain: string, subdomains: string[]): void {
        const file = this.getSubdomainFile(domain);
        fs.writeFileSync(file, JSON.stringify({
            domain,
            subdomains,
            lastUpdated: new Date().toISOString(),
            count: subdomains.length,
        }, null, 2));
    }

    private appendHistory(domain: string, result: MonitorResult): void {
        const file = this.getHistoryFile(domain);
        let history: MonitorResult[] = [];

        if (fs.existsSync(file)) {
            try {
                history = JSON.parse(fs.readFileSync(file, 'utf-8'));
            } catch {
                history = [];
            }
        }

        history.push(result);

        // Keep last 30 days of history
        if (history.length > 30) {
            history = history.slice(-30);
        }

        fs.writeFileSync(file, JSON.stringify(history, null, 2));
    }

    async sendNotification(
        config: MonitorConfig['notifications'],
        result: MonitorResult
    ): Promise<void> {
        if (!config.enabled) return;

        const message = this.formatNotificationMessage(result);

        // Discord webhook
        if (config.discordWebhook) {
            try {
                const axios = (await import('axios')).default;
                await axios.post(config.discordWebhook, {
                    content: message,
                    embeds: [{
                        title: `🎯 New Targets Found: ${result.domain}`,
                        color: result.newSubdomains.length > 0 ? 0x00ff00 : 0x808080,
                        fields: [
                            { name: '🆕 New Subdomains', value: result.newSubdomains.length.toString(), inline: true },
                            { name: '🌐 Live Hosts', value: result.liveHosts.length.toString(), inline: true },
                            { name: '🔓 Open Ports', value: result.openPorts.length.toString(), inline: true },
                            { name: '🔥 Vulnerabilities', value: result.vulnerabilities.length.toString(), inline: true },
                        ],
                        timestamp: new Date().toISOString(),
                    }],
                });
                logger.success('Discord notification sent');
            } catch (error) {
                logger.error('Failed to send Discord notification', { error: String(error) });
            }
        }

        // Slack webhook
        if (config.slackWebhook) {
            try {
                const axios = (await import('axios')).default;
                await axios.post(config.slackWebhook, {
                    text: message,
                    blocks: [
                        {
                            type: 'header',
                            text: { type: 'plain_text', text: `🎯 Monitoring Update: ${result.domain}` },
                        },
                        {
                            type: 'section',
                            fields: [
                                { type: 'mrkdwn', text: `*New Subdomains:* ${result.newSubdomains.length}` },
                                { type: 'mrkdwn', text: `*Live Hosts:* ${result.liveHosts.length}` },
                                { type: 'mrkdwn', text: `*Open Ports:* ${result.openPorts.length}` },
                                { type: 'mrkdwn', text: `*Vulnerabilities:* ${result.vulnerabilities.length}` },
                            ],
                        },
                    ],
                });
                logger.success('Slack notification sent');
            } catch (error) {
                logger.error('Failed to send Slack notification', { error: String(error) });
            }
        }
    }

    private formatNotificationMessage(result: MonitorResult): string {
        let msg = `🎯 **Monitoring Update: ${result.domain}**\n`;
        msg += `📅 ${result.timestamp}\n\n`;

        if (result.newSubdomains.length > 0) {
            msg += `🆕 **New Subdomains Found (${result.newSubdomains.length}):**\n`;
            result.newSubdomains.slice(0, 10).forEach(s => {
                msg += `  • ${s}\n`;
            });
            if (result.newSubdomains.length > 10) {
                msg += `  ... and ${result.newSubdomains.length - 10} more\n`;
            }
            msg += '\n';
        }

        if (result.vulnerabilities.length > 0) {
            msg += `🔥 **Vulnerabilities Found (${result.vulnerabilities.length}):**\n`;
            result.vulnerabilities.forEach(v => {
                msg += `  • [${v.severity.toUpperCase()}] ${v.name} - ${v.host}\n`;
            });
            msg += '\n';
        }

        msg += `📊 **Summary:**\n`;
        msg += `  • Total Subdomains: ${result.totalSubdomains}\n`;
        msg += `  • Live Hosts: ${result.liveHosts.length}\n`;
        msg += `  • Open Ports: ${result.openPorts.length}\n`;

        return msg;
    }

    async runMonitoringCycle(domain: string, config: MonitorConfig): Promise<MonitorResult> {
        logger.banner(`Monitoring: ${domain}`);
        const timestamp = new Date().toISOString();

        const result: MonitorResult = {
            domain,
            timestamp,
            newSubdomains: [],
            removedSubdomains: [],
            totalSubdomains: 0,
            liveHosts: [],
            openPorts: [],
            vulnerabilities: [],
        };

        // Load previous subdomains
        const previousSubdomains = this.loadPreviousSubdomains(domain);
        logger.info(`Previous subdomains: ${previousSubdomains.size}`);

        // Phase 1: Subdomain Discovery
        logger.info('\n📡 Phase 1: Subdomain Discovery');
        const currentSubdomains = new Set<string>();

        if (await subfinder.isAvailable()) {
            const subfinderResults = await subfinder.run({ domain, recursive: true });
            subfinderResults.forEach(r => currentSubdomains.add(r.subdomain));
        }

        // Also run amass if available
        if (await externalTools.isToolAvailable('amass')) {
            try {
                const { stdout } = await externalTools.runCommand('amass', [
                    'enum', '-passive', '-d', domain, '-silent'
                ], { timeout: 300000 });
                stdout.split('\n').filter(s => s.trim()).forEach(s => currentSubdomains.add(s.trim()));
            } catch (error) {
                logger.warn('Amass failed', { error: String(error) });
            }
        }

        // Also run assetfinder if available
        if (await externalTools.isToolAvailable('assetfinder')) {
            try {
                const { stdout } = await externalTools.runCommand('assetfinder', [
                    '--subs-only', domain
                ], { timeout: 120000 });
                stdout.split('\n').filter(s => s.trim()).forEach(s => currentSubdomains.add(s.trim()));
            } catch (error) {
                logger.warn('Assetfinder failed', { error: String(error) });
            }
        }

        result.totalSubdomains = currentSubdomains.size;
        logger.success(`Found ${currentSubdomains.size} total subdomains`);

        // Find new and removed subdomains
        currentSubdomains.forEach(s => {
            if (!previousSubdomains.has(s)) {
                result.newSubdomains.push(s);
            }
        });

        previousSubdomains.forEach(s => {
            if (!currentSubdomains.has(s)) {
                result.removedSubdomains.push(s);
            }
        });

        if (result.newSubdomains.length > 0) {
            logger.success(`🆕 NEW SUBDOMAINS FOUND: ${result.newSubdomains.length}`);
            result.newSubdomains.forEach(s => logger.info(`  + ${s}`));
        }

        if (result.removedSubdomains.length > 0) {
            logger.warn(`Removed subdomains: ${result.removedSubdomains.length}`);
        }

        // Save current subdomains
        this.saveSubdomains(domain, Array.from(currentSubdomains));

        // Phase 2: HTTP Probing
        if (currentSubdomains.size > 0 && await httpx.isAvailable()) {
            // Phase 2: Live Host Discovery (httpx)
            logger.info('\n🌐 Phase 2: Live Host Discovery');
            logger.info(`Running httpx to probe ${currentSubdomains.size} unique subdomains...`);

            const httpxResults = await httpx.run({
                targets: Array.from(currentSubdomains),
                timeout: 10,
                threads: 50,
                techDetect: true,
                statusCode: true,
            });

            logger.success(`Found ${httpxResults.length} live hosts via httpx`);

            // Save live hosts
            for (const r of httpxResults) {
                if (!result.liveHosts.includes(r.url)) {
                    result.liveHosts.push(r.url);
                }
            }
        } else if (currentSubdomains.size === 0) {
            logger.info('\n🌐 Phase 2: HTTP Probing skipped (no subdomains found)');
        }

        // Phase 3: Smart Port Scanning
        if (config.scanning.enabled && await nmap.isAvailable() && currentSubdomains.size > 0) {
            logger.info('\n🔌 Phase 3: Smart Port Scanning');

            // Get unique hosts for scanning (limit to 50 to avoid overload)
            const hostsToScan = Array.from(currentSubdomains).slice(0, 50);

            // Quick scan: top ports only
            logger.info(`Running quick scan on ${hostsToScan.length} hosts (top ${config.scanning.nmapTopPorts} ports)...`);
            const quickResults = await nmap.run({
                targets: hostsToScan,
                topPorts: config.scanning.nmapTopPorts,
                timing: 4,
            });

            // Collect interesting hosts for full scan
            const interestingHosts: string[] = [];
            const interestingPorts = config.scanning.fullScanPorts || [8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090];
            const httpPorts = [80, 443, 8080, 8443, 8000, 8008, 3000, 5000, 8888];

            for (const host of quickResults) {
                for (const port of host.ports) {
                    if (port.state === 'open') {
                        result.openPorts.push({
                            host: host.ip || host.hostname,
                            port: port.port,
                            service: port.service || 'unknown',
                        });

                        // BACKFILL: If Nmap finds open HTTP port, add to liveHosts if missing
                        if (httpPorts.includes(port.port)) {
                            const protocol = port.port === 443 || port.port === 8443 ? 'https' : 'http';
                            const url = `${protocol}://${host.hostname || host.ip}${port.port !== 80 && port.port !== 443 ? `:${port.port}` : ''}`;
                            if (!result.liveHosts.includes(url)) {
                                result.liveHosts.push(url);
                                logger.info(`   + Added ${url} to live hosts (found via Nmap)`);
                            }
                        }

                        // Check if this is an interesting port that warrants full scan
                        if (interestingPorts.includes(port.port)) {
                            interestingHosts.push(host.ip || host.hostname);
                        }
                    }
                }
            }

            logger.success(`Found ${result.openPorts.length} open ports`);

            // Full scan on interesting hosts only
            if (interestingHosts.length > 0 && interestingHosts.length <= 10) {
                logger.info(`Running full port scan on ${interestingHosts.length} interesting hosts...`);
                const fullResults = await nmap.fullScan(interestingHosts);

                for (const host of fullResults) {
                    for (const port of host.ports) {
                        if (port.state === 'open') {
                            // Add if not already in results
                            const exists = result.openPorts.some(
                                p => p.host === (host.ip || host.hostname) && p.port === port.port
                            );
                            if (!exists) {
                                result.openPorts.push({
                                    host: host.ip || host.hostname,
                                    port: port.port,
                                    service: port.service || 'unknown',
                                });

                                // BACKFILL: Start full scan results too
                                const protocol = port.port === 443 || port.port === 8443 ? 'https' : 'http';
                                const url = `${protocol}://${host.hostname || host.ip}${port.port !== 80 && port.port !== 443 ? `:${port.port}` : ''}`;
                                if (!result.liveHosts.includes(url) && httpPorts.includes(port.port)) {
                                    result.liveHosts.push(url);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Phase 4: Nuclei Vulnerability Scanning
        if (config.scanning.enabled && await nuclei.isAvailable()) {
            // Use Nmap-verified hosts if available, otherwise fallback to subdomains
            const targets = result.liveHosts.length > 0
                ? result.liveHosts
                : Array.from(currentSubdomains).map(s => `https://${s}`);

            if (targets.length > 0) {
                logger.info('\n🔥 Phase 4: Nuclei Vulnerability Scanning');
                const nucleiResults = await nuclei.run({
                    targets: targets.slice(0, 100), // Limit to 100 targets
                    severity: config.scanning.nucleiSeverity,
                    rateLimit: 100,
                });

                for (const nr of nucleiResults) {
                    result.vulnerabilities.push({
                        host: nr.host,
                        name: nr.info.name,
                        severity: nr.info.severity,
                    });

                    // Save to database
                    const targetRecord = db.getTargetByDomain(domain);
                    if (targetRecord) {
                        db.createFinding({
                            id: uuidv4(),
                            targetId: targetRecord.id,
                            type: nr.info.name,
                            severity: nr.info.severity === 'unknown' ? 'info' : nr.info.severity,
                            url: nr.host,
                            evidence: nr.matched || '',
                            description: nr.info.description || `Detected by Nuclei: ${nr.templateId}`,
                            aiAnalysis: undefined,
                            confidence: 0.9,
                            status: 'new',
                        });
                    }

                    logger.success(`Found ${result.vulnerabilities.length} vulnerabilities`);
                }
            }

            // Phase 4.5: Aggressive Discovery (Optional)
            if (config.scanning.enabled && config.scanning.aggressive) {
                logger.info('\n🧨 Phase 4.5: Aggressive Discovery (Fuzzing & Parameters)');

                // 1. Active Fuzzing
                if (await ffuf.isAvailable()) {
                    const fuzzTargets = result.liveHosts.slice(0, 5); // Limit to top 5 hosts for monitoring speed
                    logger.info(`Running ffuf on ${fuzzTargets.length} hosts...`);

                    for (const target of fuzzTargets) {
                        const paths = await ffuf.discoverDirectories(target);
                        for (const path of paths) {
                            // Log only interesting files that are not just simple 200s (e.g. look for sensitive keywords in url)
                            if (path.url.includes('admin') || path.url.includes('config') || path.url.includes('backup')) {
                                result.vulnerabilities.push({
                                    host: target,
                                    name: `Exposed File: ${path.url}`,
                                    severity: 'medium',
                                });

                                // Resolve UUID for FK
                                const targetRecord = db.getTargetByDomain(domain);
                                if (targetRecord) {
                                    db.createFinding({
                                        id: uuidv4(),
                                        targetId: targetRecord.id, // Use UUID
                                        type: `Exposed File: ${path.url}`,
                                        severity: 'medium',
                                        url: path.url,
                                        evidence: `Fuzzing found ${path.url} (Status: ${path.status})`,
                                        description: `Fuzzing detected a potentially interesting file or directory.`,
                                        confidence: 1.0,
                                        status: 'new',
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Phase 5: Screenshots (using Eyewitness if available)
            if (config.screenshots.enabled) {
                logger.info('\n📸 Phase 5: Screenshots');

                // Check if eyewitness is available using shell
                let eyewitnessAvailable = false;
                try {
                    const { exitCode } = await externalTools.runCommand('which', ['eyewitness'], { timeout: 5000 });
                    eyewitnessAvailable = exitCode === 0;
                } catch {
                    eyewitnessAvailable = false;
                }

                if (eyewitnessAvailable) {
                    const screenshotDir = path.join(this.dataDir, 'screenshots', domain.replace(/\./g, '_'),
                        new Date().toISOString().split('T')[0]);

                    if (!fs.existsSync(screenshotDir)) {
                        fs.mkdirSync(screenshotDir, { recursive: true });
                    }

                    // Create URL list file
                    const urlFile = path.join(screenshotDir, 'urls.txt');
                    fs.writeFileSync(urlFile, result.liveHosts.join('\n'));

                    try {
                        await externalTools.runCommand('eyewitness', [
                            '-f', urlFile,
                            '-d', screenshotDir,
                            '--no-prompt',
                            '--timeout', '30',
                        ], { timeout: 600000 });

                        result.screenshotsPath = screenshotDir;
                        logger.success(`Screenshots saved to: ${screenshotDir}`);
                    } catch (error) {
                        logger.warn('Eyewitness failed', { error: String(error) });
                    }
                } else {
                    logger.warn('Eyewitness not available, skipping screenshots');
                }
            }

            // Save history
            this.appendHistory(domain, result);

            // Send notifications if there are new findings
            if (result.newSubdomains.length > 0 || result.vulnerabilities.length > 0) {
                await this.sendNotification(config.notifications, result);
            }

            // Summary
            logger.banner('Monitoring Cycle Complete');
            logger.info(`📊 Summary for ${domain}:`);
            logger.info(`   New Subdomains: ${result.newSubdomains.length}`);
            logger.info(`   Total Subdomains: ${result.totalSubdomains}`);
            logger.info(`   Live Hosts: ${result.liveHosts.length}`);
            logger.info(`   Open Ports: ${result.openPorts.length}`);
            logger.info(`   Vulnerabilities: ${result.vulnerabilities.length}`);

            return result;
        }

        return result;
    }

    async monitorAll(config: MonitorConfig): Promise<MonitorResult[]> {
        const results: MonitorResult[] = [];

        for (const domain of config.targets) {
            try {
                const result = await this.runMonitoringCycle(domain, config);
                results.push(result);
            } catch (error) {
                logger.error(`Failed to monitor ${domain}`, { error: String(error) });
            }
        }

        return results;
    }
}

export const subdomainMonitor = new SubdomainMonitor();

