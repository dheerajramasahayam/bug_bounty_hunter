import { subdomainMonitor, MonitorConfig } from '../monitor/subdomain-monitor.js';
import { programDiscovery, DiscoveryConfig } from '../discovery/program-discovery.js';
import { GoogleSearchDiscovery } from '../discovery/google-search.js';
import { logger } from '../core/logger.js';
import { db } from '../core/database.js';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';

export interface DaemonConfig {
    discovery: {
        enabled: boolean;
        intervalHours: number;
        config: DiscoveryConfig;
    };
    monitoring: {
        enabled: boolean;
        intervalHours: number;
        config: MonitorConfig;
    };
    autoAddNewTargets: boolean;
    maxTargets: number;
}

class ContinuousRunner {
    private running = false;
    private discoveryTimer: NodeJS.Timeout | null = null;
    private monitoringTimer: NodeJS.Timeout | null = null;
    private googleDiscovery = new GoogleSearchDiscovery();

    async start(config: DaemonConfig): Promise<void> {
        logger.banner('🤖 BugHunter AI - Continuous Mode');
        logger.info('Starting 24/7 automated hunting...');

        this.running = true;
        db.initialize();

        // Initial runs
        if (config.discovery.enabled) {
            await this.runDiscovery(config);

            // Schedule recurring discovery
            const discoveryInterval = config.discovery.intervalHours * 60 * 60 * 1000;
            this.discoveryTimer = setInterval(async () => {
                if (this.running) {
                    await this.runDiscovery(config);
                }
            }, discoveryInterval);

            logger.info(`📅 Discovery scheduled every ${config.discovery.intervalHours} hours`);
        }

        if (config.monitoring.enabled) {
            // Wait a bit before starting monitoring to let discovery complete
            await new Promise(resolve => setTimeout(resolve, 5000));

            await this.runMonitoring(config);

            // Schedule recurring monitoring
            const monitoringInterval = config.monitoring.intervalHours * 60 * 60 * 1000;
            this.monitoringTimer = setInterval(async () => {
                if (this.running) {
                    await this.runMonitoring(config);
                }
            }, monitoringInterval);

            logger.info(`📅 Monitoring scheduled every ${config.monitoring.intervalHours} hours`);
        }

        // Keep process alive
        process.on('SIGINT', () => this.stop());
        process.on('SIGTERM', () => this.stop());

        logger.success('🚀 Continuous runner started! Press Ctrl+C to stop.');
        logger.info('The daemon will now run 24/7, discovering new programs and monitoring targets.');
    }

    private async runDiscovery(config: DaemonConfig): Promise<void> {
        logger.info('\n🔍 Running program discovery...');

        try {
            // Run standard platform discovery
            const programs = await programDiscovery.discoverAll(config.discovery.config);

            // Run Google discovery
            const googleResults = await this.googleDiscovery.discover();

            // Convert google results to program format for consistency
            const googlePrograms = googleResults.map(g => ({
                id: `google-${g.domain}`,
                name: g.title,
                platform: 'google-dork',
                url: g.url,
                domains: [g.domain],
                isNew: true, // Always treat as potentially new
                bountyRange: 'Unknown',
                type: 'unknown'
            }));

            const allPrograms = [...programs, ...googlePrograms];

            if (config.autoAddNewTargets) {
                const newPrograms = allPrograms.filter(p => p.isNew);
                const currentTargets = config.monitoring.config.targets.length;

                for (const program of newPrograms) {
                    if (currentTargets + config.monitoring.config.targets.length >= config.maxTargets) {
                        logger.warn(`Max targets limit (${config.maxTargets}) reached`);
                        break;
                    }

                    for (const domain of program.domains) {
                        if (!config.monitoring.config.targets.includes(domain)) {
                            config.monitoring.config.targets.push(domain);
                            logger.success(`Auto-added new target: ${domain}`);

                            // Save to DB
                            try {
                                db.createTarget({
                                    id: uuidv4(),
                                    domain: domain,
                                    platform: program.platform,
                                    programUrl: program.url || '',
                                    scope: [],
                                    outOfScope: [],
                                });
                            } catch (e) {
                                // Ignore duplicate domain errors
                            }
                        }
                    }
                }
            }
        } catch (error) {
            logger.error('Discovery failed', { error: String(error) });
        }
    }

    private async runMonitoring(config: DaemonConfig): Promise<void> {
        logger.info('\n📡 Running subdomain monitoring...');

        try {
            if (config.monitoring.config.targets.length === 0) {
                logger.warn('No targets to monitor. Add targets or enable auto-discovery.');
                return;
            }

            const results = await subdomainMonitor.monitorAll(config.monitoring.config);

            // Summary
            let totalNew = 0;
            let totalVulns = 0;

            for (const result of results) {
                totalNew += result.newSubdomains.length;
                totalVulns += result.vulnerabilities.length;
            }

            if (totalNew > 0 || totalVulns > 0) {
                logger.success(`Monitoring complete: ${totalNew} new subdomains, ${totalVulns} vulnerabilities`);
            }
        } catch (error) {
            logger.error('Monitoring failed', { error: String(error) });
        }
    }

    stop(): void {
        logger.info('\n⏹️ Stopping continuous runner...');
        this.running = false;

        if (this.discoveryTimer) {
            clearInterval(this.discoveryTimer);
            this.discoveryTimer = null;
        }

        if (this.monitoringTimer) {
            clearInterval(this.monitoringTimer);
            this.monitoringTimer = null;
        }

        logger.success('Continuous runner stopped.');
        process.exit(0);
    }

    async runOnce(config: DaemonConfig): Promise<void> {
        logger.banner('🤖 BugHunter AI - Single Run');
        db.initialize();

        if (config.discovery.enabled) {
            await this.runDiscovery(config);
        }

        if (config.monitoring.enabled) {
            await this.runMonitoring(config);
        }

        logger.success('Single run complete!');
    }
}

export const continuousRunner = new ContinuousRunner();

// Default config
export function getDefaultDaemonConfig(): DaemonConfig {
    return {
        discovery: {
            enabled: true,
            intervalHours: 6, // Check for new programs every 6 hours
            config: {
                platforms: {
                    hackerone: true,
                    bugcrowd: true,
                    intigriti: true,
                },
                filters: {
                    minBounty: 100, // Only programs paying at least $100
                    onlyNew: false,
                    excludeVDP: true, // Only bug bounties, not VDPs
                    keywords: [],
                },
                notifications: {},
            },
        },
        monitoring: {
            enabled: true,
            intervalHours: 24, // Monitor subdomains daily
            config: {
                targets: [],
                outputDir: 'data/monitoring',
                notifications: {
                    enabled: true,
                    scanning: {
                        enabled: true,
                        nmapTopPorts: 1000,
                        fullScanPorts: [8080, 8443, 8000, 8888, 3000, 5000],
                        nucleiSeverity: ['critical', 'high', 'medium'],
                    },
                    screenshots: {
                        enabled: false,
                    },
                },
            },
        },
        autoAddNewTargets: true,
        maxTargets: 100, // Max 100 targets to monitor
    };
}
