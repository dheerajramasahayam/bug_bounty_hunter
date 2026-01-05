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

        // MIGRATION: Sync targets from config file to Database
        this.syncConfigTargetsToDB(config);

        // Initial runs
        // Initial runs
        if (config.discovery.enabled) {
            this.runDiscoverySafe(config);

            // Schedule recurring discovery
            const discoveryInterval = Math.max(config.discovery.intervalHours, 0.1) * 60 * 60 * 1000;
            this.discoveryTimer = setInterval(() => {
                if (this.running) {
                    this.runDiscoverySafe(config);
                }
            }, discoveryInterval);

            logger.info(`📅 Discovery scheduled every ${config.discovery.intervalHours} hours`);
        }

        if (config.monitoring.enabled) {
            // Wait a bit before starting monitoring to let discovery complete
            await new Promise(resolve => setTimeout(resolve, 5000));

            this.runMonitoringSafe(config);

            // Schedule recurring monitoring
            const monitoringInterval = Math.max(config.monitoring.intervalHours, 0.1) * 60 * 60 * 1000;
            this.monitoringTimer = setInterval(() => {
                if (this.running) {
                    this.runMonitoringSafe(config);
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

    private syncConfigTargetsToDB(config: DaemonConfig) {
        if (config.monitoring.config.targets && config.monitoring.config.targets.length > 0) {
            logger.info(`Syncing ${config.monitoring.config.targets.length} targets from config to database...`);
            let added = 0;
            for (const domain of config.monitoring.config.targets) {
                // Check if exists
                if (!db.getTargetByDomain(domain)) {
                    try {
                        db.createTarget({
                            id: uuidv4(),
                            domain: domain,
                            platform: 'manual',
                            programUrl: '',
                            scope: [],
                            outOfScope: [],
                        });
                        added++;
                    } catch (e) {
                        // Ignore
                    }
                }
            }
            if (added > 0) {
                logger.success(`Migrated ${added} manual targets to database`);
            }
        }
    }

    private isDiscoveryRunning = false;
    private isMonitoringRunning = false;

    private async runDiscoverySafe(config: DaemonConfig) {
        if (this.isDiscoveryRunning) return;
        this.isDiscoveryRunning = true;
        await this.runDiscovery(config);
        this.isDiscoveryRunning = false;
        logger.info(`clock 🕒 Next discovery run in ${config.discovery.intervalHours} hours`);
    }

    private async runMonitoringSafe(config: DaemonConfig) {
        if (this.isMonitoringRunning) return;
        this.isMonitoringRunning = true;
        await this.runMonitoring(config);
        this.isMonitoringRunning = false;
        logger.info(`clock 🕒 Next monitoring run in ${config.monitoring.intervalHours} hours`);
    }

    private async runDiscovery(config: DaemonConfig): Promise<void> {
        logger.info('\n🔍 Running program discovery...');

        try {
            // Run standard platform discovery
            const programs = await programDiscovery.discoverAll(config.discovery.config);

            // Run Google discovery
            const googleResults = await this.googleDiscovery.discover();

            // Convert google results to program format 
            const googlePrograms = googleResults.map(g => ({
                id: `google-${g.domain}`,
                name: g.title,
                platform: 'google-dork',
                programUrl: g.url,
                domains: [g.domain],
                isNew: true,
                bountyRange: { min: 0, max: 0 },
                type: 'vdp',
                scope: [],
                outOfScope: []
            }));

            // Use 'any' to bypass strict type check for mixed arrays
            const allPrograms: any[] = [...programs, ...googlePrograms];

            if (config.autoAddNewTargets) {
                const newPrograms = allPrograms.filter((p: any) => p.isNew);

                // Fetch current targets from DB, NOT config
                const allDbTargets = db.getAllTargets();
                const currentTargetCount = allDbTargets.length;
                const monitoredDomains = new Set(allDbTargets.map(t => t.domain));

                for (const program of newPrograms) {
                    if (currentTargetCount >= config.maxTargets) {
                        logger.warn(`Max targets limit (${config.maxTargets}) reached`);
                        break;
                    }

                    for (const domain of program.domains) {
                        if (!monitoredDomains.has(domain)) {

                            // Save to DB
                            try {
                                db.createTarget({
                                    id: uuidv4(),
                                    domain: domain,
                                    platform: program.platform,
                                    programUrl: program.programUrl || '',
                                    scope: program.scope || [],
                                    outOfScope: program.outOfScope || [],
                                });
                                logger.success(`Auto-added new target to DB: ${domain}`);
                                monitoredDomains.add(domain); // Track locally
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
            // Fetch targets from DATABASE, ignoring config file list
            const targets = db.getAllTargets();
            const targetDomains = targets.map(t => t.domain);

            if (targetDomains.length === 0) {
                logger.warn('No targets found in database. Add targets via CLI or enable auto-discovery.');
                return;
            }

            logger.info(`Monitoring ${targetDomains.length} targets from database`);

            // Update config object locally for the monitor execution
            const monitorConfig = {
                ...config.monitoring.config,
                targets: targetDomains,
                scanning: {
                    ...config.monitoring.config.scanning,
                    aggressive: config.monitoring.config.scanning.aggressive
                }
            };

            const results = await subdomainMonitor.monitorAll(monitorConfig);

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
        this.syncConfigTargetsToDB(config);

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
                },
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
        autoAddNewTargets: true,
        maxTargets: 100, // Max 100 targets to monitor
    };
}
