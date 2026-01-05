import { externalTools } from './external.js';
import { logger } from '../core/logger.js';
import fs from 'fs';
import path from 'path';
import os from 'os';

export interface NucleiResult {
    template: string;
    templateId: string;
    templatePath: string;
    info: {
        name: string;
        author: string[];
        severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
        description: string;
        reference: string[];
        tags: string[];
    };
    type: string;
    host: string;
    matched: string;
    extractedResults: string[];
    ip: string;
    timestamp: string;
    curl: string;
    matcherName: string;
    matcherStatus: boolean;
}

export interface NucleiOptions {
    targets: string[];
    templates?: string[];
    tags?: string[];
    excludeTags?: string[];
    severity?: ('critical' | 'high' | 'medium' | 'low' | 'info')[];
    timeout?: number;
    rateLimit?: number;
    bulkSize?: number;
    concurrency?: number;
    headless?: boolean;
    newTemplates?: boolean;
    automaticScan?: boolean;
}

class NucleiWrapper {
    async isAvailable(): Promise<boolean> {
        return externalTools.isToolAvailable('nuclei');
    }

    async updateTemplates(): Promise<boolean> {
        if (!await this.isAvailable()) {
            return false;
        }

        logger.info('Updating Nuclei templates...');

        try {
            await externalTools.runCommand('nuclei', ['-update-templates', '-silent'], {
                timeout: 300000,
            });
            logger.success('Nuclei templates updated');
            return true;
        } catch (error) {
            logger.error('Failed to update Nuclei templates', { error: String(error) });
            return false;
        }
    }

    async run(options: NucleiOptions): Promise<NucleiResult[]> {
        if (!await this.isAvailable()) {
            logger.warn('Nuclei not available');
            return [];
        }

        if (!options.targets || options.targets.length === 0) {
            logger.warn('Nuclei called with no targets');
            return [];
        }

        const args: string[] = [
            '-silent',
            '-json',
            '-nc', // No color
        ];

        // Severity filter
        if (options.severity && options.severity.length > 0) {
            args.push('-severity', options.severity.join(','));
        }

        // Tags
        if (options.tags && options.tags.length > 0) {
            args.push('-tags', options.tags.join(','));
        }

        // Exclude tags
        if (options.excludeTags && options.excludeTags.length > 0) {
            args.push('-exclude-tags', options.excludeTags.join(','));
        }

        // Templates
        if (options.templates && options.templates.length > 0) {
            for (const template of options.templates) {
                args.push('-t', template);
            }
        }

        // Rate limiting
        if (options.rateLimit) {
            args.push('-rate-limit', options.rateLimit.toString());
        }

        // Bulk size
        if (options.bulkSize) {
            args.push('-bulk-size', options.bulkSize.toString());
        }

        // Concurrency
        if (options.concurrency) {
            args.push('-c', options.concurrency.toString());
        }

        // Headless for browser-based templates
        if (options.headless) {
            args.push('-headless');
        }

        // New templates only
        if (options.newTemplates) {
            args.push('-new-templates');
        }

        // Automatic scan (smart template selection)
        if (options.automaticScan) {
            args.push('-automatic-scan');
        }

        // Create temporary file with targets
        const tempFile = path.join(os.tmpdir(), `nuclei-targets-${Date.now()}.txt`);
        fs.writeFileSync(tempFile, options.targets.join('\n'));
        args.push('-l', tempFile);

        logger.info(`Running Nuclei on ${options.targets.length} targets...`);

        try {
            const results: NucleiResult[] = [];

            const { stdout, exitCode } = await externalTools.runCommand('nuclei', args, {
                timeout: options.timeout || 1800000, // 30 minutes default
                onData: (data) => {
                    // Parse results as they come in
                    const lines = data.split('\n').filter(line => line.trim());
                    for (const line of lines) {
                        try {
                            const json = JSON.parse(line);
                            if (json.info && json.host) {
                                logger.vulnerability(
                                    json.info.name || json['template-id'],
                                    json.info.severity || 'info',
                                    json.host
                                );
                            }
                        } catch {
                            // Not JSON, skip
                        }
                    }
                },
            });

            // Cleanup temp file
            fs.unlinkSync(tempFile);

            if (exitCode !== 0 && exitCode !== null) {
                logger.warn(`Nuclei exited with code ${exitCode}`);
            }

            // Parse all results
            const lines = stdout.split('\n').filter(line => line.trim());
            for (const line of lines) {
                try {
                    const json = JSON.parse(line);
                    results.push({
                        template: json.template || '',
                        templateId: json['template-id'] || '',
                        templatePath: json['template-path'] || '',
                        info: {
                            name: json.info?.name || '',
                            author: json.info?.author || [],
                            severity: json.info?.severity || 'unknown',
                            description: json.info?.description || '',
                            reference: json.info?.reference || [],
                            tags: json.info?.tags || [],
                        },
                        type: json.type || '',
                        host: json.host || '',
                        matched: json.matched || json['matched-at'] || '',
                        extractedResults: json['extracted-results'] || [],
                        ip: json.ip || '',
                        timestamp: json.timestamp || new Date().toISOString(),
                        curl: json['curl-command'] || '',
                        matcherName: json['matcher-name'] || '',
                        matcherStatus: json['matcher-status'] || false,
                    });
                } catch {
                    // Skip invalid lines
                }
            }

            logger.success(`Nuclei found ${results.length} vulnerabilities`);
            return results;
        } catch (error) {
            logger.error('Nuclei failed', { error: String(error) });
            return [];
        }
    }

    // Convenience methods for common scan types
    async scanCriticalHigh(targets: string[]): Promise<NucleiResult[]> {
        return this.run({
            targets,
            severity: ['critical', 'high'],
            rateLimit: 100,
        });
    }

    async scanCves(targets: string[]): Promise<NucleiResult[]> {
        return this.run({
            targets,
            tags: ['cve'],
            severity: ['critical', 'high', 'medium'],
        });
    }

    async scanExposures(targets: string[]): Promise<NucleiResult[]> {
        return this.run({
            targets,
            tags: ['exposure', 'config', 'misconfiguration'],
        });
    }

    async scanTakeovers(targets: string[]): Promise<NucleiResult[]> {
        return this.run({
            targets,
            tags: ['takeover'],
        });
    }

    async fullScan(targets: string[]): Promise<NucleiResult[]> {
        return this.run({
            targets,
            automaticScan: true,
            rateLimit: 150,
            concurrency: 25,
        });
    }
}

export const nuclei = new NucleiWrapper();
