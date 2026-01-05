import axios from 'axios';
import { logger } from '../core/logger.js';
import { getConfig } from '../config/settings.js';
import { subfinder } from '../tools/subfinder.js';

export interface SubdomainResult {
    subdomain: string;
    source: string;
    ip?: string;
    isAlive?: boolean;
}

export interface ReconResult {
    domain: string;
    subdomains: SubdomainResult[];
    timestamp: string;
}

class SubdomainEnumerator {
    private get config() { return getConfig(); }
    private get userAgent() { return this.config.scanner.userAgent; }

    async enumerate(domain: string, useExternalTools: boolean = true): Promise<ReconResult> {
        logger.info(`Starting subdomain enumeration for: ${domain}`);

        const results: SubdomainResult[] = [];

        // Try Subfinder first if external tools are enabled
        if (useExternalTools && await subfinder.isAvailable()) {
            logger.info('Using Subfinder for subdomain enumeration...');
            const subfinderResults = await subfinder.run({ domain, recursive: true });
            results.push(...subfinderResults.map(r => ({
                subdomain: r.subdomain,
                source: r.source,
            })));
        }

        // Always run API-based sources as well for completeness
        const sources = [
            this.fromCrtSh(domain),
            this.fromHackerTarget(domain),
            this.fromUrlscan(domain),
        ];

        // If API keys are configured, add those sources
        if (this.config.apis.securityTrails) {
            sources.push(this.fromSecurityTrails(domain));
        }

        const sourceResults = await Promise.allSettled(sources);

        sourceResults.forEach((result) => {
            if (result.status === 'fulfilled') {
                results.push(...result.value);
            } else {
                logger.warn('Subdomain source failed', { error: result.reason });
            }
        });

        // Deduplicate results
        const uniqueSubdomains = new Map<string, SubdomainResult>();
        results.forEach(r => {
            if (!uniqueSubdomains.has(r.subdomain)) {
                uniqueSubdomains.set(r.subdomain, r);
            }
        });

        const finalResults = Array.from(uniqueSubdomains.values());
        logger.success(`Found ${finalResults.length} unique subdomains for ${domain}`);

        return {
            domain,
            subdomains: finalResults,
            timestamp: new Date().toISOString(),
        };
    }

    private async fromCrtSh(domain: string): Promise<SubdomainResult[]> {
        logger.debug('Querying crt.sh...');

        try {
            const response = await axios.get(
                `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`,
                {
                    timeout: 30000,
                    headers: { 'User-Agent': this.userAgent },
                }
            );

            const subdomains = new Set<string>();

            if (Array.isArray(response.data)) {
                response.data.forEach((entry: { name_value: string }) => {
                    const names = entry.name_value.split('\n');
                    names.forEach(name => {
                        // Clean the subdomain
                        const clean = name.toLowerCase().trim().replace(/^\*\./, '');
                        if (clean.endsWith(domain) && !clean.startsWith('*')) {
                            subdomains.add(clean);
                        }
                    });
                });
            }

            logger.debug(`crt.sh found ${subdomains.size} subdomains`);

            return Array.from(subdomains).map(subdomain => ({
                subdomain,
                source: 'crt.sh',
            }));
        } catch (error) {
            logger.warn('crt.sh query failed', { error: String(error) });
            return [];
        }
    }

    private async fromHackerTarget(domain: string): Promise<SubdomainResult[]> {
        logger.debug('Querying HackerTarget...');

        try {
            const response = await axios.get(
                `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
                {
                    timeout: 30000,
                    headers: { 'User-Agent': this.userAgent },
                }
            );

            const subdomains: SubdomainResult[] = [];

            if (typeof response.data === 'string' && !response.data.includes('error')) {
                const lines = response.data.split('\n');
                lines.forEach(line => {
                    const [subdomain, ip] = line.split(',');
                    if (subdomain && subdomain.endsWith(domain)) {
                        subdomains.push({
                            subdomain: subdomain.trim(),
                            source: 'hackertarget',
                            ip: ip?.trim(),
                        });
                    }
                });
            }

            logger.debug(`HackerTarget found ${subdomains.length} subdomains`);
            return subdomains;
        } catch (error) {
            logger.warn('HackerTarget query failed', { error: String(error) });
            return [];
        }
    }

    private async fromUrlscan(domain: string): Promise<SubdomainResult[]> {
        logger.debug('Querying urlscan.io...');

        try {
            const response = await axios.get(
                `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}`,
                {
                    timeout: 30000,
                    headers: { 'User-Agent': this.userAgent },
                }
            );

            const subdomains = new Set<string>();

            if (response.data?.results) {
                response.data.results.forEach((result: { page?: { domain?: string } }) => {
                    const foundDomain = result.page?.domain;
                    if (foundDomain && foundDomain.endsWith(domain)) {
                        subdomains.add(foundDomain);
                    }
                });
            }

            logger.debug(`urlscan.io found ${subdomains.size} subdomains`);

            return Array.from(subdomains).map(subdomain => ({
                subdomain,
                source: 'urlscan.io',
            }));
        } catch (error) {
            logger.warn('urlscan.io query failed', { error: String(error) });
            return [];
        }
    }

    private async fromSecurityTrails(domain: string): Promise<SubdomainResult[]> {
        logger.debug('Querying SecurityTrails...');

        try {
            const response = await axios.get(
                `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains`,
                {
                    timeout: 30000,
                    headers: {
                        'User-Agent': this.userAgent,
                        'APIKEY': this.config.apis.securityTrails!,
                    },
                }
            );

            const subdomains: SubdomainResult[] = [];

            if (response.data?.subdomains) {
                response.data.subdomains.forEach((sub: string) => {
                    subdomains.push({
                        subdomain: `${sub}.${domain}`,
                        source: 'securitytrails',
                    });
                });
            }

            logger.debug(`SecurityTrails found ${subdomains.length} subdomains`);
            return subdomains;
        } catch (error) {
            logger.warn('SecurityTrails query failed', { error: String(error) });
            return [];
        }
    }

    async checkAlive(subdomains: SubdomainResult[]): Promise<SubdomainResult[]> {
        logger.info(`Checking ${subdomains.length} subdomains for HTTP response...`);

        const results: SubdomainResult[] = [];
        const batchSize = this.config.scanner.maxConcurrentRequests;

        for (let i = 0; i < subdomains.length; i += batchSize) {
            const batch = subdomains.slice(i, i + batchSize);

            const checks = batch.map(async (sub) => {
                try {
                    // Try HTTPS first
                    await axios.head(`https://${sub.subdomain}`, {
                        timeout: 5000,
                        maxRedirects: 3,
                        validateStatus: () => true,
                    });
                    return { ...sub, isAlive: true };
                } catch {
                    try {
                        // Fallback to HTTP
                        await axios.head(`http://${sub.subdomain}`, {
                            timeout: 5000,
                            maxRedirects: 3,
                            validateStatus: () => true,
                        });
                        return { ...sub, isAlive: true };
                    } catch {
                        return { ...sub, isAlive: false };
                    }
                }
            });

            const batchResults = await Promise.all(checks);
            results.push(...batchResults);

            logger.progress(Math.min(i + batchSize, subdomains.length), subdomains.length, 'Checking subdomains');
        }

        const alive = results.filter(r => r.isAlive);
        logger.success(`${alive.length}/${subdomains.length} subdomains are alive`);

        return results;
    }
}

export const subdomainEnumerator = new SubdomainEnumerator();
