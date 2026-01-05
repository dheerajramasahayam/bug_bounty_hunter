import { externalTools } from './external.js';
import { logger } from '../core/logger.js';

export interface SubfinderResult {
    subdomain: string;
    source: string;
}

export interface SubfinderOptions {
    domain: string;
    sources?: string[];
    timeout?: number;
    silent?: boolean;
    recursive?: boolean;
    maxEnumerationTime?: number;
}

class SubfinderWrapper {
    async isAvailable(): Promise<boolean> {
        return externalTools.isToolAvailable('subfinder');
    }

    async run(options: SubfinderOptions): Promise<SubfinderResult[]> {
        if (!await this.isAvailable()) {
            logger.warn('Subfinder not available, falling back to built-in enumeration');
            return [];
        }

        const args: string[] = [
            '-d', options.domain,
            '-silent',
            '-json',
        ];

        if (options.sources && options.sources.length > 0) {
            args.push('-s', options.sources.join(','));
        }

        if (options.recursive) {
            args.push('-recursive');
        }

        if (options.maxEnumerationTime) {
            args.push('-max-time', options.maxEnumerationTime.toString());
        }

        logger.info(`Running subfinder for ${options.domain}...`);

        try {
            const { stdout, exitCode } = await externalTools.runCommand('subfinder', args, {
                timeout: options.timeout || 300000,
            });

            if (exitCode !== 0) {
                logger.warn(`Subfinder exited with code ${exitCode}`);
            }

            const results: SubfinderResult[] = [];
            const lines = stdout.split('\n').filter(line => line.trim());

            for (const line of lines) {
                try {
                    const json = JSON.parse(line);
                    results.push({
                        subdomain: json.host || json.subdomain,
                        source: json.source || 'subfinder',
                    });
                } catch {
                    // Plain text output
                    if (line.includes('.')) {
                        results.push({
                            subdomain: line.trim(),
                            source: 'subfinder',
                        });
                    }
                }
            }

            logger.success(`Subfinder found ${results.length} subdomains`);
            return results;
        } catch (error) {
            logger.error('Subfinder failed', { error: String(error) });
            return [];
        }
    }
}

export const subfinder = new SubfinderWrapper();
