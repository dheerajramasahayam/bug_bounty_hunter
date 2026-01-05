import { externalTools } from './external.js';
import { logger } from '../core/logger.js';

export interface HttpxResult {
    url: string;
    statusCode: number;
    contentLength: number;
    contentType: string;
    title: string;
    webServer: string;
    technologies: string[];
    host: string;
    port: number;
    scheme: string;
    failed: boolean;
}

export interface HttpxOptions {
    targets: string[];
    timeout?: number;
    threads?: number;
    followRedirects?: boolean;
    techDetect?: boolean;
    statusCode?: boolean;
    contentLength?: boolean;
    title?: boolean;
    webServer?: boolean;
}

class HttpxWrapper {
    async isAvailable(): Promise<boolean> {
        return externalTools.isToolAvailable('httpx');
    }

    async run(options: HttpxOptions): Promise<HttpxResult[]> {
        if (!await this.isAvailable()) {
            logger.warn('httpx not available');
            return [];
        }

        if (!options.targets || options.targets.length === 0) {
            logger.warn('httpx called with no targets');
            return [];
        }

        const args: string[] = [
            '-silent',
            '-json',
        ];

        if (options.timeout) {
            args.push('-timeout', options.timeout.toString());
        }

        if (options.threads) {
            args.push('-threads', options.threads.toString());
        }

        if (options.followRedirects !== false) {
            args.push('-follow-redirects');
        }

        if (options.techDetect !== false) {
            args.push('-tech-detect');
        }

        if (options.statusCode !== false) {
            args.push('-status-code');
        }

        if (options.contentLength !== false) {
            args.push('-content-length');
        }

        if (options.title !== false) {
            args.push('-title');
        }

        if (options.webServer !== false) {
            args.push('-web-server');
        }

        // Create temporary file with targets
        const fs = await import('fs');
        const path = await import('path');
        const os = await import('os');

        const tempFile = path.join(os.tmpdir(), `httpx-targets-${Date.now()}.txt`);
        fs.writeFileSync(tempFile, options.targets.join('\n'));
        args.push('-l', tempFile);

        logger.info(`Running httpx on ${options.targets.length} targets...`);

        try {
            const { stdout, exitCode } = await externalTools.runCommand('httpx', args, {
                timeout: 600000, // 10 minutes
            });

            // Cleanup temp file
            fs.unlinkSync(tempFile);

            if (exitCode !== 0) {
                logger.warn(`httpx exited with code ${exitCode}`);
            }

            const results: HttpxResult[] = [];
            const lines = stdout.split('\n').filter(line => line.trim());

            for (const line of lines) {
                try {
                    const json = JSON.parse(line);
                    results.push({
                        url: json.url || '',
                        statusCode: json['status-code'] || json.status_code || 0,
                        contentLength: json['content-length'] || json.content_length || 0,
                        contentType: json['content-type'] || json.content_type || '',
                        title: json.title || '',
                        webServer: json['web-server'] || json.webserver || '',
                        technologies: json.technologies || json.tech || [],
                        host: json.host || '',
                        port: json.port || 80,
                        scheme: json.scheme || 'http',
                        failed: json.failed || false,
                    });
                } catch {
                    // Skip invalid lines
                }
            }

            logger.success(`httpx probed ${results.length} live hosts`);
            return results;
        } catch (error) {
            logger.error('httpx failed', { error: String(error) });
            return [];
        }
    }

    async probeUrls(urls: string[]): Promise<HttpxResult[]> {
        return this.run({
            targets: urls,
            techDetect: true,
            title: true,
            statusCode: true,
            webServer: true,
        });
    }
}

export const httpx = new HttpxWrapper();
