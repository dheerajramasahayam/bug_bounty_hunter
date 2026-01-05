import { externalTools } from './external.js';
import { logger } from '../core/logger.js';

export interface NmapPort {
    port: number;
    protocol: string;
    state: string;
    service: string;
    version: string;
    product: string;
    extraInfo: string;
}

export interface NmapHost {
    ip: string;
    hostname: string;
    state: string;
    ports: NmapPort[];
    os: string[];
}

export interface NmapOptions {
    targets: string[];
    ports?: string;
    topPorts?: number;
    serviceDetection?: boolean;
    osDetection?: boolean;
    scriptScan?: boolean;
    scripts?: string[];
    timing?: 0 | 1 | 2 | 3 | 4 | 5;
    timeout?: number;
}

class NmapWrapper {
    async isAvailable(): Promise<boolean> {
        return externalTools.isToolAvailable('nmap');
    }

    async run(options: NmapOptions): Promise<NmapHost[]> {
        if (!await this.isAvailable()) {
            logger.warn('Nmap not available');
            return [];
        }

        const args: string[] = [
            '-oX', '-', // XML output to stdout
        ];

        // Port specification
        if (options.ports) {
            args.push('-p', options.ports);
        } else if (options.topPorts) {
            args.push('--top-ports', options.topPorts.toString());
        }

        // Service detection
        if (options.serviceDetection) {
            args.push('-sV');
        }

        // OS detection (requires root)
        if (options.osDetection) {
            args.push('-O');
        }

        // Script scan
        if (options.scriptScan) {
            args.push('-sC');
        }

        // Custom scripts
        if (options.scripts && options.scripts.length > 0) {
            args.push('--script', options.scripts.join(','));
        }

        // Timing template
        if (options.timing !== undefined) {
            args.push(`-T${options.timing}`);
        }

        // Add targets
        args.push(...options.targets);

        logger.info(`Running Nmap on ${options.targets.length} targets...`);

        try {
            const { stdout, stderr, exitCode } = await externalTools.runCommand('nmap', args, {
                timeout: options.timeout || 600000, // 10 minutes default
            });

            if (exitCode !== 0) {
                logger.warn(`Nmap exited with code ${exitCode}`, { stderr });
            }

            return this.parseXmlOutput(stdout);
        } catch (error) {
            logger.error('Nmap failed', { error: String(error) });
            return [];
        }
    }

    private parseXmlOutput(xml: string): NmapHost[] {
        const hosts: NmapHost[] = [];

        // Simple regex-based XML parsing (for nmap output)
        const hostMatches = xml.matchAll(/<host[^>]*>([\s\S]*?)<\/host>/g);

        for (const hostMatch of hostMatches) {
            const hostXml = hostMatch[1];

            // Extract IP
            const addrMatch = hostXml.match(/<address addr="([^"]+)" addrtype="ipv4"/);
            const ip = addrMatch ? addrMatch[1] : '';

            // Extract hostname
            const hostnameMatch = hostXml.match(/<hostname name="([^"]+)"/);
            const hostname = hostnameMatch ? hostnameMatch[1] : '';

            // Extract state
            const stateMatch = hostXml.match(/<status state="([^"]+)"/);
            const state = stateMatch ? stateMatch[1] : 'unknown';

            // Extract ports
            const ports: NmapPort[] = [];
            const portMatches = hostXml.matchAll(/<port protocol="([^"]+)" portid="(\d+)">([\s\S]*?)<\/port>/g);

            for (const portMatch of portMatches) {
                const portXml = portMatch[3];
                const portStateMatch = portXml.match(/<state state="([^"]+)"/);
                const serviceMatch = portXml.match(/<service name="([^"]*)"[^>]*(?:product="([^"]*)")?[^>]*(?:version="([^"]*)")?[^>]*(?:extrainfo="([^"]*)")?/);

                ports.push({
                    port: parseInt(portMatch[2]),
                    protocol: portMatch[1],
                    state: portStateMatch ? portStateMatch[1] : 'unknown',
                    service: serviceMatch ? serviceMatch[1] : '',
                    product: serviceMatch ? (serviceMatch[2] || '') : '',
                    version: serviceMatch ? (serviceMatch[3] || '') : '',
                    extraInfo: serviceMatch ? (serviceMatch[4] || '') : '',
                });
            }

            // Extract OS
            const os: string[] = [];
            const osMatches = hostXml.matchAll(/<osmatch name="([^"]+)"/g);
            for (const osMatch of osMatches) {
                os.push(osMatch[1]);
            }

            if (ip || hostname) {
                hosts.push({ ip, hostname, state, ports, os });
            }
        }

        logger.success(`Nmap found ${hosts.length} hosts with ${hosts.reduce((sum, h) => sum + h.ports.length, 0)} open ports`);
        return hosts;
    }

    // Convenience methods
    async quickScan(targets: string[]): Promise<NmapHost[]> {
        return this.run({
            targets,
            topPorts: 100,
            timing: 4,
        });
    }

    async fullScan(targets: string[]): Promise<NmapHost[]> {
        return this.run({
            targets,
            ports: '1-65535',
            serviceDetection: true,
            timing: 3,
        });
    }

    async webScan(targets: string[]): Promise<NmapHost[]> {
        return this.run({
            targets,
            ports: '80,443,8080,8443,8000,8888,3000,5000',
            serviceDetection: true,
            scriptScan: true,
            scripts: ['http-title', 'http-headers', 'http-methods'],
        });
    }

    async vulnScan(targets: string[]): Promise<NmapHost[]> {
        return this.run({
            targets,
            topPorts: 1000,
            serviceDetection: true,
            scripts: ['vuln'],
            timing: 3,
        });
    }
}

export const nmap = new NmapWrapper();
