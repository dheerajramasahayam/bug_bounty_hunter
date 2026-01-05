import axios from 'axios';
import { logger } from '../core/logger.js';
import { db } from '../core/database.js';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';

export interface BugBountyProgram {
    name: string;
    platform: 'hackerone' | 'bugcrowd' | 'intigriti' | 'other';
    programUrl: string;
    domains: string[];
    scope: string[];
    outOfScope: string[];
    bountyRange: {
        min: number;
        max: number;
    };
    type: 'vdp' | 'bbp'; // Vulnerability Disclosure Program or Bug Bounty Program
    isNew: boolean;
    lastUpdated: string;
}

export interface DiscoveryConfig {
    platforms: {
        hackerone: boolean;
        bugcrowd: boolean;
        intigriti: boolean;
    };
    filters: {
        minBounty: number;
        onlyNew: boolean;
        excludeVDP: boolean;
        keywords: string[];
    };
    notifications: {
        discordWebhook?: string;
        slackWebhook?: string;
    };
}

class ProgramDiscovery {
    private dataDir: string;
    private knownPrograms: Set<string>;

    constructor() {
        this.dataDir = path.join(process.cwd(), 'data', 'programs');
        this.knownPrograms = new Set();

        if (!fs.existsSync(this.dataDir)) {
            fs.mkdirSync(this.dataDir, { recursive: true });
        }

        this.loadKnownPrograms();
    }

    private loadKnownPrograms(): void {
        const file = path.join(this.dataDir, 'known_programs.json');
        if (fs.existsSync(file)) {
            try {
                const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
                this.knownPrograms = new Set(data.programs || []);
            } catch {
                this.knownPrograms = new Set();
            }
        }
    }

    private saveKnownPrograms(): void {
        const file = path.join(this.dataDir, 'known_programs.json');
        fs.writeFileSync(file, JSON.stringify({
            programs: Array.from(this.knownPrograms),
            lastUpdated: new Date().toISOString(),
        }, null, 2));
    }

    async discoverHackerOne(): Promise<BugBountyProgram[]> {
        logger.info('Discovering programs from HackerOne...');
        const programs: BugBountyProgram[] = [];

        try {
            // HackerOne's public API for directory
            const response = await axios.get('https://hackerone.com/programs/search', {
                params: {
                    query: 'type:hackerone',
                    sort: 'launched_at:descending',
                    page: 1,
                },
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'BugHunter-AI/1.0',
                },
                timeout: 30000,
            });

            if (response.data?.results) {
                for (const program of response.data.results) {
                    const domains = this.extractDomainsFromScope(program.targets?.in_scope || []);

                    programs.push({
                        name: program.name || program.handle,
                        platform: 'hackerone',
                        programUrl: `https://hackerone.com/${program.handle}`,
                        domains,
                        scope: program.targets?.in_scope?.map((t: { asset_identifier: string }) => t.asset_identifier) || [],
                        outOfScope: program.targets?.out_of_scope?.map((t: { asset_identifier: string }) => t.asset_identifier) || [],
                        bountyRange: {
                            min: program.bounty_split_min || 0,
                            max: program.bounty_split_max || 0,
                        },
                        type: program.offers_bounties ? 'bbp' : 'vdp',
                        isNew: !this.knownPrograms.has(program.handle),
                        lastUpdated: new Date().toISOString(),
                    });
                }
            }
        } catch (error) {
            logger.warn('HackerOne API failed, trying alternative method...', { error: String(error) });

            // Fallback: scrape the directory page
            const fallbackPrograms = await this.scrapeHackerOneDirectory();
            programs.push(...fallbackPrograms);
        }

        logger.success(`Found ${programs.length} programs from HackerOne`);
        return programs;
    }

    private async scrapeHackerOneDirectory(): Promise<BugBountyProgram[]> {
        const programs: BugBountyProgram[] = [];

        try {
            // Use the GraphQL endpoint
            const response = await axios.post('https://hackerone.com/graphql', {
                query: `
          query DirectoryQuery($cursor: String) {
            teams(first: 100, after: $cursor, where: { _and: [{ offers_bounties: { _eq: true } }, { state: { _eq: "public_mode" } }] }) {
              edges {
                node {
                  handle
                  name
                  currency
                  offers_bounties
                  base_bounty
                  resolved_report_count
                  launched_at
                }
              }
              pageInfo {
                hasNextPage
                endCursor
              }
            }
          }
        `,
                variables: { cursor: null },
            }, {
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'BugHunter-AI/1.0',
                },
                timeout: 30000,
            });

            const teams = response.data?.data?.teams?.edges || [];

            for (const { node: team } of teams) {
                programs.push({
                    name: team.name,
                    platform: 'hackerone',
                    programUrl: `https://hackerone.com/${team.handle}`,
                    domains: [],
                    scope: [],
                    outOfScope: [],
                    bountyRange: {
                        min: team.base_bounty || 0,
                        max: team.base_bounty * 10 || 0,
                    },
                    type: team.offers_bounties ? 'bbp' : 'vdp',
                    isNew: !this.knownPrograms.has(team.handle),
                    lastUpdated: new Date().toISOString(),
                });
            }
        } catch (error) {
            logger.warn('HackerOne GraphQL failed', { error: String(error) });
        }

        return programs;
    }

    async discoverBugcrowd(): Promise<BugBountyProgram[]> {
        logger.info('Discovering programs from Bugcrowd...');
        const programs: BugBountyProgram[] = [];

        try {
            // Bugcrowd's public programs API
            const response = await axios.get('https://bugcrowd.com/programs.json', {
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'BugHunter-AI/1.0',
                },
                timeout: 30000,
            });

            if (Array.isArray(response.data)) {
                for (const program of response.data) {
                    const handle = program.code || program.program_url?.split('/').pop();

                    programs.push({
                        name: program.name,
                        platform: 'bugcrowd',
                        programUrl: `https://bugcrowd.com${program.program_url || '/' + handle}`,
                        domains: [],
                        scope: program.target_groups?.flatMap((g: { targets: { name: string }[] }) =>
                            g.targets?.map((t: { name: string }) => t.name) || []
                        ) || [],
                        outOfScope: [],
                        bountyRange: {
                            min: program.min_payout || 0,
                            max: program.max_payout || 0,
                        },
                        type: program.max_payout > 0 ? 'bbp' : 'vdp',
                        isNew: !this.knownPrograms.has(handle),
                        lastUpdated: new Date().toISOString(),
                    });
                }
            }
        } catch (error) {
            logger.warn('Bugcrowd API failed', { error: String(error) });
        }

        logger.success(`Found ${programs.length} programs from Bugcrowd`);
        return programs;
    }

    async discoverIntigriti(): Promise<BugBountyProgram[]> {
        logger.info('Discovering programs from Intigriti...');
        const programs: BugBountyProgram[] = [];

        try {
            const response = await axios.get('https://api.intigriti.com/core/public/programs', {
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'BugHunter-AI/1.0',
                },
                timeout: 30000,
            });

            if (Array.isArray(response.data)) {
                for (const program of response.data) {
                    programs.push({
                        name: program.name,
                        platform: 'intigriti',
                        programUrl: `https://app.intigriti.com/programs/${program.handle}`,
                        domains: [],
                        scope: [],
                        outOfScope: [],
                        bountyRange: {
                            min: program.minBounty || 0,
                            max: program.maxBounty || 0,
                        },
                        type: program.maxBounty > 0 ? 'bbp' : 'vdp',
                        isNew: !this.knownPrograms.has(program.handle),
                        lastUpdated: new Date().toISOString(),
                    });
                }
            }
        } catch (error) {
            logger.warn('Intigriti API failed', { error: String(error) });
        }

        logger.success(`Found ${programs.length} programs from Intigriti`);
        return programs;
    }

    private extractDomainsFromScope(scope: { asset_identifier: string; asset_type: string }[]): string[] {
        const domains: string[] = [];

        for (const target of scope) {
            if (target.asset_type === 'URL' || target.asset_type === 'WILDCARD') {
                // Extract domain from URL or wildcard
                const match = target.asset_identifier.match(/(?:\*\.)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})/);
                if (match) {
                    domains.push(match[1]);
                }
            }
        }

        return [...new Set(domains)];
    }

    async discoverAll(config: DiscoveryConfig): Promise<BugBountyProgram[]> {
        logger.banner('Bug Bounty Program Discovery');

        const allPrograms: BugBountyProgram[] = [];

        if (config.platforms.hackerone) {
            const h1Programs = await this.discoverHackerOne();
            allPrograms.push(...h1Programs);
        }

        if (config.platforms.bugcrowd) {
            const bcPrograms = await this.discoverBugcrowd();
            allPrograms.push(...bcPrograms);
        }

        if (config.platforms.intigriti) {
            const intPrograms = await this.discoverIntigriti();
            allPrograms.push(...intPrograms);
        }

        // Apply filters
        let filteredPrograms = allPrograms;

        if (config.filters.minBounty > 0) {
            filteredPrograms = filteredPrograms.filter(p => p.bountyRange.max >= config.filters.minBounty);
        }

        if (config.filters.excludeVDP) {
            filteredPrograms = filteredPrograms.filter(p => p.type === 'bbp');
        }

        if (config.filters.onlyNew) {
            filteredPrograms = filteredPrograms.filter(p => p.isNew);
        }

        if (config.filters.keywords.length > 0) {
            filteredPrograms = filteredPrograms.filter(p =>
                config.filters.keywords.some(k =>
                    p.name.toLowerCase().includes(k.toLowerCase()) ||
                    p.domains.some(d => d.toLowerCase().includes(k.toLowerCase()))
                )
            );
        }

        // Find new programs
        const newPrograms = filteredPrograms.filter(p => p.isNew);

        if (newPrograms.length > 0) {
            logger.success(`🆕 Found ${newPrograms.length} NEW programs!`);

            // Save new programs to database
            for (const program of newPrograms) {
                for (const domain of program.domains) {
                    db.createTarget({
                        id: uuidv4(),
                        domain,
                        scope: program.scope,
                        outOfScope: program.outOfScope,
                        platform: program.platform,
                        programUrl: program.programUrl,
                    });
                }

                // Mark as known
                const handle = program.programUrl.split('/').pop() || program.name;
                this.knownPrograms.add(handle);
            }

            this.saveKnownPrograms();

            // Send notification
            await this.sendNotification(config.notifications, newPrograms);
        }

        // Save discovery results
        this.saveDiscoveryResults(filteredPrograms);

        logger.success(`Total: ${allPrograms.length} programs, ${filteredPrograms.length} after filters, ${newPrograms.length} new`);
        return filteredPrograms;
    }

    private async sendNotification(
        config: DiscoveryConfig['notifications'],
        newPrograms: BugBountyProgram[]
    ): Promise<void> {
        const message = this.formatNotification(newPrograms);

        if (config.discordWebhook) {
            try {
                await axios.post(config.discordWebhook, {
                    content: message,
                    embeds: [{
                        title: '🆕 New Bug Bounty Programs Found!',
                        color: 0x00ff00,
                        fields: newPrograms.slice(0, 10).map(p => ({
                            name: `${p.platform.toUpperCase()}: ${p.name}`,
                            value: `💰 $${p.bountyRange.min}-$${p.bountyRange.max}\n🔗 ${p.programUrl}`,
                            inline: true,
                        })),
                        timestamp: new Date().toISOString(),
                    }],
                });
                logger.success('Discord notification sent for new programs');
            } catch (error) {
                logger.error('Failed to send Discord notification', { error: String(error) });
            }
        }

        if (config.slackWebhook) {
            try {
                await axios.post(config.slackWebhook, {
                    text: message,
                });
                logger.success('Slack notification sent for new programs');
            } catch (error) {
                logger.error('Failed to send Slack notification', { error: String(error) });
            }
        }
    }

    private formatNotification(programs: BugBountyProgram[]): string {
        let msg = `🆕 **New Bug Bounty Programs Found!**\n\n`;

        for (const p of programs.slice(0, 15)) {
            msg += `**${p.name}** (${p.platform})\n`;
            msg += `  💰 $${p.bountyRange.min} - $${p.bountyRange.max}\n`;
            msg += `  🔗 ${p.programUrl}\n\n`;
        }

        if (programs.length > 15) {
            msg += `... and ${programs.length - 15} more programs\n`;
        }

        return msg;
    }

    private saveDiscoveryResults(programs: BugBountyProgram[]): void {
        const file = path.join(this.dataDir, `discovery_${new Date().toISOString().split('T')[0]}.json`);
        fs.writeFileSync(file, JSON.stringify({
            timestamp: new Date().toISOString(),
            count: programs.length,
            programs,
        }, null, 2));
    }

    getKnownProgramsCount(): number {
        return this.knownPrograms.size;
    }
}

export const programDiscovery = new ProgramDiscovery();
