import { google } from 'googleapis';
import { logger } from '../core/logger.js';
import { getConfig } from '../config/settings.js';

export interface GoogleDiscoveryResult {
    url: string;
    title: string;
    snippet: string;
    domain: string;
}

export class GoogleSearchDiscovery {
    private customsearch;
    private apiKey: string;
    private cseId: string;

    // Popular dorks for finding bug bounty programs
    private dorks = [
        'inurl:security.txt "bug bounty"',
        'inurl:security.txt "reward"',
        'inurl:/.well-known/security.txt "reward"',
        'intitle:"bug bounty program" reward',
        'inurl:"/bug-bounty" reward',
        'site:hackerone.com inurl:/policy -site:www.hackerone.com',
        'site:bugcrowd.com inurl:/bounty -site:www.bugcrowd.com'
    ];

    constructor() {
        // We'll read these from the config/env
        // Users will need to add GOOGLE_SEARCH_API_KEY and GOOGLE_CSE_ID to .env
        this.apiKey = process.env.GOOGLE_SEARCH_API_KEY || '';
        this.cseId = process.env.GOOGLE_CSE_ID || '';

        if (this.apiKey) {
            this.customsearch = google.customsearch('v1');
        }
    }

    async discover(limit: number = 10): Promise<GoogleDiscoveryResult[]> {
        if (!this.apiKey || !this.cseId || !this.customsearch) {
            logger.warn('Google Search API Key or CSE ID not configured. Skipping Google discovery.');
            return [];
        }

        const results: GoogleDiscoveryResult[] = [];
        const seenDomains = new Set<string>();

        // Pick a random dork to keep it dynamic
        const dork = this.dorks[Math.floor(Math.random() * this.dorks.length)];
        logger.info(`Running Google Discovery with dork: ${dork}`);

        try {
            const res = await this.customsearch.cse.list({
                cx: this.cseId,
                q: dork,
                auth: this.apiKey,
                num: 10, // Max allowed per request
            });

            if (res.data.items) {
                for (const item of res.data.items) {
                    if (item.link) {
                        try {
                            const urlObj = new URL(item.link);
                            const domain = urlObj.hostname;

                            // Filter out platform domains themselves
                            if (!seenDomains.has(domain) &&
                                !domain.includes('hackerone.com') &&
                                !domain.includes('bugcrowd.com') &&
                                !domain.includes('google.com')) {

                                seenDomains.add(domain);
                                results.push({
                                    url: item.link,
                                    title: item.title || 'Unknown',
                                    snippet: item.snippet || '',
                                    domain: domain
                                });
                            }
                        } catch (e) {
                            // Invalid URL, skip
                        }
                    }
                }
            }
        } catch (error) {
            logger.error('Google Search failed', { error: String(error) });
        }

        logger.success(`Google Search found ${results.length} new potential targets`);
        return results;
    }
}
