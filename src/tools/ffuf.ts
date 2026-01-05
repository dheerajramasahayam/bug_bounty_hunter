import { externalTools } from './external.js';
import { logger } from '../core/logger.js';
import fs from 'fs';
import path from 'path';
import os from 'os';

export interface FfufResult {
    input: {
        FUZZ: string;
        [key: string]: string;
    };
    position: number;
    status: number;
    length: number;
    words: number;
    lines: number;
    content_type: string;
    redirectlocation: string;
    resultfile: string;
    url: string;
    host: string;
}

export interface FfufOptions {
    url: string; // URL with FUZZ keyword
    wordlist?: string;
    extensions?: string[];
    threads?: number;
    timeout?: number;
    headers?: Record<string, string>;
    method?: string;
    data?: string; // POST data
    mc?: string; // Match codes (default: 200,204,301,302,307,401,403)
    ac?: boolean; // Auto-calibration
    recursion?: boolean;
    recursionDepth?: number;
}

class FfufWrapper {
    async isAvailable(): Promise<boolean> {
        return externalTools.isToolAvailable('ffuf');
    }

    async run(options: FfufOptions): Promise<FfufResult[]> {
        if (!await this.isAvailable()) {
            logger.warn('ffuf not available');
            return [];
        }

        const args: string[] = [
            '-json', // Output JSON
            '-s', // Silent
        ];

        // Ensure URL has FUZZ keyword if not present, assume it goes at end
        let targetUrl = options.url;
        if (!targetUrl.includes('FUZZ')) {
            if (!targetUrl.endsWith('/')) targetUrl += '/';
            targetUrl += 'FUZZ';
        }
        args.push('-u', targetUrl);

        // Wordlist
        // Wordlist - ensure it exists or download it
        let wordlist = options.wordlist;
        if (!wordlist) {
            wordlist = await externalTools.ensureWordlist('directories');
        } else if (!fs.existsSync(wordlist)) {
            // If a custom path is provided but missing, warn but fall back to default
            logger.warn(`Custom wordlist not found: ${wordlist}. Using default.`);
            wordlist = await externalTools.ensureWordlist('directories');
        }
        args.push('-w', wordlist);

        // Extensions
        if (options.extensions && options.extensions.length > 0) {
            args.push('-e', options.extensions.join(','));
        }

        // Method
        if (options.method) {
            args.push('-X', options.method);
        }

        // Data
        if (options.data) {
            args.push('-d', options.data);
        }

        // Headers
        if (options.headers) {
            for (const [key, value] of Object.entries(options.headers)) {
                args.push('-H', `${key}: ${value}`);
            }
        }

        // Match codes
        if (options.mc) {
            args.push('-mc', options.mc);
        }

        // Auto calibration
        if (options.ac) {
            args.push('-ac');
        }

        // Recursion
        if (options.recursion) {
            args.push('-recursion');
            if (options.recursionDepth) {
                args.push('-recursion-depth', options.recursionDepth.toString());
            }
        }

        // Threads
        if (options.threads) {
            args.push('-t', options.threads.toString());
        }

        logger.info(`Running ffuf active fuzzing on ${targetUrl}...`);

        try {
            const results: FfufResult[] = [];

            // ffuf outputs one JSON object per line
            await externalTools.streamTool('ffuf', args, {
                timeout: options.timeout || 600000,
                onLine: (line) => {
                    try {
                        if (line.trim()) {
                            const json = JSON.parse(line);
                            results.push({
                                input: json.input,
                                position: json.position,
                                status: json.status,
                                length: json.length,
                                words: json.words,
                                lines: json.lines,
                                content_type: json.content_type,
                                redirectlocation: json.redirectlocation,
                                resultfile: json.resultfile,
                                url: json.url,
                                host: json.host,
                            });
                        }
                    } catch {
                        // Ignore parse errors (sometimes ffuf outputs banners even with -s)
                    }
                },
                onError: (err) => {
                    // Only log if active error, not progress
                    if (err.includes('Error')) {
                        logger.warn(`ffuf error: ${err}`);
                    }
                }
            });

            logger.success(`ffuf found ${results.length} valid paths`);
            return results;
        } catch (error) {
            logger.error('ffuf failed', { error: String(error) });
            return [];
        }
    }

    // Convenience methods
    async discoverDirectories(url: string, threads: number = 40): Promise<FfufResult[]> {
        return this.run({
            url,
            // Uses default directory wordlist
            threads,
            mc: '200,204,301,302,307,401,403',
            ac: true,
        });
    }

    async scanBackupFiles(url: string): Promise<FfufResult[]> {
        return this.run({
            url, // Should be full file path + FUZZ extension
            wordlist: externalTools.getWordlistPath('fuzzing'), // We'd need a specific extension wordlist here ideally
            extensions: ['.bak', '.swp', '.old', '.zip', '.tar.gz', '.sql'],
            threads: 20,
            mc: '200'
        });
    }
}

export const ffuf = new FfufWrapper();
