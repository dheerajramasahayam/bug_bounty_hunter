import { config } from 'dotenv';
import { z } from 'zod';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
config({ path: path.resolve(__dirname, '../../.env') });

// Configuration schema with validation
const ConfigSchema = z.object({
    // Gemini API
    gemini: z.object({
        apiKey: z.string().min(1, 'GEMINI_API_KEY is required'),
        model: z.string().default('gemini-2.5-pro-preview-05-06'),
    }),

    // Optional API Keys
    apis: z.object({
        securityTrails: z.string().optional(),
        shodan: z.string().optional(),
        virusTotal: z.string().optional(),
    }),

    // Scanner settings
    scanner: z.object({
        maxConcurrentRequests: z.number().min(1).max(50).default(10),
        requestDelayMs: z.number().min(0).default(100),
        maxCrawlDepth: z.number().min(1).max(20).default(5),
        respectRobotsTxt: z.boolean().default(true),
        timeout: z.number().min(1000).default(30000),
        userAgent: z.string().default('BugHunter-AI/1.0 (Security Research)'),
    }),

    // Database
    database: z.object({
        path: z.string().default('./data/bughunter.db'),
    }),

    // Dashboard
    dashboard: z.object({
        port: z.number().min(1).max(65535).default(3000),
        host: z.string().default('localhost'),
    }),

    // Logging
    logging: z.object({
        level: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
        file: z.string().default('./logs/bughunter.log'),
    }),

    // Paths
    paths: z.object({
        root: z.string(),
        data: z.string(),
        logs: z.string(),
        reports: z.string(),
        wordlists: z.string(),
    }),
});

export type Config = z.infer<typeof ConfigSchema>;

// Build configuration from environment
function buildConfig(): Config {
    const rootDir = path.resolve(__dirname, '../..');

    const rawConfig = {
        gemini: {
            apiKey: process.env.GEMINI_API_KEY || '',
            model: process.env.GEMINI_MODEL || 'gemini-2.5-pro-preview-05-06',
        },
        apis: {
            securityTrails: process.env.SECURITYTRAILS_API_KEY,
            shodan: process.env.SHODAN_API_KEY,
            virusTotal: process.env.VIRUSTOTAL_API_KEY,
        },
        scanner: {
            maxConcurrentRequests: parseInt(process.env.MAX_CONCURRENT_REQUESTS || '10'),
            requestDelayMs: parseInt(process.env.REQUEST_DELAY_MS || '100'),
            maxCrawlDepth: parseInt(process.env.MAX_CRAWL_DEPTH || '5'),
            respectRobotsTxt: process.env.RESPECT_ROBOTS_TXT !== 'false',
            timeout: parseInt(process.env.REQUEST_TIMEOUT || '30000'),
            userAgent: process.env.USER_AGENT || 'BugHunter-AI/1.0 (Security Research)',
        },
        database: {
            path: process.env.DATABASE_PATH || './data/bughunter.db',
        },
        dashboard: {
            port: parseInt(process.env.DASHBOARD_PORT || '3000'),
            host: process.env.DASHBOARD_HOST || '0.0.0.0',
        },
        logging: {
            level: (process.env.LOG_LEVEL || 'info') as 'debug' | 'info' | 'warn' | 'error',
            file: process.env.LOG_FILE || './logs/bughunter.log',
        },
        paths: {
            root: rootDir,
            data: path.resolve(rootDir, 'data'),
            logs: path.resolve(rootDir, 'logs'),
            reports: path.resolve(rootDir, 'reports'),
            wordlists: path.resolve(rootDir, 'wordlists'),
        },
    };

    return ConfigSchema.parse(rawConfig);
}

// Singleton configuration instance
let configInstance: Config | null = null;

export function getConfig(): Config {
    if (!configInstance) {
        configInstance = buildConfig();
    }
    return configInstance;
}

// For testing - allows resetting config
export function resetConfig(): void {
    configInstance = null;
}

// Validate that required API key is present
export function validateConfig(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    try {
        const cfg = getConfig();

        if (!cfg.gemini.apiKey || cfg.gemini.apiKey === 'your_gemini_api_key_here') {
            errors.push('GEMINI_API_KEY is not configured. Please set it in your .env file.');
        }
    } catch (error) {
        if (error instanceof z.ZodError) {
            errors.push(...error.errors.map(e => `${e.path.join('.')}: ${e.message}`));
        } else {
            errors.push(String(error));
        }
    }

    return { valid: errors.length === 0, errors };
}
