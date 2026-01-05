import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import { getConfig } from '../config/settings.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVELS: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
};

const LOG_COLORS: Record<LogLevel, (text: string) => string> = {
    debug: chalk.gray,
    info: chalk.blue,
    warn: chalk.yellow,
    error: chalk.red,
};

const LOG_ICONS: Record<LogLevel, string> = {
    debug: '🔍',
    info: 'ℹ️ ',
    warn: '⚠️ ',
    error: '❌',
};

class Logger {
    private level: LogLevel;
    private logFile: string | null;
    private fileStream: fs.WriteStream | null = null;

    constructor() {
        try {
            const config = getConfig();
            this.level = config.logging.level;
            this.logFile = config.logging.file;
            this.initFileStream();
        } catch {
            // Config not yet available, use defaults
            this.level = 'info';
            this.logFile = null;
        }
    }

    private initFileStream(): void {
        if (this.logFile) {
            const logDir = path.dirname(this.logFile);
            if (!fs.existsSync(logDir)) {
                fs.mkdirSync(logDir, { recursive: true });
            }
            this.fileStream = fs.createWriteStream(this.logFile, { flags: 'a' });
        }
    }

    private shouldLog(level: LogLevel): boolean {
        return LOG_LEVELS[level] >= LOG_LEVELS[this.level];
    }

    private formatMessage(level: LogLevel, message: string, meta?: object): string {
        const timestamp = new Date().toISOString();
        const metaStr = meta ? ` ${JSON.stringify(meta)}` : '';
        return `[${timestamp}] [${level.toUpperCase()}] ${message}${metaStr}`;
    }

    private writeToFile(message: string): void {
        if (this.fileStream) {
            this.fileStream.write(message + '\n');
        }
    }

    private log(level: LogLevel, message: string, meta?: object): void {
        if (!this.shouldLog(level)) return;

        const formattedMessage = this.formatMessage(level, message, meta);
        const colorFn = LOG_COLORS[level];
        const icon = LOG_ICONS[level];

        // Console output with colors
        console.log(`${icon} ${colorFn(formattedMessage)}`);

        // File output without colors
        this.writeToFile(formattedMessage);
    }

    debug(message: string, meta?: object): void {
        this.log('debug', message, meta);
    }

    info(message: string, meta?: object): void {
        this.log('info', message, meta);
    }

    warn(message: string, meta?: object): void {
        this.log('warn', message, meta);
    }

    error(message: string, meta?: object): void {
        this.log('error', message, meta);
    }

    // Special formatted outputs
    success(message: string): void {
        console.log(`✅ ${chalk.green(message)}`);
        this.writeToFile(`[${new Date().toISOString()}] [SUCCESS] ${message}`);
    }

    banner(title: string): void {
        const line = '═'.repeat(50);
        console.log(chalk.cyan(`\n╔${line}╗`));
        console.log(chalk.cyan(`║${title.padStart(25 + title.length / 2).padEnd(50)}║`));
        console.log(chalk.cyan(`╚${line}╝\n`));
    }

    table(data: Record<string, unknown>[]): void {
        console.table(data);
    }

    progress(current: number, total: number, label: string): void {
        const percentage = Math.round((current / total) * 100);
        const barLength = 30;
        const filled = Math.round((current / total) * barLength);
        const bar = '█'.repeat(filled) + '░'.repeat(barLength - filled);

        process.stdout.write(`\r${chalk.cyan(label)} [${bar}] ${percentage}% (${current}/${total})`);

        if (current === total) {
            console.log(); // New line when complete
        }
    }

    // Vulnerability-specific logging
    vulnerability(type: string, severity: string, url: string): void {
        const severityColors: Record<string, (text: string) => string> = {
            critical: chalk.bgRed.white.bold,
            high: chalk.red.bold,
            medium: chalk.yellow,
            low: chalk.blue,
            info: chalk.gray,
        };

        const colorFn = severityColors[severity.toLowerCase()] || chalk.white;
        console.log(`🎯 ${colorFn(`[${severity.toUpperCase()}]`)} ${chalk.white(type)} - ${chalk.underline(url)}`);
        this.writeToFile(`[${new Date().toISOString()}] [VULN] [${severity}] ${type} - ${url}`);
    }

    close(): void {
        if (this.fileStream) {
            this.fileStream.end();
        }
    }
}

// Singleton logger instance
export const logger = new Logger();
