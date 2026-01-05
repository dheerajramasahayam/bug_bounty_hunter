import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import { logger } from '../core/logger.js';

const execAsync = promisify(exec);

export interface ToolConfig {
    name: string;
    path: string;
    available: boolean;
    version?: string;
}

export interface ExternalToolsStatus {
    subfinder: ToolConfig;
    httpx: ToolConfig;
    nuclei: ToolConfig;
    nmap: ToolConfig;
    amass: ToolConfig;
    assetfinder: ToolConfig;
    waybackurls: ToolConfig;
    gau: ToolConfig;
    ffuf: ToolConfig;
}

class ExternalToolsManager {
    private toolsStatus: ExternalToolsStatus | null = null;
    private wordlistDir: string = process.env.WORDLIST_DIR || path.join(process.env.HOME || '', 'wordlists');

    async checkTools(): Promise<ExternalToolsStatus> {
        if (this.toolsStatus) return this.toolsStatus;

        const tools: (keyof ExternalToolsStatus)[] = [
            'subfinder', 'httpx', 'nuclei', 'nmap', 'amass',
            'assetfinder', 'waybackurls', 'gau', 'ffuf'
        ];

        const status: Partial<ExternalToolsStatus> = {};

        for (const tool of tools) {
            status[tool] = await this.checkTool(tool);
        }

        this.toolsStatus = status as ExternalToolsStatus;
        return this.toolsStatus;
    }

    private async checkTool(name: string): Promise<ToolConfig> {
        try {
            const { stdout } = await execAsync(`which ${name}`);
            const toolPath = stdout.trim();

            let version: string | undefined;
            try {
                const versionCmd = name === 'nmap' ? `${name} --version` : `${name} -version`;
                const { stdout: versionOutput } = await execAsync(versionCmd);
                version = versionOutput.split('\n')[0].trim();
            } catch {
                version = 'unknown';
            }

            return {
                name,
                path: toolPath,
                available: true,
                version,
            };
        } catch {
            return {
                name,
                path: '',
                available: false,
            };
        }
    }

    async runCommand(
        command: string,
        args: string[],
        options: {
            timeout?: number;
            onData?: (data: string) => void;
            onError?: (error: string) => void;
        } = {}
    ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
        return new Promise((resolve, reject) => {
            const timeout = options.timeout || 300000; // 5 minutes default
            let stdout = '';
            let stderr = '';

            const proc = spawn(command, args, {
                timeout,
                env: {
                    ...process.env,
                    PATH: `${process.env.PATH}:${process.env.HOME}/go/bin:/usr/local/go/bin`,
                },
            });

            proc.stdout.on('data', (data: Buffer) => {
                const str = data.toString();
                stdout += str;
                if (options.onData) options.onData(str);
            });

            proc.stderr.on('data', (data: Buffer) => {
                const str = data.toString();
                stderr += str;
                if (options.onError) options.onError(str);
            });

            proc.on('close', (code) => {
                resolve({ stdout, stderr, exitCode: code || 0 });
            });

            proc.on('error', (error) => {
                reject(error);
            });
        });
    }

    async streamTool(
        command: string,
        args: string[],
        options: {
            onLine: (line: string) => void;
            onError?: (error: string) => void;
            timeout?: number;
        }
    ): Promise<void> {
        return new Promise((resolve, reject) => {
            const timeout = options.timeout || 3600000; // 1 hour default for streaming
            const proc = spawn(command, args, {
                timeout,
                env: {
                    ...process.env,
                    PATH: `${process.env.PATH}:${process.env.HOME}/go/bin:/usr/local/go/bin`,
                },
            });

            let buffer = '';
            proc.stdout.on('data', (data: Buffer) => {
                buffer += data.toString();
                const lines = buffer.split('\n');
                // All complete lines except the last one which might be partial
                buffer = lines.pop() || '';

                for (const line of lines) {
                    if (line.trim()) options.onLine(line.trim());
                }
            });

            proc.stderr.on('data', (data: Buffer) => {
                const str = data.toString();
                if (options.onError) options.onError(str);
            });

            proc.on('close', (code) => {
                if (buffer.trim()) options.onLine(buffer.trim()); // Process remaining buffer
                if (code === 0) resolve();
                else reject(new Error(`Tool exited with code ${code}`));
            });

            proc.on('error', (error) => {
                reject(error);
            });
        });
    }

    private projectWordlistDir = path.join(process.cwd(), 'wordlists');

    constructor() {
        // Ensure wordlist directory exists
        if (!fs.existsSync(this.projectWordlistDir)) {
            fs.mkdirSync(this.projectWordlistDir, { recursive: true });
        }
    }

    getWordlistPath(type: 'subdomains' | 'directories' | 'passwords' | 'fuzzing'): string {
        const paths: Record<string, string> = {
            subdomains: path.join(this.projectWordlistDir, 'subdomains-top1million-5000.txt'),
            directories: path.join(this.projectWordlistDir, 'directory-list-2.3-medium.txt'),
            passwords: path.join(this.projectWordlistDir, '10-million-password-list-top-1000.txt'),
            fuzzing: path.join(this.projectWordlistDir, 'special-chars.txt'),
        };

        // Return path even if it doesn't exist yet, we'll download it if needed
        return paths[type] || paths.subdomains;
    }

    async ensureWordlist(type: 'subdomains' | 'directories' | 'passwords' | 'fuzzing'): Promise<string> {
        const filePath = this.getWordlistPath(type);
        if (fs.existsSync(filePath)) {
            return filePath;
        }

        logger.info(`Downloading missing wordlist: ${type}...`);

        const urls: Record<string, string> = {
            subdomains: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
            directories: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt',
            passwords: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt',
            fuzzing: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/special-chars.txt'
        };

        try {
            const response = await fetch(urls[type]);
            if (!response.ok) throw new Error(`Failed to download ${type}: ${response.statusText}`);
            const text = await response.text();
            fs.writeFileSync(filePath, text);
            logger.success(`Downloaded ${type} wordlist to ${filePath}`);
            return filePath;
        } catch (error) {
            logger.error(`Failed to download wordlist ${type}`, { error: String(error) });
            // Fallback to creating a minimal file to prevent crashing
            const minimalContent = type === 'directories' ? 'admin\nconfig\nbackup\nlogin\n' : 'test\n';
            fs.writeFileSync(filePath, minimalContent);
            return filePath;
        }
    }

    async isToolAvailable(tool: keyof ExternalToolsStatus): Promise<boolean> {
        const status = await this.checkTools();
        return status[tool]?.available || false;
    }
}

export const externalTools = new ExternalToolsManager();
