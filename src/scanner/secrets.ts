import { gemini } from '../core/gemini.js';
import { logger } from '../core/logger.js';

export interface SecretFinding {
    type: string;
    value: string;
    location: string; // e.g., "script.js:45" or "HTML body"
    confidence: 'high' | 'medium' | 'low';
}

interface SecretPattern {
    name: string;
    regex: RegExp;
    confidence: 'high' | 'medium' | 'low';
}

export class SecretsScanner {
    private patterns: SecretPattern[] = [
        // Cloud Providers
        { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/, confidence: 'high' },
        { name: 'AWS Secret Access Key', regex: /["']?[0-9a-zA-Z\/+]{40}["']?/, confidence: 'medium' }, // Prone to FPs, needs context
        { name: 'Google API Key', regex: /AIza[0-9A-Za-z\\-_]{35}/, confidence: 'high' },
        { name: 'Google OAuth Token', regex: /ya29\.[0-9A-Za-z\\-_]+/, confidence: 'high' },
        { name: 'Azure Storage Key', regex: /[a-zA-Z0-9+\/]{88}==/, confidence: 'low' }, // Very generic, needs AI validation

        // Payment Processors
        { name: 'Stripe Live Key', regex: /sk_live_[0-9a-zA-Z]{24}/, confidence: 'high' },
        { name: 'Stripe Publishable Key', regex: /pk_live_[0-9a-zA-Z]{24}/, confidence: 'high' },
        { name: 'PayPal Access Token', regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/, confidence: 'high' },

        // DevOps & SaaS
        { name: 'GitHub Personal Access Token', regex: /ghp_[0-9a-zA-Z]{36}/, confidence: 'high' },
        { name: 'Slack Bot Token', regex: /xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/, confidence: 'high' },
        { name: 'Slack User Token', regex: /xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/, confidence: 'high' },
        { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/, confidence: 'high' },
        { name: 'Heroku API Key', regex: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/, confidence: 'medium' }, // UUIDs are common

        // Private Keys
        { name: 'RSA Private Key', regex: /-----BEGIN RSA PRIVATE KEY-----/, confidence: 'high' },
        { name: 'SSH Private Key', regex: /-----BEGIN OPENSSH PRIVATE KEY-----/, confidence: 'high' },
        { name: 'PGP Private Block', regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/, confidence: 'high' },

        // Generic Indicators (Medium/Low confidence, rely on AI)
        { name: 'Generic API Key', regex: /api[_-]?key\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]/i, confidence: 'medium' },
        { name: 'Generic Secret', regex: /secret\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]/i, confidence: 'low' },
        { name: 'Authorization Bearer', regex: /Authorization:\s*Bearer\s+([a-zA-Z0-9_\-\.]+)/i, confidence: 'medium' }
    ];

    async scanText(text: string, source: string): Promise<SecretFinding[]> {
        const findings: SecretFinding[] = [];

        // Truncate text for performance if it's massive, but usually we scan file by file
        // For regex, we iterate
        for (const pattern of this.patterns) {
            const matches = text.matchAll(new RegExp(pattern.regex, 'g'));
            for (const match of matches) {
                const value = match[0];

                // Basic entropy check/validation could go here
                if (this.isFalsePositive(value, pattern.name)) continue;

                const finding: SecretFinding = {
                    type: pattern.name,
                    value: value,
                    location: `${source}`,
                    confidence: pattern.confidence
                };

                // AI Validation for Low/Medium confidence
                if (pattern.confidence !== 'high') {
                    const isReal = await gemini.validateSecret(value, pattern.name, text.substring(Math.max(0, match.index! - 50), Math.min(text.length, match.index! + 50)));
                    if (isReal) {
                        finding.confidence = 'high'; // Upgraded by AI
                        findings.push(finding);
                    }
                } else {
                    findings.push(finding);
                }
            }
        }

        return findings;
    }

    private isFalsePositive(value: string, type: string): boolean {
        // Basic static filters
        const lower = value.toLowerCase();
        if (lower.includes('example') || lower.includes('test') || lower.includes('placeholder') || lower.includes('your_key')) {
            return true;
        }

        // Filter out common UUIDs that aren't secrets if purely UUID regex
        if (type === 'Heroku API Key' && value === '00000000-0000-0000-0000-000000000000') return true;

        return false;
    }
}

export const secretsScanner = new SecretsScanner();
