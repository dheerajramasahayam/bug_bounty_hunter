import axios from 'axios';
import { logger } from '../core/logger.js';

export interface NotificationConfig {
    discord?: {
        webhookUrl: string;
    };
    slack?: {
        webhookUrl: string;
    };
    telegram?: {
        botToken: string;
        chatId: string;
    };
    email?: {
        smtpHost: string;
        smtpPort: number;
        username: string;
        password: string;
        from: string;
        to: string;
    };
}

export interface NotificationMessage {
    title: string;
    message: string;
    severity?: 'info' | 'warning' | 'critical';
    fields?: { name: string; value: string }[];
    url?: string;
}

class NotificationService {
    async sendAll(config: NotificationConfig, notification: NotificationMessage): Promise<void> {
        const promises: Promise<void>[] = [];

        if (config.discord?.webhookUrl) {
            promises.push(this.sendDiscord(config.discord.webhookUrl, notification));
        }

        if (config.slack?.webhookUrl) {
            promises.push(this.sendSlack(config.slack.webhookUrl, notification));
        }

        if (config.telegram?.botToken && config.telegram?.chatId) {
            promises.push(this.sendTelegram(config.telegram.botToken, config.telegram.chatId, notification));
        }

        await Promise.allSettled(promises);
    }

    async sendDiscord(webhookUrl: string, notification: NotificationMessage): Promise<void> {
        try {
            const color = notification.severity === 'critical' ? 0xff0000
                : notification.severity === 'warning' ? 0xffaa00
                    : 0x00ff00;

            await axios.post(webhookUrl, {
                embeds: [{
                    title: notification.title,
                    description: notification.message,
                    color,
                    fields: notification.fields?.map(f => ({
                        name: f.name,
                        value: f.value,
                        inline: true,
                    })),
                    url: notification.url,
                    timestamp: new Date().toISOString(),
                    footer: {
                        text: '🤖 BugHunter AI',
                    },
                }],
            });
            logger.success('Discord notification sent');
        } catch (error) {
            logger.error('Discord notification failed', { error: String(error) });
        }
    }

    async sendSlack(webhookUrl: string, notification: NotificationMessage): Promise<void> {
        try {
            const emoji = notification.severity === 'critical' ? '🚨'
                : notification.severity === 'warning' ? '⚠️'
                    : '✅';

            await axios.post(webhookUrl, {
                blocks: [
                    {
                        type: 'header',
                        text: { type: 'plain_text', text: `${emoji} ${notification.title}` },
                    },
                    {
                        type: 'section',
                        text: { type: 'mrkdwn', text: notification.message },
                    },
                    ...(notification.fields ? [{
                        type: 'section',
                        fields: notification.fields.map(f => ({
                            type: 'mrkdwn',
                            text: `*${f.name}:* ${f.value}`,
                        })),
                    }] : []),
                ],
            });
            logger.success('Slack notification sent');
        } catch (error) {
            logger.error('Slack notification failed', { error: String(error) });
        }
    }

    async sendTelegram(botToken: string, chatId: string, notification: NotificationMessage): Promise<void> {
        try {
            const emoji = notification.severity === 'critical' ? '🚨'
                : notification.severity === 'warning' ? '⚠️'
                    : '✅';

            let text = `${emoji} *${this.escapeMarkdown(notification.title)}*\n\n`;
            text += this.escapeMarkdown(notification.message);

            if (notification.fields && notification.fields.length > 0) {
                text += '\n\n';
                for (const field of notification.fields) {
                    text += `*${this.escapeMarkdown(field.name)}:* ${this.escapeMarkdown(field.value)}\n`;
                }
            }

            if (notification.url) {
                text += `\n🔗 [View Details](${notification.url})`;
            }

            text += '\n\n_🤖 BugHunter AI_';

            await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
                chat_id: chatId,
                text,
                parse_mode: 'MarkdownV2',
                disable_web_page_preview: true,
            });
            logger.success('Telegram notification sent');
        } catch (error) {
            logger.error('Telegram notification failed', { error: String(error) });
        }
    }

    private escapeMarkdown(text: string): string {
        return text.replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&');
    }

    // Convenience methods for common notifications
    async notifyNewProgram(config: NotificationConfig, programName: string, platform: string, bountyRange: string, url: string): Promise<void> {
        await this.sendAll(config, {
            title: '🆕 New Bug Bounty Program!',
            message: `A new program has been discovered on ${platform}`,
            severity: 'info',
            fields: [
                { name: 'Program', value: programName },
                { name: 'Platform', value: platform },
                { name: 'Bounty Range', value: bountyRange },
            ],
            url,
        });
    }

    async notifyNewSubdomain(config: NotificationConfig, domain: string, subdomains: string[]): Promise<void> {
        const count = subdomains.length;
        await this.sendAll(config, {
            title: '🌐 New Subdomains Found!',
            message: `${count} new subdomain${count > 1 ? 's' : ''} discovered for ${domain}`,
            severity: 'info',
            fields: [
                { name: 'Domain', value: domain },
                { name: 'Count', value: String(count) },
                { name: 'Examples', value: subdomains.slice(0, 5).join(', ') + (count > 5 ? '...' : '') },
            ],
        });
    }

    async notifyVulnerability(config: NotificationConfig, type: string, url: string, severity: string): Promise<void> {
        const severityLevel = ['critical', 'high'].includes(severity) ? 'critical'
            : severity === 'medium' ? 'warning'
                : 'info';

        await this.sendAll(config, {
            title: `🔥 Vulnerability Found! [${severity.toUpperCase()}]`,
            message: `${type} detected`,
            severity: severityLevel as 'info' | 'warning' | 'critical',
            fields: [
                { name: 'Type', value: type },
                { name: 'Severity', value: severity.toUpperCase() },
                { name: 'URL', value: url.length > 50 ? url.substring(0, 50) + '...' : url },
            ],
            url,
        });
    }

    async notifyDailySummary(config: NotificationConfig, stats: {
        programsDiscovered: number;
        newSubdomains: number;
        vulnerabilities: number;
        criticalCount: number;
        highCount: number;
    }): Promise<void> {
        const severity = stats.criticalCount > 0 ? 'critical'
            : stats.highCount > 0 ? 'warning'
                : 'info';

        await this.sendAll(config, {
            title: '📊 Daily Bug Hunting Summary',
            message: 'Here\'s what BugHunter AI found today',
            severity,
            fields: [
                { name: '🎯 Programs', value: String(stats.programsDiscovered) },
                { name: '🌐 New Subdomains', value: String(stats.newSubdomains) },
                { name: '🔥 Vulnerabilities', value: String(stats.vulnerabilities) },
                { name: '🚨 Critical', value: String(stats.criticalCount) },
                { name: '⚠️ High', value: String(stats.highCount) },
            ],
        });
    }
}

export const notificationService = new NotificationService();
