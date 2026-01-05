import fs from 'fs';
import path from 'path';
import { Finding } from '../core/database.js';
import { gemini } from '../core/gemini.js';
import { logger } from '../core/logger.js';
import { getConfig } from '../config/settings.js';

export interface ReportOptions {
    format: 'markdown' | 'html' | 'json';
    includeEvidence: boolean;
    includeRemediation: boolean;
    groupBySeverity: boolean;
}

class ReportGenerator {
    private get config() { return getConfig(); }

    async generateReport(
        targetDomain: string,
        findings: Finding[],
        options: Partial<ReportOptions> = {}
    ): Promise<string> {
        const opts: ReportOptions = {
            format: options.format || 'markdown',
            includeEvidence: options.includeEvidence ?? true,
            includeRemediation: options.includeRemediation ?? true,
            groupBySeverity: options.groupBySeverity ?? true,
        };

        logger.info(`Generating ${opts.format} report for ${targetDomain}`);

        switch (opts.format) {
            case 'markdown':
                return this.generateMarkdownReport(targetDomain, findings, opts);
            case 'html':
                return this.generateHtmlReport(targetDomain, findings, opts);
            case 'json':
                return this.generateJsonReport(targetDomain, findings);
            default:
                throw new Error(`Unknown format: ${opts.format}`);
        }
    }

    private generateMarkdownReport(
        domain: string,
        findings: Finding[],
        options: ReportOptions
    ): string {
        const now = new Date().toISOString();
        const severityCounts = this.countBySeverity(findings);

        let report = `# Security Assessment Report

**Target:** ${domain}  
**Date:** ${now}  
**Tool:** BugHunter AI v1.0

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | ${severityCounts.critical || 0} |
| 🟠 High | ${severityCounts.high || 0} |
| 🟡 Medium | ${severityCounts.medium || 0} |
| 🔵 Low | ${severityCounts.low || 0} |
| ⚪ Info | ${severityCounts.info || 0} |

**Total Findings:** ${findings.length}

---

## Findings

`;

        const grouped = options.groupBySeverity
            ? this.groupBySeverity(findings)
            : { all: findings };

        for (const [severity, severityFindings] of Object.entries(grouped)) {
            if (severityFindings.length === 0) continue;

            if (options.groupBySeverity) {
                report += `### ${this.getSeverityEmoji(severity)} ${severity.toUpperCase()} Severity\n\n`;
            }

            for (const finding of severityFindings) {
                report += this.formatFinding(finding, options);
            }
        }

        report += `
---

## Methodology

This assessment was performed using BugHunter AI, which combines:
- Automated reconnaissance (subdomain enumeration, technology detection)
- Web and API crawling
- Pattern-based vulnerability detection
- AI-powered analysis using Google Gemini

---

## Disclaimer

This report is for authorized security testing purposes only. Findings should be verified manually before submission to bug bounty programs. False positives may occur.
`;

        return report;
    }

    private formatFinding(finding: Finding, options: ReportOptions): string {
        let output = `#### ${finding.type}

**URL:** \`${finding.url}\`  
**Severity:** ${this.getSeverityEmoji(finding.severity)} ${finding.severity.toUpperCase()}  
**Confidence:** ${Math.round(finding.confidence * 100)}%  
**Status:** ${finding.status}

**Description:**
${finding.description}

`;

        if (options.includeEvidence && finding.evidence) {
            output += `**Evidence:**
\`\`\`
${finding.evidence.substring(0, 500)}${finding.evidence.length > 500 ? '\n...(truncated)' : ''}
\`\`\`

`;
        }

        if (options.includeRemediation && finding.aiAnalysis) {
            try {
                const analysis = JSON.parse(finding.aiAnalysis);
                if (analysis.remediation) {
                    output += `**Remediation:**
${analysis.remediation}

`;
                }
                if (analysis.impact) {
                    output += `**Impact:**
${analysis.impact}

`;
                }
                if (analysis.cweId) {
                    output += `**CWE:** ${analysis.cweId}  \n`;
                }
                if (analysis.cvssScore) {
                    output += `**CVSS Score:** ${analysis.cvssScore}  \n`;
                }
            } catch {
                // Invalid JSON, skip
            }
        }

        output += `---\n\n`;
        return output;
    }

    private generateHtmlReport(
        domain: string,
        findings: Finding[],
        options: ReportOptions
    ): string {
        const now = new Date().toISOString();
        const severityCounts = this.countBySeverity(findings);

        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Report - ${domain}</title>
  <style>
    :root {
      --critical: #dc3545;
      --high: #fd7e14;
      --medium: #ffc107;
      --low: #17a2b8;
      --info: #6c757d;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
      background: #f5f5f5;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 30px;
      border-radius: 10px;
      margin-bottom: 20px;
    }
    .stats {
      display: flex;
      gap: 15px;
      margin: 20px 0;
    }
    .stat {
      background: white;
      padding: 20px;
      border-radius: 8px;
      text-align: center;
      flex: 1;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .stat-value {
      font-size: 2em;
      font-weight: bold;
    }
    .finding {
      background: white;
      padding: 20px;
      border-radius: 8px;
      margin: 15px 0;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      border-left: 4px solid;
    }
    .finding.critical { border-color: var(--critical); }
    .finding.high { border-color: var(--high); }
    .finding.medium { border-color: var(--medium); }
    .finding.low { border-color: var(--low); }
    .finding.info { border-color: var(--info); }
    .severity-badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 20px;
      color: white;
      font-size: 0.85em;
      font-weight: bold;
    }
    .severity-badge.critical { background: var(--critical); }
    .severity-badge.high { background: var(--high); }
    .severity-badge.medium { background: var(--medium); }
    .severity-badge.low { background: var(--low); }
    .severity-badge.info { background: var(--info); }
    pre {
      background: #2d2d2d;
      color: #f8f8f2;
      padding: 15px;
      border-radius: 5px;
      overflow-x: auto;
    }
    .url { 
      word-break: break-all;
      color: #667eea;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔒 Security Assessment Report</h1>
    <p><strong>Target:</strong> ${domain}</p>
    <p><strong>Date:</strong> ${now}</p>
    <p><strong>Tool:</strong> BugHunter AI v1.0</p>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="stat-value" style="color: var(--critical)">${severityCounts.critical || 0}</div>
      <div>Critical</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color: var(--high)">${severityCounts.high || 0}</div>
      <div>High</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color: var(--medium)">${severityCounts.medium || 0}</div>
      <div>Medium</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color: var(--low)">${severityCounts.low || 0}</div>
      <div>Low</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color: var(--info)">${severityCounts.info || 0}</div>
      <div>Info</div>
    </div>
  </div>

  <h2>Findings</h2>
  ${findings.map(f => this.formatHtmlFinding(f, options)).join('\n')}

  <footer style="text-align: center; color: #666; margin-top: 40px;">
    <p>Generated by BugHunter AI</p>
  </footer>
</body>
</html>`;
    }

    private formatHtmlFinding(finding: Finding, options: ReportOptions): string {
        let analysis = null;
        if (finding.aiAnalysis) {
            try {
                analysis = JSON.parse(finding.aiAnalysis);
            } catch { /* ignore */ }
        }

        return `
  <div class="finding ${finding.severity}">
    <h3>${finding.type}</h3>
    <p><span class="severity-badge ${finding.severity}">${finding.severity.toUpperCase()}</span></p>
    <p><strong>URL:</strong> <span class="url">${finding.url}</span></p>
    <p><strong>Confidence:</strong> ${Math.round(finding.confidence * 100)}%</p>
    <p>${finding.description}</p>
    ${options.includeEvidence && finding.evidence ? `<pre>${this.escapeHtml(finding.evidence.substring(0, 500))}</pre>` : ''}
    ${analysis?.remediation ? `<p><strong>Remediation:</strong> ${analysis.remediation}</p>` : ''}
    ${analysis?.cweId ? `<p><strong>CWE:</strong> ${analysis.cweId}</p>` : ''}
  </div>`;
    }

    private generateJsonReport(domain: string, findings: Finding[]): string {
        return JSON.stringify({
            target: domain,
            generatedAt: new Date().toISOString(),
            tool: 'BugHunter AI v1.0',
            summary: this.countBySeverity(findings),
            totalFindings: findings.length,
            findings: findings.map(f => ({
                ...f,
                aiAnalysis: f.aiAnalysis ? JSON.parse(f.aiAnalysis) : null,
            })),
        }, null, 2);
    }

    async generateBugBountyReport(finding: Finding): Promise<string> {
        logger.info(`Generating bug bounty report for finding: ${finding.id}`);

        let analysis = null;
        if (finding.aiAnalysis) {
            try {
                analysis = JSON.parse(finding.aiAnalysis);
            } catch { /* ignore */ }
        }

        // Use AI to generate a professional report
        const report = await gemini.generateReport(
            finding.type,
            finding.severity,
            finding.url,
            [finding.evidence],
            finding.description,
            analysis?.impact || 'Impact assessment pending'
        );

        return report;
    }

    async saveReport(
        targetDomain: string,
        content: string,
        format: 'markdown' | 'html' | 'json'
    ): Promise<string> {
        const reportsDir = path.join(this.config.paths.root, 'reports');

        if (!fs.existsSync(reportsDir)) {
            fs.mkdirSync(reportsDir, { recursive: true });
        }

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const extension = format === 'markdown' ? 'md' : format;
        const filename = `${targetDomain.replace(/[^a-zA-Z0-9]/g, '_')}_${timestamp}.${extension}`;
        const filepath = path.join(reportsDir, filename);

        fs.writeFileSync(filepath, content);
        logger.success(`Report saved to: ${filepath}`);

        return filepath;
    }

    private countBySeverity(findings: Finding[]): Record<string, number> {
        const counts: Record<string, number> = {};
        for (const finding of findings) {
            counts[finding.severity] = (counts[finding.severity] || 0) + 1;
        }
        return counts;
    }

    private groupBySeverity(findings: Finding[]): Record<string, Finding[]> {
        const order = ['critical', 'high', 'medium', 'low', 'info'];
        const grouped: Record<string, Finding[]> = {};

        for (const severity of order) {
            grouped[severity] = findings.filter(f => f.severity === severity);
        }

        return grouped;
    }

    private getSeverityEmoji(severity: string): string {
        const emojis: Record<string, string> = {
            critical: '🔴',
            high: '🟠',
            medium: '🟡',
            low: '🔵',
            info: '⚪',
        };
        return emojis[severity] || '⚪';
    }

    private escapeHtml(text: string): string {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}

export const reportGenerator = new ReportGenerator();
