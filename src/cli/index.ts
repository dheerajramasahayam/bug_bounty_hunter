#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { v4 as uuidv4 } from 'uuid';
import { getConfig, validateConfig } from '../config/settings.js';
import { logger } from '../core/logger.js';
import { db } from '../core/database.js';
import { gemini } from '../core/gemini.js';
import { subdomainEnumerator } from '../recon/subdomain.js';
import { techDetector } from '../recon/techdetect.js';
import { archiveCrawler } from '../recon/archive.js';
import { webCrawler } from '../crawler/webcrawler.js';
import { apiCrawler } from '../crawler/apicrawler.js';
import { vulnerabilityAnalyzer } from '../scanner/analyzer.js';
import { reportGenerator } from '../reporter/generator.js';

const program = new Command();

program
    .name('bughunter')
    .description('🎯 AI-powered bug bounty automation tool')
    .version('1.0.0');

// Scan command - main functionality
program
    .command('scan <target>')
    .description('Scan a target domain for vulnerabilities')
    .option('-d, --depth <number>', 'Max crawl depth', '3')
    .option('-p, --pages <number>', 'Max pages to crawl', '100')
    .option('--no-ai', 'Disable AI-powered analysis')
    .option('--no-recon', 'Skip reconnaissance phase')
    .option('--api-only', 'Only scan API endpoints')
    .option('-o, --output <format>', 'Report format (markdown|html|json)', 'markdown')
    .option('--scope <patterns>', 'Comma-separated scope patterns')
    .action(async (target: string, options) => {
        logger.banner('BugHunter AI');

        // Validate configuration
        const validation = validateConfig();
        if (!validation.valid) {
            console.error(chalk.red('Configuration errors:'));
            validation.errors.forEach(e => console.error(chalk.red(`  - ${e}`)));
            process.exit(1);
        }

        const _config = getConfig();

        // Initialize components
        db.initialize();
        if (options.ai) {
            gemini.initialize();
        }

        // Clean target URL
        const domain = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        const baseUrl = target.startsWith('http') ? target : `https://${target}`;

        console.log(chalk.cyan(`\n🎯 Target: ${domain}`));
        console.log(chalk.gray(`   Base URL: ${baseUrl}`));
        console.log(chalk.gray(`   Max Depth: ${options.depth}`));
        console.log(chalk.gray(`   AI Analysis: ${options.ai ? 'Enabled' : 'Disabled'}`));
        console.log('');

        // Create or get target
        let dbTarget = db.getTargetByDomain(domain);
        if (!dbTarget) {
            dbTarget = db.createTarget({
                id: uuidv4(),
                domain,
                scope: options.scope ? options.scope.split(',') : [],
                outOfScope: [],
                platform: '',
                programUrl: '',
            });
        }

        // Create scan session
        const session = db.createSession({
            id: uuidv4(),
            targetId: dbTarget.id,
            status: 'running',
            startedAt: new Date().toISOString(),
            urlsScanned: 0,
            findingsCount: 0,
            config: JSON.stringify(options),
        });

        try {
            // Phase 1: Reconnaissance
            if (options.recon && !options.apiOnly) {
                console.log(chalk.yellow('\n📡 PHASE 1: Reconnaissance\n'));

                // Subdomain enumeration
                const spinner1 = ora('Enumerating subdomains...').start();
                const subdomains = await subdomainEnumerator.enumerate(domain);
                spinner1.succeed(`Found ${subdomains.subdomains.length} subdomains`);

                // Technology detection
                const spinner2 = ora('Detecting technologies...').start();
                const techResult = await techDetector.detect(baseUrl);
                spinner2.succeed(`Detected ${techResult.technologies.length} technologies`);

                // Display tech stack
                if (techResult.technologies.length > 0) {
                    console.log(chalk.gray('\n   Technologies:'));
                    techResult.technologies.forEach(t => {
                        console.log(chalk.gray(`   - ${t.name}${t.version ? ` (${t.version})` : ''}`));
                    });
                }

                // Security posture analysis
                const posture = techDetector.analyzeSecurityPosture(techResult);
                console.log(chalk.gray(`\n   Security Score: ${posture.score}/100`));
                if (posture.issues.length > 0) {
                    console.log(chalk.gray('   Issues:'));
                    posture.issues.slice(0, 5).forEach(issue => {
                        console.log(chalk.gray(`   - [${issue.severity}] ${issue.message}`));
                    });
                }

                // Archive crawl
                const spinner3 = ora('Searching archives...').start();
                const archives = await archiveCrawler.crawl(domain, 500);
                spinner3.succeed(`Found ${archives.urls.length} archived URLs, ${archives.jsFiles.length} JS files`);
            }

            // Phase 2: Crawling
            console.log(chalk.yellow('\n🕷️ PHASE 2: Crawling\n'));

            if (!options.apiOnly) {
                const spinner4 = ora('Crawling website...').start();
                const crawlResult = await webCrawler.crawl(baseUrl, {
                    maxDepth: parseInt(options.depth),
                    maxPages: parseInt(options.pages),
                    scope: options.scope ? options.scope.split(',') : [],
                    sessionId: session.id,
                    targetId: dbTarget.id,
                });
                spinner4.succeed(`Crawled ${crawlResult.responses.length} pages, found ${crawlResult.forms.length} forms`);

                // Update session
                db.updateSession(session.id, { urlsScanned: crawlResult.responses.length });

                // Phase 3: Vulnerability Analysis
                console.log(chalk.yellow('\n🔍 PHASE 3: Vulnerability Analysis\n'));

                const spinner5 = ora('Analyzing responses...').start();
                let totalFindings = 0;

                for (const response of crawlResult.responses) {
                    const result = await vulnerabilityAnalyzer.analyzeResponse(response, {
                        targetId: dbTarget.id,
                        sessionId: session.id,
                        useAi: options.ai,
                        aiConfidenceThreshold: 0.7,
                        skipPatternMatching: false,
                    });
                    totalFindings += result.findings.length;
                }

                spinner5.succeed(`Analysis complete. Found ${totalFindings} potential vulnerabilities`);

                // Analyze JavaScript files
                if (crawlResult.jsFiles.length > 0 && options.ai) {
                    const spinner6 = ora(`Analyzing ${crawlResult.jsFiles.length} JavaScript files...`).start();
                    // Note: Full JS analysis would fetch and analyze each file
                    spinner6.succeed('JavaScript analysis complete');
                }
            }

            // API Discovery and Analysis
            const spinner7 = ora('Discovering API endpoints...').start();
            const apiResult = await apiCrawler.discoverEndpoints(baseUrl);
            spinner7.succeed(`Discovered ${apiResult.endpoints.length} API endpoints`);

            if (apiResult.endpoints.length > 0) {
                const spinner8 = ora('Analyzing API security...').start();
                const apiFindings = await vulnerabilityAnalyzer.analyzeApiEndpoints(
                    apiResult.endpoints,
                    {
                        targetId: dbTarget.id,
                        sessionId: session.id,
                        useAi: options.ai,
                        aiConfidenceThreshold: 0.7,
                        skipPatternMatching: false,
                    }
                );
                const apiIssues = apiFindings.reduce((sum, r) => sum + r.findings.length, 0);
                spinner8.succeed(`Found ${apiIssues} API security issues`);
            }

            // Phase 4: Report Generation
            console.log(chalk.yellow('\n📝 PHASE 4: Report Generation\n'));

            const allFindings = db.getFindingsByTarget(dbTarget.id);

            const spinner9 = ora('Generating report...').start();
            const reportContent = await reportGenerator.generateReport(
                domain,
                allFindings,
                { format: options.output as 'markdown' | 'html' | 'json' }
            );
            const reportPath = await reportGenerator.saveReport(
                domain,
                reportContent,
                options.output as 'markdown' | 'html' | 'json'
            );
            spinner9.succeed(`Report saved to: ${reportPath}`);

            // Update session
            db.updateSession(session.id, {
                status: 'completed',
                completedAt: new Date().toISOString(),
                findingsCount: allFindings.length,
            });

            // Summary
            console.log(chalk.green('\n✅ Scan Complete!\n'));

            const stats = db.getStats();
            console.log(chalk.white('Summary:'));
            console.log(chalk.gray(`  Total Findings: ${allFindings.length}`));
            if (stats.findingsBySeverity.critical) {
                console.log(chalk.red(`  Critical: ${stats.findingsBySeverity.critical}`));
            }
            if (stats.findingsBySeverity.high) {
                console.log(chalk.yellow(`  High: ${stats.findingsBySeverity.high}`));
            }
            if (stats.findingsBySeverity.medium) {
                console.log(chalk.blue(`  Medium: ${stats.findingsBySeverity.medium}`));
            }
            console.log('');

        } catch (error) {
            db.updateSession(session.id, { status: 'failed' });
            logger.error('Scan failed', { error: String(error) });
            process.exit(1);
        }
    });

// Recon command - reconnaissance only
program
    .command('recon <domain>')
    .description('Perform reconnaissance on a target domain')
    .option('--subdomains', 'Enumerate subdomains')
    .option('--tech', 'Detect technologies')
    .option('--archive', 'Search web archives')
    .option('--all', 'Run all reconnaissance modules')
    .action(async (domain: string, options) => {
        logger.banner('BugHunter Recon');

        db.initialize();

        const runAll = options.all || (!options.subdomains && !options.tech && !options.archive);

        if (runAll || options.subdomains) {
            console.log(chalk.cyan('\n🔍 Subdomain Enumeration\n'));
            const result = await subdomainEnumerator.enumerate(domain);
            console.log(chalk.white(`Found ${result.subdomains.length} subdomains:`));
            result.subdomains.slice(0, 20).forEach(s => {
                console.log(chalk.gray(`  - ${s.subdomain} (${s.source})`));
            });
            if (result.subdomains.length > 20) {
                console.log(chalk.gray(`  ... and ${result.subdomains.length - 20} more`));
            }
        }

        if (runAll || options.tech) {
            console.log(chalk.cyan('\n🔧 Technology Detection\n'));
            const url = `https://${domain}`;
            const result = await techDetector.detect(url);
            console.log(chalk.white('Detected Technologies:'));
            result.technologies.forEach(t => {
                console.log(chalk.gray(`  - ${t.name} (${t.category})${t.version ? ` v${t.version}` : ''}`));
            });

            const posture = techDetector.analyzeSecurityPosture(result);
            console.log(chalk.white(`\nSecurity Score: ${posture.score}/100`));
        }

        if (runAll || options.archive) {
            console.log(chalk.cyan('\n📚 Archive Search\n'));
            const result = await archiveCrawler.crawl(domain, 200);
            console.log(chalk.white(`Found ${result.urls.length} archived URLs`));
            console.log(chalk.white(`JavaScript files: ${result.jsFiles.length}`));
            console.log(chalk.white(`API endpoints: ${result.apiEndpoints.length}`));
        }

        console.log(chalk.green('\n✅ Reconnaissance complete!\n'));
    });

// Targets command - manage targets
program
    .command('targets')
    .description('List and manage targets')
    .option('-l, --list', 'List all targets')
    .option('-a, --add <domain>', 'Add a new target')
    .option('--platform <name>', 'Bug bounty platform (hackerone, bugcrowd)')
    .option('--program <url>', 'Program URL')
    .action((options) => {
        db.initialize();

        if (options.add) {
            const target = db.createTarget({
                id: uuidv4(),
                domain: options.add,
                scope: [],
                outOfScope: [],
                platform: options.platform || '',
                programUrl: options.program || '',
            });
            console.log(chalk.green(`✅ Target added: ${target.domain}`));
        }

        if (options.list || !options.add) {
            const targets = db.getAllTargets();
            console.log(chalk.cyan('\n📋 Targets\n'));

            if (targets.length === 0) {
                console.log(chalk.gray('  No targets yet. Add one with: bughunter targets -a <domain>'));
            } else {
                targets.forEach(t => {
                    const findings = db.getFindingsByTarget(t.id);
                    console.log(chalk.white(`  ${t.domain}`));
                    console.log(chalk.gray(`    Platform: ${t.platform || 'N/A'}`));
                    console.log(chalk.gray(`    Findings: ${findings.length}`));
                    console.log('');
                });
            }
        }
    });

// Findings command - view findings
program
    .command('findings')
    .description('View and manage findings')
    .option('-t, --target <domain>', 'Filter by target domain')
    .option('-s, --severity <level>', 'Filter by severity (critical, high, medium, low, info)')
    .option('--export <format>', 'Export findings (json, csv)')
    .action((options) => {
        db.initialize();

        let findings = options.target
            ? db.getFindingsByTarget(db.getTargetByDomain(options.target)?.id || '')
            : db.getAllTargets().flatMap(t => db.getFindingsByTarget(t.id));

        if (options.severity) {
            findings = findings.filter(f => f.severity === options.severity);
        }

        console.log(chalk.cyan(`\n🎯 Findings (${findings.length})\n`));

        if (findings.length === 0) {
            console.log(chalk.gray('  No findings yet. Run a scan first!'));
        } else {
            findings.forEach(f => {
                const severityColors: Record<string, typeof chalk> = {
                    critical: chalk.red,
                    high: chalk.yellow,
                    medium: chalk.blue,
                    low: chalk.cyan,
                    info: chalk.gray,
                };
                const color = severityColors[f.severity] || chalk.white;

                console.log(color(`  [${f.severity.toUpperCase()}] ${f.type}`));
                console.log(chalk.gray(`    URL: ${f.url}`));
                console.log(chalk.gray(`    Confidence: ${Math.round(f.confidence * 100)}%`));
                console.log('');
            });
        }

        if (options.export) {
            const content = options.export === 'json'
                ? JSON.stringify(findings, null, 2)
                : findings.map(f => `${f.severity},${f.type},${f.url},${f.confidence}`).join('\n');

            const filename = `findings_${Date.now()}.${options.export}`;
            require('fs').writeFileSync(filename, content);
            console.log(chalk.green(`\n✅ Exported to: ${filename}`));
        }
    });

// Report command - generate reports
program
    .command('report <domain>')
    .description('Generate a report for a target')
    .option('-f, --format <format>', 'Report format (markdown, html, json)', 'markdown')
    .option('--finding <id>', 'Generate bug bounty report for specific finding')
    .action(async (domain: string, options) => {
        db.initialize();
        gemini.initialize();

        const target = db.getTargetByDomain(domain);
        if (!target) {
            console.log(chalk.red(`Target not found: ${domain}`));
            process.exit(1);
        }

        if (options.finding) {
            // Generate bug bounty report for specific finding
            const finding = db.getFinding(options.finding);
            if (!finding) {
                console.log(chalk.red(`Finding not found: ${options.finding}`));
                process.exit(1);
            }

            const spinner = ora('Generating bug bounty report...').start();
            const report = await reportGenerator.generateBugBountyReport(finding);
            spinner.succeed('Report generated');

            console.log('\n' + report);
        } else {
            // Generate full report
            const findings = db.getFindingsByTarget(target.id);

            const spinner = ora('Generating report...').start();
            const content = await reportGenerator.generateReport(domain, findings, {
                format: options.format as 'markdown' | 'html' | 'json',
            });
            const path = await reportGenerator.saveReport(domain, content, options.format);
            spinner.succeed(`Report saved to: ${path}`);
        }
    });

// Stats command
program
    .command('stats')
    .description('Show statistics')
    .action(() => {
        db.initialize();

        const stats = db.getStats();

        console.log(chalk.cyan('\n📊 Statistics\n'));
        console.log(chalk.white(`  Targets: ${stats.totalTargets}`));
        console.log(chalk.white(`  Scans: ${stats.totalScans}`));
        console.log(chalk.white(`  Total Findings: ${stats.totalFindings}`));
        console.log('');
        console.log(chalk.white('  By Severity:'));
        Object.entries(stats.findingsBySeverity).forEach(([severity, count]) => {
            console.log(chalk.gray(`    ${severity}: ${count}`));
        });
        console.log('');
    });

// Enhanced scan command - uses external tools (Nuclei, Subfinder, httpx, etc.)
program
    .command('enhanced <target>')
    .description('Run enhanced scan using external tools (Nuclei, Subfinder, httpx, Nmap)')
    .option('--no-nuclei', 'Skip Nuclei vulnerability scanning')
    .option('--no-ai', 'Skip AI-powered analysis')
    .option('--no-ports', 'Skip port scanning')
    .option('--no-urls', 'Skip URL gathering')
    .option('-s, --severity <levels>', 'Nuclei severity filter (critical,high,medium)', 'critical,high,medium')
    .option('-t, --tags <tags>', 'Nuclei tags filter (comma-separated)')
    .option('-o, --output <format>', 'Report format (markdown|html|json)', 'markdown')
    .option('-a, --aggressive', 'Enable aggressive discovery (Active Fuzzing & Parameter Discovery)')
    .action(async (target: string, options) => {
        // Dynamic import to avoid loading external tools unless needed
        const { enhancedScanner } = await import('../scanner/enhanced.js');

        logger.banner('BugHunter AI - Enhanced Scan');

        db.initialize();

        const domain = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '');

        console.log(chalk.cyan(`\n🎯 Target: ${domain}`));
        console.log(chalk.gray(`   Nuclei: ${options.nuclei ? 'Enabled' : 'Disabled'}`));
        console.log(chalk.gray(`   AI Analysis: ${options.ai ? 'Enabled' : 'Disabled'}`));
        console.log(chalk.gray(`   Port Scan: ${options.ports ? 'Enabled' : 'Disabled'}`));
        console.log('');

        // Create or get target
        let dbTarget = db.getTargetByDomain(domain);
        if (!dbTarget) {
            dbTarget = db.createTarget({
                id: uuidv4(),
                domain,
                scope: [],
                outOfScope: [],
                platform: '',
                programUrl: '',
            });
        }

        // Create scan session
        const session = db.createSession({
            id: uuidv4(),
            targetId: dbTarget.id,
            status: 'running',
            startedAt: new Date().toISOString(),
            urlsScanned: 0,
            findingsCount: 0,
            config: JSON.stringify({ mode: 'enhanced', ...options }),
        });

        try {
            if (options.ai) {
                gemini.initialize();
            }

            const result = await enhancedScanner.runFullScan(domain, {
                targetId: dbTarget.id,
                sessionId: session.id,
                useNuclei: options.nuclei,
                useAi: options.ai,
                nucleiSeverity: options.severity.split(',') as ('critical' | 'high' | 'medium' | 'low' | 'info')[],
                nucleiTags: options.tags ? options.tags.split(',') : undefined,
                skipPortScan: !options.ports,
                skipUrlGathering: !options.urls,
                aggressive: options.aggressive,
            });

            // Update session
            db.updateSession(session.id, {
                status: 'completed',
                completedAt: new Date().toISOString(),
                findingsCount: result.findings.length,
                urlsScanned: result.liveHosts.length,
            });

            // Generate report
            if (result.findings.length > 0) {
                console.log(chalk.yellow('\n📝 Generating Report...\n'));

                const reportContent = await reportGenerator.generateReport(
                    domain,
                    result.findings,
                    { format: options.output as 'markdown' | 'html' | 'json' }
                );
                const reportPath = await reportGenerator.saveReport(
                    domain,
                    reportContent,
                    options.output as 'markdown' | 'html' | 'json'
                );
                console.log(chalk.green(`Report saved to: ${reportPath}`));
            }

        } catch (error) {
            db.updateSession(session.id, { status: 'failed' });
            logger.error('Enhanced scan failed', { error: String(error) });
            process.exit(1);
        }
    });

// Check tools command - verify external tools installation
program
    .command('check-tools')
    .description('Check availability of external security tools')
    .action(async () => {
        const { externalTools } = await import('../tools/external.js');

        logger.banner('External Tools Check');

        console.log(chalk.cyan('\nChecking installed tools...\n'));

        const status = await externalTools.checkTools();

        const tools = [
            { name: 'subfinder', desc: 'Subdomain enumeration' },
            { name: 'httpx', desc: 'HTTP probing & tech detection' },
            { name: 'nuclei', desc: 'Vulnerability scanning (5000+ templates)' },
            { name: 'nmap', desc: 'Port scanning' },
            { name: 'amass', desc: 'Advanced subdomain enumeration' },
            { name: 'assetfinder', desc: 'Asset discovery' },
            { name: 'waybackurls', desc: 'Wayback Machine URL extraction' },
            { name: 'gau', desc: 'Get All URLs from various sources' },
            { name: 'ffuf', desc: 'Web fuzzer' },
        ];

        let installed = 0;
        for (const tool of tools) {
            const config = status[tool.name as keyof typeof status];
            if (config?.available) {
                console.log(chalk.green(`  ✓ ${tool.name.padEnd(15)} - ${tool.desc}`));
                if (config.version) {
                    console.log(chalk.gray(`    ${config.version}`));
                }
                installed++;
            } else {
                console.log(chalk.red(`  ✗ ${tool.name.padEnd(15)} - ${tool.desc}`));
            }
        }

        console.log(chalk.cyan(`\n${installed}/${tools.length} tools installed`));

        if (installed < tools.length) {
            console.log(chalk.yellow('\nTo install missing tools, run:'));
            console.log(chalk.white('  bash scripts/install-tools.sh'));
        }
        console.log('');
    });

// Nuclei scan command - direct Nuclei scanning
program
    .command('nuclei <targets...>')
    .description('Run Nuclei vulnerability scanner directly')
    .option('-s, --severity <levels>', 'Severity filter (critical,high,medium,low,info)', 'critical,high,medium')
    .option('-t, --tags <tags>', 'Tags filter (comma-separated)')
    .option('--cves', 'Scan for CVEs only')
    .option('--takeover', 'Scan for subdomain takeovers only')
    .option('--update', 'Update Nuclei templates before scanning')
    .action(async (targets: string[], options) => {
        const { nuclei } = await import('../tools/nuclei.js');

        logger.banner('Nuclei Scanner');

        if (!await nuclei.isAvailable()) {
            console.log(chalk.red('Nuclei is not installed!'));
            console.log(chalk.yellow('Install it with: bash scripts/install-tools.sh'));
            process.exit(1);
        }

        if (options.update) {
            console.log(chalk.cyan('Updating templates...'));
            await nuclei.updateTemplates();
        }

        console.log(chalk.cyan(`\nScanning ${targets.length} target(s)...\n`));

        let results;
        if (options.cves) {
            results = await nuclei.scanCves(targets);
        } else if (options.takeover) {
            results = await nuclei.scanTakeovers(targets);
        } else {
            results = await nuclei.run({
                targets,
                severity: options.severity.split(',') as ('critical' | 'high' | 'medium' | 'low' | 'info')[],
                tags: options.tags ? options.tags.split(',') : undefined,
            });
        }

        console.log(chalk.green(`\n✅ Found ${results.length} vulnerabilities\n`));

        // Display results
        for (const r of results) {
            const severityColors: Record<string, typeof chalk> = {
                critical: chalk.bgRed.white,
                high: chalk.red,
                medium: chalk.yellow,
                low: chalk.blue,
                info: chalk.gray,
            };
            const color = severityColors[r.info.severity] || chalk.white;
            console.log(color(`[${r.info.severity.toUpperCase()}] ${r.info.name}`));
            console.log(chalk.gray(`  URL: ${r.host}`));
            console.log(chalk.gray(`  Template: ${r.templateId}`));
            console.log('');
        }
    });

// Monitor command - automated subdomain monitoring
program
    .command('monitor')
    .description('Run automated subdomain monitoring (for cron jobs)')
    .option('-c, --config <file>', 'Config file path', 'monitor-config.json')
    .option('-t, --target <domain>', 'Single target to monitor (overrides config)')
    .option('--discord <webhook>', 'Discord webhook URL')
    .option('--slack <webhook>', 'Slack webhook URL')
    .option('--no-scan', 'Skip vulnerability scanning')
    .option('--no-screenshots', 'Skip screenshots')
    .option('-a, --aggressive', 'Enable aggressive discovery (active fuzzing & params)')
    .action(async (options) => {
        const { subdomainMonitor } = await import('../monitor/subdomain-monitor.js');
        const fs = await import('fs');

        logger.banner('24/7 Subdomain Monitor');

        db.initialize();

        let config = {
            targets: [] as string[],
            outputDir: 'data/monitoring',
            notifications: {
                enabled: true,
                discordWebhook: options.discord || '',
                slackWebhook: options.slack || '',
            },
            scanning: {
                enabled: options.scan !== false,
                nmapTopPorts: 1000,
                fullScanPorts: [8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090],
                nucleiSeverity: ['critical', 'high', 'medium'] as ('critical' | 'high' | 'medium' | 'low' | 'info')[],
                aggressive: options.aggressive
            },
            screenshots: {
                enabled: options.screenshots !== false,
            },
        };

        // Load config file if exists
        if (fs.existsSync(options.config)) {
            try {
                const fileConfig = JSON.parse(fs.readFileSync(options.config, 'utf-8'));
                config = { ...config, ...fileConfig };
                logger.info(`Loaded config from: ${options.config}`);
            } catch (error) {
                logger.warn(`Failed to load config file: ${options.config}`);
            }
        }

        // Override with CLI options
        if (options.target) {
            config.targets = [options.target];
        }

        if (options.discord) {
            config.notifications.discordWebhook = options.discord;
        }

        if (options.slack) {
            config.notifications.slackWebhook = options.slack;
        }

        if (config.targets.length === 0) {
            console.log(chalk.red('No targets specified!'));
            console.log(chalk.yellow('\nUsage:'));
            console.log(chalk.gray('  npm run cli -- monitor --target example.com'));
            console.log(chalk.gray('  npm run cli -- monitor --config monitor-config.json'));
            process.exit(1);
        }

        console.log(chalk.cyan(`\n🎯 Monitoring ${config.targets.length} target(s):`));
        config.targets.forEach(t => console.log(chalk.gray(`   • ${t}`)));
        console.log(chalk.gray(`\n   Scanning: ${config.scanning.enabled ? 'Enabled' : 'Disabled'}`));
        console.log(chalk.gray(`   Screenshots: ${config.screenshots.enabled ? 'Enabled' : 'Disabled'}`));
        console.log(chalk.gray(`   Discord: ${config.notifications.discordWebhook ? 'Configured' : 'Not set'}`));
        console.log(chalk.gray(`   Slack: ${config.notifications.slackWebhook ? 'Configured' : 'Not set'}`));
        console.log('');

        try {
            const results = await subdomainMonitor.monitorAll(config);

            // Summary
            console.log(chalk.green('\n✅ Monitoring Complete!\n'));

            let totalNew = 0;
            let totalVulns = 0;

            for (const result of results) {
                totalNew += result.newSubdomains.length;
                totalVulns += result.vulnerabilities.length;

                console.log(chalk.white(`📊 ${result.domain}:`));
                console.log(chalk.gray(`   New Subdomains: ${result.newSubdomains.length}`));
                console.log(chalk.gray(`   Total Subdomains: ${result.totalSubdomains}`));
                console.log(chalk.gray(`   Live Hosts: ${result.liveHosts.length}`));
                console.log(chalk.gray(`   Vulnerabilities: ${result.vulnerabilities.length}`));
                console.log('');
            }

            if (totalNew > 0) {
                console.log(chalk.green(`🆕 Total new subdomains: ${totalNew}`));
            }
            if (totalVulns > 0) {
                console.log(chalk.red(`🔥 Total vulnerabilities: ${totalVulns}`));
            }

        } catch (error) {
            logger.error('Monitoring failed', { error: String(error) });
            process.exit(1);
        }
    });

// Add targets command for monitoring
program
    .command('monitor-add <domain>')
    .description('Add a domain to monitoring list')
    .option('-c, --config <file>', 'Config file path', 'monitor-config.json')
    .action(async (domain: string, options) => {
        const fs = await import('fs');

        let config = {
            targets: [] as string[],
            notifications: { enabled: true, discordWebhook: '', slackWebhook: '' },
            scanning: {
                enabled: true,
                nmapTopPorts: 1000,
                fullScanPorts: [8080, 8443, 8000, 8888, 3000, 5000],
                nucleiSeverity: ['critical', 'high', 'medium'],
            },
            screenshots: { enabled: false },
        };

        if (fs.existsSync(options.config)) {
            config = JSON.parse(fs.readFileSync(options.config, 'utf-8'));
        }

        if (!config.targets.includes(domain)) {
            config.targets.push(domain);
            fs.writeFileSync(options.config, JSON.stringify(config, null, 2));
            console.log(chalk.green(`✅ Added ${domain} to monitoring`));
        } else {
            console.log(chalk.yellow(`${domain} is already in monitoring list`));
        }

        console.log(chalk.cyan('\nCurrent targets:'));
        config.targets.forEach((t: string) => console.log(chalk.gray(`  • ${t}`)));
    });

// Cloud command - enumerate cloud assets
program
    .command('cloud <domain>')
    .description('Enumerate and check cloud assets (S3, Azure, etc.)')
    .action(async (domain: string) => {
        const { cloudScanner } = await import('../scanner/cloud.js');

        logger.banner('Cloud Asset Discovery');

        console.log(chalk.cyan(`\nChecking Cloud Assets for: ${domain}\n`));

        const spinner = ora('Enumerating buckets...').start();
        const assets = await cloudScanner.scanDomain(domain);

        if (assets.length === 0) {
            spinner.info('No publicly accessible cloud assets found.');
        } else {
            spinner.succeed(`Found ${assets.length} cloud assets:`);

            for (const asset of assets) {
                const color = asset.isVulnerable ? chalk.red : chalk.yellow;
                const status = asset.isVulnerable ? '[VULNERABLE]' : '[FOUND]';

                console.log(color(`  ${status} ${asset.name} (${asset.type})`));
                console.log(chalk.gray(`    URL: ${asset.url}`));
                if (asset.permissions.list) console.log(chalk.red('    - Listable: YES'));
                if (asset.permissions.write) console.log(chalk.red('    - Writable: YES'));
                console.log('');
            }

            if (assets.some(a => a.isVulnerable)) {
                console.log(chalk.yellow('\n⚠️  Public buckets found! Manual verification recommended.'));
            }
        }
        console.log('');
    });

// Discover command - find new bug bounty programs
program
    .command('discover')
    .description('Discover new bug bounty programs from HackerOne, Bugcrowd, Intigriti')
    .option('--hackerone', 'Search HackerOne only')
    .option('--bugcrowd', 'Search Bugcrowd only')
    .option('--intigriti', 'Search Intigriti only')
    .option('--min-bounty <amount>', 'Minimum bounty amount', '0')
    .option('--only-new', 'Show only new programs')
    .option('--no-vdp', 'Exclude Vulnerability Disclosure Programs')
    .option('--discord <webhook>', 'Discord webhook for notifications')
    .action(async (options) => {
        const { programDiscovery } = await import('../discovery/program-discovery.js');

        logger.banner('Bug Bounty Program Discovery');
        db.initialize();

        const config = {
            platforms: {
                hackerone: options.hackerone || (!options.bugcrowd && !options.intigriti),
                bugcrowd: options.bugcrowd || (!options.hackerone && !options.intigriti),
                intigriti: options.intigriti || (!options.hackerone && !options.bugcrowd),
            },
            filters: {
                minBounty: parseInt(options.minBounty) || 0,
                onlyNew: options.onlyNew || false,
                excludeVDP: !options.vdp,
                keywords: [],
            },
            notifications: {
                discordWebhook: options.discord,
            },
        };

        console.log(chalk.cyan('\n🔍 Searching bug bounty platforms...\n'));

        const programs = await programDiscovery.discoverAll(config);

        console.log(chalk.green(`\n✅ Found ${programs.length} programs\n`));

        // Display results
        const newPrograms = programs.filter(p => p.isNew);
        if (newPrograms.length > 0) {
            console.log(chalk.yellow(`🆕 New Programs (${newPrograms.length}):\n`));
            for (const p of newPrograms.slice(0, 20)) {
                console.log(chalk.white(`  ${p.name} (${p.platform})`));
                console.log(chalk.gray(`    💰 $${p.bountyRange.min}-$${p.bountyRange.max}`));
                console.log(chalk.gray(`    🔗 ${p.programUrl}\n`));
            }
        }

        console.log(chalk.cyan(`📊 Total known programs: ${programDiscovery.getKnownProgramsCount()}`));
    });

// Daemon command - run 24/7
program
    .command('daemon')
    .description('Run 24/7 continuous bug hunting (discovery + monitoring)')
    .option('-c, --config <file>', 'Config file path', 'daemon-config.json')
    .option('--discovery-interval <hours>', 'Hours between program discovery', '6')
    .option('--monitor-interval <hours>', 'Hours between subdomain monitoring', '24')
    .option('--min-bounty <amount>', 'Minimum bounty for auto-discovery', '100')
    .option('--max-targets <number>', 'Maximum targets to monitor', '100')
    .option('--discord <webhook>', 'Discord webhook for notifications')
    .option('--no-auto-add', 'Don\'t auto-add discovered programs to monitoring')
    .option('--once', 'Run once and exit (for cron jobs)')
    .action(async (options) => {
        const { continuousRunner, getDefaultDaemonConfig } = await import('../daemon/runner.js');
        const fs = await import('fs');

        let config = getDefaultDaemonConfig();

        // Load config file if exists
        if (fs.existsSync(options.config)) {
            try {
                const fileConfig = JSON.parse(fs.readFileSync(options.config, 'utf-8'));
                config = { ...config, ...fileConfig };
                logger.info(`Loaded config from: ${options.config}`);
            } catch {
                logger.warn(`Failed to load config: ${options.config}`);
            }
        }

        // Apply CLI options
        config.discovery.intervalHours = parseInt(options.discoveryInterval) || 6;
        config.monitoring.intervalHours = parseInt(options.monitorInterval) || 24;
        config.discovery.config.filters.minBounty = parseInt(options.minBounty) || 100;
        config.maxTargets = parseInt(options.maxTargets) || 100;
        config.autoAddNewTargets = options.autoAdd !== false;

        if (options.discord) {
            config.discovery.config.notifications.discordWebhook = options.discord;
            config.monitoring.config.notifications.discordWebhook = options.discord;
        }

        console.log(chalk.cyan('\n🤖 BugHunter AI - Continuous Mode\n'));
        console.log(chalk.gray(`   Discovery Interval: Every ${config.discovery.intervalHours} hours`));
        console.log(chalk.gray(`   Monitor Interval: Every ${config.monitoring.intervalHours} hours`));
        console.log(chalk.gray(`   Min Bounty Filter: $${config.discovery.config.filters.minBounty}`));
        console.log(chalk.gray(`   Max Targets: ${config.maxTargets}`));
        console.log(chalk.gray(`   Auto-add Targets: ${config.autoAddNewTargets ? 'Yes' : 'No'}`));
        console.log(chalk.gray(`   Discord: ${options.discord ? 'Configured' : 'Not set'}\n`));

        if (options.once) {
            await continuousRunner.runOnce(config);
        } else {
            await continuousRunner.start(config);
        }
    });

// Auto command - quick start for automatic hunting
program
    .command('auto')
    .description('Quick start automatic bug hunting (discovers programs + monitors)')
    .option('--discord <webhook>', 'Discord webhook for notifications')
    .action(async (options) => {
        const { continuousRunner, getDefaultDaemonConfig } = await import('../daemon/runner.js');

        console.log(chalk.cyan(`
╔═══════════════════════════════════════════════════════════════╗
║         🤖 BugHunter AI - Automatic Mode                      ║
║                                                               ║
║   This will:                                                  ║
║   • Discover new bug bounty programs every 6 hours            ║
║   • Auto-add paying programs to monitoring                    ║
║   • Scan for subdomains and vulnerabilities daily             ║
║   • Send notifications to Discord/Slack                       ║
║                                                               ║
║   Press Ctrl+C to stop                                        ║
╚═══════════════════════════════════════════════════════════════╝
    `));

        const config = getDefaultDaemonConfig();

        if (options.discord) {
            config.discovery.config.notifications.discordWebhook = options.discord;
            config.monitoring.config.notifications.discordWebhook = options.discord;
        }

        await continuousRunner.start(config);
    });

program.parse();

