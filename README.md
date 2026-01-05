# 🎯 BugHunter AI

An AI-powered bug bounty automation tool that leverages **Google Gemini 3.0 Pro** for intelligent vulnerability discovery, analysis, and reporting.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Node](https://img.shields.io/badge/node-%3E%3D20.0.0-green)
![License](https://img.shields.io/badge/license-MIT-purple)

## ✨ Features

- 🔍 **Automated Reconnaissance**
  - Subdomain enumeration (Subfinder + crt.sh, HackerTarget, urlscan.io, SecurityTrails)
  - Technology fingerprinting (httpx integration)
  - Port scanning (Nmap integration)
  - Wayback Machine archive crawling (gau, waybackurls)

- 🕷️ **Intelligent Crawling**
  - Web page crawling with form extraction
  - API endpoint discovery (Swagger/OpenAPI parsing)
  - JavaScript file analysis
  - Parameter extraction

- 🔥 **Nuclei Integration**
  - 5000+ vulnerability templates
  - CVE scanning
  - Subdomain takeover detection
  - Automatic template updates

- 🤖 **AI-Powered Analysis**
  - Gemini 3.0 Pro integration for smart vulnerability detection
  - Pattern-based pre-filtering + AI confirmation
  - False positive reduction
  - Automatic severity classification

- 🎯 **Vulnerability Detection**
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Insecure Direct Object Reference (IDOR)
  - API Security Issues
  - Information Disclosure
  - Security Misconfigurations
  - CVEs and known vulnerabilities

- 📝 **Report Generation**
  - Professional bug bounty reports
  - Markdown, HTML, and JSON formats
  - AI-assisted remediation suggestions
  - HackerOne/Bugcrowd ready

- 📊 **Dashboard & CLI**
  - Web-based findings management
  - 9 CLI commands for different scan types
  - Status tracking (new, verified, reported)

## 🚀 Quick Start

### Prerequisites

- Node.js 20.0.0 or higher
- Google Gemini API key

### Installation

```bash
# Clone or navigate to the project
cd Bug_Bounty_Hunter

# Install dependencies
npm install

# Copy environment file and add your API key
cp .env.example .env

# Edit .env and add your Gemini API key
nano .env
```

### Configuration

Edit `.env` file:

```env
# Required
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-pro-preview-05-06

# Optional - Enhanced reconnaissance
SECURITYTRAILS_API_KEY=
SHODAN_API_KEY=

# Scanner settings
MAX_CONCURRENT_REQUESTS=10
REQUEST_DELAY_MS=100
MAX_CRAWL_DEPTH=5
```

### Basic Usage

```bash
# Run a full scan
npm run cli -- scan example.com

# Scan with custom options
npm run cli -- scan example.com --depth 5 --pages 200

# Scan without AI (faster, less accurate)
npm run cli -- scan example.com --no-ai

# Reconnaissance only
npm run cli -- recon example.com --all

# API-only scan
npm run cli -- scan example.com --api-only
```

### 🔧 External Tools (Recommended for Production)

For maximum effectiveness, install external security tools:

```bash
# On Ubuntu/Debian (GCloud, AWS, etc.)
bash scripts/install-tools.sh
```

This installs:
- **Subfinder** - Fast subdomain enumeration
- **httpx** - HTTP probing with tech detection
- **Nuclei** - Vulnerability scanning (5000+ templates)
- **Nmap** - Port scanning
- **Amass** - Advanced subdomain enumeration
- **gau/waybackurls** - URL gathering from archives
- **ffuf** - Web fuzzer

Verify installation:
```bash
npm run cli -- check-tools
```

### Enhanced Scan (Uses External Tools)

```bash
# Full enhanced scan with all tools
npm run cli -- enhanced example.com

# Enhanced scan with specific options
npm run cli -- enhanced example.com --severity critical,high --no-ports

# Direct Nuclei scanning
npm run cli -- nuclei https://example.com --cves

# Nuclei with specific tags
npm run cli -- nuclei https://example.com --tags xss,sqli,rce
```

## 📖 Commands

### `scan <target>`

Perform a full vulnerability scan on a target.

```bash
npm run cli -- scan example.com [options]

Options:
  -d, --depth <number>    Max crawl depth (default: 3)
  -p, --pages <number>    Max pages to crawl (default: 100)
  --no-ai                 Disable AI-powered analysis
  --no-recon              Skip reconnaissance phase
  --api-only              Only scan API endpoints
  -o, --output <format>   Report format: markdown|html|json (default: markdown)
  --scope <patterns>      Comma-separated scope patterns
```

### `recon <domain>`

Perform reconnaissance on a target domain.

```bash
npm run cli -- recon example.com [options]

Options:
  --subdomains    Enumerate subdomains
  --tech          Detect technologies
  --archive       Search web archives
  --all           Run all reconnaissance modules
```

### `targets`

Manage scan targets.

```bash
# List all targets
npm run cli -- targets --list

# Add a new target
npm run cli -- targets --add example.com --platform hackerone --program https://hackerone.com/example
```

### `findings`

View and manage findings.

```bash
# View all findings
npm run cli -- findings

# Filter by target
npm run cli -- findings --target example.com

# Filter by severity
npm run cli -- findings --severity critical

# Export findings
npm run cli -- findings --export json
```

### `report <domain>`

Generate reports for a target.

```bash
# Generate full report
npm run cli -- report example.com --format html

# Generate bug bounty report for specific finding
npm run cli -- report example.com --finding <finding-id>
```

### `stats`

Show statistics.

```bash
npm run cli -- stats
```

## 🖥️ Dashboard

Start the web dashboard:

```bash
npm run dashboard
```

Access at: http://localhost:3000

Features:
- View all findings with filters
- Update finding status
- Statistics overview
- Target management

## 🏗️ Project Structure

```
Bug_Bounty_Hunter/
├── src/
│   ├── cli/              # CLI commands
│   ├── config/           # Configuration management
│   ├── core/             # Core modules (Gemini, DB, Logger)
│   ├── crawler/          # Web and API crawlers
│   ├── dashboard/        # Web dashboard
│   ├── recon/            # Reconnaissance modules
│   ├── reporter/         # Report generation
│   └── scanner/          # Vulnerability scanner
│       └── patterns/     # Detection patterns (SQLi, XSS, etc.)
├── data/                 # SQLite database
├── logs/                 # Log files
├── reports/              # Generated reports
└── wordlists/            # Wordlists for enumeration
```

## ⚠️ Legal & Ethical Considerations

> **IMPORTANT**: This tool is for authorized security testing only.

1. **Always get written permission** before scanning any target
2. **Respect scope boundaries** - only scan authorized domains
3. **Follow platform rules** - read bug bounty program policies
4. **Use responsibly** - avoid excessive requests that could cause DoS
5. **Verify findings** - AI can produce false positives

### Safe Usage Tips

- Use `--scope` to limit scanning to authorized domains
- Use `REQUEST_DELAY_MS` to control request rate
- Enable `RESPECT_ROBOTS_TXT` for ethical crawling
- Always verify findings before reporting

## 💰 Revenue Potential

Based on typical bug bounty payouts:

| Vulnerability Type | Typical Payout | AI Detection |
|-------------------|----------------|--------------|
| Critical RCE | $5,000-$50,000+ | Medium |
| SQL Injection | $1,000-$10,000 | High |
| XSS (Stored) | $500-$5,000 | High |
| IDOR | $500-$3,000 | High |
| API Auth Bypass | $1,000-$10,000 | Medium-High |
| Info Disclosure | $100-$1,000 | High |

**Realistic expectation**: 2-5 valid medium-severity bugs/month = $1,000-$5,000/month

## 🔧 Development

```bash
# Build TypeScript
npm run build

# Run in development mode
npm run dev

# Run tests
npm test

# Lint code
npm run lint
```

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- Google Gemini for AI capabilities
- The bug bounty community for inspiration
- OWASP for security standards

---

**Disclaimer**: This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool.
