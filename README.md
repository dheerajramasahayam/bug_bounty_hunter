# 🎯 BugHunter AI

An AI-powered bug bounty automation tool that runs **24/7**, discovering programs, finding vulnerabilities, and notifying you when it finds bugs.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Node](https://img.shields.io/badge/node-%3E%3D20.0.0-green)
![License](https://img.shields.io/badge/license-MIT-purple)

## 🚀 What It Does

```
┌─────────────────────────────────────────────────────────────────┐
│                    24/7 AUTOMATED BUG HUNTING                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Every 6 hours:                                                │
│   🔍 Discover new programs from HackerOne/Bugcrowd/Intigriti    │
│   ➕ Auto-add paying programs to monitoring                      │
│                                                                  │
│   Every 24 hours:                                               │
│   📡 Enumerate subdomains (Subfinder + Amass + Assetfinder)     │
│   🆕 Detect NEW subdomains (compare with yesterday)             │
│   🌐 Probe live hosts (httpx)                                   │
│   🔌 Smart port scan (quick → full on interesting ports)        │
│   🔥 Vulnerability scan (Nuclei 5000+ templates)                │
│                                                                  │
│   On findings:                                                  │
│   📱 Notify via Discord/Slack/Telegram                          │
│   💾 Save to database for reporting                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## ⚡ Quick Start

### Local Development (Mac/Linux)

```bash
# Clone
git clone https://github.com/dheerajramasahayam/bug_bounty_hunter.git
cd bug_bounty_hunter

# Install
npm install
cp .env.example .env
nano .env  # Add GEMINI_API_KEY

# Run a scan
npm run cli -- scan example.com
```

### Production (GCloud Ubuntu VM)

```bash
# SSH into your VM
gcloud compute ssh your-instance

# One-command deploy
git clone https://github.com/dheerajramasahayam/bug_bounty_hunter.git
cd bug_bounty_hunter
bash scripts/deploy-gcloud.sh

# Start 24/7 automated hunting
npm run cli -- auto --discord "YOUR_WEBHOOK_URL"
```

## 📖 Commands

### 🎯 Scanning Commands

| Command | Description |
|---------|-------------|
| `scan <target>` | Basic scan with AI analysis |
| `enhanced <target>` | Full scan with all external tools |
| `nuclei <targets...>` | Direct Nuclei vulnerability scanning |
| `recon <domain>` | Reconnaissance only |

```bash
# Basic scan
npm run cli -- scan example.com

# Enhanced scan with Nuclei + Nmap
npm run cli -- enhanced example.com --severity critical,high

# Direct Nuclei scan
npm run cli -- nuclei https://example.com --cves --tags xss,sqli
```

### 🔍 Discovery Commands

| Command | Description |
|---------|-------------|
| `discover` | Find new bug bounty programs |
| `monitor` | Run subdomain monitoring cycle |
| `monitor-add <domain>` | Add domain to monitoring list |

```bash
# Discover programs paying $500+
npm run cli -- discover --min-bounty 500

# Monitor specific target
npm run cli -- monitor --target hackerone.com

# Add domain to monitoring
npm run cli -- monitor-add bugcrowd.com
```

### 🤖 24/7 Automation Commands

| Command | Description |
|---------|-------------|
| `auto` | **Easiest** - Start automatic hunting |
| `daemon` | Advanced continuous mode with options |

```bash
# Quick start (recommended)
npm run cli -- auto --discord "https://discord.com/api/webhooks/..."

# Advanced daemon with options
npm run cli -- daemon \
  --discovery-interval 6 \
  --monitor-interval 24 \
  --min-bounty 100 \
  --max-targets 100 \
  --discord "YOUR_WEBHOOK"
```

### 📊 Management Commands

| Command | Description |
|---------|-------------|
| `targets` | List and manage targets |
| `findings` | View vulnerability findings |
| `report <domain>` | Generate reports |
| `stats` | Show statistics |
| `check-tools` | Verify tool installation |

## 🔧 External Tools

For maximum effectiveness, install these on your server:

```bash
bash scripts/install-tools.sh
```

| Tool | Purpose | Status |
|------|---------|--------|
| Subfinder | Subdomain enumeration | ⚡ Fast |
| Amass | Advanced subdomain discovery | 🔍 Thorough |
| httpx | HTTP probing + tech detection | 🌐 Essential |
| Nuclei | Vulnerability scanning (5000+ templates) | 🔥 Critical |
| Nmap | Port scanning | 🔌 Important |
| gau/waybackurls | Historical URL discovery | 📜 Useful |

Check installation:
```bash
npm run cli -- check-tools
```

## 📱 Notifications

### Discord

1. Go to Server Settings → Integrations → Webhooks
2. Create New Webhook, copy URL
3. Use with `--discord "WEBHOOK_URL"`

### Slack

1. Go to api.slack.com/apps → Create App
2. Add Incoming Webhooks, copy URL
3. Use with `--slack "WEBHOOK_URL"`

### Telegram

1. Message @BotFather → /newbot → Get token
2. Message @userinfobot → Get chat ID
3. Configure in `daemon-config.json`

## ⚙️ Configuration

### Environment Variables (.env)

```env
# Required
GEMINI_API_KEY=your_gemini_api_key

# Optional APIs (for enhanced recon)
SECURITYTRAILS_API_KEY=
SHODAN_API_KEY=

# Scanner settings
MAX_CONCURRENT_REQUESTS=10
REQUEST_DELAY_MS=100
```

### Daemon Config (daemon-config.json)

```json
{
  "discovery": {
    "enabled": true,
    "intervalHours": 6,
    "filters": {
      "minBounty": 100,
      "excludeVDP": true
    }
  },
  "monitoring": {
    "enabled": true,
    "intervalHours": 24,
    "targets": ["example.com"]
  },
  "notifications": {
    "discord": {
      "webhookUrl": "https://discord.com/api/webhooks/..."
    }
  },
  "autoAddNewTargets": true,
  "maxTargets": 100
}
```

## 🏗️ Project Structure

```
bug_bounty_hunter/
├── src/
│   ├── cli/           # CLI commands (14 commands)
│   ├── core/          # Database, Logger, Gemini AI, Notifications
│   ├── crawler/       # Web and API crawlers
│   ├── daemon/        # 24/7 continuous runner
│   ├── dashboard/     # Web dashboard
│   ├── discovery/     # Bug bounty program discovery
│   ├── monitor/       # Subdomain monitoring
│   ├── recon/         # Reconnaissance modules
│   ├── reporter/      # Report generation
│   ├── scanner/       # Vulnerability scanner
│   └── tools/         # External tool wrappers
├── scripts/
│   ├── install-tools.sh   # Install Nuclei, Subfinder, etc.
│   ├── deploy-gcloud.sh   # GCloud deployment
│   └── setup-cron.sh      # Cron job setup
├── ecosystem.config.cjs   # PM2 configuration
└── daemon-config.example.json
```

## 💰 Realistic Earnings

Based on typical bug bounty payouts:

| Vulnerability | Typical Payout | AI Detection Rate |
|--------------|----------------|-------------------|
| Critical RCE | $5,000-$50,000+ | Medium |
| SQL Injection | $1,000-$10,000 | High |
| XSS (Stored) | $500-$5,000 | High |
| IDOR | $500-$3,000 | High |
| Subdomain Takeover | $500-$2,000 | Very High |
| Info Disclosure | $100-$1,000 | High |

**Conservative estimate**: 2-5 valid medium-severity bugs/month = **$1,000-$5,000/month**

## ⚠️ Legal & Ethics

> **IMPORTANT**: Only scan authorized targets!

1. ✅ Only scan programs you're authorized to test
2. ✅ Respect scope boundaries
3. ✅ Follow platform rules (HackerOne Terms, Bugcrowd ToS)
4. ✅ Verify findings before reporting
5. ❌ Never scan without permission
6. ❌ Don't cause DoS or damage

## 🔧 PM2 Commands (Production)

```bash
pm2 start ecosystem.config.cjs    # Start daemon
pm2 status                        # Check status
pm2 logs                          # View logs
pm2 monit                         # Interactive monitor
pm2 restart bughunter-daemon      # Restart
pm2 stop all                      # Stop all
pm2 save                          # Save process list
pm2 startup                       # Auto-start on reboot
```

## 📄 License

MIT License - see LICENSE file.

## 🙏 Acknowledgments

- Google Gemini for AI capabilities
- ProjectDiscovery for Nuclei, Subfinder, httpx
- The bug bounty community

---

**Made for hunters who want to wake up to bug bounty notifications.** 🤑
