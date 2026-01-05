#!/bin/bash

# =============================================================================
# BugHunter AI - Automated Monitoring Cron Setup
# Runs monitoring every 24 hours and sends notifications on new findings
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_DIR/logs"
CONFIG_FILE="$PROJECT_DIR/monitor-config.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         BugHunter AI - Cron Monitoring Setup                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Create log directory
mkdir -p "$LOG_DIR"

# Check if config exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}Creating default monitoring config...${NC}"
    cat > "$CONFIG_FILE" << 'EOF'
{
  "targets": [
    "example.com"
  ],
  "notifications": {
    "enabled": true,
    "discordWebhook": "",
    "slackWebhook": ""
  },
  "scanning": {
    "enabled": true,
    "nmapTopPorts": 1000,
    "fullScanPorts": [8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090],
    "nucleiSeverity": ["critical", "high", "medium"]
  },
  "screenshots": {
    "enabled": false
  },
  "schedule": {
    "intervalHours": 24
  }
}
EOF
    echo -e "${GREEN}Created: $CONFIG_FILE${NC}"
    echo -e "${YELLOW}Please edit this file to add your targets and webhook URLs${NC}"
fi

# Create the monitoring script
MONITOR_SCRIPT="$SCRIPT_DIR/run-monitor.sh"
cat > "$MONITOR_SCRIPT" << EOF
#!/bin/bash
# Auto-generated monitoring script
cd "$PROJECT_DIR"
export PATH="\$PATH:\$HOME/go/bin:/usr/local/go/bin"
source ~/.bashrc 2>/dev/null || true

LOG_FILE="$LOG_DIR/monitor-\$(date +%Y-%m-%d).log"

echo "[\$(date)] Starting monitoring cycle..." >> "\$LOG_FILE"

# Run the monitoring command
npm run cli -- monitor --config "$CONFIG_FILE" >> "\$LOG_FILE" 2>&1

echo "[\$(date)] Monitoring cycle complete" >> "\$LOG_FILE"
EOF

chmod +x "$MONITOR_SCRIPT"
echo -e "${GREEN}Created: $MONITOR_SCRIPT${NC}"

# Set up cron job
echo -e "\n${BLUE}Setting up cron job...${NC}"

# Check if cron job already exists
CRON_CMD="0 */24 * * * $MONITOR_SCRIPT"
EXISTING_CRON=$(crontab -l 2>/dev/null | grep -F "$MONITOR_SCRIPT" || true)

if [ -z "$EXISTING_CRON" ]; then
    # Add new cron job
    (crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -
    echo -e "${GREEN}✓ Cron job added: Runs every 24 hours${NC}"
else
    echo -e "${YELLOW}Cron job already exists${NC}"
fi

# Show current cron jobs
echo -e "\n${BLUE}Current cron jobs:${NC}"
crontab -l 2>/dev/null | grep -v "^#" | head -10

echo -e "\n${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Next steps:"
echo -e "  1. Edit ${YELLOW}$CONFIG_FILE${NC}"
echo -e "     - Add your target domains"
echo -e "     - Add Discord/Slack webhook URLs"
echo ""
echo -e "  2. Test monitoring manually:"
echo -e "     ${YELLOW}npm run cli -- monitor --config $CONFIG_FILE${NC}"
echo ""
echo -e "  3. View logs:"
echo -e "     ${YELLOW}tail -f $LOG_DIR/monitor-\$(date +%Y-%m-%d).log${NC}"
echo ""
echo -e "  4. Manage cron jobs:"
echo -e "     ${YELLOW}crontab -e${NC}  # Edit"
echo -e "     ${YELLOW}crontab -l${NC}  # List"
echo ""
