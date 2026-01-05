#!/bin/bash

# =============================================================================
# BugHunter AI - GCloud Ubuntu Deployment Script
# Run this on a fresh GCloud Ubuntu VM to set up 24/7 automated bug hunting
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         🤖 BugHunter AI - GCloud Deployment                   ║"
echo "║                                                               ║"
echo "║   This script will:                                          ║"
echo "║   • Install Node.js, Go, and all dependencies                ║"
echo "║   • Install security tools (Nuclei, Subfinder, etc.)         ║"
echo "║   • Set up PM2 for 24/7 operation                            ║"
echo "║   • Configure auto-restart on boot                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}Warning: Running as root. Creating non-root user is recommended.${NC}"
fi

# Update system
echo -e "\n${BLUE}[1/7] Updating system...${NC}"
sudo apt-get update && sudo apt-get upgrade -y

# Install Node.js 20
echo -e "\n${BLUE}[2/7] Installing Node.js 20...${NC}"
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify Node.js
node --version
npm --version

# Install PM2 globally
echo -e "\n${BLUE}[3/7] Installing PM2...${NC}"
sudo npm install -g pm2

# Install security tools
echo -e "\n${BLUE}[4/7] Installing security tools...${NC}"
if [ -f "scripts/install-tools.sh" ]; then
    chmod +x scripts/install-tools.sh
    bash scripts/install-tools.sh
else
    echo -e "${YELLOW}install-tools.sh not found, skipping...${NC}"
fi

# Install project dependencies
echo -e "\n${BLUE}[5/7] Installing project dependencies...${NC}"
npm install

# Build the project
echo -e "\n${BLUE}[6/7] Building project...${NC}"
npm run build

# Create logs directory
mkdir -p logs

# Check for .env file
if [ ! -f ".env" ]; then
    echo -e "\n${YELLOW}[IMPORTANT] No .env file found!${NC}"
    echo -e "Please create .env with your API key:"
    echo -e "${GREEN}cp .env.example .env${NC}"
    echo -e "${GREEN}nano .env${NC}"
    echo ""
fi

# Set up PM2
echo -e "\n${BLUE}[7/7] Setting up PM2 for 24/7 operation...${NC}"

# Start the daemon
pm2 start ecosystem.config.cjs --only bughunter-daemon

# Save PM2 process list
pm2 save

# Set up PM2 to start on boot
sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u $USER --hp $HOME
pm2 save

echo -e "\n${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Deployment Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "BugHunter AI is now running 24/7!"
echo ""
echo -e "${YELLOW}Important next steps:${NC}"
echo -e "  1. Add your Gemini API key to .env:"
echo -e "     ${GREEN}nano .env${NC}"
echo ""
echo -e "  2. Add Discord webhook for notifications:"
echo -e "     ${GREEN}pm2 stop bughunter-daemon${NC}"
echo -e "     ${GREEN}pm2 start ecosystem.config.cjs --only bughunter-daemon -- daemon --discord 'YOUR_WEBHOOK_URL'${NC}"
echo ""
echo -e "${YELLOW}Useful PM2 commands:${NC}"
echo -e "  ${GREEN}pm2 status${NC}           - Check status"
echo -e "  ${GREEN}pm2 logs${NC}             - View logs"
echo -e "  ${GREEN}pm2 restart all${NC}      - Restart all processes"
echo -e "  ${GREEN}pm2 stop all${NC}         - Stop all processes"
echo -e "  ${GREEN}pm2 monit${NC}            - Interactive monitoring"
echo ""
echo -e "${YELLOW}Check current status:${NC}"
pm2 status
echo ""
