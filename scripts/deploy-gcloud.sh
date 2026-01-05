#!/bin/bash

# =============================================================================
# BugHunter AI - GCloud Ubuntu Deployment Script
# Run this from the project root directory
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         🤖 BugHunter AI - GCloud Deployment                   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}Project directory: $PROJECT_DIR${NC}"
cd "$PROJECT_DIR"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}Warning: Running as root. Consider using a non-root user.${NC}"
fi

# Update system
echo -e "\n${BLUE}[1/7] Updating system...${NC}"
sudo apt-get update && sudo apt-get upgrade -y

# Install Node.js 20
echo -e "\n${BLUE}[2/7] Installing Node.js 20...${NC}"
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
else
    echo -e "${GREEN}Node.js already installed: $(node --version)${NC}"
fi

# Verify Node.js
echo "Node.js: $(node --version)"
echo "npm: $(npm --version)"

# Install PM2 globally
echo -e "\n${BLUE}[3/7] Installing PM2...${NC}"
if ! command -v pm2 &> /dev/null; then
    sudo npm install -g pm2
else
    echo -e "${GREEN}PM2 already installed${NC}"
fi

# Install security tools
echo -e "\n${BLUE}[4/7] Installing security tools...${NC}"
INSTALL_SCRIPT="$PROJECT_DIR/scripts/install-tools.sh"
if [ -f "$INSTALL_SCRIPT" ]; then
    chmod +x "$INSTALL_SCRIPT"
    bash "$INSTALL_SCRIPT"
else
    echo -e "${YELLOW}install-tools.sh not found at $INSTALL_SCRIPT${NC}"
    echo -e "${YELLOW}You can install tools later with: bash scripts/install-tools.sh${NC}"
fi

# Install project dependencies
echo -e "\n${BLUE}[5/7] Installing project dependencies...${NC}"
cd "$PROJECT_DIR"
npm install

# Build the project
echo -e "\n${BLUE}[6/7] Building project...${NC}"
npm run build

# Create logs directory
mkdir -p "$PROJECT_DIR/logs"

# Check for .env file
if [ ! -f "$PROJECT_DIR/.env" ]; then
    echo -e "\n${YELLOW}[IMPORTANT] No .env file found!${NC}"
    echo -e "Please create .env with your API key:"
    echo -e "${GREEN}cp .env.example .env${NC}"
    echo -e "${GREEN}nano .env${NC}"
    echo ""
fi

# Set up PM2
echo -e "\n${BLUE}[7/7] Setting up PM2 for 24/7 operation...${NC}"

cd "$PROJECT_DIR"

# Check if ecosystem.config.cjs exists
ECOSYSTEM_FILE="$PROJECT_DIR/ecosystem.config.cjs"
if [ -f "$ECOSYSTEM_FILE" ]; then
    echo -e "${GREEN}Found ecosystem.config.cjs${NC}"
    
    # Start the daemon
    pm2 start "$ECOSYSTEM_FILE" --only bughunter-daemon || {
        echo -e "${YELLOW}PM2 start failed. You may need to configure .env first.${NC}"
        echo -e "${YELLOW}After configuring, run: pm2 start ecosystem.config.cjs${NC}"
    }

    # Save PM2 process list
    pm2 save

    # Set up PM2 to start on boot
    echo -e "\n${BLUE}Setting up PM2 startup...${NC}"
    pm2 startup systemd -u $USER --hp $HOME || sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u $USER --hp $HOME
    pm2 save
else
    echo -e "${RED}ecosystem.config.cjs not found at $ECOSYSTEM_FILE${NC}"
    echo -e "${YELLOW}You can start manually with: npm run cli -- daemon${NC}"
fi

echo -e "\n${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Deployment Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo ""
echo -e "  1. Configure your API key:"
echo -e "     ${GREEN}cd $PROJECT_DIR${NC}"
echo -e "     ${GREEN}cp .env.example .env${NC}"
echo -e "     ${GREEN}nano .env${NC}"
echo ""
echo -e "  2. Install security tools (if skipped):"
echo -e "     ${GREEN}bash scripts/install-tools.sh${NC}"
echo ""
echo -e "  3. Start 24/7 hunting with Discord notifications:"
echo -e "     ${GREEN}npm run cli -- auto --discord 'YOUR_WEBHOOK_URL'${NC}"
echo ""
echo -e "  4. Or use PM2 for production:"
echo -e "     ${GREEN}pm2 start ecosystem.config.cjs${NC}"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo -e "  ${GREEN}npm run cli -- --help${NC}    - See all commands"
echo -e "  ${GREEN}npm run cli -- check-tools${NC} - Verify tools installed"
echo -e "  ${GREEN}pm2 status${NC}              - Check PM2 status"
echo -e "  ${GREEN}pm2 logs${NC}                - View logs"
echo ""
