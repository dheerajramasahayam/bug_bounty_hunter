#!/bin/bash

# =============================================================================
# BugHunter AI - External Tools Installation Script
# For Ubuntu/Debian servers (GCloud, AWS, etc.)
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           BugHunter AI - Tools Installation Script            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Note: Some installations may require sudo password${NC}"
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}Cannot detect OS. This script is designed for Ubuntu/Debian.${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS${NC}"

# Update package list
echo -e "\n${BLUE}[1/10] Updating package lists...${NC}"
sudo apt-get update -qq

# Install basic dependencies
echo -e "\n${BLUE}[2/10] Installing basic dependencies...${NC}"
sudo apt-get install -y -qq \
    git \
    curl \
    wget \
    unzip \
    jq \
    chromium-browser \
    libssl-dev \
    build-essential \
    python3 \
    python3-pip \
    2>/dev/null

# Install Go (required for many security tools)
echo -e "\n${BLUE}[3/10] Installing Go 1.21...${NC}"
if ! command -v go &> /dev/null; then
    wget -q https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
    rm go1.21.6.linux-amd64.tar.gz
    
    # Add Go to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo -e "${GREEN}Go installed successfully${NC}"
else
    echo -e "${YELLOW}Go already installed: $(go version)${NC}"
fi

# Install Node.js 20 LTS
echo -e "\n${BLUE}[4/10] Installing Node.js 20 LTS...${NC}"
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
    echo -e "${GREEN}Node.js installed: $(node --version)${NC}"
else
    echo -e "${YELLOW}Node.js already installed: $(node --version)${NC}"
fi

# Install Subfinder
echo -e "\n${BLUE}[5/10] Installing Subfinder...${NC}"
if ! command -v subfinder &> /dev/null; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    echo -e "${GREEN}Subfinder installed${NC}"
else
    echo -e "${YELLOW}Subfinder already installed${NC}"
fi

# Install httpx
echo -e "\n${BLUE}[6/10] Installing httpx...${NC}"
if ! command -v httpx &> /dev/null; then
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    echo -e "${GREEN}httpx installed${NC}"
else
    echo -e "${YELLOW}httpx already installed${NC}"
fi

# Install Nuclei
echo -e "\n${BLUE}[7/10] Installing Nuclei...${NC}"
if ! command -v nuclei &> /dev/null; then
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    # Update nuclei templates
    nuclei -update-templates -silent 2>/dev/null || true
    echo -e "${GREEN}Nuclei installed with templates${NC}"
else
    echo -e "${YELLOW}Nuclei already installed${NC}"
    nuclei -update-templates -silent 2>/dev/null || true
fi

# Install Nmap
echo -e "\n${BLUE}[8/10] Installing Nmap...${NC}"
if ! command -v nmap &> /dev/null; then
    sudo apt-get install -y nmap
    echo -e "${GREEN}Nmap installed${NC}"
else
    echo -e "${YELLOW}Nmap already installed: $(nmap --version | head -n1)${NC}"
fi

# Install Amass
echo -e "\n${BLUE}[9/10] Installing Amass...${NC}"
if ! command -v amass &> /dev/null; then
    go install -v github.com/owasp-amass/amass/v4/...@master
    echo -e "${GREEN}Amass installed${NC}"
else
    echo -e "${YELLOW}Amass already installed${NC}"
fi

# Install additional Go tools
echo -e "\n${BLUE}[10/10] Installing additional tools...${NC}"

# Assetfinder
if ! command -v assetfinder &> /dev/null; then
    go install github.com/tomnomnom/assetfinder@latest
    echo -e "${GREEN}Assetfinder installed${NC}"
fi

# waybackurls
if ! command -v waybackurls &> /dev/null; then
    go install github.com/tomnomnom/waybackurls@latest
    echo -e "${GREEN}waybackurls installed${NC}"
fi

# gau (Get All URLs)
if ! command -v gau &> /dev/null; then
    go install github.com/lc/gau/v2/cmd/gau@latest
    echo -e "${GREEN}gau installed${NC}"
fi

# ffuf (web fuzzer)
if ! command -v ffuf &> /dev/null; then
    go install github.com/ffuf/ffuf/v2@latest
    echo -e "${GREEN}ffuf installed${NC}"
fi

# Create tools directory for wordlists
echo -e "\n${BLUE}Downloading wordlists...${NC}"
WORDLIST_DIR="$HOME/wordlists"
mkdir -p "$WORDLIST_DIR"

# Download SecLists (most popular wordlists)
if [ ! -d "$WORDLIST_DIR/SecLists" ]; then
    echo "Downloading SecLists (this may take a while)..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLIST_DIR/SecLists" 2>/dev/null
    echo -e "${GREEN}SecLists downloaded${NC}"
else
    echo -e "${YELLOW}SecLists already exists${NC}"
fi

# Verify installations
echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Installation Complete! Verifying tools...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"

# Source bashrc to get updated PATH
source ~/.bashrc 2>/dev/null || true

declare -A tools=(
    ["subfinder"]="subfinder -version 2>&1 | head -n1"
    ["httpx"]="httpx -version 2>&1 | head -n1"
    ["nuclei"]="nuclei -version 2>&1 | head -n1"
    ["nmap"]="nmap --version 2>&1 | head -n1"
    ["amass"]="amass -version 2>&1 | head -n1"
    ["assetfinder"]="echo 'assetfinder installed'"
    ["waybackurls"]="echo 'waybackurls installed'"
    ["gau"]="gau -version 2>&1 | head -n1"
    ["ffuf"]="ffuf -V 2>&1 | head -n1"
    ["go"]="go version"
    ["node"]="node --version"
)

for tool in "${!tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        version=$(eval "${tools[$tool]}" 2>/dev/null || echo "installed")
        echo -e "  ${GREEN}✓${NC} $tool: $version"
    else
        echo -e "  ${RED}✗${NC} $tool: NOT FOUND"
    fi
done

echo -e "\n${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}All tools installed! You may need to restart your shell or run:${NC}"
echo -e "${YELLOW}  source ~/.bashrc${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"

# Create a config file for tool paths
CONFIG_FILE="$(dirname "$0")/.tools-config"
cat > "$CONFIG_FILE" << EOF
# BugHunter AI - External Tools Configuration
# Auto-generated by install-tools.sh

SUBFINDER_PATH=$(which subfinder 2>/dev/null || echo "")
HTTPX_PATH=$(which httpx 2>/dev/null || echo "")
NUCLEI_PATH=$(which nuclei 2>/dev/null || echo "")
NMAP_PATH=$(which nmap 2>/dev/null || echo "")
AMASS_PATH=$(which amass 2>/dev/null || echo "")
ASSETFINDER_PATH=$(which assetfinder 2>/dev/null || echo "")
WAYBACKURLS_PATH=$(which waybackurls 2>/dev/null || echo "")
GAU_PATH=$(which gau 2>/dev/null || echo "")
FFUF_PATH=$(which ffuf 2>/dev/null || echo "")
WORDLIST_DIR=$WORDLIST_DIR
EOF

echo -e "\n${GREEN}Tools configuration saved to: $CONFIG_FILE${NC}"
