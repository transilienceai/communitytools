#!/bin/bash
# Kali Tool Installation Script
# Installs common Kali Linux pentesting tools for pentest-executor agents

set -e

echo "🔧 Installing Kali Pentesting Tools..."

# Detect platform
PLATFORM=$(uname -s)
echo "Platform: $PLATFORM"

# Check if running as root (some tools require sudo)
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  Running as root. This is not recommended."
    SUDO=""
else
    SUDO="sudo"
fi

# Tool installation function
install_tool() {
    local tool=$1
    local install_cmd=$2

    if command -v "$tool" &> /dev/null; then
        echo "  ✅ $tool already installed: $(command -v $tool)"
    else
        echo "  📦 Installing $tool..."
        eval "$install_cmd"
        if command -v "$tool" &> /dev/null; then
            echo "  ✅ $tool installed successfully"
        else
            echo "  ⚠️  $tool installation may have failed"
        fi
    fi
}

# Platform-specific installation
if [ "$PLATFORM" = "Darwin" ]; then
    # macOS
    echo "📦 Installing tools via Homebrew..."

    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew not found. Please install from https://brew.sh/"
        exit 1
    fi

    echo ""
    echo "🔍 Network Scanning Tools:"
    install_tool "nmap" "$SUDO brew install nmap"
    install_tool "masscan" "$SUDO brew install masscan"

    echo ""
    echo "🕷️  Web Scanning Tools:"
    install_tool "nikto" "$SUDO brew install nikto"
    install_tool "dirb" "$SUDO brew install dirb"
    install_tool "gobuster" "$SUDO brew install gobuster"
    install_tool "ffuf" "$SUDO brew install ffuf"

    echo ""
    echo "💉 Injection Testing Tools:"
    install_tool "sqlmap" "$SUDO brew install sqlmap"

    echo ""
    echo "🔐 SSL/TLS Testing:"
    install_tool "testssl" "$SUDO brew install testssl"

    echo ""
    echo "🌐 HTTP Tools:"
    install_tool "curl" "$SUDO brew install curl"
    install_tool "wget" "$SUDO brew install wget"
    install_tool "jq" "$SUDO brew install jq"

    echo ""
    echo "📡 DNS Tools:"
    install_tool "dig" "echo 'dig is built-in on macOS'"
    install_tool "host" "echo 'host is built-in on macOS'"

elif [ "$PLATFORM" = "Linux" ]; then
    # Linux
    echo "📦 Installing tools via package manager..."

    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
        UPDATE_CMD="$SUDO apt-get update"
        INSTALL_CMD="$SUDO apt-get install -y"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        UPDATE_CMD="$SUDO yum update"
        INSTALL_CMD="$SUDO yum install -y"
    elif command -v pacman &> /dev/null; then
        PKG_MANAGER="pacman"
        UPDATE_CMD="$SUDO pacman -Sy"
        INSTALL_CMD="$SUDO pacman -S --noconfirm"
    else
        echo "❌ No supported package manager found"
        exit 1
    fi

    echo "Using package manager: $PKG_MANAGER"
    echo "Updating package list..."
    $UPDATE_CMD

    echo ""
    echo "🔍 Network Scanning Tools:"
    install_tool "nmap" "$INSTALL_CMD nmap"
    install_tool "masscan" "$INSTALL_CMD masscan"

    echo ""
    echo "🕷️  Web Scanning Tools:"
    install_tool "nikto" "$INSTALL_CMD nikto"
    install_tool "dirb" "$INSTALL_CMD dirb"
    install_tool "gobuster" "$INSTALL_CMD gobuster"
    install_tool "ffuf" "$INSTALL_CMD ffuf || echo 'ffuf not in repos, install manually'"

    echo ""
    echo "💉 Injection Testing Tools:"
    install_tool "sqlmap" "$INSTALL_CMD sqlmap"

    echo ""
    echo "🔐 SSL/TLS Testing:"
    install_tool "testssl" "$INSTALL_CMD testssl || $INSTALL_CMD testssl.sh"

    echo ""
    echo "🌐 HTTP Tools:"
    install_tool "curl" "$INSTALL_CMD curl"
    install_tool "wget" "$INSTALL_CMD wget"
    install_tool "jq" "$INSTALL_CMD jq"

    echo ""
    echo "📡 DNS Tools:"
    install_tool "dig" "$INSTALL_CMD dnsutils || $INSTALL_CMD bind-utils"
    install_tool "host" "$INSTALL_CMD dnsutils || $INSTALL_CMD bind-utils"

else
    echo "❌ Unsupported platform: $PLATFORM"
    exit 1
fi

# Install Python-based tools
echo ""
echo "🐍 Python-based Tools:"
echo "-------------------"
if command -v pip &> /dev/null || command -v pip3 &> /dev/null; then
    PIP_CMD=$(command -v pip3 &> /dev/null && echo "pip3" || echo "pip")

    # Install common Python security tools
    echo "  📦 Installing Python security packages..."
    $PIP_CMD install --upgrade \
        requests \
        beautifulsoup4 \
        urllib3 \
        dnspython \
        python-nmap \
        wappalyzer \
        shodan \
        censys || echo "  ⚠️  Some Python packages may have failed"
else
    echo "  ⚠️  pip not found, skipping Python tools"
fi

# Create tool registry
echo ""
echo "📝 Creating tool configuration..."
cat > "$(dirname "$0")/config.json" <<EOF
{
  "name": "kali",
  "version": "1.0.0",
  "installed": true,
  "categories": {
    "network_scanning": ["nmap", "masscan"],
    "web_scanning": ["nikto", "dirb", "gobuster", "ffuf"],
    "injection_testing": ["sqlmap"],
    "ssl_testing": ["testssl"],
    "http_tools": ["curl", "wget", "jq"],
    "dns_tools": ["dig", "host", "nslookup"]
  },
  "capabilities": [
    "port_scanning",
    "service_enumeration",
    "web_vulnerability_scanning",
    "directory_bruteforcing",
    "sql_injection_testing",
    "ssl_tls_testing",
    "dns_enumeration",
    "http_request_manipulation"
  ],
  "use_cases": [
    "Network reconnaissance",
    "Service enumeration",
    "Web application scanning",
    "SQL injection testing",
    "SSL/TLS vulnerability testing",
    "Directory/file discovery",
    "DNS enumeration",
    "HTTP/HTTPS manipulation"
  ]
}
EOF

# Create tool paths registry
echo ""
echo "📋 Registering tool paths..."
TOOLS_FILE="$(dirname "$0")/tools.txt"
> "$TOOLS_FILE"  # Clear file

for tool in nmap masscan nikto dirb gobuster ffuf sqlmap testssl curl wget jq dig host; do
    if command -v "$tool" &> /dev/null; then
        echo "$tool=$(command -v $tool)" >> "$TOOLS_FILE"
    fi
done

echo ""
echo "✅ Kali tools installed successfully!"
echo ""
echo "Installed tools:"
cat "$TOOLS_FILE" | sed 's/^/  /'
echo ""
echo "Next steps:"
echo "  1. Run './tools/kali/run.sh' to verify tools"
echo "  2. Pentest-executor agents can now use these tools via Bash"
echo "  3. Check 'tools/kali/README.md' for usage examples"
