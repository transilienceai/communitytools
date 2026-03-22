#!/bin/bash
# Kali Tool Runtime Script
# Verifies Kali tools availability and provides diagnostic information

set -e

echo "🔧 Kali Pentesting Tools Status Check"
echo "====================================="
echo ""

# Load tool paths if available
TOOLS_FILE="$(dirname "$0")/tools.txt"
if [ -f "$TOOLS_FILE" ]; then
    echo "📋 Loading tool registry..."
    source "$TOOLS_FILE" 2>/dev/null || true
else
    echo "⚠️  Tool registry not found. Run install.sh first."
fi

# Check each category of tools
check_tool() {
    local tool=$1
    local required=${2:-false}

    if command -v "$tool" &> /dev/null; then
        local version=$($tool --version 2>&1 | head -n1 | cut -d' ' -f2-4 || echo "unknown")
        echo "  ✅ $tool: $version"
        return 0
    else
        if [ "$required" = "true" ]; then
            echo "  ❌ $tool (REQUIRED - not found)"
        else
            echo "  ⚠️  $tool (optional - not found)"
        fi
        return 1
    fi
}

echo "🔍 Network Scanning Tools:"
echo "------------------------"
check_tool "nmap" true
check_tool "masscan" false

echo ""
echo "🕷️  Web Scanning Tools:"
echo "---------------------"
check_tool "nikto" false
check_tool "dirb" false
check_tool "gobuster" false
check_tool "ffuf" false

echo ""
echo "💉 Injection Testing Tools:"
echo "-------------------------"
check_tool "sqlmap" true

echo ""
echo "🔐 SSL/TLS Testing:"
echo "-----------------"
check_tool "testssl" false
check_tool "openssl" true

echo ""
echo "🌐 HTTP Tools:"
echo "------------"
check_tool "curl" true
check_tool "wget" true
check_tool "jq" true

echo ""
echo "📡 DNS Tools:"
echo "-----------"
check_tool "dig" true
check_tool "host" true
check_tool "nslookup" false

echo ""
echo "🐍 Python Security Packages:"
echo "--------------------------"
python_packages=("requests" "beautifulsoup4" "dnspython" "python-nmap")
for pkg in "${python_packages[@]}"; do
    if python -c "import ${pkg//-/_}" 2>/dev/null; then
        echo "  ✅ $pkg"
    else
        echo "  ⚠️  $pkg (not installed)"
    fi
done

echo ""
echo "📋 Tool Configuration:"
echo "--------------------"
if [ -f "$(dirname "$0")/config.json" ]; then
    echo "  ✅ Config exists"
    echo ""
    echo "Capabilities:"
    cat "$(dirname "$0")/config.json" | python -m json.tool 2>/dev/null | grep -A 15 "capabilities" | sed 's/^/  /' || echo "  (couldn't parse config)"
else
    echo "  ⚠️  Config missing"
fi

echo ""
echo "📋 Environment:"
echo "-------------"
echo "  Platform: $(uname -s)"
echo "  Arch: $(uname -m)"
echo "  Python: $(python --version 2>&1)"
echo "  Working dir: $(pwd)"

echo ""
echo "🧪 Testing Basic Functionality:"
echo "-----------------------------"

# Test nmap
if command -v nmap &> /dev/null; then
    echo -n "  Testing nmap... "
    if nmap -V &> /dev/null; then
        echo "✅"
    else
        echo "❌"
    fi
fi

# Test sqlmap
if command -v sqlmap &> /dev/null; then
    echo -n "  Testing sqlmap... "
    if sqlmap --version &> /dev/null; then
        echo "✅"
    else
        echo "❌"
    fi
fi

# Test curl
if command -v curl &> /dev/null; then
    echo -n "  Testing curl... "
    if curl --version &> /dev/null; then
        echo "✅"
    else
        echo "❌"
    fi
fi

echo ""
echo "====================================="
echo "✅ Kali tools ready for pentest-executor agents"
echo ""
echo "Quick Reference:"
echo "  Network scan: nmap -sV -sC target.com"
echo "  Web scan: nikto -h https://target.com"
echo "  Dir brute: gobuster dir -u https://target.com -w /path/to/wordlist"
echo "  SQL inject: sqlmap -u 'https://target.com/page?id=1' --batch"
echo "  SSL test: testssl https://target.com"
echo ""
echo "See tools/kali/README.md for complete usage guide"
