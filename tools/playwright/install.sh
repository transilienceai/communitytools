#!/bin/bash
# Playwright Tool Installation Script
# Installs Playwright and required browsers for pentest-executor agents

set -e

echo "🎭 Installing Playwright Tool..."

# Check if running in virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
    echo "⚠️  Warning: Not running in a virtual environment"
    echo "   Consider activating venv first: source .venv/bin/activate"
fi

# Detect platform
PLATFORM=$(uname -s)
echo "Platform: $PLATFORM"

# Install Node.js if not present (required for Playwright)
if ! command -v node &> /dev/null; then
    echo "📦 Node.js not found. Installing..."
    if [ "$PLATFORM" = "Darwin" ]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install node
        else
            echo "❌ Homebrew not found. Please install Node.js manually from https://nodejs.org/"
            exit 1
        fi
    elif [ "$PLATFORM" = "Linux" ]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y nodejs npm
        elif command -v yum &> /dev/null; then
            sudo yum install -y nodejs npm
        else
            echo "❌ Package manager not found. Please install Node.js manually from https://nodejs.org/"
            exit 1
        fi
    else
        echo "❌ Unsupported platform: $PLATFORM"
        exit 1
    fi
else
    echo "✅ Node.js already installed: $(node --version)"
fi

# Install Playwright Python package
echo "📦 Installing Playwright Python package..."
pip install playwright playwright-pytest

# Install Playwright browsers
echo "🌐 Installing Playwright browsers (Chromium, Firefox, WebKit)..."
playwright install

# Install system dependencies for browsers (Linux only)
if [ "$PLATFORM" = "Linux" ]; then
    echo "🔧 Installing system dependencies for browsers..."
    playwright install-deps
fi

# Verify installation
echo ""
echo "🔍 Verifying installation..."
if python -c "import playwright; print('✅ Playwright Python package installed')" 2>/dev/null; then
    echo "✅ Playwright installation successful"
else
    echo "❌ Playwright installation failed"
    exit 1
fi

# Create tool config
echo ""
echo "📝 Creating tool configuration..."
cat > "$(dirname "$0")/config.json" <<EOF
{
  "name": "playwright",
  "version": "$(playwright --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo 'unknown')",
  "installed": true,
  "browsers": ["chromium", "firefox", "webkit"],
  "capabilities": [
    "browser_automation",
    "screenshot_capture",
    "network_interception",
    "javascript_execution",
    "form_interaction",
    "navigation"
  ],
  "mcp_integration": true,
  "use_cases": [
    "XSS testing",
    "CSRF testing",
    "Clickjacking testing",
    "DOM-based vulnerabilities",
    "Client-side validation bypass",
    "Authentication testing",
    "Session management testing"
  ]
}
EOF

echo ""
echo "✅ Playwright tool installed successfully!"
echo ""
echo "Next steps:"
echo "  1. Run './tools/playwright/run.sh' to verify the tool"
echo "  2. Pentest-executor agents can now use Playwright MCP tools"
echo "  3. Check 'tools/playwright/README.md' for usage examples"
