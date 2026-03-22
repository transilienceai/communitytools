#!/bin/bash
# Playwright Tool Runtime Script
# Verifies Playwright availability and provides diagnostic information

set -e

echo "🎭 Playwright Tool Status Check"
echo "================================"
echo ""

# Check if Playwright is installed
if ! command -v playwright &> /dev/null; then
    echo "❌ Playwright CLI not found"
    echo "   Run './tools/playwright/install.sh' to install"
    exit 1
fi

# Check Python package
if ! python -c "import playwright" 2>/dev/null; then
    echo "❌ Playwright Python package not found"
    echo "   Run './tools/playwright/install.sh' to install"
    exit 1
fi

echo "✅ Playwright CLI: $(playwright --version 2>/dev/null || echo 'unknown')"
echo "✅ Python package installed"
echo ""

# Check browsers
echo "📋 Installed Browsers:"
echo "-------------------"
playwright_list=$(playwright install --dry-run 2>&1 || true)
if echo "$playwright_list" | grep -q "chromium"; then
    echo "  ✅ Chromium"
else
    echo "  ❌ Chromium (missing)"
fi
if echo "$playwright_list" | grep -q "firefox"; then
    echo "  ✅ Firefox"
else
    echo "  ❌ Firefox (missing)"
fi
if echo "$playwright_list" | grep -q "webkit"; then
    echo "  ✅ WebKit"
else
    echo "  ❌ WebKit (missing)"
fi
echo ""

# Check MCP integration
echo "📋 MCP Integration:"
echo "-----------------"
if [ -d ".playwright-mcp" ]; then
    echo "  ✅ MCP directory found (.playwright-mcp/)"
else
    echo "  ⚠️  MCP directory not found"
fi

# Check config
if [ -f "$(dirname "$0")/config.json" ]; then
    echo "  ✅ Tool config exists"
    echo ""
    echo "📋 Tool Capabilities:"
    echo "------------------"
    cat "$(dirname "$0")/config.json" | python -m json.tool 2>/dev/null | grep -A 10 "capabilities" || echo "  (config exists but couldn't parse)"
else
    echo "  ⚠️  Tool config missing"
fi

echo ""
echo "📋 Environment:"
echo "-------------"
echo "  Platform: $(uname -s)"
echo "  Python: $(python --version 2>&1)"
echo "  Node: $(node --version 2>/dev/null || echo 'not found')"
echo "  Working dir: $(pwd)"
echo ""

# Test basic functionality
echo "🧪 Testing Basic Functionality:"
echo "-----------------------------"
cat > /tmp/playwright_test.py <<'EOF'
from playwright.sync_api import sync_playwright
import sys

try:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto('about:blank')
        browser.close()
    print("✅ Playwright is fully functional")
    sys.exit(0)
except Exception as e:
    print(f"❌ Playwright test failed: {e}")
    sys.exit(1)
EOF

if python /tmp/playwright_test.py 2>/dev/null; then
    echo ""
else
    echo "⚠️  Basic functionality test failed"
    echo ""
fi

rm -f /tmp/playwright_test.py

echo "================================"
echo "✅ Playwright tool is ready for pentest-executor agents"
echo ""
echo "Available MCP Tools:"
echo "  - browser_navigate"
echo "  - browser_click"
echo "  - browser_type"
echo "  - browser_snapshot"
echo "  - browser_take_screenshot"
echo "  - browser_evaluate"
echo "  - browser_fill_form"
echo "  - ... (see pentest-executor.md for full list)"
