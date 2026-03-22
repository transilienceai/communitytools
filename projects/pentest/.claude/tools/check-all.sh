#!/bin/bash
# Check All Tools Status
# Verifies installation status of all pentesting tools

echo "================================================"
echo "  Pentesting Tools Framework - Status Check"
echo "================================================"
echo ""

# Track overall status
all_ok=true

# Check Playwright
echo "🎭 PLAYWRIGHT"
echo "=============================================="
if [ -f "tools/playwright/run.sh" ]; then
    ./tools/playwright/run.sh
    if [ $? -ne 0 ]; then
        all_ok=false
    fi
else
    echo "❌ Playwright not found"
    echo "   Run: ./tools/playwright/install.sh"
    all_ok=false
fi

echo ""
echo ""

# Check Kali
echo "🔧 KALI TOOLS"
echo "=============================================="
if [ -f "tools/kali/run.sh" ]; then
    ./tools/kali/run.sh
    if [ $? -ne 0 ]; then
        all_ok=false
    fi
else
    echo "❌ Kali tools not found"
    echo "   Run: ./tools/kali/install.sh"
    all_ok=false
fi

echo ""
echo ""
echo "================================================"

# Summary
if [ "$all_ok" = true ]; then
    echo "✅ All tools are ready for pentest-executor agents"
else
    echo "⚠️  Some tools need attention"
    echo ""
    echo "To install missing tools:"
    echo "  ./tools/playwright/install.sh"
    echo "  ./tools/kali/install.sh"
fi

echo ""
echo "Documentation:"
echo "  Framework overview: tools/README.md"
echo "  Playwright guide: tools/playwright/README.md"
echo "  Kali guide: tools/kali/README.md"
echo "  Executor agent: .claude/agents/pentester-executor.md"
echo "================================================"
