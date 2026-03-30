#!/bin/bash
# Run this INSIDE the Docker container to debug Playwright MCP
echo "=== Environment ==="
whoami
echo "DISPLAY=$DISPLAY"
echo "HOME=$HOME"
echo "PWD=$PWD"

echo ""
echo "=== Xvfb running? ==="
ps aux | grep -v grep | grep Xvfb || echo "NOT RUNNING"

echo ""
echo "=== Node/npx available? ==="
which node && node --version
which npx && npx --version

echo ""
echo "=== @playwright/mcp installed? ==="
npm list -g @playwright/mcp 2>&1 || echo "NOT FOUND globally"

echo ""
echo "=== Chromium installed? ==="
npx playwright install --dry-run chromium 2>&1 | head -5
ls ~/.cache/ms-playwright/ 2>/dev/null || echo "No playwright cache in ~/.cache"
ls /root/.cache/ms-playwright/ 2>/dev/null || echo "No playwright cache in /root/.cache"
ls /home/claude/.cache/ms-playwright/ 2>/dev/null || echo "No playwright cache in /home/claude/.cache"

echo ""
echo "=== Project .mcp.json ==="
cat /workspace/.mcp.json 2>/dev/null || echo "NOT FOUND at /workspace/.mcp.json"

echo ""
echo "=== .claude/ contents ==="
ls -la /workspace/.claude/ 2>/dev/null || echo "No .claude dir"

echo ""
echo "=== ~/.claude/ contents ==="
ls -la ~/.claude/ 2>/dev/null || echo "No ~/.claude dir"
cat ~/.claude/settings.json 2>/dev/null || echo "No settings.json"
cat ~/.claude/plugins/installed_plugins.json 2>/dev/null || echo "No installed_plugins.json"

echo ""
echo "=== Git repo? ==="
git rev-parse --is-inside-work-tree 2>&1

echo ""
echo "=== Test MCP server startup ==="
echo "Trying to start Playwright MCP server for 3 seconds..."
timeout 3 npx @playwright/mcp@latest --launch-options '{"args":["--no-sandbox"]}' 2>&1 || echo "Exit code: $?"

echo ""
echo "=== Done ==="
