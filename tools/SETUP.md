# Tools Framework Setup Guide

Quick setup guide for the pentesting tools framework.

## Overview

The tools framework provides modular, installable tools for pentest-executor agents:

- **Playwright**: Browser automation for client-side testing (XSS, CSRF, clickjacking)
- **Kali**: Command-line pentesting tools (nmap, sqlmap, nikto, gobuster)

## Quick Setup

### 1. Install Tools

```bash
# Install Playwright
./tools/playwright/install.sh

# Install Kali tools
./tools/kali/install.sh
```

### 2. Verify Installation

```bash
# Check all tools
./tools/check-all.sh

# Or check individually
./tools/playwright/run.sh
./tools/kali/run.sh
```

### 3. Start Using

Pentest-executor agents will automatically use these tools:

```yaml
# .claude/agents/pentester-executor.md
tools: [mcp__plugin_playwright_playwright__*, Bash, Read, Write]
```

## Tool Selection Guide

| Task | Tool | Command |
|------|------|---------|
| XSS Testing | Playwright | `browser_navigate`, `browser_type`, `browser_click` |
| CSRF Testing | Playwright | `browser_navigate`, `browser_fill_form` |
| SQL Injection | Kali | `sqlmap -u "..." --batch` |
| Network Scan | Kali | `nmap -sV -sC target.com` |
| Web Scan | Kali | `nikto -h https://target.com` |
| Dir Brute | Kali | `gobuster dir -u https://target.com -w wordlist.txt` |
| SSL Test | Kali | `testssl https://target.com` |

## Directory Structure

```
tools/
├── README.md           # Framework overview
├── SETUP.md           # This file
├── check-all.sh       # Verify all tools
├── playwright/        # Browser automation
│   ├── install.sh    # Install script
│   ├── run.sh        # Verification script
│   └── README.md     # Usage guide
└── kali/             # Pentesting tools
    ├── install.sh    # Install script
    ├── run.sh        # Verification script
    └── README.md     # Usage guide
```

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| macOS | ✅ Full support | Uses Homebrew for Kali tools |
| Linux (Debian/Ubuntu) | ✅ Full support | Native packages |
| Linux (RHEL/CentOS) | ✅ Full support | Native packages |
| Linux (Arch) | ✅ Full support | Native packages |
| Windows | ⚠️ WSL | Use Windows Subsystem for Linux |

## Requirements

**Playwright:**
- Node.js 14+
- Python 3.7+
- ~1GB disk space (for browsers)

**Kali:**
- Package manager (apt, yum, pacman, or brew)
- sudo access (for some tools)
- ~500MB disk space

## Common Issues

### "Command not found"
```bash
# Ensure scripts are executable
chmod +x tools/*/*.sh

# Check PATH
echo $PATH
```

### "Permission denied"
```bash
# Use sudo for system-wide tools
sudo ./tools/kali/install.sh
```

### "Playwright browsers not installed"
```bash
# Install browsers manually
playwright install

# Install system dependencies (Linux)
playwright install-deps
```

## Next Steps

1. **Read the guides:**
   - Framework overview: `tools/README.md`
   - Playwright usage: `tools/playwright/README.md`
   - Kali usage: `tools/kali/README.md`

2. **Review integration:**
   - Pentest-executor agent: `.claude/agents/pentester-executor.md`
   - See "Tool Usage Examples" section

3. **Start testing:**
   - Use `/pentest` skill to launch executor agents
   - Executors will automatically use installed tools

## Documentation

- **Framework**: `tools/README.md`
- **Playwright**: `tools/playwright/README.md`
- **Kali**: `tools/kali/README.md`
- **Executor Agent**: `.claude/agents/pentester-executor.md`
- **Pentest Skill**: `.claude/skills/pentest/SKILL.md`

## Support

For issues or questions:
- Check README files in each tool directory
- Review pentest-executor.md for integration details
- Check tool-specific documentation links in READMEs
