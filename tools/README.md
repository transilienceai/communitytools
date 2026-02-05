# Pentesting Tools Framework

Modular tool framework for pentest-executor agents. Provides browser automation, network scanning, web scanning, and injection testing capabilities.

## Overview

The tools framework provides a standardized way to install, configure, and use pentesting tools within pentest-executor agents. Each tool has:

- **Install script** (`install.sh`) - Automated installation and configuration
- **Run script** (`run.sh`) - Verification and diagnostic information
- **README** - Usage guide and examples
- **Config** (`config.json`) - Tool metadata and capabilities

## Available Tools

### Playwright
**Browser automation for client-side testing**

- **Location**: `tools/playwright/`
- **Capabilities**: Browser automation, screenshot capture, network interception, JavaScript execution
- **Use cases**: XSS, CSRF, clickjacking, DOM-based vulnerabilities, client-side validation bypass
- **Integration**: MCP tools (`mcp__plugin_playwright_playwright__*`)

```bash
# Install
./tools/playwright/install.sh

# Verify
./tools/playwright/run.sh
```

**Attack types supported:**
- XSS (reflected, stored, DOM-based)
- CSRF
- Clickjacking
- Prototype pollution
- Client-side validation bypass
- Authentication testing
- Session management testing

See `tools/playwright/README.md` for complete guide.

### Kali
**Command-line pentesting tools**

- **Location**: `tools/kali/`
- **Capabilities**: Port scanning, web scanning, SQL injection testing, SSL/TLS testing, DNS enumeration
- **Tools included**: nmap, masscan, nikto, dirb, gobuster, ffuf, sqlmap, testssl, curl, wget, jq, dig
- **Integration**: Bash commands

```bash
# Install
./tools/kali/install.sh

# Verify
./tools/kali/run.sh
```

**Attack types supported:**
- Network reconnaissance
- Service enumeration
- Web vulnerability scanning
- SQL injection
- Directory/file discovery
- SSL/TLS vulnerabilities
- DNS enumeration

See `tools/kali/README.md` for complete guide.

## Quick Start

### Install All Tools

```bash
# Install Playwright
./tools/playwright/install.sh

# Install Kali tools
./tools/kali/install.sh

# Verify installations
./tools/playwright/run.sh
./tools/kali/run.sh
```

### Verify Tool Status

```bash
# Check all tools
for tool in playwright kali; do
    echo "Checking $tool..."
    ./tools/$tool/run.sh
    echo ""
done
```

## Integration with Pentest-Executor

Pentest-executor agents automatically use these tools:

```yaml
---
name: Pentester Executor
tools: [mcp__plugin_playwright_playwright__*, Bash, Read, Write]
---
```

**Tool selection by attack type:**

| Attack Type | Primary Tool | Secondary Tool |
|-------------|-------------|----------------|
| XSS | Playwright | Bash (curl) |
| CSRF | Playwright | Bash (curl) |
| SQL Injection | Bash (sqlmap) | Bash (curl) |
| Network Recon | Bash (nmap) | - |
| Web Scanning | Bash (nikto, gobuster) | Playwright |
| Clickjacking | Playwright | - |
| SSL/TLS Testing | Bash (testssl) | - |

## Usage Examples

### Client-Side Testing (Playwright)

```python
# XSS Testing
browser_navigate(url="https://target.com/search")
browser_type(ref="input#q", text="<script>alert(1)</script>")
browser_click(ref="button[type=submit]")
browser_snapshot()
browser_console_messages(level="error")
```

### Server-Side Testing (Kali)

```bash
# SQL Injection Testing
sqlmap -u "https://target.com/page?id=1" --batch --level=3 --risk=2

# Network Scanning
nmap -sV -sC -p- target.com -oN scan_results.txt

# Web Scanning
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
```

### Combined Testing

```bash
# 1. Network recon (Kali)
nmap -sV -p80,443 target.com

# 2. Web scanning (Kali)
nikto -h https://target.com

# 3. Client-side testing (Playwright)
browser_navigate(url="https://target.com")
browser_snapshot()

# 4. SQL injection (Kali)
sqlmap -u "https://target.com/page?id=1" --batch
```

## Tool Architecture

```
tools/
├── README.md                 # This file
├── playwright/               # Browser automation
│   ├── install.sh           # Installation script
│   ├── run.sh               # Verification script
│   ├── README.md            # Usage guide
│   └── config.json          # Tool metadata (created by install.sh)
└── kali/                    # Command-line tools
    ├── install.sh           # Installation script
    ├── run.sh               # Verification script
    ├── README.md            # Usage guide
    ├── config.json          # Tool metadata (created by install.sh)
    └── tools.txt            # Tool paths (created by install.sh)
```

## Configuration Files

### config.json
Created by `install.sh`, contains tool metadata:

```json
{
  "name": "tool-name",
  "version": "x.y.z",
  "installed": true,
  "capabilities": [...],
  "use_cases": [...]
}
```

### tools.txt (Kali only)
Registry of installed tool paths:

```
nmap=/usr/local/bin/nmap
sqlmap=/usr/local/bin/sqlmap
...
```

## Adding New Tools

To add a new tool to the framework:

1. **Create tool directory:**
   ```bash
   mkdir -p tools/new-tool
   ```

2. **Create install script:**
   ```bash
   cat > tools/new-tool/install.sh <<'EOF'
   #!/bin/bash
   # Installation logic
   # Create config.json
   EOF
   chmod +x tools/new-tool/install.sh
   ```

3. **Create run script:**
   ```bash
   cat > tools/new-tool/run.sh <<'EOF'
   #!/bin/bash
   # Verification logic
   # Display status and diagnostics
   EOF
   chmod +x tools/new-tool/run.sh
   ```

4. **Create README:**
   ```bash
   # Document purpose, installation, usage, examples
   ```

5. **Update this README** to include the new tool

6. **Update pentest-executor.md** if needed

## Platform Support

| Platform | Playwright | Kali Tools |
|----------|-----------|-----------|
| macOS | ✅ Full support | ✅ Via Homebrew |
| Linux (Debian/Ubuntu) | ✅ Full support | ✅ Native packages |
| Linux (RHEL/CentOS) | ✅ Full support | ✅ Native packages |
| Linux (Arch) | ✅ Full support | ✅ Native packages |
| Windows | ⚠️ WSL recommended | ⚠️ WSL recommended |

## Requirements

**Playwright:**
- Node.js 14+
- Python 3.7+
- ~1GB disk space (browsers)

**Kali:**
- Package manager (apt, yum, pacman, or brew)
- sudo access (for some tools)
- ~500MB disk space

## Troubleshooting

### General Issues

**Scripts not executable:**
```bash
chmod +x tools/*/install.sh tools/*/run.sh
```

**Permission errors:**
```bash
# Use sudo for system-wide installation
sudo ./tools/kali/install.sh
```

### Playwright Issues

**Browsers not installed:**
```bash
playwright install
```

**System dependencies missing (Linux):**
```bash
playwright install-deps
```

### Kali Issues

**Tools not found after install:**
```bash
# Check PATH
echo $PATH

# Find tool location
which nmap

# Add to PATH if needed
export PATH=$PATH:/usr/local/bin
```

**Package manager errors:**
```bash
# Update package list first
sudo apt-get update  # Debian/Ubuntu
sudo yum update      # RHEL/CentOS
brew update          # macOS
```

## Security Considerations

- **Authorization**: Only use tools on authorized targets
- **Legal compliance**: Ensure testing is legal and compliant
- **Scope boundaries**: Respect engagement scope
- **Rate limiting**: Avoid overwhelming targets
- **Logging**: All tool usage is logged by pentest-executor
- **Credentials**: Never commit credentials or API keys

## References

**Pentest-Executor Agent:**
- `.claude/agents/pentester-executor.md`

**Tool Documentation:**
- `tools/playwright/README.md`
- `tools/kali/README.md`

**Attack Guides:**
- `.claude/skills/pentest/attacks/`

**External Resources:**
- [Playwright Documentation](https://playwright.dev/python/)
- [Nmap Documentation](https://nmap.org/book/man.html)
- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
