# Service Enumeration Testing Log

**Attack Type**: Service Version Detection & Banner Grabbing
**MITRE**: T1046 (Network Service Discovery)

## Last Updated
<!-- Auto-updated by pentester-executor -->

## Test Matrix

| Row | Target:Port | Service | Version | Command | CVEs Found | Notes |
|-----|-------------|---------|---------|---------|------------|-------|
<!-- Append test results below -->

## Command Templates

```bash
# Service version detection
nmap -sV -p PORTS TARGET

# Aggressive version detection
nmap -sV --version-intensity 9 TARGET

# Version + OS detection
nmap -sV -O TARGET

# Version + NSE scripts
nmap -sV -sC TARGET

# Banner grabbing (netcat)
nc -v TARGET PORT
```

## Common Patterns

### Version Detection Levels
- **Intensity 0**: Light probes only
- **Intensity 5**: Default balance
- **Intensity 9**: All probes (slowest, most accurate)

### High-Value Services to Enumerate
- **SSH (22)**: Version → CVE lookup
- **HTTP/HTTPS (80/443)**: Server, frameworks
- **SMB (445)**: Windows version
- **MySQL/PostgreSQL (3306/5432)**: Database versions
- **RDP (3389)**: Windows remote desktop

### NSE Scripts for Enumeration
- `http-methods`: Allowed HTTP methods
- `ssh-auth-methods`: SSH authentication
- `smb-os-discovery`: Windows OS info
- `ssl-cert`: Certificate details

## Learnings

### Successful Techniques
<!-- Add entries as tests are performed -->

### Failed Techniques
<!-- Add entries when techniques fail -->

### Version Fingerprinting
<!-- Document accurate vs inaccurate version detection -->

## CVE Mapping

### Vulnerable Services Found
<!-- Track services with known CVEs -->

### Exploitation Candidates
<!-- Services worth deeper testing -->
