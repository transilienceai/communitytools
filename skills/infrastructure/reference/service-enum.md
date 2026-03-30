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
- **SMB (445)**: Windows version, share enumeration (`smbclient -L //target -N` for null session, `smbclient -L //target -U guest%` for guest). Download binaries from shares — decompile .NET (ILSpy/dnSpy) and Java (JD-GUI/CFR) for hardcoded credentials, connection strings, internal hostnames
- **MSSQL (1433)**: Version fingerprint, `nmap --script ms-sql-info -p1433 target`. After auth: `SELECT * FROM sys.servers WHERE is_linked = 1;` for linked servers, `SELECT name FROM sys.databases;` for DB enumeration. Linked servers pointing to unresolvable hostnames are AD DNS poisoning targets. Check `db_owner` role: `SELECT IS_MEMBER('db_owner');`
- **FTP (21)**: Version fingerprint (`nmap -sV -p21`), check anonymous access (`ftp anonymous@target`), look for web admin interfaces on alternate ports (e.g., 8443, 5466), config file locations (`/opt/*/Data/*/users/*.xml` for per-user hashes)

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
