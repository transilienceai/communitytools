# Data Leakage in Redirect / Error / Source

## When this applies

- Endpoint returns 302 redirect AND a response body that contains the data being protected.
- Server-side rendering leaks values into HTML attributes (`<input type="password" value="...">`).
- 401/403 / error pages include sensitive context (usernames, emails, internal IDs).

## Technique

Examine the FULL response (not just the rendered page) for sensitive data. Browsers follow 302s automatically and discard the original body — use Burp / curl to capture it.

## Steps

Lab — Data Leakage in Redirect:
```bash
# Request: /my-account?id=carlos
# Check response body (302) for API key before redirect
```

Lab — Password Disclosure:
```bash
# Request: /my-account?id=administrator
# View HTML source for password in input field value
# Login as administrator with extracted password
```

Lab — IDOR Files:
```bash
# View transcript, note URL: /download-transcript/2.txt
# Change to: /download-transcript/1.txt
# Extract password from carlos's transcript
```

Capture redirect bodies with curl:
```bash
# -i prints headers; do NOT use -L (would follow redirects and discard body)
curl -i "https://target.com/my-account?id=carlos" -H "Cookie: session=..."
```

Burp Repeater: simply send the request and view the body of the 302 response.

Reveal masked password fields in browser:
```javascript
// Reveal all password fields
document.querySelectorAll('input[type="password"]').forEach(
  input => input.type = 'text'
);
```

View HTML source for masked passwords:
```html
<!-- Visible in source, masked in browser -->
<input type="password" value="secret-password-123" />
```

## Verifying success

- Response body contains the target value (API key, password, transcript content) even though the visible page is a redirect or error.
- The extracted credential authenticates against the application's login.
- Sensitive HTML attributes (`value=...`) carry the data despite browser masking.

## Common pitfalls

- `curl -L` follows redirects and discards the original body — use `-i` (or `-v`) without `-L`.
- Browsers cache 302 → final-URL — disable cache (DevTools → Network → "Disable cache") before retesting.
- Some apps strip the body on 302 only when the User-Agent is a real browser — try with `User-Agent: curl/8.0`.

## Tools

- Burp Suite Repeater (always shows raw response, doesn't follow redirects)
- curl `-i` (include headers, don't follow)
- Browser DevTools Network tab (preserve log + view response body of 302)
