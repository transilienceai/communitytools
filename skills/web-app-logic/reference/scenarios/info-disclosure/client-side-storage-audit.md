# Client-Side Storage Security Audit

## When this applies

- App is a SPA / mobile webview / heavy-JS frontend.
- You suspect tokens / PII / session data are stashed in `localStorage`, `sessionStorage`, IndexedDB, or non-HttpOnly cookies.
- Compliance scope (HIPAA, PCI) — local storage of sensitive data is a finding.

## Technique

Inspect browser storage at runtime, then grep the JS bundle for `localStorage.setItem` patterns to confirm what's stored. Anything sensitive in localStorage is a finding.

## Steps

### Browser storage mechanisms to check

```
□ localStorage — persists indefinitely, survives browser close
  Risk: auth tokens, PII, session data stored here are accessible to any JS on the same origin
  Finding if: tokens (JWT, API keys, session IDs) are stored in localStorage instead of sessionStorage or httpOnly cookies
□ sessionStorage — cleared when tab closes (acceptable for non-sensitive session data)
□ IndexedDB — check for sensitive data in structured storage
□ Cookies without HttpOnly — accessible via JavaScript (document.cookie)
```

### Detection via JavaScript bundle analysis

Search minified/beautified JS for:

```
localStorage.setItem
localStorage.getItem
sessionStorage.setItem
window.localStorage
.storeLocal(
setItem("token"
setItem("tkn"
setItem("jwt"
setItem("auth"
setItem("session"
setItem("user"
```

### Why this matters

- localStorage data persists after logout if not explicitly cleared
- Shared/public computers: next user can extract stored tokens
- XSS escalation: even without httpOnly cookies, localStorage tokens are accessible via `document.cookie` alternatives

### Runtime inspection

```javascript
// In DevTools console, after login:
JSON.stringify(localStorage)
JSON.stringify(sessionStorage)

// IndexedDB (asynchronous)
indexedDB.databases().then(dbs => console.log(dbs))
```

### Bundle grep

```bash
# Find all setItem call sites
curl -s https://target.com/static/js/main.js | grep -oE '(local|session)Storage\.setItem\([^)]+\)'

# Find token-style keys
curl -s https://target.com/static/js/main.js | grep -oE 'setItem\("(token|tkn|jwt|auth|session|user)[^"]*"'
```

## Verifying success

- localStorage / sessionStorage contains JWTs, API keys, or session IDs visible at runtime.
- Bundle confirms that `setItem("token", ...)` calls happen post-login.
- After logout, sensitive items persist in localStorage (not cleared).

## Common pitfalls

- Some apps encrypt the localStorage value — still a finding if the encryption key is also in the bundle.
- IndexedDB is harder to inspect ad-hoc; use DevTools → Application → IndexedDB.
- Service workers may also stash data — check `caches.keys()` in the console.

## Tools

- Browser DevTools (Application tab → Storage)
- curl + grep on JS bundles
- Burp DOM Invader (DOM-related sources/sinks)
- Chrome DevTools Recorder
