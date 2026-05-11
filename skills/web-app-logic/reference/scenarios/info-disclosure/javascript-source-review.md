# JavaScript Source Review — Hidden API Discovery

## When this applies

- Modern web app (React, Vue, Angular) where most logic lives in JS bundles.
- App appears to expose only a small UI but you suspect hidden admin / debug routes.
- You're enumerating attack surface and want to find every fetch() call, secret, and "secret/admin" command.

## Technique

Download all JS bundles, grep for endpoints, secrets, and hidden command keys. Look for `availableOptions['secret']`-type maps that reveal admin routes not surfaced in the UI.

## Steps

```bash
# Download all JS bundles from the page
curl -s https://target.com | grep -oE 'src="[^"]*\.js"' | sed 's/src="//;s/"//'

# Search for API endpoints and secrets in JS
curl -s https://target.com/static/js/main.js | grep -oiE '"/api/[^"]*"|fetch\("[^"]*"\)|secret|admin|hidden|flag'

# Search for hardcoded credentials or tokens
curl -s https://target.com/static/js/main.js | grep -oiE 'api[_-]?key|token|password|secret|bearer'
```

**Pattern:** Game/interactive apps often have a `/api/options` or `/api/config` endpoint that returns ALL available commands/routes, including hidden "secret" or "admin" ones not shown in the UI. Always check for:
- `availableOptions['secret']` or `availableOptions['admin']` keys
- Undocumented API routes in fetch() calls
- Commented-out endpoints in source
- Environment variables leaked in webpack bundles (`process.env.*`)

### Source maps

Source maps (`.map` files) deminify the entire bundle — sometimes including original developer comments and full file paths.

```bash
# Check for source maps
curl https://target.com/app.js.map
```

### Comments & metadata

```
□ HTML comments
□ JavaScript comments
□ CSS comments
□ Source map files
□ Metadata in documents
```

**Burp Suite Method:**
```
Target > Site map > Right-click domain
> Engagement tools > Find comments
```

**Manual Method:**
```bash
# Search for comments
curl https://target.com | grep -E "<!--.*-->"
```

## Verifying success

- Bundle grep returns API endpoints not visible in the UI (`/api/admin`, `/api/secret`, `/api/options`).
- Hardcoded API keys / bearer tokens found and authenticate against the target.
- Source map exposes original directory structure / variable names.

## Common pitfalls

- Bundles may be split into chunks (`_next/static/chunks/`) — recursively enumerate all `.js` files.
- Webpack name-mangling may obscure obvious keywords; search for hex/base64 strings as well.
- `process.env.*` in client bundles often resolves at build time; search for the resolved values, not the literal `process.env`.

## Tools

- Burp Suite (Find scripts, Find comments)
- nuclei `-t exposures/`
- LinkFinder (regex over JS bundles)
- jsluice (extract endpoints/secrets from JS)
- secretlint
