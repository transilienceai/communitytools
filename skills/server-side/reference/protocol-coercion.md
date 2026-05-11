# Web — Cross-Protocol Bridges & Internal-Service Coercion

When a web target has an HTTP/1.1 SSRF primitive but the high-value internal service speaks something else (gRPC HTTP/2, FCGI, redis, memcached, etc.), the puzzle is to find a bridge inside the container itself.

## Recurring bridges

| Bridge | Source primitive | Target | When to use |
|--------|------------------|--------|-------------|
| **`gopher://` via curl** | `subprocess.run(["curl", url])` with attacker-controlled URL | Any TCP service | Any internal port; gopher writes raw bytes per URL-decoded path. Works for HTTP/2 frames, redis CLI, SMTP, etc. |
| **`gopher://` via Python `urllib`** | `urllib.request.urlopen(url)` (Python ≥ 2.x has gopher handler) | Same | Easier to find than curl variants |
| **`file://` via SSRF** | Python `requests.get` doesn't support file://, but `urllib`/`aiohttp`/`httplib2` may | Local file read | Test scheme support per library |
| **PDF.js JavaScript exec (CVE-2024-4367)** | Admin-bot fetches PDF rendered in browser pdf.js | Same-origin requests with admin cookie | Firefox ≤ 125.0.x in container; pdf.js executes JS from malformed PDFs in the document's origin. Combine with form-submit to POST endpoints the bot can't normally hit. |
| **DOM Clobbering / template ←injection** | Admin-bot navigates to attacker-influenced page | Same-origin POST/PUT | When direct bot-issues-GET pattern fails |
| **Cache deception** | Public route caches a private route's response | Reads admin response on next public hit | When dynamic-vs-cached path classifier is fuzzy (CDN cache key on URL-decoded path while origin sees encoded path) |
| **Form-submit + `target=_top`** | XSS or CVE-pdf-js | Authenticated POST endpoints | Browser auto-attaches admin cookie |

## gRPC-over-HTTP/2 from gopher://

gRPC speaks HTTP/2 binary frames. The wire format is:
- 24-byte connection preface: `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`
- SETTINGS frame
- HEADERS frame (request method/path/content-type)
- DATA frame (protobuf payload)

Construct each frame as bytes, URL-encode, embed in `gopher://host:port/_<encoded>`. curl's gopher protocol writes the path verbatim to the TCP socket.

Tools: any HTTP/2 client + `protoc` to serialize the protobuf request. Or capture a working gRPC request with mitmproxy and replay via gopher.

## CVE-2024-4367 (pdf.js JavaScript execution) — recipe

1. Identify Firefox version in container (e.g. 125.0.1 — vulnerable). Confirm Selenium/headless_chrome similar.
2. Build a malformed PDF whose `/Resources` `/Font` `/Encoding` includes a JS handler. Reference PoC: search "CVE-2024-4367 pdf.js JavaScript".
3. Host the PDF reachable from the bot — typically via the `view-pdf?url=` SSRF that Flask/Express forwards via `requests.get`.
4. PDF JS runs in `http://localhost:port` origin (the bot's origin, not the PDF's source origin) — admin cookie attached.
5. JS body submits a hidden form: `<form action="/admin/api-health" method="post"><input name="url" value="gopher://127.0.0.1:50051/_..."></form>` then `.submit()`.
6. Server-side handler runs curl/python with the gopher URL → bridges to internal service → secret.

## Worked example — admin-bot pdf.js → gopher → gRPC chain

When you encounter: a path-traversal-looking parameter that drives a server-side `requests.get`, an admin bot that renders fetched PDFs in Firefox, a backend `curl` invoked with attacker-influenced URLs, and an internal gRPC service on a non-HTTP port — chain them together. Bot navigates to `/admin/view-pdf?url=<atk>` → backend fetches malicious PDF → Firefox pdf.js CVE-2024-4367 fires JS in the bot's origin → JS submits form to a same-origin admin endpoint that takes a `url` parameter → backend runs `curl gopher://127.0.0.1:50051/_<HTTP/2 frames>` → gRPC `UpdateService`-style RPC mutates server state (e.g. `price_formula`) → a downstream evaluator runs attacker-controlled Python → reads `/flag.txt`. **Lesson: the container's bundled curl version + bundled Firefox version are critical recon items.**

## Anti-patterns

- Don't insist that `requests.get`-based SSRF will reach HTTP/2 services — it can't. Look for second-hop primitives (curl in subprocess, urllib's protocol handlers).
- Don't ignore browser-side attack surface in admin-bot challenges. The bot is a browser; same-origin DOM-level attacks (CVE-pdf-js, DOM clobbering, prototype pollution in admin templates) bypass server-side restrictions.
- Don't submit flags from public writeups without verifying the technical chain matches your image.
