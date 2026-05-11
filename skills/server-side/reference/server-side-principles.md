# Server-Side Principles

This file is the entry point for server-side vulnerabilities. It contains decision logic, sequencing, and cross-cutting gotchas. Specific techniques live under `scenarios/<area>/<scenario>.md`. Use `INDEX.md` to pick a scenario by trigger.

## Decision tree

| Fingerprint | Family | Where to start |
|---|---|---|
| App fetches a URL from user input | `scenarios/ssrf/` | `localhost-and-ip-bypass.md`, `cloud-metadata.md` |
| App proxies path to internal storage | `scenarios/ssrf/proxy-path-traversal.md` | `..%2F<bucket>` |
| Validator vs fetcher disagree on URL | `scenarios/ssrf/url-parser-and-allowlist-bypass.md` | `@`, `#`, fragment double-encoding |
| Non-HTTP scheme accepted | `scenarios/ssrf/protocol-exploitation-gopher.md` | gopher://Redis/MySQL/FastCGI |
| Need to confirm blind SSRF | `scenarios/ssrf/blind-detection-and-portscan.md` | Collaborator + timing |
| Front-end / back-end disagree on body length | `scenarios/http-smuggling/cl-te.md` or `te-cl.md` | Detect via time / differential |
| Both sides parse TE | `scenarios/http-smuggling/te-te-obfuscation.md` | Whitespace / xchunked variants |
| HTTP/2 front-end, HTTP/1.1 back-end | `scenarios/http-smuggling/h2-downgrade.md` | H2.CL / H2.TE / tunneling |
| Pause-based / CL.0 desync | `scenarios/http-smuggling/cl-zero-and-pause-based.md` | Send-with-pauses |
| Smuggling primitive confirmed | `scenarios/http-smuggling/exploitation-patterns.md` | Bypass / capture / cache / XSS |
| Filename / path parameter is read | `scenarios/path-traversal/basic-payloads-and-encoding.md` | `../../../etc/passwd` + encodings |
| Sanitizer with non-recursive strip | `scenarios/path-traversal/filter-bypass-techniques.md` | `....//`, `str_replace` ordering |
| Path read confirmed, enumerate files | `scenarios/path-traversal/target-files.md` | OS-specific filelists |
| Apache 2.4.49/50, IIS, Tomcat, nginx alias | `scenarios/path-traversal/platform-specific.md` | Server-specific CVEs |
| LFI reaches `include()` | `scenarios/path-traversal/lfi-to-rce.md` | Wrappers / log poisoning / filter chain |
| File upload functionality | `scenarios/file-upload/web-shell-payloads.md` | PHP / ASP / JSP / disable_functions |
| Extension blocked | `scenarios/file-upload/extension-bypass.md` | Case / double / null / alt extensions |
| Magic-byte / Content-Type validated | `scenarios/file-upload/content-type-and-magic-bytes.md` | Hybrid file |
| Strict content scanner | `scenarios/file-upload/polyglot-and-metadata-injection.md` | EXIF / SVG / EPS GhostScript |
| Filename concatenated to path | `scenarios/file-upload/path-traversal-and-htaccess.md` | `../`, `.htaccess`, `web.config` |
| Upload + AV scan + delete | `scenarios/file-upload/race-conditions.md` | Save-vs-delete window |
| YARA / signature scanner | `scenarios/file-upload/defense-evasion-and-yara.md` | HTA / MSI / LNK / FTP session |
| Base64 prefix `Tzo`/`YTo` (PHP) | `scenarios/deserialization/php-deserialization.md` | unserialize / PHAR |
| Base64 prefix `rO0` (Java) | `scenarios/deserialization/java-deserialization.md` | ysoserial / Jackson / SnakeYAML |
| Base64 prefix `gAN`/`gAR` (Python pickle) or `BAh` (Ruby) | `scenarios/deserialization/python-and-ruby.md` | __reduce__ / Marshal+YAML |
| Base64 prefix `AAEAAA` (.NET) | `scenarios/deserialization/dotnet-deserialization.md` | ysoserial.net / TypeConfuseDelegate |
| Reset email contains Host-based URL | `scenarios/host-header/password-reset-poisoning.md` | Host: attacker.com on POST /forgot |
| Admin gated by "local users" | `scenarios/host-header/auth-bypass-localhost.md` | Host: localhost / 127.0.0.1 / connection-state |
| Cache-poisoning via Host reflection | `scenarios/host-header/cache-poisoning-via-host.md` | Duplicate Host / X-Forwarded-Host |
| LB routes by Host | `scenarios/host-header/routing-ssrf-and-flawed-parsing.md` | Host: 192.168.0.1 / 169.254.169.254 |

## Sequencing principles

1. **Source code first** — read source / config / openapi.json / decompile when available. Faster than blind probing.
2. **Confirm primitive before chaining** — a smuggling proof or SSRF callback is required before building patterns 1-5 attacks.
3. **Use `--path-as-is`** with curl when testing path-traversal / nginx-alias / Apache CGI to prevent client-side normalization.
4. **HTTP/1.1 for smuggling, HTTP/2 for racing** — pick the right transport per attack class.
5. **Out-of-band > inline** for blind SSRF and command injection — Collaborator confirms what time-based hints suggest.
6. **Match payload to validator weakness** — don't try filter bypass when validator is allowlist-based; pivot to wrapper or framework gadgets.
7. **Test depth iteratively** — path traversal needs 3–8 levels; start at 4 and adjust.
8. **Cache deception/poisoning needs unique cache buster per probe** — reusing payloads collides with your own cache writes.
9. **Combine primitives** — SSRF + Redis-via-gopher → RCE. Smuggling + cache → mass XSS. Path-traversal + log-poison → RCE.
10. **Restart logs / redis after failed exploit attempts** — corrupted state breaks subsequent attempts.

## Cross-cutting gotchas

- **HTTP/2 doesn't support smuggling** — must use HTTP/1.1 in Burp Repeater.
- **`Set-Cookie` disables caching** — pick endpoints without cookies for poisoning.
- **`allow_url_include = Off`** blocks `data://`/`php://input` — use filter chain.
- **`file_exists()` before `include()`** blocks all PHP wrappers — pivot to log poisoning.
- **`disable_functions`** rarely covers `popen`, `error_log`, `pcntl_exec` — probe phpinfo first.
- **Apache `.htaccess` requires `AllowOverride`** — modern installs default to None.
- **PHP loose comparison** (`"0" == 0`, `null == []`) underlies several attacks — try `0`, `null`, `[]`, `true`.
- **IMDSv2 requires PUT + custom header** — most SSRF can't reach AWS metadata.
- **`Vary:` header without `Host`** flags cache-poisoning vulnerability.
- **`Content-Length` byte-counting**: CRLF = 2 bytes, not 1. Use Burp HTTP Request Smuggler to auto-calculate.
- **Connection state** lets second request bypass Host validation — use Burp 2022.8.1+ "Send in sequence (single connection)".
- **Mass-assign field names are language-specific** — try `is_admin`, `isAdmin`, `IsAdmin`, `admin`, `role` (see `web-app-logic`).
- **Path traversal `--path-as-is` matters** — curl normalizes by default, breaking the payload.
- **PHAR deserialization patched in PHP 8.0+** — older targets only.
- **Java 16+** requires `--add-opens` for ysoserial.
- **CL.TE detection** uses time-based hang or differential 404 — easier than capturing user data.
- **Public S3 / MinIO without auth** is the common ssrf-target via `proxy-path-traversal.md`.
