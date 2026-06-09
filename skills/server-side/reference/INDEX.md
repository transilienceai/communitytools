# Server-Side — Scenario Index

Read `server-side-principles.md` first for the decision tree and sequencing principles.

## SSRF

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| App fetches user-supplied URL | `scenarios/ssrf/localhost-and-ip-bypass.md` | Encoded localhost, 0.0.0.0 DNS, private IPs |
| Validator vs fetcher disagree | `scenarios/ssrf/url-parser-and-allowlist-bypass.md` | `@`, `#`, fragment double-encoding, DNS rebinding |
| Non-HTTP scheme accepted | `scenarios/ssrf/protocol-exploitation-gopher.md` | gopher Redis/MySQL/FastCGI, file://, dict:// |
| AWS / Azure / GCP / Alibaba target | `scenarios/ssrf/cloud-metadata.md` | 169.254.169.254, IAM creds |
| Blind SSRF, need confirmation | `scenarios/ssrf/blind-detection-and-portscan.md` | Burp Collaborator + timing |
| App proxies path to internal storage | `scenarios/ssrf/proxy-path-traversal.md` | `..%2F<bucket>` to S3 / MinIO |
| SSRF sink forwards user header names; internal Redis reachable | `scenarios/ssrf/redis-inline-via-header-name.md` | Header NAME = `eval <lua> 0 dummy` → Redis runs Lua before `Host:` filter closes connection |
| SSRF response bytes 0x80-0xFF replaced by U+FFFD; binary exfil broken | `scenarios/ssrf/utf8-binary-loss-limit.md` | Pivot to text-only refs/logs, try gopher/dict/ftp schemes, or fetch public mirror |
| Created resource stores a URL the server later fetches (base_url/webhook_url) | `scenarios/ssrf/stored-connector-url-ssrf.md` | CREATE pointing at 169.254.170.2/metadata/collaborator → trigger sync; validator-fails-open at use |

## HTTP Smuggling

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Front-end CL, back-end TE | `scenarios/http-smuggling/cl-te.md` | Detect via time / 404 differential |
| Front-end TE, back-end CL | `scenarios/http-smuggling/te-cl.md` | Reverse of CL.TE |
| Both honor TE | `scenarios/http-smuggling/te-te-obfuscation.md` | xchunked / whitespace variants |
| HTTP/2 front-end | `scenarios/http-smuggling/h2-downgrade.md` | H2.CL / H2.TE / tunneling |
| Back-end ignores CL OR pause-based desync | `scenarios/http-smuggling/cl-zero-and-pause-based.md` | Send-with-pauses |
| Smuggling primitive established | `scenarios/http-smuggling/exploitation-patterns.md` | Bypass / capture / cache / XSS |

## Path Traversal

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Filename / path parameter read | `scenarios/path-traversal/basic-payloads-and-encoding.md` | `..`/encoded/Unicode/UTF-8 |
| Sanitizer in place | `scenarios/path-traversal/filter-bypass-techniques.md` | Nested, str_replace ordering, null byte, UNC |
| Read confirmed, enumerate files | `scenarios/path-traversal/target-files.md` | Linux/Windows/macOS/Cloud filelists |
| Apache 2.4.49/50, IIS, nginx alias | `scenarios/path-traversal/platform-specific.md` | Server-specific CVEs |
| LFI hits include() | `scenarios/path-traversal/lfi-to-rce.md` | Wrappers / log poison / filter chain |
| Upload accepts `.ipynb`, output is HTML/Markdown | `scenarios/path-traversal/nbconvert-jupyter-notebook.md` | nbconvert `embed_images` LFI + attachment-filename write → overwrite converter subprocess for RCE |

## File Upload

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Need a web shell | `scenarios/file-upload/web-shell-payloads.md` | PHP/ASP/JSP, disable_functions bypass, PHAR |
| Extension blocked | `scenarios/file-upload/extension-bypass.md` | Case, double, null, alt extensions |
| Magic-byte / Content-Type validated | `scenarios/file-upload/content-type-and-magic-bytes.md` | Hybrid file |
| Strict content scanner | `scenarios/file-upload/polyglot-and-metadata-injection.md` | EXIF, SVG, EPS GhostScript, Roundcube |
| Filename concatenated to path | `scenarios/file-upload/path-traversal-and-htaccess.md` | `../`, .htaccess, web.config, Struts2 |
| Upload + AV scan + delete | `scenarios/file-upload/race-conditions.md` | Save-vs-delete window |
| Signature/YARA scanner | `scenarios/file-upload/defense-evasion-and-yara.md` | HTA, MSI, LNK, FTP session injection |
| Predictable Windows upload subdir + foothold user | `scenarios/file-upload/ntfs-junction-write-redirect.md` | `mklink /J` swap to web root → RCE as service account |
| Reviewer opens uploaded media on Windows | `scenarios/file-upload/ntlm-hash-leak-via-media-upload.md` | `.asx`/`.wax`/`.wvx` `<REF HREF=UNC>` → NTLMv2 capture |
| Python/WSGI target, blacklist only blocks `.py`/`.pyc`, cwd writable via `../` | `scenarios/file-upload/python-module-shadowing-via-so.md` | Drop `.so` (or `.pth`) into `sys.path[0]` → shadow lazily-imported stdlib (`subprocess`/`ssl`) → RCE in fresh gunicorn workers |

## Deserialization

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Base64 prefix `Tzo`/`YTo` | `scenarios/deserialization/php-deserialization.md` | unserialize / PHAR / PHPGGC |
| Base64 prefix `rO0` (or Jackson/SnakeYAML errors) | `scenarios/deserialization/java-deserialization.md` | ysoserial / Jackson CVEs / ActiveMQ |
| Base64 prefix `gAN`/`gAR` or `BAh` | `scenarios/deserialization/python-and-ruby.md` | pickle `__reduce__` / Marshal+YAML |
| Base64 prefix `AAEAAA` | `scenarios/deserialization/dotnet-deserialization.md` | ysoserial.net / TypeConfuseDelegate |
| `node-serialize`/`funcster`/`serialize-to-js` in source, `_$$ND_FUNC$$_` smuggling | `scenarios/deserialization/nodejs-deserialization.md` | IIFE eval RCE via `unserialize()` on cookies/body |
| Next.js / React Server Components with React 19.0.0/19.1.x/19.2.0 (incl Next.js 15.0.x) | `scenarios/deserialization/react-server-components-flight.md` | CVE-2025-55182 — Flight multipart body + `next-action` header → pre-auth RCE |

## Host Header

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Reset email contains Host-based URL | `scenarios/host-header/password-reset-poisoning.md` | Host: attacker.com → token capture |
| Admin gated by "local users" | `scenarios/host-header/auth-bypass-localhost.md` | Host: localhost / connection-state |
| Cacheable response reflects Host | `scenarios/host-header/cache-poisoning-via-host.md` | Duplicate Host / X-Forwarded-Host |
| LB routes by Host | `scenarios/host-header/routing-ssrf-and-flawed-parsing.md` | Host: internal IP / 169.254.169.254 |
