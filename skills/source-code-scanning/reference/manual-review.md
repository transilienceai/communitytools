# Manual Security Code Review

## Taint Analysis Approach

**Sources** (user-controlled input) → **Sinks** (dangerous operations)

### Sources to Track
```
HTTP: request.params, request.body, req.query, request.headers, req.cookies
File: argv[], stdin, file.read(), config files if user-editable
DB: results from queries fed back into queries
Environment: getenv() if user-influenced
```

### Critical Sinks

| Sink Type | Functions to Find |
|---|---|
| Command exec | `exec`, `system`, `popen`, `subprocess`, `Runtime.exec`, `os.system`, `shell_exec`, `eval` |
| SQL query | `query`, `execute`, `rawQuery`, `cursor.execute`, `db.run` |
| **SQL ORDER BY sink** | Template-literal interpolation into `ORDER BY ${col}` / `ORDER BY ' + req.query.sort` — parametrized binders skip ORDER BY columns by spec (PreparedStatements only protect data, not identifiers). A `// TODO: parametrize` or `// FIXME` comment near such a query is a near-certain blind-SQLi sink. SQLite + node-sqlite3/better-sqlite3 are particularly forgiving — accept full subqueries in the sort key. |
| Deserialization | `pickle.loads`, `yaml.load`, `ObjectInputStream`, `unserialize`, `JSON.parse` (sometimes) |
| **PHP session forgery via DB-row injection** | `session_decode($row['data'])` where the row was loaded from a SQLi-controllable column. Forging a session is `UNION SELECT` of a `key|s:N:"value";` string — `session_decode()` writes directly into `$_SESSION`. Common in CMSes/appliances that store sessions in a DB table (e.g., `tsessions_php`, `sessions`, `wp_session`) and look them up by an unsanitized request parameter. Forging `id_usuario|s:5:"admin";` (or whatever the framework uses for the user identity) bypasses login. |
| **HTML-decode helpers used as shell-escape** | `io_safe_output()`, `htmlspecialchars_decode()`, `html_entity_decode()`, `strip_tags()`, custom "sanitize" functions that only deal with HTML — when their output is concatenated into `system()`/`exec()`/`shell_exec()`/`passthru()`/`popen()`/`proc_open()`, it's RCE. The functions strip/decode HTML entities but do NOT shell-quote — `;`, `|`, `&`, backticks, `$()` all pass through. Grep pattern: `grep -rE '(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*(io_safe_output|html\w*decode|strip_tags)' --include='*.php'` — every match is a candidate. |
| **.NET deserialization sinks** (unauth RCE on attacker-controlled bytes) | `BinaryFormatter.Deserialize`, `LosFormatter.Deserialize`, `NetDataContractSerializer.ReadObject`, `ObjectStateFormatter.Deserialize`, `SoapFormatter.Deserialize`, `JavaScriptSerializer(new SimpleTypeResolver())`, Json.NET with `TypeNameHandling != None`, `DataContractJsonSerializer` with attacker-controlled `KnownTypes`. Red-flag pattern: TCP/HTTP service that reads a `RequestType`/`Command` enum FIRST, then deserializes a base64 payload — usually means the deserialize branch runs BEFORE auth check (per-connection-stateless = unauth bypass). Decompile with `ilspycmd`/`dnSpy`/`dotPeek`, search for `Deserialize(` — typically <1 minute to find. Exploit via ysoserial.net `TextFormattingRunProperties` gadget. |
| Template render | `render_template_string`, `Mustache.render`, `eval` with template |
| File ops | `open`, `readFile`, `writeFile`, `sendFile`, `Path(user_input)` |
| Redirect | `redirect`, `header("Location:")`, `res.redirect` |
| HTML output | `innerHTML`, `document.write`, `dangerouslySetInnerHTML` |
| SSRF | `requests.get(url)`, `fetch(url)`, `HttpClient.get`, `curl` |

## CWE Top 25 (2024) Checklist

| Rank | CWE | What to Look For |
|---|---|---|
| 1 | CWE-79 | XSS: user input reflected without encoding |
| 2 | CWE-787 | OOB write: buffer overflows (C/C++) |
| 3 | CWE-89 | SQLi: string concatenation into SQL |
| 4 | CWE-416 | Use after free (C/C++) |
| 5 | CWE-78 | OS command injection: user input in shell command |
| 6 | CWE-20 | Improper input validation: missing type/length/format checks |
| 7 | CWE-125 | OOB read (C/C++) |
| 8 | CWE-22 | Path traversal: `../` in file paths from user input |
| 9 | CWE-352 | CSRF: state-changing requests without token |
| 10 | CWE-434 | Unrestricted file upload: no content-type/extension validation |
| 11 | CWE-862 | Missing authorization: no permission check before action |
| 12 | CWE-476 | Null pointer dereference |
| 13 | CWE-287 | Improper auth: weak/missing authentication |
| 14 | CWE-190 | Integer overflow |
| 15 | CWE-502 | Deserialization of untrusted data |
| 16 | CWE-77 | Command injection (non-OS) |
| 17 | CWE-119 | Buffer errors |
| 18 | CWE-798 | Hardcoded credentials |
| 19 | CWE-918 | SSRF |
| 20 | CWE-306 | Missing auth for critical function |

## High-Risk Code Patterns

### Authentication & Session
```python
# WEAK: predictable session token
session_id = str(user_id) + timestamp

# WEAK: timing attack in comparison
if token == stored_token:  # use hmac.compare_digest instead

# WEAK: JWT without verification
payload = jwt.decode(token, options={"verify_signature": False})
```

### Cryptography
```python
# BAD: weak algorithms
hashlib.md5(password)         # CWE-327
hashlib.sha1(password)        # CWE-327
Cipher.new(key, AES.MODE_ECB) # CWE-327 (ECB)
random.random()               # not cryptographic, CWE-338

# BAD: hardcoded key
SECRET_KEY = "abc123"
```

### Access Control
```python
# MISSING: no ownership check before delete
def delete_item(item_id):
    Item.objects.get(id=item_id).delete()  # any user can delete any item

# MISSING: role check bypassed by parameter
def admin_action(user, is_admin=False):
    if request.args.get('admin'):  # user-controlled!
        is_admin = True
```

### Race Conditions (TOCTOU)
```python
# TOCTOU: check then act
if os.path.exists(filename):
    os.remove(filename)  # file could change between check and remove
```

## Secure Design Checks

- [ ] Defense in depth: validation at every layer, not just frontend
- [ ] Least privilege: DB user, service accounts have minimal permissions
- [ ] Error handling: no stack traces / internal paths in error responses
- [ ] Logging: sensitive data (passwords, PII, tokens) NOT logged
- [ ] Dependencies: no dev dependencies in production bundle
- [ ] HTTPS enforced: no HTTP fallback, HSTS header present
- [ ] Security headers: CSP, X-Frame-Options, X-Content-Type-Options
- [ ] Secrets: loaded from env/vault, not source code

## Data Flow Documentation Template

```
Source: req.body.username (line 42, routes/auth.js)
  → passed to: buildQuery() (line 15, db/queries.js)
  → concatenated into: "SELECT * FROM users WHERE name='" + username + "'"
  → executed via: db.query() (line 18, db/queries.js)
Sink: SQL query execution
CWE: CWE-89 (SQL Injection)
Severity: Critical
```
