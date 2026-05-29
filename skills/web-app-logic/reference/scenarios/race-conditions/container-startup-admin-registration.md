# Container Startup — Admin Registration Race

## When this applies

- Web framework opens listening port BEFORE running DB seed code (e.g., `app.listen()` before `loop.run_sync(create_tables)`).
- Seed code INSERTs the admin row with a random password into a `users` table with `UNIQUE(username)`.
- `/register` handler reaches the same DB with no transactional coordination.
- Result: between `CREATE TABLE users` and `INSERT admin`, a concurrent register request can claim the `admin` row first.

## Technique

Reach the listening port the moment it opens (before seed `INSERT admin` runs) and POST `/register username=admin&password=<known>`. The seed script's `INSERT` then fails with `UNIQUE constraint failed`; the attacker's row stays.

**Vulnerable bootstrap pattern (Tornado/aiosqlite):**
```python
app.listen(8888)                    # port opens here, IOLoop not yet running
loop.run_sync(create_tables)        # runs executescript: DROP, CREATE, INSERT admin
loop.run_sync(fill_tables)
loop.start()
```

`executescript` runs each statement as its own auto-committed transaction in SQLite. Between statements the write lock is released, so a coroutine running on the same IOLoop can squeeze in an INSERT to `users`.

**Local PoC (70% win rate over 20 trials):**
```python
async def attacker(i):
    async with aiosqlite.connect(db) as conn:
        try:
            await conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'attacker_pass')")
            await conn.commit()
            return i
        except: return None

async def main():
    tasks = [setup()] + [attacker(i) for i in range(100)]
    await asyncio.gather(*tasks, return_exceptions=True)
```

## Steps

### Detection signals

- DB schema with `username TEXT UNIQUE` constraint.
- App bootstrap that `listen` then `run_sync(seed)` — port is reachable before seed completes.
- `executescript` (or any non-atomic seed) splitting CREATE and INSERT into separate auto-commits.
- Public `/register` endpoint reachable without rate limiting.

### Operationalising against a live container

Network RTT (~30ms) plus CDN/reverse-proxy forwarding overhead typically masks the few-millisecond seed window in production. Tactics that improve odds:

- Pre-resolve DNS / re-use TCP connections (HTTP/1.1 keep-alive pipelining) so the request hits as soon as the port accepts.
- Hammer the API health endpoint until it goes from 502 → 200 (CDN→origin connect just succeeded); fire all register attempts in the same TCP window.
- Spin many TCP workers (200+) issuing `POST /register` continuously; the kernel queues SYNs in the listen backlog before `accept()` even runs.
- If the container exposes the origin port directly (rare), target it instead of the CDN to remove a hop of latency.
- When the CDN→origin path is the bottleneck, the seed often completes during the first CDN→origin TCP handshake; in that case the race is effectively unwinnable from outside without orchestration help.

### Verification

Success = `POST /register username=admin&password=X` returns `302 Found Location: /login` instead of the register page with "User already exists" error.

Confirm by `POST /login username=admin&password=X` returning `302 Location: /quotes` with a fresh `Set-Cookie: username=...` signed cookie.

## Variations

- Other frameworks: Express + Sequelize `sync({ force: true })`, Flask + SQLAlchemy `create_all()` followed by seed insert.
- Other unique columns: `email`, `role`, `permission_grant`.
- Other seed patterns: separate INSERT after `executemany`; INSERT before commit.

## Defenses

- Run schema and seed BEFORE `listen()`.
- Wrap seed in a single transaction (`BEGIN; ... COMMIT;`).
- Use `INSERT OR IGNORE` and verify the canonical row exists after insert — abort startup if attacker won.
- Disable `/register` (or any privileged-row-write endpoint) until startup is complete.
