# IIS / Web Access Log Credential Goldmine

## When this applies

- Windows foothold on an IIS / web host (or any host with web-server logs).
- Goal: dump web access logs and grep for credentials accidentally placed in URL query strings.

## Technique

Internal "alert", "callback", or "healthcheck" endpoints frequently take credentials in the QUERY STRING (`?auth=1&username=X&password=Y&...`). IIS (and most web servers) log the full URL **URL-decoded** to the access log. After foothold on any web host, ALWAYS grep the logs for `password=`, `pwd=`, `token=`, `apikey=`, `auth=`, then URL-decode any hits. Works on automated bots calling internal endpoints (the bot supplies the credentials in the URL on every iteration → cleartext lands in the log every time).

## Steps

```powershell
# Sweep all IIS log directories (default + custom)
Select-String -Path 'C:\inetpub\logs\LogFiles\*\*.log','C:\Windows\System32\LogFiles\*\*.log' `
  -Pattern 'password=|pwd=|token=|apikey=|auth=' -ErrorAction SilentlyContinue
# URL-decode the matched query strings (PowerShell):
[System.Web.HttpUtility]::UrlDecode('7y4Z4%5E*y9Zzj')   # → 7y4Z4^*y9Zzj
```

The same pattern applies to Apache (`/var/log/apache2/access.log*`), nginx (`/var/log/nginx/access.log*`), and any reverse-proxy access log. The endpoint design pattern that produces this is recognizable from the source — look for `$_GET['password']`, `request.args.get('password')`, `Request.QueryString["pwd"]` in code, then trace which service/scheduled task calls it.

## Verifying success

- `Select-String` returns hits with `password=...` in the URL.
- After URL-decoding, the recovered value authenticates against the corresponding service.

## Common pitfalls

- Logs may be rotated/compressed (`.log.gz`) — extend the pattern accordingly.
- The credential may belong to an internal automation account — verify what service uses it before chaining.

## Tools

- Select-String (PowerShell)
- `[System.Web.HttpUtility]::UrlDecode`
- grep (Linux equivalents)
