# Forgotten-Backup-Zip on the IIS Web Root (recon archetype)

## When this applies

- Windows-AD web boxes with IIS — recon stage.
- Goal: locate developer-left backup archives directly downloadable from the IIS root, looking for service-account credentials in dotfiles.

## Technique

Windows-AD web boxes routinely ship a developer-left backup archive directly downloadable from the IIS root. Recursive `feroxbuster` against generic wordlists is wasteful here — the file is at depth 1 with a predictable name. A 30-line targeted wordlist beats 30 minutes of brute recursion.

## Steps

```
website-backup.zip
website-backup-DD-MM-YY.zip            # try DD-MM-YY, MM-DD-YY, YYYY-MM-DD; -old, .old, .bak suffixes
backup-DDMMYY.zip
<sitename>-backup.zip                  # derive <sitename> from the page title / og:site_name
wwwroot-YYYY-MM-DD.zip
iis-backup-MMM-YYYY.tar.gz
web.config.bak
*.zip.old / *-old.zip / *.bak / *.tar.gz
```

Generate the date variants from the box's "release year" range — most retired AD boxes were authored in the past 3 calendar years. After download, **always `unzip -l <file>` first**: it lists hidden dotfiles (`.old-conf.xml`, `.env`, `.htpasswd`, `.git/`, `appsettings.development.json`) that Windows GUI extractors silently mask. Service-account credentials and LDAP bind passwords land in those dotfiles far more often than in regular configs.

```bash
curl -s -o backup.zip http://target/website-backup-DD-MM-YY-old.zip
unzip -l backup.zip                                # see EVERYTHING incl. dotfiles
unzip backup.zip                                   # extract — hidden dotfiles materialize on Linux
grep -RIE 'password|pwd|secret|connectionString|bindDN' .  # find creds in any leaked file
```

Pair with the AD foothold archetypes block above — the recovered creds typically authenticate to WinRM/SMB and provide the entry shell.

## Verifying success

- The downloaded archive exists at the guessed URL.
- `unzip -l` reveals dotfiles that contained credentials.
- Recovered creds authenticate via `nxc smb`/`nxc winrm`.

## Common pitfalls

- Windows GUI extractors silently mask dotfiles — always `unzip -l` first on Linux.
- Dotfiles `.env`, `.htpasswd`, `.git/`, `appsettings.development.json` carry the highest-signal creds.

## Tools

- curl / wget
- unzip (Linux — preserves dotfiles)
- grep
