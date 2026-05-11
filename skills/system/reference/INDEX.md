# System Exploitation — Scenario Index

Read `system-exploitation-principles.md` first for the decision tree and sequencing principles. This index maps environment fingerprints to scenario files.

## Active Directory

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Service accounts with SPN, any creds | `scenarios/ad/kerberoast.md` | Request TGS, crack offline |
| User with `DONT_REQ_PREAUTH`, no creds needed | `scenarios/ad/as-rep-roast.md` | Pull AS-REP, crack offline |
| Have `.pfx` cert, want NT hash | `scenarios/ad/pkinit.md` | Cert → PKINIT → TGT + NT hash |
| `.pfx` cert but `certipy auth` fails | `scenarios/ad/certipy-ldap-shell-fallback.md` | Schannel LDAP shell — universal PKINIT-failure fallback |
| GenericWrite on user + ADCS deployed | `scenarios/ad/shadow-credentials.md` | `msDS-KeyCredentialLink` → PKINIT → NT hash |
| Vulnerable template with ENROLLEE_SUPPLIES_SUBJECT | `scenarios/ad/adcs-esc1.md` | Enrol with arbitrary UPN |
| WriteProperty on template DACL | `scenarios/ad/adcs-esc4.md` | Flip template to ESC1, enrol, restore |
| ManageCa on Enterprise CA | `scenarios/ad/adcs-esc6.md` | Enable EDITF_ATTRIBUTESUBJECTALTNAME2 |
| ManageCa, want full DA | `scenarios/ad/adcs-esc7.md` | Officer + SubCA chain → cert as any UPN |
| Template has CT_FLAG_NO_SECURITY_EXTENSION + GenericWrite on enroller | `scenarios/ad/adcs-esc16.md` | UPN-only auth via no-SID cert |
| ADCS Web Enrollment + NTLM disabled (ESC8 NTLM-relay blocked) | `scenarios/ad/adcs-esc8-kerb-relay.md` | CTI DNS spoof + coerce_plus → DC cert via Kerberos relay |
| gMSA account (member of msDS-GroupMSAMembership) | `scenarios/ad/gmsa.md` | Read managed password → NT hash |
| WriteProperty on `msDS-AllowedToActOnBehalfOfOtherIdentity` | `scenarios/ad/rbcd.md` | RBCD chain to SYSTEM on target |
| Unconstrained delegation host (DC, etc.) + SYSTEM there | `scenarios/ad/unconstrained-delegation.md` | Coerce + capture forwarded TGT |
| `msDS-AllowedToDelegateTo` + service hash | `scenarios/ad/constrained-delegation.md` | S4U2Self/S4U2Proxy abuse + SPN jacking |
| Kerberoasted service NT hash, NTLM disabled | `scenarios/ad/silver-ticket.md` | Forge MSSQL TGS as Administrator |
| `krbtgt` hash | `scenarios/ad/golden-ticket.md` | Forge arbitrary TGTs |
| Account with `DS-Replication-Get-Changes*` | `scenarios/ad/dcsync.md` | Dump credentials from DC |
| AD-joined appliance with "set LDAP server IP" admin form | `scenarios/ad/ldap-simple-bind-capture.md` | Capture cleartext bind DN + password |
| Authenticated user on AD-integrated DNS | `scenarios/ad/dns-record-poisoning.md` | Create A record + rogue service capture |
| WSUS clients use HTTPS upstream + CA enroll rights | `scenarios/ad/wsus-mitm.md` | Hijack updates → SYSTEM |
| Target machine reachable on 445 + can coerce | `scenarios/ad/ntlm-relay.md` | Coercer + ntlmrelayx → RBCD |
| NTLM disabled domain-wide | `scenarios/ad/kerberos-only-domain.md` | Bootstrap krb5.conf, run all tools `-k` |
| Pre-Win2K group has machine accounts | `scenarios/ad/pre-windows-2000-access.md` | Predictable passwords (lowercase name) |
| Foothold + outgoing ACL edge in BloodHound | `scenarios/ad/acl-abuse-chains.md` | Chain ACL primitives to DA |
| User in `LAPS_Readers` / similar | `scenarios/ad/laps-readers.md` | Dump cleartext local Admin passwords |
| Need to reset Protected User password | `scenarios/ad/protected-users-bypass.md` | GSSAPI LDAP `unicodePwd` modify |
| RODC present | `scenarios/ad/rodc-exploitation.md` | Forge RODC golden ticket + Key List |
| Have NT hash, NTLM enabled | `scenarios/ad/pass-the-hash.md` | PtH against WinRM/SMB/LDAP/MSSQL |
| Have ccache, need programmatic SMB read | `scenarios/ad/pass-the-ticket-impacket.md` | impacket SMBConnection.kerberosLogin |
| Forest trust + SYSTEM on child DC | `scenarios/ad/cross-forest-trust.md` | Trust key + forged inter-realm TGT |
| ADFS + read access to gMSA | `scenarios/ad/adfs-golden-saml.md` | Decrypt EncryptedPfx → forged SAML |
| `.wim` files on SMB share (Windows imaging backup) | `scenarios/ad/wim-image-credential-extraction.md` | 7zz extract SAM/SECURITY/SYSTEM → secretsdump |
| KDC_ERR_KEY_EXPIRED on Kerberos pre-auth | `scenarios/ad/kpasswd-expired-password-reset.md` | kpasswd self-service reset (no admin); valid pw, just expired |
| Lansweeper inventory server reachable as low-priv user | `scenarios/ad/lansweeper-cred-mapping-honeypot.md` | Add attacker IP range + map cred + SSH honeypot → cleartext capture |
| RBCD primitive but `ms-DS-MachineAccountQuota=0` | `scenarios/ad/spn-less-rbcd-nthash-trick.md` | Forshaw NTHash=SessionKey trick → U2U S4U2self+S4U2proxy without fake computer |
| LDAP `description` field credential leak | `scenarios/ad/kpasswd-expired-password-reset.md` | spray candidate against users via getTGT — diff PREAUTH_FAILED vs KEY_EXPIRED |
| SeBackupPrivilege but `C:\Windows\Temp` not writable | `scenarios/ad/kpasswd-expired-password-reset.md` | diskshadow `set metadata <writable_dir>\meta.cab` |
| Privileged user in another RDP session, you have NETWORK logon | `scenarios/ad/cross-session-ntlm-relay.md` | RemotePotato0 + socat → NETNTLMv2 capture/relay |
| Have NTLM hash, can't crack to plaintext password, target runs OpenSSH | `scenarios/ad/openssh-key-drop-via-smb-home.md` | SMB-write `~\.ssh\authorized_keys` → SSH key auth |
| LDAP 389/636 filtered, only 3268/3269 (GC) reachable | `scenarios/ad/ldap-via-gc-when-389-filtered.md` | ldap3 NTLM PtH on GC; impacket `gc://` URL |

## Linux Privilege Escalation

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| New Linux foothold | `scenarios/linux-privesc/credential-files-hunt.md` | Sweep language/framework cred files |
| `sudo -l` shows misconfigs | `scenarios/linux-privesc/sudo-symlink.md` | Argument injection / wrapper bypass / pager / symlink chain |
| SUID-root binaries present | `scenarios/linux-privesc/suid-binary-exploitation.md` | GTFOBins / `system()` injection / world-writable bin replace |
| `getcap` shows interesting caps | `scenarios/linux-privesc/cap-dac-override.md` | cap_setuid/dac_override/net_raw/sys_admin abuse |
| User in `docker`/`lxd`/`disk` group | `scenarios/linux-privesc/lxd-privesc.md` | Mount host fs, gshadow newgrp |
| Inside Docker/k8s container | `scenarios/linux-privesc/docker-escape.md` | Env vars, socket, privileged, mounts, NFS GID |
| Backup script runs `zip --recurse-paths` on writable dir | `scenarios/linux-privesc/info-zip-symlink-follow.md` | Symlink → exfil through backup |
| Can write `/proc/sys/fs/binfmt_misc/register` | `scenarios/linux-privesc/binfmt-misc-suid-laundering.md` | Launder root via binfmt `C` flag |
| pkexec ≤ 0.105-26ubuntu1.1, no TTY | `scenarios/linux-privesc/pwnkit.md` | gconv_init inline syscalls (no system()) |
| sudo 1.8.0–1.8.31p2 / 1.9.0–1.9.5p1 | `scenarios/linux-privesc/baron-samedit.md` | worawit's exploit_nss.py |
| polkit < 0.120 + dbus | `scenarios/linux-privesc/polkit-race.md` | Race admin user creation |
| snap-confine SUID + tmpfiles cleanup | `scenarios/linux-privesc/snap-confine-race.md` | RENAME_EXCHANGE library swap |
| udisks2 + polkit allow_active | `scenarios/linux-privesc/udisks2-polkit.md` | XFS SUID mount via loop-setup |
| SSH cert auth, no AuthorizedPrincipalsFile | `scenarios/linux-privesc/ssh-ca-forgery.md` | Forge cert with principal=root |
| sudo Python script `tarfile.extractall(filter="data")` | `scenarios/linux-privesc/pycache-poisoning.md` | CVE-2025-4517 PATH_MAX bypass |
| `sudo … git ^apply -v <pattern>$`, git ≤ 2.39.1 | `scenarios/linux-privesc/sudo-git-apply-symlink.md` | CVE-2023-23946 symlink-rename → write authorized_keys |
| `sudo … clamscan ^--debug <path>$`, ClamAV ≤ 1.0.1 | `scenarios/linux-privesc/clamav-debug-xxe.md` | CVE-2023-20052 DMG XXE → read /root/.ssh/id_rsa |
| Container/host with multiplex SSH sockets | `scenarios/linux-privesc/ssh-controlmaster-hijack.md` | Ride open session without creds |
| Web RCE inside AppArmor hat | `scenarios/linux-privesc/apparmor-hat-bypass.md` | World-writable shared dirs / `wk` bypass |
| Stuck in rbash | `scenarios/linux-privesc/rbash-escape.md` | SSH `-L`/`-D`/`-t`/SCP pre-shell |
| Localhost WCF/SOAP service | `scenarios/linux-privesc/wcf-soap-localhost.md` | WSDL recon + SOAP command injection |
| Vulnerable network/SUID binary memory bug | `scenarios/linux-privesc/buffer-overflow.md` | Stack/heap overflow exploit dev |

## Windows Privilege Escalation

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Backup Operators / SeBackupPrivilege | `scenarios/windows-privesc/sebackuprivilege.md` | DiskShadow + robocopy /B → ntds.dit |
| Server/Print/Backup/Account Operators on filtered token | `scenarios/windows-privesc/server-operators-imagepath.md` | Registry ImagePath rewrite + reboot |
| AutoAdminLogon configured | `scenarios/windows-privesc/autoadminlogon.md` | Read DefaultPassword from registry/LSA |
| LAPS readers (see also AD) | `scenarios/ad/laps-readers.md` | Cleartext local Admin passwords |
| PowerShell environment with profiles | `scenarios/windows-privesc/psreadline-history.md` | Sweep ConsoleHost_history.txt |
| Found writable service binary | `scenarios/windows-privesc/service-required-privileges.md` | Pre-Potato sanity check (RequiredPrivileges) |
| SeImpersonate present, modern Windows | `scenarios/windows-privesc/potatoes-sanity-check.md` | GodPotato → SigmaPotato → PrintSpoofer |
| SYSTEM/admin obtained | `scenarios/windows-privesc/multi-user-flag-sweep.md` | Sweep all user Desktop/Documents |
| Any IIS / web host log access | `scenarios/windows-privesc/iis-log-credentials.md` | Grep query strings for password= |
| Memory dump file found | `scenarios/windows-privesc/memory-dump-creds.md` | volatility3 lsadump → `_SC_*` cleartext |
| RCE as Chromium browser user | `scenarios/windows-privesc/dpapi-browser-creds.md` | In-process `CryptUnprotectData` |
| Writable service binary + restart trigger | `scenarios/windows-privesc/writable-service-binary-race.md` | Race CopyFile during stop window |
| Scheduled task polls ZIP dir | `scenarios/windows-privesc/scheduled-task-zip-poll.md` | Drop malicious ZIP+DLL |
| Print Spooler running, MS-RPRN exposed | `scenarios/windows-privesc/printnightmare.md` | CVE-2021-1675 driver load |
| Installed MSI uses temp .cmd custom action | `scenarios/windows-privesc/msi-repair-toctou.md` | C# FileSystemWatcher race |
| Localhost WCF service running as SYSTEM | `scenarios/windows-privesc/wcf-named-pipe.md` | WSDL discovery + parameter injection |
| Windows over SSH non-PTY | `scenarios/windows-privesc/file-transfer-ssh-pty.md` | certutil / WebClient — NOT iwr |
| Recon stage on IIS-AD web box | `scenarios/windows-privesc/forgotten-backup-zip.md` | Targeted backup-zip wordlist + dotfile grep |
| App writes/searches DLLs in writable dirs | `scenarios/windows-privesc/dll-hijacking.md` | Place malicious DLL in search path |
| No SeImpersonate, missing patches | `scenarios/windows-privesc/kernel-eop.md` | Match build to CVE-2024-30088 / 2023-28252 |
| Service path with spaces, unquoted | `scenarios/windows-privesc/unquoted-service-path.md` | Drop binary at parent prefix |
| Custom Windows network service, no ASLR/SafeSEH | `scenarios/windows-privesc/seh-overflow-static-binary.md` | SEH overwrite via POP/POP/RET, NSEH short-jmp bridge |
| Writable HKLM\...\Services\<svc>\Performance | `scenarios/windows-privesc/perflib-dll-hijack.md` | DLL hijack via PerfLib — MSDTC fallback when RpcEptMapper unavailable |
| .accdb / .mdb file recovered from share | `scenarios/foothold-access-db-vba.md` | jackcess-encrypt decrypt + MS-OVBA RLE for VBA-stored creds |
| User in `adm`/`audit`/`systemd-journal` group | `scenarios/linux-privesc/log-and-tmux-credential-reuse.md` | Mine /var/log/audit/audit.log + journald argv for cleartext creds |
| postgres RCE + root-cron pg_basebackup → zip/tar | `scenarios/linux-privesc/postgres-tablespace-symlink-zip.md` | Plant pg_tblspc/<oid> symlink to /root, archiver follows → arbitrary file read as root |
| Root cron runs md5sum-verified shell script + writable parent dir | `scenarios/linux-privesc/toctou-cron-md5-symlink-flip.md` | Atomic symlink flip during verify→exec window |
| sudo 1.9.14–1.9.17 + CHROOT= in any rule | `scenarios/linux-privesc/sudo-cve-2025-32463-chwoot.md` | NSS module hijack via `sudo -R` — probe policy gate first |
| sudoers regex `^[a-zA-Z0-9]+$` style guard | `scenarios/linux-privesc/sudo-cve-2025-32463-chwoot.md` | POSIX ERE on joined argv — multi-arg injection blocked |
| Writable tmux/screen socket of higher-priv user | `scenarios/linux-privesc/log-and-tmux-credential-reuse.md` | tmux -S send-keys → drive live pty; reuse warm sudo cache |
| `Defaults timestamp_timeout=-1` in sudoers + boot pty | `scenarios/linux-privesc/log-and-tmux-credential-reuse.md` | Reach the original tty (send-keys, chvt) → passwordless root |
| sudo NOPASSWD on nano/vim/less/man | `scenarios/linux-privesc/log-and-tmux-credential-reuse.md` | nano ^T / vim :!sh / less !sh — GTFOBins one-keystroke escapes |
| Kiosk-mode Edge / RDP RemoteApp / restricted shell | `scenarios/windows-privesc/kiosk-and-applocker-escape.md` | file:// recon + rename to allowlisted name + UAC consent |
| Masked-bullet password in vendor GUI app | `scenarios/windows-privesc/kiosk-and-applocker-escape.md` | WM_GETTEXT P/Invoke (BulletsPassView equivalent) |
| AppLocker enabled, name-based allowlist | `scenarios/windows-privesc/kiosk-and-applocker-escape.md` | Rename payload to msedge.exe / explorer.exe / notepad.exe |
| Medium-integrity admin via runas | `scenarios/windows-privesc/kiosk-and-applocker-escape.md` | Start-Process -Verb RunAs (UAC consent) or fodhelper bypass |

## MSSQL

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Sysadmin or IMPERSONATE on sa | `scenarios/mssql/xp-cmdshell.md` | EXECUTE AS LOGIN='sa' → xp_cmdshell |
| ANY MSSQL login (public) | `scenarios/mssql/xp-dirtree-coercion.md` | NetNTLMv2 capture via fake SMB share |
| Linked servers configured | `scenarios/mssql/linked-server-chain.md` | EXEC AT + EXECUTE AS LOGIN='sa' on remote |
| Foothold on SQL host | `scenarios/mssql/errorlog-secrets.md` | Grep ERRORLOG / 4625 for password-as-username |
