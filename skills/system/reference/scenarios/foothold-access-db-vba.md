# Microsoft Access (.accdb / .mdb) — Decryption + VBA Credential Extraction

## When this applies

- An `.accdb` (Access 2007/2010/2013/2016+) or `.mdb` (Access 97/2000/2002/2003) file is recovered from a public SMB share, document folder, NFS export, web upload directory, or backup tarball.
- The file is password-protected; the password may itself be a goal, but more often the **VBA modules** inside contain hardcoded credentials, connection strings, or SOAP/API keys for AD service accounts.

## Identification

```bash
file <database>.accdb        # → "Microsoft Access database" (ACE) or "OLE 2 Compound Document" (Jet)
hexdump -C <database>.accdb | head -2
# ACE 2010+/2013+: header starts with `\x00\x01\x00\x00 Standard ACE DB`
# 2013+ encryption: bytes 0x18..0x1F = "EncryptionInfo" + agile-encryption blob
```

| Engine version | Format | Encryption | Right tool |
|---|---|---|---|
| Access 97/2000/2002/2003 | Jet 4 (OLE2 .mdb)            | RC4 / weak XOR | `mdbtools`, `office2john -F` (john) |
| Access 2007              | ACE 12 (.accdb)              | RC4 — known weak | jackcess, `office2john` mode 0 |
| Access 2010              | ACE 14 (.accdb)              | AES-128 (legacy) | jackcess-encrypt, `office2john` mode 1 |
| Access 2013/2016+        | ACE 14/16 (.accdb)           | AES-128 / AES-256 **agile** | jackcess-encrypt only — `msoffcrypto-tool` does NOT handle ACE |

## Decryption — Access 2013/2016+ (agile encryption)

`msoffcrypto-tool`, `office2john`, and Hashcat -m 9600 (Office 2013) work for `.docx`/`.xlsx`/`.pptx` because those are OOXML zips. **`.accdb` is not a zip** — it's a single binary with an embedded EncryptionInfo blob. The right library is **jackcess-encrypt** (Java):

```java
// Decrypt.java — compile with jackcess-encrypt-3.0.0.jar + jackcess-4.0.5.jar on classpath
import com.healthmarketscience.jackcess.*;
import com.healthmarketscience.jackcess.crypt.*;
import java.io.File;

public class Decrypt {
  public static void main(String[] a) throws Exception {
    Database db = new DatabaseBuilder(new File(a[0]))
        .setReadOnly(false)
        .setCodecProvider(new CryptCodecProvider(a[1]))     // password
        .open();
    db.saveAs(new File(a[2]));                              // writes decrypted copy
    db.close();
  }
}
```

```bash
# Build classpath and run
javac -cp jackcess-4.0.5.jar:jackcess-encrypt-3.0.0.jar Decrypt.java
java -cp .:jackcess-4.0.5.jar:jackcess-encrypt-3.0.0.jar:bcprov-jdk18on-1.78.jar:commons-logging-1.2.jar:commons-lang3-3.14.0.jar \
     Decrypt encrypted.accdb 'p@ssw0rd' decrypted.accdb
```

If the password is unknown, **office2john's patched-fork (`office2john_msaccess.py`)** extracts the hash for cracking with **hashcat -m 9600** (mode 9600 IS Office 2013 agile encryption — it works on `.accdb` too because the EncryptionInfo blob has the same structure):

```bash
python3 office2john_msaccess.py encrypted.accdb > db.hash    # patched fork
hashcat -m 9600 -a 0 db.hash rockyou.txt
```

Stock `office2john.py` from john-the-ripper rejects `.accdb` — use the [Vovkulak fork](https://github.com/Vovkulak/office2john) or the patched script that reads the EncryptionInfo blob from byte 0x18.

## VBA module extraction from a decrypted .accdb

VBA project storage in ACE 2013+ lives in **`MSysAccessStorage`** rows under the path `VBAProject\VBA\<ModuleName>`. The data column is the LZNT1-style **MS-OVBA RLE-compressed** blob — same compression as `.docm`/`.xlsm` `vbaProject.bin`.

```python
# Extract VBA modules from a decrypted .accdb via jackcess Python bindings (JPype) or via mdb-export:
# 1. List raw rows
mdb-tables -1 decrypted.accdb | grep -i AccessStorage
mdb-export decrypted.accdb MSysAccessStorage > storage.csv  # works for .mdb only

# For .accdb, dump via jackcess (Java) into a binary, then RLE-decompress:
import struct

def ovba_decompress(data: bytes) -> bytes:
    # MS-OVBA Section 2.4: 4096-byte chunks, 12-bit offset / 4-bit length tokens.
    assert data[0] == 0x01                # signature byte
    out = bytearray(); i = 1
    while i < len(data):
        h = struct.unpack_from("<H", data, i)[0]; i += 2
        chunk_len = (h & 0x0FFF) + 3
        if h & 0x8000 == 0:               # uncompressed chunk
            out += data[i:i+chunk_len-3]; i += chunk_len - 3; continue
        end = i + chunk_len - 2; flags_pos = i; out_chunk_start = len(out)
        while i < end:
            flags = data[i]; i += 1
            for b in range(8):
                if i >= end: break
                if not (flags & (1 << b)):                # literal
                    out.append(data[i]); i += 1
                else:                                     # back-reference
                    tok = struct.unpack_from("<H", data, i)[0]; i += 2
                    pos = len(out) - out_chunk_start
                    bitcount = max(4, (pos - 1).bit_length())
                    length = (tok & ((1 << bitcount) - 1)) + 3
                    offset = (tok >> bitcount) + 1
                    src = len(out) - offset
                    for _ in range(length): out.append(out[src]); src += 1
    return bytes(out)
```

The decompressed buffer is plaintext VBA source (CRLF). `grep -i "password\|connect\|user\|pwd\|key=\|secret"` against every module — service-account creds and connection strings are the usual prize.

## Verifying success

- `decrypted.accdb` opens in LibreOffice Base / `mdb-tools` without prompting for a password.
- Decompressed VBA source contains readable `Public Const PASSWORD = "..."` / `ADODB.Connection.Open "Provider=...;User ID=...;Password=..."` / SOAP credentials.

## Common pitfalls

- Running `msoffcrypto-tool` against `.accdb` returns "not a valid Office file" — wrong library family entirely.
- jackcess **without** the `-encrypt` companion JAR throws `UnsupportedCodecException` — confirm both jars are on the classpath (and `bcprov`/`commons-*` runtime deps).
- `office2john.py` (mainline) silently emits no hash for `.accdb`; the Vovkulak fork or any patch that reads from byte 0x18 onward is required.
- Hash cracked but jackcess still rejects the password: the password may be UTF-16-LE with trailing NUL — try `printf '<pw>\0' | iconv -t UTF-16LE` and pass as a byte string.

## Tools

- jackcess + jackcess-encrypt (Java) — only reliable .accdb decrypter
- office2john_msaccess.py (patched fork) — hash extractor
- hashcat -m 9600 — Office 2013 agile cracker (handles ACE 2013+ blob)
- mdbtools (`mdb-export`, `mdb-tables`) — Jet (.mdb) dumping
- [Magnet ACE Trace](https://www.magnetforensics.com/) — closed-source forensics alternative
