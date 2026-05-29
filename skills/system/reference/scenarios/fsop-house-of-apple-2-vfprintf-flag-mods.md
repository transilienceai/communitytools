# House of Apple 2 — Bit-level _flags Survival Across vfprintf

**When to use:** glibc 2.34+ FSOP via `_IO_wfile_jumps` where the shell command lives in `stdout._flags` and is read as a `char *` by `system(fp)`. `vfprintf` modifies `_flags` BEFORE the trigger fires, so the first 4 bytes of `_flags` get bit-twiddled — your literal pre-image will become a different (often garbage) command.

**Why:** Standard HOA2 chain ends with `_IO_wdoallocbuf(stdout) → fake_wd._wide_vtable->__doallocate(stdout) = system(stdout)`. `stdout` starts with `_flags` (4 bytes), then 4 bytes pad, then `_IO_read_ptr` etc. `system` reads `stdout` as a null-terminated string. The first byte(s) are your `_flags`.

But `vfprintf` between your `arb_write(stdout._vtable, ...)` and the trigger printf will modify `_flags`:
- `_IO_setp(f, b, e)` → `f->_flags &= ~_IO_USER_BUF (0x1)` — clears byte0 bit0
- `_IO_new_file_overflow` → `f->_flags |= _IO_CURRENTLY_PUTTING (0x800)` — sets byte1 bit3
- Various paths → `&= ~_IO_IN_BACKUP (0x100)` — clears byte1 bit0

Cumulative: byte0 bit0 cleared, byte1 bit0 cleared, byte1 bit3 set.

## Choosing the pre-image

You want the **post-modification** bytes to form a sh command that spawns a shell. Constraints:

| Bit | Byte | Constraint for vfprintf to reach the chain | Constraint for post-mod sh command |
|-----|------|--------------------------------------------|------------------------------------|
| byte0 bit1 | `_IO_UNBUFFERED` (0x2) | **clear** — else vfprintf takes `buffered_vfprintf` path which uses a temp FILE (`_IO_helper_jumps`) and bypasses your hijacked vtable | free |
| byte0 bit3 | `_IO_NO_WRITES` (0x8) | **clear** — else `_IO_wfile_overflow` early-returns WEOF | free |
| byte0 bit0 | `_IO_USER_BUF` (0x1) | n/a | cleared by vfprintf — pre value doesn't matter |
| byte1 bit0 | `_IO_IN_BACKUP` (0x100) | n/a | cleared by vfprintf — pre value doesn't matter |
| byte1 bit3 | `_IO_CURRENTLY_PUTTING` (0x800) | n/a | set by vfprintf — pre value doesn't matter (post will be set) |

## Working pre-image: `" :;sh\0"`

Bytes 0x20 0x3a 0x3b 0x73 0x68 0x00:
- byte0 = 0x20 (' '): bit0=0, bit1=0, bit3=0 ✓
- byte1 = 0x3a (':'): bit0=0, bit3=1 ✓ (already; modifications are no-ops)
- bytes 2..4 = `;sh\0` — sh -c `:;sh` → `:` (no-op) + `;` (separator) + `sh` (spawn shell)

After vfprintf mods: bytes 0..5 unchanged → `system(" :;sh")` → `/bin/sh -c " :;sh"` → strip leading space → `:;sh` → shell.

**Why `:;sh`:**
- bash refuses leading `;` as syntax error. `:;sh` is fine because `:` is the bash null builtin.
- "sh" as first token has byte0 = 's' (0x73) which has bit1=1 → UNBUFFERED would be set → buffered_vfprintf would bypass our hijack. Cannot use bare "sh" in _flags.
- `:` (0x3a) byte1 satisfies all post-mod constraints without further encoding.

## Other candidate pre-images (with caveats)

| Pre-image (bytes) | Post-mod | Result |
|-------------------|----------|--------|
| `" sh\0"` (0x20 0x73 0x68 0x00) | `" zh\0"` (byte1 0x73→0x7A because bit0 cleared, bit3 set) | `sh: 1: zh: not found` — sh exits |
| `" h;sh\0"` (0x20 0x68 0x3b 0x73 0x68 0x00) | unchanged (byte1 0x68 has bit0=0, bit3=1) | `sh: 1: h: not found` then `sh` runs — works but noisy |
| `"$0\0"` (0x24 0x30 0x00 0x00) | `"$8\0"` (0x30→0x38, byte1 bit3 set) | bash errors on `$8` (positional arg) |

## Lock target (`stdout._lock`)

The lock pointer must point to writable memory whose first 4 bytes are 0 (unlocked recursive mutex). Common choices:
- A heap region you already zero-filled (e.g., your DTV-poison Create's zero-fill area)
- `libc + (some always-zero BSS slot)` — verify with arb_read first

A pthread recursive lock struct is 16 bytes (lock:i32, cnt:i32, owner:u64). Initial zero state allows the first `__libc_lock_lock_recursive` to succeed; same-thread reentrance increments `cnt` without contention.

## Verifying the trigger fires once

After your 4 stdout writes (flags, lock, _wide_data, _vtable), do NOT `wait_idle` on the 4th write — the menu redraw after the worker's plugin_process is what fires HOA2, and `[Worker: idle]` will never print because `system()` blocks before reaching that printf. Send your shell commands after a short `time.sleep`.

## Trigger flow (glibc 2.39)

```
vfprintf → outchar → write_ptr >= write_end → __overflow
  = stdout._vtable->__overflow = _IO_wfile_overflow
  → _IO_wdoallocbuf (because _wide_data->_IO_write_base == 0)
  → fake_wd._wide_vtable->__doallocate(stdout)
  = system(stdout)
  → /bin/sh -c " :;sh"
  → shell waits on stdin
```
