# DTV Poisoning via Worker Thread UAF → Arbitrary R/W

**When to use:** Multi-threaded binary with a worker thread that calls dlopen'd plugin functions via TLS (`__tls_get_addr`). UAF or controlled heap write on the main heap. glibc 2.34+ where `__free_hook`/`__malloc_hook` are removed and traditional `house of ...` techniques are blocked.

**Why it works:**
- `pthread_create` runs in the **main thread**, so `_dl_allocate_tls` uses **main arena's allocator** — the worker's DTV chunk lands on the **main heap**.
- Each thread has its own `dtv_t *dtv` (stored in TCB at `%fs:0x8`). For module N (libplugin loaded via dlopen), `dtv[N].pointer.val` is the per-thread TLS block address.
- `__tls_get_addr({modid=N, offset=0})` returns `dtv[N].pointer.val + 0` after a fast-path check that `dtv[0].counter == GL(dl_tls_generation)`.
- Overwriting `dtv[N].pointer.val` with an attacker-chosen address makes every `__tls_get_addr` for module N return that address. If `plugin_process(src, n)` does `memcpy(__tls_get_addr(N), src, n)` then you get **arbitrary write of n bytes** to anywhere. If `plugin_read(dst, n)` does `memcpy(dst, __tls_get_addr(N), n)` then you get **arbitrary read of n bytes** from anywhere.

## Locating the DTV chunk on main heap

DTV is allocated by `_dl_allocate_tls` → `calloc(dtv_length, sizeof(dtv_t))`. Layout (glibc 2.39, x86_64):

```
chunk header (16 bytes)
[user pointer +0x00]: dtv[-1].counter = dtv array length (e.g. 0x10)
[user pointer +0x10]: dtv[0].counter  = dl_tls_generation (typically 2 after a single dlopen)
[user pointer +0x20]: dtv[1].pointer.val = libc TLS image
[user pointer +0x30]: dtv[2].pointer.val = libplugin TLS (UNALLOCATED=0xff..f initially)
...
```

Note `_dl_resize_dtv` returns `&newp[1]` (16 bytes into the calloc'd buffer), so the user pointer is at the start of `dtv[-1]`.

**Empirical location:** dump heap chunks (via tcache poison + view) around `heap_base + 0x100..0x300`. DTV is a small chunk (`0x70-0x130`) whose user payload looks like:
- offset 0: small int (dtv length, often 0x10)
- offset 0x10: small int (generation counter, typically 1-3)
- offsets 0x20, 0x30, ...: pointers (TLS image addresses) and `0xffff...ffff` sentinels

In gdb: `set $dtv = *(unsigned long*)($fs_base + 8); x/24gx $dtv - 0x10` shows the chunk.

## Corrupting only `dtv[N].pointer.val`

The challenge: tcache poison + Create zero-fills 0x100 bytes at the target. You **must** choose a target that does NOT zero out:
- `dtv[-1].counter` (or _dl_resize_dtv may be triggered when reading the modified DTV)
- `dtv[0].counter` (mismatch with `GL(dl_tls_generation)` triggers `update_get_addr` which may abort)
- `dtv[1].pointer.val` (the calling thread's libc TLS — destroys errno, locale, anything libc TLS-backed)

**Working choice for libplugin = modid 2:** target = `heap_base + 0x230` exactly. Zero-fill covers `dtv[2..0x10]` only. Edit 8 bytes at offset 0 of the slot to set `dtv[2].pointer.val`. `dtv[1]` (libc) and `dtv[0]` (counter) are preserved.

## End-to-end skeleton

```python
# After heap leak + libc leak via the worker-tcache-fill technique:
DTV_TARGET = heap_base + 0x230
poison = (some_freed_chunk_addr >> 12) ^ DTV_TARGET
edit(some_dangling_slot, 8, p64(poison))   # poison the freed chunk's FD
create()    # pop freed chunk
create()    # pop DTV_TARGET → slot.data = DTV_TARGET. Zero-fills 0x230..0x330.

def set_dtv(target):
    edit(dtv_slot, 8, p64(target))         # sets dtv[2].pointer.val

def arb_read(target):
    set_dtv(target)
    return read_plugin_state()             # case-6 in many designs → returns 32 bytes from target

def arb_write(target, data32):
    edit(source_slot, 32, data32)          # source slot.data is the chunk worker plugin_process reads from
    set_dtv(target)
    process_(source_slot)                  # case-5 worker → memcpy(target, source.data, 32)
```

**Source slot must stay alive across multiple writes.** If the worker frees `source_slot`'s chunk on each `process_`, you burn the slot after one write. Solution: keep `source_slot.refcount == 1` so `main: refcount++ (1→2), worker: refcount-- (2→1), no free`. Achieved by NOT calling `delete()` on the source slot before the writes.

## Constraints to verify before exploiting

- `dl_tls_generation` matches `dtv[0].counter` after the dlopen (no further dlopens in the binary's main loop).
- libplugin's modid (usually 2 if only one user `dlopen` happened, but verify in gdb: `p ((tcbhead_t*)$fs_base)->dtv[2].pointer.val` should be UNALLOCATED before the worker's first `__tls_get_addr`, then a real TLS pointer after).
- `plugin_process` and `plugin_read` clamp size to the TLS block size (here 0x20). Use multiple calls if you need >32 bytes contiguous.

## Combine with: House of Apple 2 trigger

Once you have arbitrary R/W on libc:
- Read `__environ` → main stack pointer.
- Overwrite `_IO_2_1_stdout_` fields (`_flags`, `_lock`, `_wide_data`, `_vtable`) for FSOP. See [`fsop-house-of-apple-2-vfprintf-flag-mods.md`](fsop-house-of-apple-2-vfprintf-flag-mods.md) for the byte-bit-level adjustments needed because `vfprintf` modifies `_flags` (`|= CURRENTLY_PUTTING (0x800)`, `&= ~USER_BUF (0x1)`, `&= ~IN_BACKUP (0x100)`) before your shell command in `_flags` is parsed by `system()`.

## Worked example

HTB Pwn challenge "Threadweaver" (2026-05): exact constants: DTV at `heap_base + 0x200..0x300`, modid=2, `dtv[2].pointer.val` at `heap_base + 0x230`, `dtv[1].pointer.val` at `heap_base + 0x220` (do not clobber). Confirmed working on glibc 2.39 (Ubuntu 24.04). Full exploit: [`projects/ctf/260515_threadweaver/artifacts/pwn_threadweaver/exploit4.py`](../../../../projects/ctf/260515_threadweaver/artifacts/pwn_threadweaver/exploit4.py).
