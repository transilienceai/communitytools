# House of Botcake — glibc 2.32+ Safe-Linking Bypass for Arbitrary Write

**Scenario**: You have heap+libc+stack leaks but can't tcache-poison because glibc 2.32+ `tcache_put` overwrites `e->next = PROTECT_PTR(&e->next, head)` on every insertion — any attacker-written `fd` is clobbered on re-free. Classic "free → write fake fd → second free → malloc to TARGET" doesn't work. You need arbitrary write to overwrite a saved RIP or hook.

## Why classic tcache poison fails on glibc 2.32+

```c
// _int_free → tcache_put
e->key = tcache_key;
e->next = PROTECT_PTR(&e->next, tcache->entries[tc_idx]);  // OVERWRITES attacker-written fd
tcache->entries[tc_idx] = e;
```

The `e->next` write happens AFTER attacker control. Old technique: free A → write fake_fd to A_user → free A again → tcache_put clobbers fake_fd. Dead.

## The House of Botcake bypass (glibc 2.37 verified)

Key insight: **don't write `fd` before re-free.** Instead, exploit `_int_free`'s loose double-free check by:
1. Putting a chunk in tcache and **also inside a merged unsorted chunk** (via backward consolidation).
2. The unsorted chunk's user-data covers the tcache chunk's `fd` slot.
3. `malloc()` from unsorted bin returns the merged chunk → `memcpy` of attacker payload writes the tcache `fd` slot WITH our crafted value AFTER tcache_put's clobber.
4. Next `malloc()` of tcache size pops the chunk, then the NEXT pop returns TARGET.

### Setup prerequisites

- Heap-base leak (e.g., via [glibc-tcache-info-leak-via-small-chunk-overlap.md](glibc-tcache-info-leak-via-small-chunk-overlap.md))
- Libc-base leak (e.g., via unsorted-bin fd, same scenario)
- An OOB-write primitive that can overwrite a `spells[i]`-style global pointer (or any pointer fed into the free path)
- A "remove" path that calls `free(spells[i])` and a "create" path that calls `malloc(N) + memcpy(buf, n)` with attacker payload

### Step-by-step

State after leak phases: tcache bin K = [c2..c8] (7 entries, FULL), c9 in unsorted bin, c10 still alive at `heap+X` immediately adjacent to c9.

```
1. remove(c10):
   - tcache bin K full → falls to _int_free slow path
   - reads PREV_INUSE of c10 header = 0 (c9 is free)
   - backward-consolidates c10 with c9 → ONE merged chunk at heap+X, size = c9.size + c10.size
   - merged chunk placed in unsorted bin
   - CRITICAL: c10's internal header at heap+X is UNTOUCHED (only c9's header at the start
     of the merged chunk is updated; c10's old prev_size at heap+X stays 0 and c10's
     old size 0x91 at heap+X+8 stays valid)

2. create(any size from tcache bin K):
   - malloc pops tcache bin K head (c8). count → 6.
   - Doesn't matter what payload; just frees a tcache slot.

3. OOB-write spells[0] = c10_user (heap+X+0x10):
   - Use the bug to alias spells[0] at the freed-but-inside-merged-chunk address.
   - spells[0] now points INSIDE the merged unsorted chunk.

4. remove(0):
   - free(c10_user). _int_free reads size from c10_user-8 = 0x91 → valid tcache size.
   - Walks tcache bin K entries → c10 is NOT in the list (was consolidated away).
   - Double-free check: reads c10_user[8..15] = e->key. If this slot was never overwritten
     to equal tcache_key (or holds attacker-controllable bytes != tcache_key), check passes.
   - tcache_put writes new key + new fd at c10_user. tcache bin K head = c10.
   - **c10 is now in tcache bin K AND inside the merged unsorted chunk simultaneously.**

5. create(size_of_merged_chunk - 0x10):
   - malloc finds tcache bin J (for the merged size) empty.
   - Falls to unsorted-bin scan. Finds merged chunk exact-size match. Returns
     user=heap+X-... (start of merged user data). Removes from unsorted bin.
   - memcpy of attacker payload covers the WHOLE merged user area, INCLUDING c10's
     fd slot at heap+X+0x10.
   - Payload byte at offset (X+0x10 - merged_user_base) =
     PROTECT_PTR(c10_addr, TARGET) = TARGET XOR (c10_addr >> 12).
   - This OVERWRITES tcache_put's clobber with our crafted fd.

6. create(size_of_tcache_bin_K):
   - malloc pops tcache bin K head = c10. Returns c10_user.
   - tcache HEAD updated to unmangle(stored_fd, c10_addr >> 12) = TARGET.
   - spells[N] = c10_user. (We don't care what we write here.)

7. create(size_of_tcache_bin_K):
   - malloc pops tcache bin K head = TARGET.
   - memcpy writes our ROP payload at TARGET.
```

### ROP payload at saved-RBP slot

If TARGET = the `saved RBP` slot of the currently-executing function (e.g., `create_spell`), the layout is:

```
[0x00..0x07]  junk           ← saved_rbp slot (popped to rbp by `leave`)
[0x08..0x0F]  pop_rdi_ret    ← saved RIP overwrite
[0x10..0x17]  &/bin/sh
[0x18..0x1F]  bare_ret       ← realigns rsp to 16 bytes for system's `movaps`
[0x20..0x27]  system
[rest..]      0x00
```

When the final create_spell finishes: `leave` sets rsp=rbp+8 then pops junk-into-rbp; `ret` pops `pop_rdi_ret` into RIP, ROP fires. **`movaps` 16-byte alignment crash mitigated by the bare_ret realigning gadget** (required on Ubuntu glibc 2.34+).

## Finding the saved RBP slot

Read `libc.environ` (libc + 0x1db320 on 2.37-7) → envp pointer on stack. Scan downward in 8-byte steps for the known value `__libc_start_main_ret` (libc + 0x276ca). That slot is main's saved RIP. The 16-byte-aligned slot just below it (envp - 0x198 in our case) is the saved RBP of the function ABOVE main — typically the function you're currently inside (`create_spell`).

## Why this works where classic tcache poison doesn't

Classic tcache poison: free → write fd → free again. `tcache_put`'s clobber happens **after** the attacker write → wins.

House of Botcake: re-free a chunk that LIVES INSIDE an unsorted chunk's user data. The `tcache_put` clobber happens DURING the re-free, but is then OVERWRITTEN by the subsequent unsorted-bin `malloc`'s `memcpy` of the attacker's payload. The tcache `fd` slot is read by the NEXT `malloc` of that size, which happens AFTER the unsorted-bin memcpy. So:

```
tcache_put clobber → unsorted memcpy OVERWRITE → tcache pop READ
                                      ↑                       ↑
                                  attacker wins here    target redirected here
```

## Double-free check bypass

The `_int_free` double-free check at glibc 2.32+:

```c
if (__glibc_unlikely(e->key == tcache_key)) {
    for (size_t i = 0; i < tcache->counts[tc_idx]; ++i)
        if (tmp == e) malloc_printerr("free(): double free detected in tcache 2");
}
```

It only walks the bin if `e->key == tcache_key`. After backward-consolidation, c10's old `e->key` slot (heap+X+0x18) is whatever the attacker last wrote there during `create(c10)` — typically attacker-controllable bytes (e.g., 'C' x 8 = 0x4343...). Unless that exactly equals the random `tcache_key`, the check is skipped entirely.

If the bug forces `e->key == tcache_key` (e.g., backward-consolidation preserves an old `tcache_key` from a previous tcache stay), you may need an additional alloc/memcpy through that slot to overwrite it before the double-free.

## References

- shellphish how2heap, `house_of_botcake.c`: https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c
- glibc 2.37 source: `malloc/malloc.c` `_int_free`, `tcache_put`, `tcache_get_n`.
- Confirmed working on HTB "Magic Scrolls" (challenge 634, glibc 2.37-7, Pwn Hard).
