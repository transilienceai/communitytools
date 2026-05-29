# glibc 2.32+ Tcache Info Leak via Small-Chunk Overlap

**Scenario**: Heap exploitation with bounded read primitive (length-confusion or similar) that lands inside `tcache_perthread_struct` (heap_base+0x10..+0x290). Need heap-base leak. Traditional approach reads `tcache->entries[bin_idx]` for a populated bin, but the readable bins (typically 46..62) are too large to populate (request capped at ~0x1FF).

## Source pattern

```c
// Pseudo-code: a function with arbitrary-read at attacker-controlled offset
//              within heap_base+0x200..+0x300 area, max 0x100 bytes.

void leak() {
    // Read at heap_base+0x200..+0x2FE only covers tcache entries[46..63].
    // Those bins are for chunk_size 0x300..0x420.
    // App's max malloc is 0x1FF → max chunk_size 0x210 → max bin 31.
    // So entries[46..63] never populated → all zeros.
}
```

The naive conclusion is: no leak possible. **Wrong.** The trick is to OVERLAP the read window with a freed CHUNK's user-data, not with tcache entries.

## Working technique

```
1. Create chunk0 SMALL (size 0x20, request 0x10). spells[0] = heap_base+0x2A0.
2. Create chunk1 LARGE for length-locking (size 0x110, request 0xFE).
   spells[1] = heap_base+0x2C0.
3. set_fav(1) → super_spell_set=1, super_spell_len=0xFE (locked).
4. remove(0) → chunk0 enters tcache bin 0.
   chunk0_user[0..7] now = safe-linked NULL = (heap_base+0x2A0) >> 12 = heap_base>>12.
5. memset_spells1 (mn[1]=mn[3]=0) → spells[1]_LSB = 0 → spells[1] = heap_base+0x200.
6. Re-trigger set_fav (else branch) → super_spell = heap_base+0x200, super_spell_len = 0xFE.
7. read_spell → prints 0xFE bytes from heap_base+0x200.
   At byte offset 0xA0 of the read: heap_base+0x2A0 = freed chunk0's user data.
   First 8 bytes = safe-linked fd = heap_base >> 12.
8. heap_base = leaked_value << 12.
```

## Why this works

- The read window (0xFE bytes from heap_base+0x200) extends from heap_base+0x200 to heap_base+0x2FE.
- This crosses INTO chunk0's user data area (which starts at heap_base+0x2A0 since chunk0 is right after the tcache_perthread_struct chunk).
- A freed chunk's user_data[0..7] contains its safe-linked fd (per `tcache_put`).
- For a chunk freed into an empty bin, fd = `PROTECT_PTR(NULL, &e->next)` = `chunk_user_addr >> 12`.
- For chunk0 at heap_base+0x2A0: safe = (heap_base+0x2A0) >> 12 = heap_base >> 12 (since 0x2A0 < 0x1000).

## Chained libc leak

Once heap_base is known:

```
1. After heap leak: create N chunks of size 0x90 (bin 7), free N-1.
   (N-1 = 8: first 7 fill tcache bin 7 [counts=7]; 8th overflows to unsorted bin.)
2. The 8th-freed chunk's user_data[0..7] = unsorted_chunks(av) = &av->bins[0] - 0x10 = av + 0x80.
3. OOB-write spells[1] = heap_base + (unsorted_chunk_offset) (computable from known heap_base + layout).
4. set_fav (else) → super_spell = unsorted_chunk_user.
5. read_spell → first 8 bytes = main_arena + 0x80 = libc + main_arena_offset + 0x80.
6. libc_base = leaked - main_arena_offset - 0x80.
   (For libc 2.37-7 amd64 BuildID 072feb..25d72: main_arena_offset = 0x1d3c60.)
```

## Chained stack leak

Once libc_base is known:

```
1. OOB-write spells[1] = libc_base + 0x1db320 (environ).
2. Read → gives envp on stack.
3. Scan stack downward from envp searching for __libc_start_main_ret value (libc + 0x276ca).
4. Found at envp - 0x120 → this is main's saved RIP slot.
```

## Limitations / glibc 2.37 protections

- **tcache_put always overwrites e->next** with `safe(HEAD)`. The classic "double-free + key bypass" tcache poison technique is BROKEN: even after setting `e->key = 0` to bypass duplicate detection, the re-free `tcache_put` immediately overwrites the attacker's fd value.
- **entries[X] storage is unprotected** (no PROTECT_PTR on `tcache->entries[tc_idx] = e`). So if you can write to entries[X] directly, you control the next alloc's return. But writing to entries[X] requires an existing arbitrary-write primitive (chicken-egg).
- **House of Botcake** remains the recommended path for arbitrary write in glibc 2.32+ with the leaks above.

## Reference: HTB Magic Scrolls (Pwn, Hard, 40pts, challenge_id=634)

- Binary: `magic`, glibc 2.37-7, full RELRO + PIE + canary + NX.
- Vulnerability: power-state-controlled OOB write of `spells[0]`/`spells[1]` plus length-confusion in `set_favorite_spell` ELSE branch.
- Heap leak path: as above. Library: `glibc 2.37-7 amd64 BuildID 072feb34c63e054d60d94cbc68d92e4caad25d72`.
- Recovered leak chain: heap_base, libc_base, environ→stack, main saved RIP.
