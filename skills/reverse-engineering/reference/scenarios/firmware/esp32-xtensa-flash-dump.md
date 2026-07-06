# ESP32 / Xtensa Firmware Flash-Dump RE

## When this applies

- A delivered artifact is a multi-MB binary blob (commonly 4 MB) that `binwalk`/`strings` shows is built with ESP-IDF: tags like `boot`, `esp_image`, `phy_init`, `nvs`, partition labels (`factory`, `ota_0`), and ESP-IDF version strings.
- `file` reports `data`; the blob starts with byte `0xE9` (ESP image magic) at offset `0x1000`.
- The flag is **generated at runtime** (no literal `flag{`/`HTB{` in the image) and is gated behind a hardware/anti-clone check — strings such as "cloned hardware", "did not generate correctly", or an explicit "try to emulate it" hint.
- Target arch is **Xtensa LX6** (windowed ABI), not ARM/MIPS — r2/capstone disassembly is unreliable here.

## Technique

Two complementary paths. **Emulate first** when the firmware hints at anti-clone/anti-emulation behaviour (the device prints the flag itself once its HW gate passes) — lowest friction, self-validating. Fall back to **static decode** when emulation is blocked, the gate rejects default eFuses, or you need to explain *why* the flag is what it is. Run both as one recon batch when time allows — agreement between the UART print and a re-derived transform is the strongest validation.

## Steps

### 1. Triage the flash layout

ESP-IDF flash dumps follow a fixed map. Verify the magic bytes before trusting any tool:

| Offset | Content | Magic |
|---|---|---|
| `0x1000` | 2nd-stage bootloader (`esp_image`) | `0xE9` |
| `0x8000` | partition table | `0xAA 0x50` (`0x50AA` LE) |
| `0x9000` | NVS data (often empty `0xFF` — secrets usually NOT here) | — |
| `0x10000` | `factory` app image (the code you want) | `0xE9` |

```bash
pip install esptool                       # v5+: subcommands use hyphens
esptool --chip esp32 image-info firmware.bin            # whole-flash header
esptool --chip esp32 image-info --version 2 firmware.bin
# carve the factory app, then inspect its segments + load addrs:
dd if=firmware.bin of=app.bin bs=1 skip=$((0x10000)) count=$((0x100000))
esptool --chip esp32 image-info app.bin   # lists segments: IROM/DROM load VMAs + file offsets
```

Record each segment's **load VMA** and **file offset** — the IROM segment (load VMA in the `0x400d_xxxx` range) holds the flag-generation code; the DROM segment (`0x3f40_xxxx`) holds its constants/ciphertext.

### 2. EMULATE — Espressif QEMU fork (primary path)

Stock `qemu-system-xtensa` (Homebrew/apt) has **no `esp32` machine** — you must use the Espressif fork.

```bash
# fetch a prebuilt release (no build needed):
gh release download --repo espressif/qemu <release-tag> \
  --pattern 'qemu-xtensa-softmmu-*-aarch64-apple-darwin.tar.xz'   # match your host triple
tar xf qemu-xtensa-softmmu-*.tar.xz
xattr -dr com.apple.quarantine qemu/                              # macOS Gatekeeper — required

# boot the whole 4 MB flash as an MTD device; capture UART to a file:
gtimeout 45 qemu/bin/qemu-system-xtensa -nographic -machine esp32 \
  -drive file=firmware.bin,if=mtd,format=raw \
  -serial file:uart.log -monitor none
grep -aE 'flag|HTB\{|FLAG\{' uart.log        # flag usually within ~1-2 s guest time
```

- QEMU's **default emulated eFuses** (incl. factory MAC) satisfy most anti-clone gates → no crafted eFuse needed. Try defaults first.
- Only if the gate rejects defaults: supply `-drive file=efuse.bin,if=...` / `efuse_file=` matching the value the gate expects (often all-zero MAC, or a specific MAC the code compares against — recover the expected value from step 3 first).
- Boot the **full flash** image (bootloader at `0x1000` chains to the app), not the carved `app.bin`.

### 3. STATIC decode — Xtensa disassembly (fallback / corroboration)

r2/capstone mis-decode the windowed ABI. Use Espressif's GNU toolchain:

```bash
# xtensa-esp32-elf-objdump ships in the espressif/idf docker image:
docker run --rm -v "$PWD":/w -w /w espressif/idf:latest \
  xtensa-esp32-elf-objdump -D -b binary -m xtensa \
  --adjust-vma=0x400d0020 irom.bin > irom.asm      # VMA = IROM segment load addr from step 1
```

Carve the IROM segment to `irom.bin` using the file offset + length from `image-info`, then disassemble at its load VMA. To find the flag function:

- Locate the literal pool referenced by the print/log strings (the DROM ciphertext address and the format strings live in adjacent literal pools).
- Scan IROM for `l32r` instructions whose backward PC-relative target lands in that known literal pool — those are the functions loading the flag constants. The flag routine's *code* often lives far from its *literal pool*; the `l32r` cross-reference bridges them.
- Wrapping the carved IROM into a minimal ELF at the load VMA lets Ghidra/objdump resolve symbols and cross-references cleanly.

### 4. Recognise the transform (pattern lesson)

ESP32 "hardware-locked" flags are usually a **gate + trivial obfuscation**, not keyed crypto:

- The HW check (reads eFuse factory MAC via an IDF helper, `memcmp` against a constant) typically only decides **whether to print** the flag — it does **not** feed the flag derivation.
- The flag itself is commonly an embedded ciphertext in DROM decoded by a constant-XOR loop (`out[i] = ct[i] ^ K`) or a short additive/rotate transform. Check for an embedded blob near the print strings + a tight decode loop **before** assuming SHA/HMAC.
- Distinguish real flag logic from ESP-IDF noise: "Calculated hash"/"Expected hash" strings are the **bootloader image-verification** (`bootloader_sha.c`), unrelated to the flag.

```python
# typical decode once the constant + ciphertext offset are known:
ct = open("firmware.bin","rb").read()[0x17688:0x17688+31]   # DROM file offset, length
print(bytes(b ^ 0x42 for b in ct).decode())
```

## Validation

- **Two independent paths agree** — the UART print (step 2) and the re-derived transform output (steps 3-4) produce the identical string. A device-side print is self-validating; a static re-derivation explains it.

## Tooling notes

- `esptool` v5 renamed subcommands to hyphenated form (`image-info`, not `image_info`).
- Match the Espressif QEMU release asset to your host triple (`aarch64-apple-darwin`, `x86_64-linux-gnu`, …).
- `xtensa-esp32-elf-objdump` via `espressif/idf` docker avoids installing the full toolchain locally.
