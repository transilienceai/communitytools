---
name: protect-with-password
description: Generate ONE strong password and apply it to each referenced file (PDF, Word, Excel, PowerPoint, or any type). Use when asked to password-protect / encrypt / lock one or more deliverable files with a single password before sharing.
---

# Protect With Password

Mint a single strong password and password-protect every referenced file with it, "accordingly" per file type. Deterministic, non-destructive (originals are never touched), AES-256 or nothing.

## Run it

```
python3 tools/protect_with_password.py FILE [FILE ...] \
    [--password PW] [--length 24] [--out-dir DIR] \
    [--password-file PATH | --no-password-file]
```

- Pass every file the user referenced as positional arguments.
- By default a strong password is generated (`--password` overrides to reuse one).
- Protected copies are written alongside each input, or into `--out-dir`.
- The tool prints a JSON summary on stdout and a password banner on stderr, and (unless `--no-password-file`) writes the password to a chmod-600 `PROTECT-PASSWORD.txt`.

## How each type is protected

| File | Protection | Result |
|------|-----------|--------|
| `.pdf` | Native AES-256 (qpdf → pypdf fallback) | `<name>-protected.pdf` — recipient is prompted for the password on open |
| `.docx/.xlsx/.pptx`, `.doc/.xls/.ppt`, images, anything else | AES-256 7-Zip archive (`-mhe=on`, filenames encrypted) | `<name>.7z` — recipient extracts with the password (7-Zip / Keka / WinRAR) |

Native in-file Office (MS-OFFCRYPTO "agile") encryption needs LibreOffice or a dedicated encryptor that is not bundled here, so Office files are wrapped in a strong AES-256 archive instead. If no AES-256 tool is available for a file, it is reported as a failure — never downgraded to weak ZipCrypto/RC4 (no false assurance).

## After running

Relay the password to the user and remind them to **share it OUT-OF-BAND** — never in the same channel/email as the protected files — and to delete `PROTECT-PASSWORD.txt` once handed over. Exit code is 0 only if every file was protected; 1 if any failed (check `results[].reason`).

Related: [`tools/protect_deliverable.py`](../../tools/protect_deliverable.py) does the engagement-wide variant (one protected PDF + an AES-256 deliverable zip); this skill protects an arbitrary set of individual files.
