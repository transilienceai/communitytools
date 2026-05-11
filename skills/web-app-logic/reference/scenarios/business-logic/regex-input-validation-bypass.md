# Regex Input Validation Bypass for Command Injection

## When this applies

- Server filters user input via regex (e.g., `^[^;/\&.<>]*$`) to block dangerous characters.
- Filter is incomplete — misses one or more shell metacharacters.
- Backend uses `subprocess.run(cmd, shell=True)` or `os.system()` with the filtered value.

## Technique

Identify which characters are NOT in the deny list. Combine remaining shell features (pipe, backticks, `$()`, newlines, octal/base64 encoding) to assemble payloads despite missing chars.

## Steps

**Common oversights:**
- Blocks `;`, `$`, `&`, `.`, `<`, `>` but allows `|` (pipe) or backticks
- Check the character class: `^[^;/\&.<>]*$` — identify what is NOT blocked
- Test in order: `|cmd`, `` `cmd` ``, `$(cmd)`, `\n`, `\r`, tab (`%09`), unicode equivalents

**Bypassing `/` restriction (can't type paths):**
```bash
# Octal encoding via printf subshell
$(printf "\057tmp\057script")      # produces /tmp/script
$(printf "\057etc\057passwd")       # produces /etc/passwd
```

**Bypassing character restrictions with shell features:**
```bash
# If $() is allowed but / is blocked:
$(printf '\057')                    # slash via octal
# If backticks allowed:
`echo L2V0Yy9wYXNzd2Q= | base64 -d`  # base64-decoded path
```

**Key indicator:** If `subprocess.run(cmd, shell=True)` or `os.system()` is used server-side, ANY unfiltered shell metacharacter leads to RCE. Always test the full set: `|`, `` ` ``, `$()`, `\n`, `%0a`, `%09`, `||`, `&&`.

## Verifying success

- Output of an injected command (e.g., `id`, `whoami`) appears in the response, error, or out-of-band channel.
- Octal/base64-decoded path traversal succeeds when raw `/` was blocked.
- Time-based payload (`sleep 5`) measurably delays response.

## Common pitfalls

- Some filters strip rather than reject — check whether the input is rejected with an error or silently sanitized.
- Regex filters often run on a single field; chained fields may concatenate before execution — inject into both halves.
- Backslash, ANSI-C `$'...'`, and `${IFS}` substitutions can recover spaces if `\s` is blocked.

## Tools

- Burp Suite Repeater
- ffuf with custom wordlist of metacharacter combinations
- commix (automated)
