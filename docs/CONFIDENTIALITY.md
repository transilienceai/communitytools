# Confidentiality — what may never enter this repository

**This repository is public.** It holds reusable security-testing scaffolding: skills,
workflows, tools, formats. Client and engagement material lives under `projects/`, which is
excluded by a fail-closed `.gitignore` in every subtree.

This file is the single canonical home for that rule. Other documents link here; none restate
it.

## The boundary

Only `projects/` may reference a real customer or engagement. Everything else — `skills/`,
`tools/`, `formats/`, `docs/`, `scripts/`, `.claude/`, `benchmarks/`, root documents — must be
free of:

| Class | Examples |
|---|---|
| Customer identity | company or brand names, people's names, postal addresses, phone numbers, customer email domains |
| Engagement identity | engagement directory names (`<tree>/<YYYYMMDD>_<slug>`), finding ids minted inside one (`fNN_<name>.py`, `F-SWEEP-*`) |
| Target identity | real hostnames, routable public IPs, internal hostnames, SAP SIDs |
| Credentials | keys, tokens, certificates, VPN profiles, password material |
| Operator identity | absolute home paths (`/Users/<n>/`, `/home/<n>/`, `C:\Users\<n>\`), including inside symlink targets |
| Deliverables | client reports and workbooks in any binary format |

Use placeholders instead: `acme` / `example.com` for names and domains, RFC 5737
(`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) for addresses, RFC 1918 for internal ones. Public
training targets (OWASP Juice Shop, HTB, XBOW/XBEN, DVWA, PortSwigger labs) and our own
`transilience.ai` branding are fine — they identify nobody's customer.

Write about the **class** of issue, never the customer: *"a recurring mobile re-test crux"*,
not a client's name.

## The customer roster is never committed

`scripts/check_client_data.py` matches client names against **salted SHA-256 digests**, never
plaintext. The digest file is generated locally by `scripts/gen_denylist.py`, read from
`$CLIENT_DENYLIST` (default `~/.config/transilience/client-denylist.sha256`), and supplied to
CI as the `CLIENT_DENYLIST_B64` secret. A committed roster would itself be the disclosure, so
the guard reports the *location* of a name match and never echoes the term — a failing CI log
is public too.

When the digest file is absent the term lane is skipped and every other lane still runs.

## What is enforced, and where

`scripts/check_client_data.py` runs over the whole publishable universe: tracked files **plus**
untracked-not-ignored ones, because the latter is what the next commit would publish.

- **Symlinks** are read from the git blob, never followed. A symlink target is ordinary
  published content; an absolute one exposes a local filesystem path.
- **Binaries** are pinned by sha256 in `scripts/content-guard-binaries.json`. No text lane can
  read them, so the guarantee is *unchanged since a human reviewed it* — not *inspected*. A new
  or modified binary blocks until reviewed.
- **Coverage** is provable: `--manifest` writes one entry per publishable path, each either
  scanned or carrying an explicit reason it was not. Its set equality against git is asserted
  in the tests, so "every file, every folder" is checkable rather than claimed.

| Seam | Scope | Bypassable |
|---|---|---|
| `.githooks/pre-commit` | staged content | yes (`--no-verify`) |
| `.githooks/pre-push` | whole tree | yes (`--no-verify`) |
| `.github/workflows/content-guards.yml` | whole tree, **no path filter** | no |

Enable the hooks once per clone: `git config core.hooksPath .githooks`

**CI is the control, not the hooks.** `--no-verify` cannot be removed client-side, so the local
hooks exist to catch the *accident* — a pasted path, a `git add -A` sweep. Content-guards must
be a required status check on `main`; if that protection is ever removed, the hooks alone are
not a control.

## What this cannot guarantee

Stated plainly, because a guard that is trusted beyond its reach is worse than none:

- **An unlisted name is just a word.** A customer never engaged locally has no digest.
- **Paraphrase defeats every pattern.** A description with no proper noun can still identify a
  customer completely to anyone in the industry. Only a reader catches that.
- **Person names are not a regular language.** Only labelled forms (`Contact:`, `Prepared by:`)
  and email-derived names are detected.
- **Binaries are pinned, not read.**
- **History is detectable, not retractable.** Removing something already pushed requires
  rewriting history and force-pushing, and anything already cloned, forked, or cached is gone
  regardless. Treat a history finding as an incident: rotate any exposed credential first.

## If something did leak

1. Rotate any exposed credential immediately — assume it is compromised.
2. Fix forward on a branch; do not amend published history casually.
3. For a genuine disclosure, decide with the customer whether history rewriting
   (`git filter-repo` + force-push + cache purge) is warranted. It breaks every clone and does
   not recall what was already fetched.
4. Add the missed class as a rule with a test, so the same shape cannot return.

## Adding or relaxing a rule

Every rule needs a test in `scripts/test_check_client_data.py`: a synthetic true positive
(invented names, RFC 5737 addresses — a fixture must never be borrowed from a real engagement)
and, if it risks noise, entries in the false-positive corpus.

`test_current_tree_noise_floor` asserts the guard stays clean on the real tree. It is the
anti-rot device: a rule that fires on legitimate content fails this test and must be narrowed
or dropped. A guard people learn to bypass protects nothing — precision is a feature, not a
nicety.
