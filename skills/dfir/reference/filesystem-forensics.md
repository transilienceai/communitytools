# Filesystem Forensics

## MFT Analysis

The Master File Table ($MFT) records metadata for every file on an NTFS volume.

### Parsing with analyzeMFT

```bash
pip install analyzeMFT
analyzeMFT -f '$MFT' -o mft_output.csv
```

### Finding Dumped Files

Search for recently created sensitive files:
```bash
# Search for ntds.dit, SYSTEM hive, SAM, or other dump artifacts
grep -ai "ntds\.dit\|SYSTEM\|SAM\|\.dit" mft_output.csv | grep "2024-" | head
```

### Path Reconstruction

MFT records reference parent directories by record number. Trace the full path:

```python
import csv

records = {}
with open('mft_output.csv', 'r', errors='replace') as f:
    reader = csv.reader(f)
    header = next(reader)
    for row in reader:
        if row:
            records[row[0]] = row  # Key: Record Number

def get_path(record_num):
    path = []
    current = record_num
    seen = set()
    while current in records and current not in seen:
        seen.add(current)
        rec = records[current]
        path.append(rec[7])           # Filename (column 7)
        current = rec[5]              # Parent Record Number (column 5)
    path.reverse()
    return 'C:\\' + '\\'.join(path)
```

### File Size from Raw MFT

When `analyzeMFT` reports `content_size=None` (non-resident data), read directly:

```python
import struct

with open('$MFT', 'rb') as f:
    f.seek(record_number * 1024)  # Each MFT record = 1024 bytes
    data = f.read(1024)

    offset = struct.unpack_from('<H', data, 20)[0]  # First attribute offset
    while offset < len(data) - 4:
        attr_type = struct.unpack_from('<I', data, offset)[0]
        if attr_type == 0xFFFFFFFF: break
        attr_len = struct.unpack_from('<I', data, offset + 4)[0]
        if attr_len == 0: break

        if attr_type == 0x80:  # $DATA attribute
            if data[offset + 8]:  # Non-resident flag
                real_size = struct.unpack_from('<Q', data, offset + 48)[0]
                # real_size = actual file size in bytes
        offset += attr_len
```

### Key Timestamps

MFT stores 4 timestamps per file (in both $STANDARD_INFORMATION and $FILE_NAME):
- **Created** (column 9 in analyzeMFT CSV)
- **Modified** (column 10)
- **MFT Modified** (column 11)
- **Accessed** (column 12)

**SI vs FN timestamps**: $STANDARD_INFORMATION timestamps can be tampered. $FILE_NAME timestamps (columns 13-16) are harder to forge — compare both for timestomping detection.

## Windows Prefetch Analysis

Prefetch files record program execution history. Located at `C:\Windows\prefetch\`.

### File Naming

`PROGRAM.EXE-HASHVALUE.pf` — hash is based on the executable path.

### Win10 Decompression

Win10 prefetch uses MAM compression (header: `MAM\x04`):

```python
import struct
from dissect.util.compression import lzxpress_huffman

with open('PROGRAM.EXE-HASH.pf', 'rb') as f:
    data = f.read()

if data[:4] == b'MAM\x04':
    decomp_size = struct.unpack_from('<I', data, 4)[0]
    decompressed = lzxpress_huffman.decompress(data[8:])
```

### Extracting Execution Times and File References

From decompressed prefetch v30 (Win10):
```python
import re, struct, datetime

# Last run timestamps: offset 80, up to 8 entries of 8 bytes each
epoch = datetime.datetime(1601, 1, 1)
for i in range(8):
    ts = struct.unpack_from('<Q', decompressed, 80 + i*8)[0]
    if ts > 0:
        dt = epoch + datetime.timedelta(microseconds=ts // 10)
        if 2000 < dt.year < 2030:
            print(f"Run time: {dt}")

# Run count at offset 200
run_count = struct.unpack_from('<I', decompressed, 200)[0]

# File references (UTF-16LE strings)
for s in re.findall(b'(?:[\x20-\x7e]\x00){4,}', decompressed):
    decoded = s.decode('utf-16-le', errors='ignore')
    if '\\USERS\\' in decoded.upper() or '\\DOWNLOADS\\' in decoded.upper():
        print(f"Referenced: {decoded}")
```

**Note**: `windowsprefetch` Python library only works on Windows (needs `ctypes.windll`). Use manual binary parsing on macOS/Linux.

## VSS Artifacts

Volume Shadow Copy creates snapshots visible as `\Device\HarddiskVolumeShadowCopy<N>`.

- **Volume GUID**: Found in NTFS operational log — `\\?\Volume{GUID}` associated with the shadow copy device
- **Snapshot path**: `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\<path>` — visible in ESENT Event 216/330
- **ntdsutil snapshot mount**: Creates `C:\$SNAP_<timestamp>_VOLUMEC$\` mount point
