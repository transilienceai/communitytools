# Cereal (10.129.28.172) — Attack Chain

## HTB Profile (synopsis)
Hard Windows. Gitea-hosted source repo → leaked JWT/encryption key in old commits → forged auth → .NET deserialization + XSS chain → reverse shell as user. SSRF + SeImpersonate (Potato) → SYSTEM.

## Services (TBD — recon in progress)

## Surface
- HTTPS: source.cereal.htb (Gitea expected)
- HTTPS: cereal.htb (main app expected)

## Theory
1. Enumerate ports → 80/443 → cert SAN reveals VHosts
2. Browse Gitea → find Cereal source repo
3. `git log` history → leak (JWT secret / key)
4. Forge admin JWT → access protected endpoints
5. Trigger .NET BinaryFormatter deserialization via XSS-stored or admin endpoint
6. Reverse shell as `sonny` → user.txt
7. Read source → SSRF in API bound to localhost
8. Use SSRF to invoke privileged endpoint OR PrintSpoofer/GodPotato (SeImpersonate)
9. SYSTEM → root.txt

## Tested
(none yet)

## Next
- Full nmap (top + UDP top 100)
- Add hosts entries: cereal.htb, source.cereal.htb
- Browse Gitea, locate repos
