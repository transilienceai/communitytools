---
name: system
description: System exploitation testing - Active Directory attacks, privilege escalation (Linux/Windows), and exploit development.
---

# System

Test system-level security including Active Directory, privilege escalation, and exploit development.

## Techniques

| Type | Key Vectors |
|------|-------------|
| **Active Directory** | Kerberoasting, AS-REP roasting, DCSync, Pass-the-Hash, Golden Ticket |
| **Privilege Escalation** | SUID/sudo abuse, kernel exploits, service misconfig, token manipulation |
| **Exploit Development** | Buffer overflow, format string, ROP chains, shellcode |

## Workflow

1. Enumerate system and domain information
2. Identify escalation paths and misconfigurations
3. Exploit with appropriate techniques
4. Demonstrate impact (domain admin, root access)
5. Document attack chain with evidence

## Reference

- `reference/system-exploitation.md` - AD attacks, privilege escalation, exploit development techniques
