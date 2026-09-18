# ffuf Cheatsheet

A reference for `ffuf` (Fuzz Faster U Fool) — fast web fuzzer for content discovery, vhost discovery, parameter discovery, and more.

---

## 1. Basic Syntax

The `FUZZ` keyword marks the injection point — it can go anywhere in the URL, headers, or POST body.

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ
```

**Core required flags:**

|Flag|Purpose|
|---|---|
|`-w`|Wordlist path (can specify multiple, see §7)|
|`-u`|Target URL, with `FUZZ` marking the injection point|

---

## 2. Directory / File Discovery

```bash
# Basic directory brute force
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u https://target.com/FUZZ

# With file extensions
ffuf -w wordlist.txt -u https://target.com/FUZZ -e .php,.html,.txt,.bak,.zip

# Recursive discovery (auto-fuzz found directories)
ffuf -w wordlist.txt -u https://target.com/FUZZ -recursion -recursion-depth 2

# Specific file extension fuzzing appended to found dirs
ffuf -w wordlist.txt -u https://target.com/FUZZ.php
```

---

## 3. Filtering & Matching Results

This is where ffuf gets useful — cutting noise so real hits stand out.

|Flag|Meaning|
|---|---|
|`-fc`|Filter by HTTP status code(s)|
|`-fs`|Filter by response size|
|`-fw`|Filter by word count|
|`-fl`|Filter by line count|
|`-ft`|Filter by response time (ms)|
|`-mc`|Match status code(s) (default: 200-299,301,302,307,401,403,405)|
|`-ms`|Match response size|
|`-mw`|Match word count|
|`-ml`|Match line count|
|`-mt`|Match response time|

```bash
# Hide 404s explicitly (usually automatic, but useful for soft-404s returning 200)
ffuf -w wordlist.txt -u https://target.com/FUZZ -fc 404

# Filter out a specific response size (common for a "not found" page returning 200)
ffuf -w wordlist.txt -u https://target.com/FUZZ -fs 4242

# Filter by word count
ffuf -w wordlist.txt -u https://target.com/FUZZ -fw 18

# Only show 200 and 403
ffuf -w wordlist.txt -u https://target.com/FUZZ -mc 200,403

# Combine filters (AND logic between different flag types)
ffuf -w wordlist.txt -u https://target.com/FUZZ -fc 404 -fs 0
```

**Auto-calibration** (lets ffuf learn the "not found" baseline automatically):

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac
```

---

## 4. Virtual Host (Subdomain) Discovery

Fuzz the `Host` header instead of the URL path.

```bash
ffuf -w subdomains.txt -u https://target.com -H "Host: FUZZ.target.com" -fs 1234
```

Or for subdomain enumeration via DNS-style resolution differences, filter on response size since default vhosts often return a fixed-size page.

---

## 5. Parameter Discovery

**GET parameter names:**

```bash
ffuf -w params.txt -u "https://target.com/page.php?FUZZ=test" -fs 4242
```

**GET parameter values (once param name is known):**

```bash
ffuf -w values.txt -u "https://target.com/page.php?id=FUZZ"
```

**POST parameter discovery:**

```bash
ffuf -w params.txt -u https://target.com/login \
  -X POST \
  -d "FUZZ=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fc 400
```

---

## 6. POST Data / Body Fuzzing

```bash
ffuf -w wordlist.txt -u https://target.com/login \
  -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fc 401

# JSON body fuzzing
ffuf -w wordlist.txt -u https://target.com/api/login \
  -X POST \
  -d '{"username":"admin","password":"FUZZ"}' \
  -H "Content-Type: application/json" \
  -fc 401
```

---

## 7. Multiple Wordlists / Fuzzing Positions

Use named FUZZ keywords for multiple simultaneous positions (clusterbomb-style by default).

```bash
ffuf -w users.txt:FUZZ1 -w passwords.txt:FUZZ2 \
  -u https://target.com/login \
  -X POST -d "username=FUZZ1&password=FUZZ2" \
  -fc 401

# Pitchfork mode (pairs wordlists by line index instead of all combinations)
ffuf -w users.txt:FUZZ1 -w passwords.txt:FUZZ2 -mode pitchfork \
  -u https://target.com/login \
  -X POST -d "username=FUZZ1&password=FUZZ2"
```

---

## 8. Headers & Cookies

```bash
# Fuzz a header value
ffuf -w wordlist.txt -u https://target.com/ -H "X-Custom-Header: FUZZ"

# Fuzz User-Agent
ffuf -w wordlist.txt -u https://target.com/ -H "User-Agent: FUZZ"

# Fuzz a cookie value
ffuf -w wordlist.txt -u https://target.com/ -H "Cookie: session=FUZZ"

# Auth bypass testing on headers (e.g. X-Forwarded-For)
ffuf -w wordlist.txt -u https://target.com/admin -H "X-Forwarded-For: FUZZ"
```

---

## 9. Rate Limiting, Threads & Delays

Important for not tripping IDS/rate-limits (or DoSing your own lab boxes).

|Flag|Purpose|
|---|---|
|`-t`|Number of concurrent threads (default 40)|
|`-rate`|Max requests per second|
|`-p`|Delay between requests, e.g. `-p 0.1-0.5` (random range)|
|`-timeout`|Per-request timeout in seconds|
|`-maxtime`|Max total run time in seconds|
|`-maxtime-job`|Max time per fuzzing job (with recursion)|

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -t 20 -rate 50 -p 0.1-0.3
```

---

## 10. Output Formats

```bash
# JSON output
ffuf -w wordlist.txt -u https://target.com/FUZZ -o results.json -of json

# HTML report
ffuf -w wordlist.txt -u https://target.com/FUZZ -o results.html -of html

# CSV, Markdown also supported
ffuf -w wordlist.txt -u https://target.com/FUZZ -o results.csv -of csv
ffuf -w wordlist.txt -u https://target.com/FUZZ -o results.md -of md

# All formats at once
ffuf -w wordlist.txt -u https://target.com/FUZZ -o results -of all
```

---

## 11. Useful Extras

|Flag|Purpose|
|---|---|
|`-c`|Colorized output|
|`-v`|Verbose output (full URLs, headers)|
|`-s`|Silent mode (only results, good for piping)|
|`-se`|Silent mode but still show errors|
|`-x`|Proxy requests, e.g. `-x http://127.0.0.1:8080` (Burp)|
|`-r`|Follow redirects|
|`-recursion`|Recurse into discovered directories|
|`-recursion-depth`|Limit recursion depth|
|`-ic`|Ignore wordlist comments|
|`-D`|DirSearch-style wordlist mode (auto-appends extensions)|
|`-request`|Load a raw HTTP request file (e.g. from Burp) as the base request|
|`-request-proto`|Protocol for `-request` file (http/https)|

**Load a raw request captured from Burp Suite:**

```bash
ffuf -request request.txt -request-proto https -w wordlist.txt
```

(Mark the injection point with `FUZZ` inside the saved raw request file itself.)

**Route through Burp for manual review while fuzzing:**

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -x http://127.0.0.1:8080
```

---

## 12. Combining with Recon Workflow

Fits naturally ahead of or alongside gobuster/nikto in a recon chain:

```bash
# Quick triage: find live dirs first, low noise
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u https://target.com/FUZZ -mc 200,301,302,403 -t 50 -s -o quick_dirs.txt

# Then deeper recursive pass on what's found
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -u https://target.com/FUZZ -recursion -recursion-depth 2 -e .php,.bak,.old \
  -fc 404 -ac -o full_scan.json -of json
```

---

## 13. Quick Reference — Command Skeleton

```
ffuf -w WORDLIST -u URL_WITH_FUZZ \
  -mc STATUS_CODES \
  -fc FILTER_CODES -fs FILTER_SIZE -fw FILTER_WORDS \
  -t THREADS -rate RATE \
  -H "Header: value" \
  -X METHOD -d "BODY_WITH_FUZZ" \
  -o OUTPUT_FILE -of FORMAT \
  -recursion -recursion-depth N \
  -x PROXY
```

---

**Note:** Only fuzz targets you own or are explicitly authorized to test — CTF boxes, your own lab environment (e.g. DVWA), or scoped engagements. Aggressive fuzzing against third-party infrastructure without authorization is illegal under laws like the CFAA.
