# PawXssScanner

Fast reflected-XSS scanner with a bypass engine, for targets you are allowed
to test. It sends one unique marker per parameter first (probe-first), and
only parameters that reflect the marker get tested further - with payloads
picked for the exact reflection context (HTML, attribute, script, comment)
and expanded into WAF-bypass variants (case, comments, separators, event
swaps, quote swaps, and only the encodings the target provably decodes).

> Authorized testing only. Scan systems you own or have written permission
> to test.

## Installation

Prerequisites: Python 3.8 or newer, `pip`, and git. Check yours first:

```bash
python3 --version   # needs 3.8+
pip --version
```

**1. Clone and enter the project**

```bash
git clone https://github.com/Rushikesh362/PawXssScanner.git
cd PawXssScanner
```

**2. (Recommended) Use a virtual environment** so the dependency never
clashes with system packages:

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

**3. Install the one dependency**

```bash
pip install -r requirements.txt
```

**4. Verify it works**

```bash
python3 pawxss.py --help        # prints all flags
python3 tests/test_pawxss.py    # 38 offline tests, expect OK
```

**5. (Optional) Run it from anywhere**

```bash
chmod +x pawxss.py
sudo ln -s "$PWD/pawxss.py" /usr/local/bin/pawxss
pawxss -u "https://target.com/search?q=test" -p "$PWD/payloads.txt"
```

Note: `-p` defaults to `payloads.txt` in the current directory, so when
running via the symlink either `cd` into the project first or pass the full
payload path as shown above.

**Troubleshooting**

| Problem | Fix |
|---|---|
| `No module named requests` | Step 3 was skipped, or `pip` belongs to a different Python than `python3`. Re-run it as `python3 -m pip install -r requirements.txt`. |
| `can't open file 'pawxss.py'` | Wrong directory. `cd` into the cloned `PawXssScanner` folder first. |
| `payload file ... has no usable lines` | The `-p` path is wrong or the file is empty. Pass the full path to `payloads.txt`. |
| Lab uses a self-signed certificate | Test over plain HTTP instead, or add the lab CA to the system trust store. |
| Everything times out | The target may be rate-limiting you. Lower `--threads`, add `--delay 1`, raise `--timeout 30`. |

## Usage

```bash
# basic scan
python3 pawxss.py -u "https://target.com/search?q=test" -p payloads.txt

# scan with reports
python3 pawxss.py -u "https://target.com/search?q=test" --json out.json -o out.txt -v

# login-protected page, slow and polite
python3 pawxss.py -u "https://target.com/account?tab=1" \
  --cookie "session=<value>" --threads 5 --delay 0.5

# POST form
python3 pawxss.py -u "https://target.com/login" --method POST \
  -H "Authorization: Bearer <token>"

# keep a big run bounded
python3 pawxss.py -u "https://target.com/s?q=test" --max-payloads 100 --threads 10
```

## Use cases

**Bug bounty triage.** Point it at a scope URL with parameters during recon.
Probe-first means parameters that never reflect cost one request each, so a
50-parameter page is cheap to rule out and the real candidates get the full
treatment.

**Pentest evidence.** `--json` writes machine-readable findings (URL,
parameter, context, payload, evidence snippet) you can paste straight into a
report. Every finding carries the exact request that produced it.

**Filter review.** Point it at a staging app behind a WAF with `-v` and read
the `filter passes` line: it shows which separators, tags, and event handlers
the filter lets through. That is your gap list.

**Regression checks.** Re-run the same command with `--json` after a fix and
diff the output. An empty findings array is the expected result.

## Options

| Flag | Meaning |
|---|---|
| `-u, --url` | Target URL with parameters |
| `-p, --payloads` | Payload wordlist (default `payloads.txt`, ~3000 entries) |
| `--threads` | Concurrent workers (default 20) |
| `--delay` | Seconds between requests (default 0) |
| `--timeout` | Request timeout in seconds (default 12) |
| `--method` | `GET` or `POST` |
| `-H, --header` | Custom header `'Name: Value'`, repeatable |
| `--cookie` | Cookie header value |
| `--max-payloads` | Cap payloads per parameter (`0` = all) |
| `--max-variants` | Bypass variants per payload (default 6, `0` = unlimited) |
| `--max-adaptive` | Cap adaptive payloads per parameter (default 150, `0` = unlimited) |
| `--no-mutate` | Disable bypass mutations |
| `--no-charset` | Disable charset viability probe |
| `--no-adaptive` | Disable adaptive filter probing |
| `--no-throttle` | Never slow down on blocks |
| `-o, --output` | Text report file |
| `--json` | JSON report file |
| `-v, -vv` | Verbose / very verbose |

## How it works

1. **Probe** - a random marker like `pwpw7k2d9q1x` goes into each parameter.
   A fixed string like `test123` often already exists on the page and causes
   false positives; randomness avoids that.
2. **Classify** - each reflection is located in the HTML: text node, quoted
   attribute, script block, or comment.
3. **Learn the filter** - tiny probes discover which separators, tag names,
   and event handlers pass unblocked, plus which encodings the server
   decodes. Payloads are then built only from passing components.
4. **Strike** - context-tailored breakouts and bypass variants fire.
   A finding needs the **full payload echoed back verbatim** - not just
   a fragment.
5. **Report** - script/HTML-context hits are High, attribute hits Medium,
   each with the URL, context, and an evidence snippet.

A WAF fingerprint (Cloudflare, Akamai, Imperva, Sucuri, AWS, F5,
ModSecurity, Barracuda) runs on the first response. When one is found the
scanner auto-tunes (fewer threads, gentler delay). After 3 blocked responses
it backs off further unless `--no-throttle` is set.

## Example output

```
PawXssScanner v1.3.0 - Reflected XSS Scanner + Bypass Engine
Made by Rushikesh362

────────────────────────────────────────
[*] Fingerprinting WAF...
[*] WAF detected: none
[*] Targets      : 1
[*] Base payload : 2995
[*] Method       : GET
[*] Threads      : 20
[*] Mutations    : on (cap 6)
[*] Charset probe: on
[*] Adaptive     : on (probe filter, craft around it)
────────────────────────────────────────
[*] Scanning https://target.com/search?q=test
[*] parameters: q
[+] q: <svg/onload=alert(1)>
────────────────────────────────────────
[✓] Scan completed
[✓] Requests : 31
[✓] WAF      : none
────────────────────────────────────────
[!] 1 reflected XSS finding(s) in 24 payloads:
  [High] param 'q' (html)
```

## Tests

```bash
python3 tests/test_pawxss.py
```

38 offline unit tests for URL handling, context detection, payload
selection, mutations, and adaptive probing - no network needed.

## References

Techniques implemented here follow public research: s0md3v's
*Bypassing XSS detection mechanisms* (probe, assume, craft methodology),
kh4sh3i's WAF-bypass collection (CC0), and the payload-box XSS payload list
(MIT) for wordlist categories. All code is original.

## License

MIT. See `LICENSE`.
