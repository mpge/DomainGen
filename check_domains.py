"""Bulk domain availability checker via RDAP (authoritative) with WHOIS fallback.

Usage:
    python check_domains.py names.txt results.jsonl [--tlds=com,ai] [--no-whois-verify]

Statuses: available (RDAP 404 confirmed by WHOIS "not found"), available(rdap-only)
(RDAP 404 but WHOIS could not confirm — treat as unverified for high-stakes use),
registered, restricted (registry-reserved: RDAP 404 but WHOIS reports usage
restrictions, e.g. CIRA error 01044), unverified.

names.txt: one candidate name per line (bare name, no TLD). '#' comments allowed.
results.jsonl: append-mode JSON Lines, one record per candidate with per-TLD status.

How it works:
  - Every TLD's RDAP endpoint is resolved at runtime from the IANA RDAP bootstrap
    file (https://data.iana.org/rdap/dns.json), so any TLD with a published RDAP
    service works out of the box: com, net, org, ai, dev, app, io, xyz, sh, gg, ...
  - RDAP semantics: HTTP 404 -> available, HTTP 200 -> registered. 429s are retried
    once after a backoff.
  - If a TLD has no RDAP service (or RDAP is unreachable), the script falls back to
    WHOIS: it asks whois.iana.org for the TLD's WHOIS server, then queries it on
    TCP/43 and matches conservative "not found" / "domain name:" patterns.
Anything ambiguous is recorded as "unverified" — the script never guesses.
"""
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

UA = {"User-Agent": "domaingen-availability-checker/2.0 (+https://github.com/mpge/DomainGen)"}
IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"

# Used only if the IANA bootstrap itself cannot be fetched.
FALLBACK_RDAP = {
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    "ca": "https://rdap.ca.fury.ca/rdap/domain/",
}

# Working RDAP services for TLDs absent from the IANA bootstrap (ccTLD listing
# is opt-in). Verified 2026-07: registered controls return 200, gibberish 404.
# Only applied when the bootstrap doesn't already carry the TLD.
SUPPLEMENTAL_RDAP = {
    "io": "https://rdap.identitydigital.services/rdap/domain/",
    "sh": "https://rdap.identitydigital.services/rdap/domain/",
    "me": "https://rdap.identitydigital.services/rdap/domain/",
    "us": "https://rdap.nic.us/domain/",
    "so": "https://rdap.nic.so/domain/",
}

# Unambiguous "does not exist" statements, checked BEFORE registered evidence:
# .so echoes "Domain Name: <name>" on free domains, which would otherwise match
# the registered patterns (same trap as DENIC's "Domain:" echo).
WHOIS_DEFINITIVE_AVAILABLE_PATTERNS = (
    "the queried object does not exist",  # .so
)

WHOIS_AVAILABLE_PATTERNS = (
    "no object found",
    "not found",
    "no match",
    "no entries found",
    "no data found",
    "domain not found",
    "is free",
    "available for registration",
    "status: free",
    "status: available",       # .be, .eu, .it
    "nothing found",           # .at
    "we do not have an entry", # .ch (SWITCH)
    "no information available",  # .pl WHOIS
    "object_not_found",        # .mx
    "query_status: 220",       # .nz (220 = available)
)
# TLDs whose RDAP serves 404 for registry-restricted names, making WHOIS
# cross-verification of "available" results necessary. gTLD RDAP (Verisign,
# Identity Digital, Google Registry, ...) does not need this.
WHOIS_VERIFY_TLDS = {"ca"}

# Registry-reserved/blocked names. Some registries (e.g. CIRA/.ca) serve RDAP 404
# for these even though they cannot be registered — WHOIS is the only tell.
# Patterns are deliberately specific: bare words like "restricted" appear in the
# legal boilerplate of ordinary WHOIS responses (.us, .co, ...) and must not match.
WHOIS_RESTRICTED_PATTERNS = (
    "usage restrictions",
    "error code: 01044",
    "reserved by the registry",
    "registry reserved",
    "not available for registration",
)
# NOTE: no bare "domain:" here — DENIC (.de) echoes "Domain: <name>" even for
# free domains ("Status: free"). Registered evidence must be more specific.
WHOIS_REGISTERED_PATTERNS = (
    "domain name:",
    "domain_name:",            # .nz
    "registrar:",
    "creation date",
    "created:",
    "registered on",
    "status: connect",         # .de (DENIC)
    "holder of domain name",   # .ch (SWITCH)
    "query_status: 200",       # .nz (200 = active)
)


def http_status(url, timeout=15):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return f"ERR:{type(e).__name__}"


def load_rdap_map():
    """Return {tld: rdap_domain_query_base} from the IANA bootstrap file."""
    try:
        req = urllib.request.Request(IANA_BOOTSTRAP, headers=UA)
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
        mapping = {}
        for tlds, urls in data["services"]:
            base = urls[0]
            if not base.endswith("/"):
                base += "/"
            for tld in tlds:
                mapping[tld.lower()] = base + "domain/"
    except Exception:
        mapping = dict(FALLBACK_RDAP)
    for tld, url in SUPPLEMENTAL_RDAP.items():
        mapping.setdefault(tld, url)
    return mapping


def whois_query(server, query, timeout=15):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks).decode(errors="replace")


_whois_server_cache = {}


def whois_server_for_tld(tld):
    """Discover a TLD's WHOIS server from whois.iana.org (cached)."""
    if tld in _whois_server_cache:
        return _whois_server_cache[tld]
    server = None
    try:
        text = whois_query("whois.iana.org", tld)
        for line in text.splitlines():
            if line.lower().startswith("whois:"):
                server = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass
    _whois_server_cache[tld] = server
    return server


def classify_whois(text):
    """Classify a raw WHOIS response: registered | available | restricted | unverified.

    Order matters: a registered record's boilerplate can contain words from the
    other pattern sets, so the most affirmative evidence wins first — except an
    explicit "object does not exist", which beats a registry's echoed query.
    Whitespace is collapsed because some registries pad status columns (.it/.be
    write "Status:             AVAILABLE").
    """
    text = " ".join(text.lower().split())
    if any(p in text for p in WHOIS_DEFINITIVE_AVAILABLE_PATTERNS):
        return "available"
    if any(p in text for p in WHOIS_REGISTERED_PATTERNS):
        return "registered"
    if any(p in text for p in WHOIS_AVAILABLE_PATTERNS):
        return "available"
    if any(p in text for p in WHOIS_RESTRICTED_PATTERNS):
        return "restricted"
    return "unverified"


def whois_check(domain, tld, retry=True):
    """Return (status, source) via the TLD's WHOIS server."""
    server = whois_server_for_tld(tld)
    if not server:
        return "unverified(no-whois-server)", "whois.iana.org"
    try:
        return classify_whois(whois_query(server, domain)), server
    except Exception:
        if retry:
            time.sleep(10)  # ccTLD WHOIS servers (e.g. CIRA) rate-limit hard
            return whois_check(domain, tld, retry=False)
        return "unverified", f"{server}(error)"


# RDAP throttling. Registries rate-limit without a Retry-After header (Google
# Registry, which serves .dev/.app/.page, answers bare 429s), so a 429 backs off
# and also slows every later query to that registry host for the rest of the run.
RDAP_429_BACKOFF = (5, 15, 45)  # seconds slept before each retry
HOST_INTERVAL_MIN = 1.5         # first slow-down: Google Registry took 30 queries
                                # at 1.5s spacing, throttled after 11 at 0.7s (2026-09)
HOST_INTERVAL_MAX = 8.0         # ceiling for the per-host query interval

_host_interval = {}  # registry host -> minimum seconds between queries
_host_last = {}      # registry host -> time.monotonic() of the last query


def paced_status(url):
    """http_status(), spaced out per host once that host has throttled us."""
    host = urllib.parse.urlsplit(url).netloc
    interval = _host_interval.get(host, 0)
    if interval:
        wait = _host_last.get(host, 0) + interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
    _host_last[host] = time.monotonic()
    return http_status(url)


def rdap_check(base, domain):
    url = base + domain
    st = paced_status(url)
    for backoff in RDAP_429_BACKOFF:
        if st != 429:
            break
        host = urllib.parse.urlsplit(url).netloc
        _host_interval[host] = min(max(HOST_INTERVAL_MIN, _host_interval.get(host, 0) * 2),
                                   HOST_INTERVAL_MAX)
        time.sleep(backoff)
        st = paced_status(url)
    if st == 404:
        return "available"
    if st == 200:
        return "registered"
    return f"unverified({st})"


def check(name, tld, rdap_map, whois_verify=True):
    """Return (status, source) for name.tld — RDAP first, WHOIS fallback.

    For TLDs in WHOIS_VERIFY_TLDS an RDAP 404 is necessary but NOT sufficient
    proof of registrability (CIRA/.ca serves 404 for registry-restricted names),
    so RDAP "available" is cross-verified against WHOIS there; only a WHOIS
    "not found" upgrades it to a confirmed "available". Other TLDs trust RDAP.

    If RDAP fails (say, a 429 that outlasts the backoff) and WHOIS cannot settle
    the name either, the RDAP failure is what gets reported: .dev has no WHOIS
    server, and "unverified(429)" says what went wrong where
    "unverified(no-whois-server)" would not.
    """
    domain = f"{name}.{tld}"
    base = rdap_map.get(tld)
    rdap_failure = None
    if base:
        status = rdap_check(base, domain)
        if status == "registered":
            return status, base
        if status == "available":
            if tld not in WHOIS_VERIFY_TLDS:
                return "available", base
            if not whois_verify:
                return "available(rdap-only)", base
            w_status, w_server = whois_check(domain, tld)
            if w_status == "available":
                return "available", f"{base} + {w_server}"
            if w_status in ("restricted", "registered"):
                return w_status, f"{base} + {w_server}"
            return "available(rdap-only)", base
        rdap_failure = status
    w_status, w_source = whois_check(domain, tld)
    if rdap_failure and w_status.startswith("unverified"):
        return rdap_failure, base
    return w_status, w_source


def settled_candidates(lines, tlds):
    """Names in a ledger whose results for `tlds` are settled.

    Unverified results (rate limits, timeouts, no WHOIS server) are not settled:
    the next run retries them and appends a newer record, which supersedes the
    older one. When a candidate appears more than once, its last record decides.
    """
    settled = set()
    for ln in lines:
        try:
            rec = json.loads(ln)
            name = rec["candidate"]
        except Exception:
            continue
        if any(str(rec.get(t, "")).startswith("unverified") for t in tlds):
            settled.discard(name)
        else:
            settled.add(name)
    return settled


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    opts = [a for a in sys.argv[1:] if a.startswith("--")]
    if len(args) != 2:
        print(__doc__)
        sys.exit(1)
    names_file, out_file = args
    tlds = ["com", "ai"]
    whois_verify = "--no-whois-verify" not in opts
    for o in opts:
        if o.startswith("--tlds="):
            tlds = [t.strip().lstrip(".").lower() for t in o.split("=", 1)[1].split(",") if t.strip()]

    with open(names_file, encoding="utf-8") as f:
        names = [ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")]

    # de-dup against names the output file already settled
    try:
        with open(out_file, encoding="utf-8") as f:
            seen = settled_candidates(f, tlds)
    except FileNotFoundError:
        seen = set()

    rdap_map = load_rdap_map()
    for tld in tlds:
        ep = rdap_map.get(tld)
        print(f".{tld} RDAP endpoint: {ep or 'NONE (will use WHOIS fallback)'}", flush=True)

    out = open(out_file, "a", encoding="utf-8")
    for name in names:
        if name in seen:
            print(f"skip (already checked): {name}", flush=True)
            continue
        seen.add(name)
        rec = {"candidate": name, "checked_at": datetime.now(timezone.utc).isoformat()}
        line = f"{name:<16}"
        for tld in tlds:
            status, source = check(name, tld, rdap_map, whois_verify)
            rec[tld] = status
            rec[f"{tld}_source"] = source
            line += f" .{tld}={status:<14}"
            time.sleep(0.15)
        out.write(json.dumps(rec) + "\n")
        out.flush()
        print(line, flush=True)
        time.sleep(0.2)
    out.close()


if __name__ == "__main__":
    main()
