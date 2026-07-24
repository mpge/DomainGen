"""Domain availability checker for .com and .ai via RDAP (authoritative) with WHOIS fallback.

Usage:
    python check_domains.py names.txt results.jsonl

names.txt: one candidate name per line (bare name, no TLD).
results.jsonl: append-mode JSON Lines, one record per (name, tld) check.

Semantics:
  - .com  : Verisign RDAP  https://rdap.verisign.com/com/v1/domain/<name>.com
            HTTP 404 -> available, HTTP 200 -> registered, else unverified (retried once)
  - .ai   : RDAP endpoint discovered from IANA bootstrap (data.iana.org/rdap/dns.json),
            404 -> available, 200 -> registered.
            Fallback: WHOIS TCP/43 to whois.nic.ai; "NOT FOUND"/"No Object Found" -> available,
            a populated record -> registered, anything else -> unverified.
Never guesses: any ambiguous response is recorded as "unverified".
"""
import json
import socket
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

UA = {"User-Agent": "domain-availability-research/1.0"}
IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
COM_RDAP = "https://rdap.verisign.com/com/v1/domain/"


def http_status(url, timeout=15):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return f"ERR:{type(e).__name__}"


def discover_ai_rdap():
    try:
        req = urllib.request.Request(IANA_BOOTSTRAP, headers=UA)
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
        for tlds, urls in data["services"]:
            if "ai" in tlds:
                base = urls[0]
                if not base.endswith("/"):
                    base += "/"
                return base + "domain/"
    except Exception:
        pass
    return None


def whois_ai(domain, timeout=15):
    """Return 'available' | 'registered' | 'unverified' via whois.nic.ai:43."""
    try:
        with socket.create_connection(("whois.nic.ai", 43), timeout=timeout) as s:
            s.sendall((domain + "\r\n").encode())
            chunks = []
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
        text = b"".join(chunks).decode(errors="replace")
        low = text.lower()
        if "no object found" in low or "not found" in low or "no match" in low:
            return "available", "whois.nic.ai"
        if "domain name:" in low or "registrar:" in low or "creation date" in low:
            return "registered", "whois.nic.ai"
        return "unverified", "whois.nic.ai"
    except Exception:
        return "unverified", "whois.nic.ai(error)"


def check_rdap(url):
    st = http_status(url)
    if st == 404:
        return "available"
    if st == 200:
        return "registered"
    if st == 429:
        time.sleep(5)
        st = http_status(url)
        if st == 404:
            return "available"
        if st == 200:
            return "registered"
    return f"unverified({st})"


def main():
    names_file, out_file = sys.argv[1], sys.argv[2]
    with open(names_file, encoding="utf-8") as f:
        names = [ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")]

    # de-dup against already-checked names in the output file
    seen = set()
    try:
        with open(out_file, encoding="utf-8") as f:
            for ln in f:
                try:
                    seen.add(json.loads(ln)["candidate"])
                except Exception:
                    pass
    except FileNotFoundError:
        pass

    ai_rdap = discover_ai_rdap()
    print(f"AI RDAP endpoint: {ai_rdap or 'NONE (will use WHOIS)'}", flush=True)

    out = open(out_file, "a", encoding="utf-8")
    for name in names:
        if name in seen:
            print(f"skip (already checked): {name}", flush=True)
            continue
        seen.add(name)
        rec = {"candidate": name, "checked_at": datetime.now(timezone.utc).isoformat()}

        # .com via Verisign RDAP
        com_status = check_rdap(COM_RDAP + name + ".com")
        rec["com"] = com_status
        rec["com_source"] = "rdap.verisign.com"
        time.sleep(0.15)

        # .ai via RDAP, fallback WHOIS
        if ai_rdap:
            ai_status = check_rdap(ai_rdap + name + ".ai")
            ai_source = ai_rdap
            if ai_status.startswith("unverified"):
                ai_status, ai_source = whois_ai(name + ".ai")
        else:
            ai_status, ai_source = whois_ai(name + ".ai")
        rec["ai"] = ai_status
        rec["ai_source"] = ai_source

        out.write(json.dumps(rec) + "\n")
        out.flush()
        print(f"{name:<16} .com={com_status:<14} .ai={ai_status}", flush=True)
        time.sleep(0.2)
    out.close()


if __name__ == "__main__":
    main()
