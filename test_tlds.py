"""Validate the checker across popular TLDs using control domains.

For each TLD, 'google' must come back registered and a gibberish string
available. Any other combination is flagged for manual review.

    python test_tlds.py [tld1,tld2,...]
"""
import sys
import check_domains as cd

DEFAULT_TLDS = [
    "com", "net", "org", "ai", "ca", "io", "co", "dev", "app", "me",
    "xyz", "sh", "gg", "us", "uk", "de", "tv", "cc", "info", "biz",
    "shop", "store", "tech", "online", "site",
]

GIBBERISH = "xqzvkwplormtj"

# Per-TLD registered-control overrides where neither google.<tld> nor nic.<tld>
# is a normally-registered domain (e.g. google.nz is registry-restricted).
REGISTERED_CONTROL = {"nz": "internetnz"}

# No public RDAP and IP-allowlisted WHOIS — the checker correctly reports
# "unverified" for these; they cannot be validated (or used) remotely.
KNOWN_UNSUPPORTED = {"ch", "es"}


def main():
    tlds = sys.argv[1].split(",") if len(sys.argv) > 1 else DEFAULT_TLDS
    rdap_map = cd.load_rdap_map()
    print(f"{'tld':<8}{'rdap endpoint':<55}{'registered-ctl':<24}gibberish")
    failures = []
    for t in tlds:
        ep = rdap_map.get(t, "-- no RDAP (whois fallback) --")
        if t in KNOWN_UNSUPPORTED:
            print(f"{t:<8}{ep:<55}-- unsupported: no public RDAP/WHOIS access --")
            continue
        # 'nic.<tld>' is registry-registered on every gTLD (ICANN mandate) and
        # most ccTLDs; 'google.<tld>' covers the rest. Either counts.
        g, _ = cd.check(REGISTERED_CONTROL.get(t, "google"), t, rdap_map)
        if g != "registered":
            g2, _ = cd.check("nic", t, rdap_map)
            g = f"registered(nic)" if g2 == "registered" else g
        x, _ = cd.check(GIBBERISH, t, rdap_map)
        ok = g.startswith("registered") and x.startswith("available")
        flag = "" if ok else "   <-- CHECK"
        if not ok:
            failures.append(t)
        print(f"{t:<8}{ep:<55}{g:<24}{x}{flag}")
    tested = [t for t in tlds if t not in KNOWN_UNSUPPORTED]
    print(f"\n{len(tested) - len(failures)}/{len(tested)} TLDs verified" +
          (f"; needs review: {', '.join(failures)}" if failures else "") +
          (f"; unsupported: {', '.join(t for t in tlds if t in KNOWN_UNSUPPORTED)}"
           if any(t in KNOWN_UNSUPPORTED for t in tlds) else ""))


if __name__ == "__main__":
    main()
