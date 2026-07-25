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


def main():
    tlds = sys.argv[1].split(",") if len(sys.argv) > 1 else DEFAULT_TLDS
    rdap_map = cd.load_rdap_map()
    print(f"{'tld':<8}{'rdap endpoint':<55}{'google':<24}gibberish")
    failures = []
    for t in tlds:
        ep = rdap_map.get(t, "-- no RDAP (whois fallback) --")
        g, _ = cd.check("google", t, rdap_map)
        x, _ = cd.check(GIBBERISH, t, rdap_map)
        ok = g == "registered" and x.startswith("available")
        flag = "" if ok else "   <-- CHECK"
        if not ok:
            failures.append(t)
        print(f"{t:<8}{ep:<55}{g:<24}{x}{flag}")
    print(f"\n{len(tlds) - len(failures)}/{len(tlds)} TLDs verified" +
          (f"; needs review: {', '.join(failures)}" if failures else ""))


if __name__ == "__main__":
    main()
