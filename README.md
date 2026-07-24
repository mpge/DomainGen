# DomainGen

A small, dependency-free Python script for **bulk domain availability checking** over any TLD with a published RDAP service (`.com`, `.ai`, `.dev`, `.app`, `.io`, `.org`, …), using authoritative registry data rather than scraping registrar websites or trusting search results.

Built for brand-naming sprints: feed it a list of candidate names, get back a JSON Lines ledger of verified availability you can filter, score, and iterate on.

[Want to find a domain without running this?](https://namerobo.com)

## Why RDAP?

RDAP is the registries' own machine-readable successor to WHOIS. Querying it means:

- **Every TLD's endpoint is discovered at runtime** from the [IANA RDAP bootstrap file](https://data.iana.org/rdap/dns.json) — `.com` resolves to Verisign, `.ai` to the .ai registry, `.dev` to Google Registry, and so on. The script keeps working if a registry migrates providers. HTTP `404` = unregistered, `200` = registered. No API key, no rate-limit games at sane volumes.
- **WHOIS fallback** — if a TLD has no RDAP service or RDAP is unreachable, the script asks `whois.iana.org` for the TLD's WHOIS server, queries it on TCP/43, and matches conservative "not found" / "domain name:" patterns.
- Anything ambiguous (timeouts, odd status codes, unparseable WHOIS) is recorded as **`unverified`** — the script never guesses.

## Usage

Requires Python 3.8+. No third-party packages.

```
python check_domains.py names.txt results.jsonl              # defaults to --tlds=com,ai
python check_domains.py names.txt results.jsonl --tlds=com,ai,dev,io
python check_domains.py names.txt results.jsonl --tlds=ca    # ccTLDs work too (.ca via CIRA)
```

- `names.txt` — one bare candidate per line (no TLD). `#` comments allowed.
- `results.jsonl` — appended, one JSON object per candidate:

```json
{"candidate": "examplename", "checked_at": "2026-07-23T18:04:11+00:00",
 "com": "available", "com_source": "rdap.verisign.com",
 "ai": "registered", "ai_source": "https://rdap.identitydigital.services/rdap/domain/"}
```

Candidates already present in the output file are skipped, so you can run many iterations against one ledger and it doubles as your dedup list.

### Sanity-check a run

Before trusting results, validate against controls:

```
printf 'google\nxqzvkwplormtj\n' > control.txt
python check_domains.py control.txt control_results.jsonl
```

Expect `google` → registered on both TLDs and the gibberish → available on both. If not, a registry endpoint changed.

## Extending to other TLDs

Add the TLD's RDAP base URL (find it in the IANA bootstrap file) and mirror the `.com` block in `main()`. Most gTLDs (`.dev`, `.app`, `.xyz`, …) work identically; some ccTLDs have no RDAP and need a WHOIS fallback like the `.ai` one.

## Caveats

- Availability is a **point-in-time snapshot**. Always re-verify at your registrar immediately before purchase.
- "Available" means *unregistered at the registry* — it says nothing about trademarks, premium pricing, or registry-reserved names (reserved names sometimes 404 in RDAP but can't actually be bought).
- Be polite: the script sleeps between queries. Don't strip the delays and hammer registry endpoints.

## License

MIT
