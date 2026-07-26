---
name: domaingen
description: Use when checking domain name availability — a single name, a shortlist, or a bulk brand-naming sprint. Verifies against authoritative registry RDAP (with WHOIS fallback and registry-restricted-name detection) instead of guessing from web search or memory. Trigger on "is X.com available", "check these domains", "find me a domain/brand name", or any naming sprint.
---

# DomainGen — verified domain availability

Never state domain availability from memory, web search, or a registrar's marketing page. Always verify with this tool, which queries the registries' own RDAP services (Verisign for .com, CIRA for .ca, etc.) with a conservative WHOIS fallback.

## Commands

Quick check (one or more names, comma-separated, no TLD suffix):

```
npx domaingen "coveranew,inkanew" --tlds=com,ai
```

Bulk sprint with a persistent ledger (skips already-checked names on re-run):

```
npx domaingen names.txt results.jsonl --tlds=com,ai
```

If npx is unavailable, the Python twin behaves identically:

```
python check_domains.py names.txt results.jsonl --tlds=com,ai
```

`--tlds` accepts any of ~68 verified extensions (com, net, org, ai, ca, io, dev, app, uk, de, fr, au, shop, store, …). `.ch` and `.es` cannot be checked (no public registry access). For an untested TLD, validate it first: `python test_tlds.py <tld>` — a known-registered control must report `registered` and gibberish must report `available`.

## Interpreting statuses

- `available` — confirmed unregistered (for .ca: RDAP **and** WHOIS agree).
- `registered` — taken.
- `restricted` — looks free in RDAP but the registry blocks registration (e.g. CIRA error 01044). NOT purchasable; never present as available.
- `available(rdap-only)` — RDAP says free but WHOIS could not confirm. Present as "likely available, unconfirmed".
- `unverified` — no reliable answer. Never present as available.

## Rules

1. Availability is a point-in-time snapshot — tell the user to re-verify at a registrar immediately before purchase; registrar checkout is the final word (premium pricing and reservations exist beyond registry data).
2. In naming sprints, pair availability checks with a web search for brand conflicts before recommending a name — an available domain with an active same-name competitor is not a win.
3. Be polite to registries: the tool's built-in delays stay; don't parallelize hard against one registry. ccTLD WHOIS (CIRA especially) rate-limits aggressively.
