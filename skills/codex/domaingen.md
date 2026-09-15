# /domaingen — verified domain availability checks

Check domain availability for: $ARGUMENTS

Use the DomainGen CLI — never assert availability from memory or web search results.

Quick check of specific names (comma-separated, bare names without TLD):

    npx domaingen "name1,name2" --tlds=com,ai

Bulk list with a persistent JSONL ledger (re-runs skip already-settled names; `unverified` rows are retried and the newest record for a name wins):

    npx domaingen names.txt results.jsonl --tlds=com,ai

Python twin (identical behavior) if Node is unavailable: `python check_domains.py names.txt results.jsonl --tlds=...` from https://github.com/mpge/DomainGen.

Status semantics — report these faithfully:
- `available`: confirmed unregistered at the registry (for .ca, RDAP and WHOIS both agree).
- `registered`: taken.
- `restricted`: RDAP shows no record but the registry blocks registration (CIRA 01044 and similar). Not purchasable — never call this available.
- `available(rdap-only)` / `unverified`: unconfirmed — never present as available. `unverified(429)` means the registry throttled past the backoff (Google Registry's .dev/.app/.page RDAP does this above roughly one query a second); re-run the ledger later and those rows are retried. Run at most one checker process per registry.

~69 TLDs are verified working (com, net, org, ai, ca, io, co, so, dev, app, uk, de, fr, au, shop, …). `.ch`/`.es` cannot be checked remotely. Always tell the user to re-verify at a registrar checkout before purchase, and pair availability with a brand-conflict web search before recommending a name.
