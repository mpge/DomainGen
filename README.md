# DomainGen

Dependency-free **bulk domain availability checking** over ~68 verified TLDs (`.com`, `.ai`, `.ca`, `.io`, `.dev`, `.uk`, `.de`, `.fr`, `.au`, `.shop`, …), using authoritative registry data (RDAP) rather than scraping registrar websites or trusting search results. Available as an **npm CLI/library** (Node 18+) and an identical **Python script** (3.8+).

Built for brand-naming sprints: feed it a list of candidate names, get back a JSON Lines ledger of verified availability you can filter, score, and iterate on.

## Quick start (npm)

```
npx domaingen "coveranew,inkanew" --tlds=com,ai     # inline check, no files
npx domaingen names.txt results.jsonl --tlds=com,ca  # bulk ledger mode
```

Or as a library:

```js
import { loadRdapMap, check, checkDomains } from "domaingen";
const records = await checkDomains(["coveranew", "inkanew"], ["com", "ai"]);
```

[Want to find a domain without running this?](https://namerobo.com)

## Why RDAP?

RDAP is the registries' own machine-readable successor to WHOIS. Querying it means:

- **Every TLD's endpoint is discovered at runtime** from the [IANA RDAP bootstrap file](https://data.iana.org/rdap/dns.json) — `.com` resolves to Verisign, `.ai` to the .ai registry, `.dev` to Google Registry, and so on. The script keeps working if a registry migrates providers. HTTP `404` = unregistered, `200` = registered. No API key, no rate-limit games at sane volumes.
- **Supplemental endpoints** for TLDs the bootstrap doesn't list (ccTLD participation is opt-in): `.io`, `.sh`, `.me` (Identity Digital) and `.us` are pinned in `SUPPLEMENTAL_RDAP`, verified against registered/gibberish controls.
- **WHOIS fallback** — if a TLD has no RDAP service or RDAP is unreachable, the script asks `whois.iana.org` for the TLD's WHOIS server, queries it on TCP/43, and matches conservative "not found" / "domain name:" patterns.
- **WHOIS cross-verification of "available"** — an RDAP 404 is *not* sufficient proof a name can be registered: some registries (CIRA/.ca, for example) serve 404 for registry-restricted names that are actually unregistrable (CIRA WHOIS error 01044 "usage restrictions"). By default every RDAP-available result is therefore double-checked against WHOIS: only a WHOIS "not found" yields a confirmed `available`; a restriction response yields `restricted`; an unreachable WHOIS yields `available(rdap-only)`. Skip the cross-check with `--no-whois-verify` if you want raw RDAP speed.
- Anything ambiguous (timeouts, odd status codes, unparseable WHOIS) is recorded as **`unverified`** — the script never guesses.

## Usage (Python)

Requires Python 3.8+. No third-party packages. Identical behavior and flags to the npm CLI.

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

## Tested TLDs

`python test_tlds.py` validates any TLD list against control domains (a known-registered name — google.tld or the ICANN-mandated nic.tld — must report `registered`, gibberish must report `available`). All 68 currently pass:

**gTLD:** `com net org info biz pro xyz one art fun space site online store shop tech cloud digital agency studio design club live world today news blog page network tools software email group media dev app`
**ccTLD:** `ai ca io co me sh gg us uk de fr nl eu be at it pt se no dk fi pl cz ie au nz in br mx sg tv cc`

**Unsupported:** `.ch` and `.es` — no public RDAP, and WHOIS is IP-allowlisted; the checker reports `unverified` for them rather than guessing.

`.co`, `.gg`, `.de`, `.be`, `.it`, `.nz` and several others have no public RDAP and are served by the WHOIS fallback (per-registry response dialects are handled). Any other TLD in the IANA bootstrap works without code changes — run `test_tlds.py your,tlds` first to confirm its registry behaves.

## Testing

Both implementations have offline unit suites (all network mocked) covering the WHOIS dialect classifier, RDAP status mapping, the .ca cross-verification flow, bootstrap/supplemental endpoint resolution, and ledger dedup:

```
node --test              # Node suite (node:test, built-in)
python -m unittest -v    # Python suite (unittest, stdlib)
```

CI runs both on every push and PR (`.github/workflows/test.yml`). `test_tlds.py` is the complementary *live* integration check against real registries.

## Agent skills

The `skills/` directory ships ready-made integrations:

- **Claude Code**: copy `skills/claude/domaingen/` to `~/.claude/skills/domaingen/` — Claude then verifies availability with real registry data whenever domains come up.
- **Codex CLI**: copy `skills/codex/domaingen.md` to `~/.codex/prompts/` — invoke with `/domaingen name1,name2`.

## Caveats

- Availability is a **point-in-time snapshot**. Always re-verify at your registrar immediately before purchase.
- "Available" means *unregistered at the registry and not flagged restricted by WHOIS* — it still says nothing about trademarks or premium registry pricing. The final word is always an actual registrar checkout.
- ccTLD WHOIS servers can rate-limit aggressively (CIRA especially); the script retries once after a 10s backoff, and anything still unconfirmed is labeled `available(rdap-only)` rather than guessed.
- Be polite: the script sleeps between queries. Don't strip the delays and hammer registry endpoints.

## License

MIT
