#!/usr/bin/env node
/**
 * domaingen CLI
 *
 *   domaingen <name[,name2,...]> [--tlds=com,ai] [--json] [--no-whois-verify]
 *       Inline mode: check one or more comma-separated names, print results.
 *
 *   domaingen <names.txt> <results.jsonl> [--tlds=com,ai] [--no-whois-verify]
 *       File mode: one bare name per line ('#' comments allowed); appends one
 *       JSON record per name to the ledger, skipping already-checked names.
 *
 * Statuses: available (confirmed) | available(rdap-only) | registered |
 *           restricted (registry-reserved) | unverified — never trust
 *           "unverified" as available.
 */
import fs from "node:fs";
import { loadRdapMap, check, checkDomains } from "../index.mjs";

const args = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const opts = process.argv.slice(2).filter((a) => a.startsWith("--"));

let tlds = ["com", "ai"];
for (const o of opts) {
  if (o.startsWith("--tlds=")) {
    tlds = o.slice(7).split(",").map((t) => t.trim().replace(/^\./, "").toLowerCase()).filter(Boolean);
  }
}
const whoisVerify = !opts.includes("--no-whois-verify");
const asJson = opts.includes("--json");

function usage() {
  console.error("Usage: domaingen <name[,name2]> [--tlds=com,ai] [--json]");
  console.error("       domaingen <names.txt> <results.jsonl> [--tlds=com,ai]");
  process.exit(1);
}

if (args.length === 1 && !fs.existsSync(args[0])) {
  // Inline mode
  const names = args[0].split(",").map((n) => n.trim().toLowerCase()).filter(Boolean);
  const rdapMap = await loadRdapMap();
  const out = [];
  for (const name of names) {
    const rec = { candidate: name };
    for (const tld of tlds) {
      const { status, source } = await check(name, tld, rdapMap, { whoisVerify });
      rec[tld] = status;
      rec[`${tld}_source`] = source;
    }
    out.push(rec);
    if (!asJson) {
      const cols = tlds.map((t) => `.${t}=${rec[t]}`).join("  ");
      console.log(`${name.padEnd(16)} ${cols}`);
    }
  }
  if (asJson) console.log(JSON.stringify(out, null, 2));
} else if (args.length === 2) {
  // File mode
  const [namesFile, outFile] = args;
  if (!fs.existsSync(namesFile)) usage();
  const names = fs.readFileSync(namesFile, "utf8").split("\n");

  const seen = new Set();
  if (fs.existsSync(outFile)) {
    for (const line of fs.readFileSync(outFile, "utf8").split("\n")) {
      try { seen.add(JSON.parse(line).candidate); } catch { /* skip */ }
    }
  }
  const fresh = names.filter((n) => {
    const name = n.trim().toLowerCase();
    return name && !name.startsWith("#") && !seen.has(name);
  });

  const fd = fs.openSync(outFile, "a");
  await checkDomains(fresh, tlds, {
    whoisVerify,
    onResult(rec) {
      fs.writeSync(fd, JSON.stringify(rec) + "\n");
      const cols = tlds.map((t) => `.${t}=${String(rec[t]).padEnd(14)}`).join(" ");
      console.log(`${rec.candidate.padEnd(16)} ${cols}`);
    },
  });
  fs.closeSync(fd);
} else {
  usage();
}
