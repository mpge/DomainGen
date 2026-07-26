/**
 * DomainGen — bulk domain availability checking via authoritative registry RDAP,
 * with WHOIS fallback and (for .ca) WHOIS cross-verification of available results.
 *
 * Zero dependencies. Node 18+.
 */
import net from "node:net";

const UA = "domaingen-availability-checker/3.0 (+https://github.com/mpge/DomainGen)";
const IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json";

/** Used only if the IANA bootstrap itself cannot be fetched. */
export const FALLBACK_RDAP = {
  com: "https://rdap.verisign.com/com/v1/domain/",
  net: "https://rdap.verisign.com/net/v1/domain/",
  ca: "https://rdap.ca.fury.ca/rdap/domain/",
};

/**
 * Working RDAP services for TLDs absent from the IANA bootstrap (ccTLD listing
 * is opt-in). Verified against registered/gibberish controls.
 * Only applied when the bootstrap doesn't already carry the TLD.
 */
export const SUPPLEMENTAL_RDAP = {
  io: "https://rdap.identitydigital.services/rdap/domain/",
  sh: "https://rdap.identitydigital.services/rdap/domain/",
  me: "https://rdap.identitydigital.services/rdap/domain/",
  us: "https://rdap.nic.us/domain/",
};

/** TLDs whose RDAP serves 404 for registry-restricted names (CIRA/.ca). */
export const WHOIS_VERIFY_TLDS = new Set(["ca"]);

// NOTE: no bare "domain:" — DENIC (.de) echoes "Domain: <name>" even for free
// domains ("Status: free"). Registered evidence must be more specific.
const WHOIS_REGISTERED = [
  "domain name:", "domain_name:", "registrar:", "creation date", "created:",
  "registered on", "status: connect", "holder of domain name", "query_status: 200",
];
const WHOIS_AVAILABLE = [
  "no object found", "not found", "no match", "no entries found",
  "no data found", "domain not found", "is free", "available for registration",
  "status: free", "status: available", "nothing found", "we do not have an entry",
  "no information available", "object_not_found", "query_status: 220",
];
// Deliberately specific: bare words like "restricted" appear in the legal
// boilerplate of ordinary WHOIS responses (.us, .co, ...) and must not match.
const WHOIS_RESTRICTED = [
  "usage restrictions", "error code: 01044", "reserved by the registry",
  "registry reserved", "not available for registration",
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Classify a raw WHOIS response: registered | available | restricted | unverified.
 * Order matters: a registered record's boilerplate can contain words from the
 * other pattern sets, so the most affirmative evidence wins first. Whitespace is
 * collapsed because some registries pad status columns
 * (.it/.be write "Status:             AVAILABLE").
 */
export function classifyWhois(text) {
  const t = text.toLowerCase().split(/\s+/).join(" ");
  if (WHOIS_REGISTERED.some((p) => t.includes(p))) return "registered";
  if (WHOIS_AVAILABLE.some((p) => t.includes(p))) return "available";
  if (WHOIS_RESTRICTED.some((p) => t.includes(p))) return "restricted";
  return "unverified";
}

/** Network + timing seams, swappable in tests. */
export const internals = { httpStatus, whoisQuery, sleep };

async function httpStatus(url, timeoutMs = 15000) {
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": UA },
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "follow",
    });
    return res.status;
  } catch (e) {
    return `ERR:${e.name ?? "fetch"}`;
  }
}

/** Resolve {tld: rdapDomainQueryBase} from the IANA bootstrap file. */
export async function loadRdapMap() {
  let mapping = {};
  try {
    const res = await fetch(IANA_BOOTSTRAP, {
      headers: { "User-Agent": UA },
      signal: AbortSignal.timeout(20000),
    });
    const data = await res.json();
    for (const [tlds, urls] of data.services) {
      let base = urls[0];
      if (!base.endsWith("/")) base += "/";
      for (const tld of tlds) mapping[tld.toLowerCase()] = base + "domain/";
    }
  } catch {
    mapping = { ...FALLBACK_RDAP };
  }
  for (const [tld, url] of Object.entries(SUPPLEMENTAL_RDAP)) {
    mapping[tld] ??= url;
  }
  return mapping;
}

function whoisQuery(server, query, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const sock = net.createConnection({ host: server, port: 43, timeout: timeoutMs });
    sock.on("connect", () => sock.write(query + "\r\n"));
    sock.on("data", (b) => chunks.push(b));
    sock.on("timeout", () => { sock.destroy(); reject(new Error("timeout")); });
    sock.on("error", reject);
    sock.on("close", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

const whoisServerCache = new Map();

async function whoisServerForTld(tld) {
  if (whoisServerCache.has(tld)) return whoisServerCache.get(tld);
  let server = null;
  try {
    const text = await internals.whoisQuery("whois.iana.org", tld);
    for (const line of text.split("\n")) {
      if (line.toLowerCase().startsWith("whois:")) {
        server = line.slice(line.indexOf(":") + 1).trim();
        break;
      }
    }
  } catch { /* no server discovered */ }
  whoisServerCache.set(tld, server);
  return server;
}

async function whoisCheck(domain, tld, retry = true) {
  const server = await whoisServerForTld(tld);
  if (!server) return { status: "unverified(no-whois-server)", source: "whois.iana.org" };
  try {
    const status = classifyWhois(await internals.whoisQuery(server, domain));
    return { status, source: server };
  } catch {
    if (retry) {
      await internals.sleep(10000); // ccTLD WHOIS servers (e.g. CIRA) rate-limit hard
      return whoisCheck(domain, tld, false);
    }
    return { status: "unverified", source: `${server}(error)` };
  }
}

async function rdapCheck(base, domain) {
  let st = await internals.httpStatus(base + domain);
  if (st === 429) {
    await internals.sleep(5000);
    st = await internals.httpStatus(base + domain);
  }
  if (st === 404) return "available";
  if (st === 200) return "registered";
  return `unverified(${st})`;
}

/**
 * Check one name on one TLD. RDAP first, WHOIS fallback.
 * For TLDs in WHOIS_VERIFY_TLDS an RDAP 404 is cross-verified against WHOIS —
 * only a WHOIS "not found" upgrades it to a confirmed "available".
 * @returns {Promise<{status: string, source: string}>}
 */
export async function check(name, tld, rdapMap, { whoisVerify = true } = {}) {
  const domain = `${name}.${tld}`;
  const base = rdapMap[tld];
  if (base) {
    const status = await rdapCheck(base, domain);
    if (status === "registered") return { status, source: base };
    if (status === "available") {
      if (!WHOIS_VERIFY_TLDS.has(tld)) return { status: "available", source: base };
      if (!whoisVerify) return { status: "available(rdap-only)", source: base };
      const w = await whoisCheck(domain, tld);
      if (w.status === "available") return { status: "available", source: `${base} + ${w.source}` };
      if (w.status === "restricted" || w.status === "registered") {
        return { status: w.status, source: `${base} + ${w.source}` };
      }
      return { status: "available(rdap-only)", source: base };
    }
  }
  return whoisCheck(domain, tld);
}

/**
 * Check many names across TLDs sequentially (politeness delays included).
 * @param {string[]} names bare names, no TLD
 * @param {string[]} tlds e.g. ["com","ai"]
 * @param {{whoisVerify?: boolean, onResult?: (rec: object) => void}} [opts]
 * @returns {Promise<object[]>} one record per name with per-TLD status/source
 */
export async function checkDomains(names, tlds, opts = {}) {
  const rdapMap = await loadRdapMap();
  const records = [];
  for (const raw of names) {
    const name = raw.trim().toLowerCase();
    if (!name || name.startsWith("#")) continue;
    const rec = { candidate: name, checked_at: new Date().toISOString() };
    for (const tld of tlds) {
      const { status, source } = await check(name, tld, rdapMap, opts);
      rec[tld] = status;
      rec[`${tld}_source`] = source;
      await internals.sleep(150);
    }
    records.push(rec);
    opts.onResult?.(rec);
    await internals.sleep(200);
  }
  return records;
}
