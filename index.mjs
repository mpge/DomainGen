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
  so: "https://rdap.nic.so/domain/",
};

/** TLDs whose RDAP serves 404 for registry-restricted names (CIRA/.ca). */
export const WHOIS_VERIFY_TLDS = new Set(["ca"]);

// NOTE: no bare "domain:" — DENIC (.de) echoes "Domain: <name>" even for free
// domains ("Status: free"). Registered evidence must be more specific.
const WHOIS_REGISTERED = [
  "domain name:", "domain_name:", "registrar:", "creation date", "created:",
  "registered on", "status: connect", "holder of domain name", "query_status: 200",
];
// Unambiguous "does not exist" statements, checked BEFORE registered evidence:
// .so echoes "Domain Name: <name>" on free domains, which would otherwise match
// WHOIS_REGISTERED (same trap as DENIC's "Domain:" echo).
const WHOIS_DEFINITIVE_AVAILABLE = [
  "the queried object does not exist", // .so
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
 * other pattern sets, so the most affirmative evidence wins first — except an
 * explicit "object does not exist", which beats a registry's echoed query.
 * Whitespace is collapsed because some registries pad status columns
 * (.it/.be write "Status:             AVAILABLE").
 */
export function classifyWhois(text) {
  const t = text.toLowerCase().split(/\s+/).join(" ");
  if (WHOIS_DEFINITIVE_AVAILABLE.some((p) => t.includes(p))) return "available";
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

/**
 * RDAP throttling. Registries rate-limit without a Retry-After header (Google
 * Registry, which serves .dev/.app/.page, answers bare 429s), so a 429 backs off
 * and also slows every later query to that registry host for the rest of the run.
 */
export const RDAP_429_BACKOFF_MS = [5000, 15000, 45000];
// First slow-down: Google Registry took 30 queries at 1.5s spacing and
// throttled after 11 at 0.7s (2026-09).
const HOST_INTERVAL_MIN_MS = 1500;
const HOST_INTERVAL_MAX_MS = 8000;
const hostInterval = new Map(); // registry host -> minimum ms between queries
const hostLast = new Map();     // registry host -> Date.now() of the last query

async function pacedStatus(url) {
  const host = new URL(url).host;
  const interval = hostInterval.get(host) ?? 0;
  if (interval) {
    const wait = (hostLast.get(host) ?? 0) + interval - Date.now();
    if (wait > 0) await internals.sleep(wait);
  }
  hostLast.set(host, Date.now());
  return internals.httpStatus(url);
}

async function rdapCheck(base, domain) {
  const url = base + domain;
  let st = await pacedStatus(url);
  for (const backoff of RDAP_429_BACKOFF_MS) {
    if (st !== 429) break;
    const host = new URL(url).host;
    hostInterval.set(host, Math.min(Math.max(HOST_INTERVAL_MIN_MS, (hostInterval.get(host) ?? 0) * 2), HOST_INTERVAL_MAX_MS));
    await internals.sleep(backoff);
    st = await pacedStatus(url);
  }
  if (st === 404) return "available";
  if (st === 200) return "registered";
  return `unverified(${st})`;
}

/**
 * Check one name on one TLD. RDAP first, WHOIS fallback.
 * For TLDs in WHOIS_VERIFY_TLDS an RDAP 404 is cross-verified against WHOIS —
 * only a WHOIS "not found" upgrades it to a confirmed "available".
 * If RDAP fails and WHOIS cannot settle the name either, the RDAP failure is
 * reported: .dev has no WHOIS server, and "unverified(429)" says what went
 * wrong where "unverified(no-whois-server)" would not.
 * @returns {Promise<{status: string, source: string}>}
 */
export async function check(name, tld, rdapMap, { whoisVerify = true } = {}) {
  const domain = `${name}.${tld}`;
  const base = rdapMap[tld];
  let rdapFailure = null;
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
    rdapFailure = status;
  }
  const w = await whoisCheck(domain, tld);
  if (rdapFailure && w.status.startsWith("unverified")) return { status: rdapFailure, source: base };
  return w;
}

/**
 * Names in a ledger whose results for `tlds` are settled. Unverified results
 * (rate limits, timeouts, no WHOIS server) are not settled: the next run retries
 * them and appends a newer record, which supersedes the older one. When a
 * candidate appears more than once, its last record decides.
 * @param {string[]} lines JSON Lines ledger content
 * @param {string[]} tlds
 * @returns {Set<string>}
 */
export function settledCandidates(lines, tlds) {
  const settled = new Set();
  for (const line of lines) {
    let rec;
    try { rec = JSON.parse(line); } catch { continue; }
    if (!rec?.candidate) continue;
    if (tlds.some((t) => String(rec[t] ?? "").startsWith("unverified"))) settled.delete(rec.candidate);
    else settled.add(rec.candidate);
  }
  return settled;
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
