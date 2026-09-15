/** Unit tests for index.mjs — fully offline, all network stubbed via `internals`.
 *
 * Run:  node --test
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  classifyWhois, check, checkDomains, loadRdapMap, internals, settledCandidates,
  FALLBACK_RDAP, SUPPLEMENTAL_RDAP, RDAP_429_BACKOFF_MS,
} from "../index.mjs";

const RDAP = { com: "https://rdap.example/com/", ca: "https://rdap.example/ca/" };
const noop = async () => {};

/** Swap internals for a test, restore afterwards. */
function withInternals(t, overrides) {
  const saved = { ...internals };
  Object.assign(internals, { sleep: noop }, overrides);
  t.after(() => Object.assign(internals, saved));
}

// Route WHOIS server discovery to a fixed fake server, then serve `body`
// (or throw, if body is an Error) for the actual domain query.
function whoisStub(body) {
  return async (server, query) => {
    if (server === "whois.iana.org") return "whois: whois.fake.test";
    if (body instanceof Error) throw body;
    return body;
  };
}

test("classifyWhois: real-world registry dialects", () => {
  const cases = [
    ["Error code: 01044\nError message: The domain name requested has usage restrictions applied to it.", "restricted"],
    ["Not found: xqzvkwplormtj.ca", "available"],
    ["   Domain Name: GOOGLE.COM\n   Registrar: MarkMonitor Inc.", "registered"],
    ["Domain: xqzvkwplormtj.de\nStatus: free", "available"],          // DENIC echo trap
    ["Domain: google.de\nStatus: connect", "registered"],
    ["Domain Name: xqzvkwplormtj.so\nThe queried object does not exist: No Object Found", "available"], // .so echo trap
    ["Domain Name: google.so\nRegistrar: Mark Monitor", "registered"],
    ["Domain:             xqz.it\nStatus:             AVAILABLE", "available"], // padded columns
    ["domain_name: google.nz\nquery_status: 200 Active", "registered"],
    ["query_status: 220 Available", "available"],
    ["Object_Not_Found", "available"],                                 // .mx
    ["% nothing found", "available"],                                  // .at
    ["Holder of domain name: Example LLC", "registered"],              // .ch
    ["Access is restricted to query-based lookups.\nDomain Name: GOOGLE.US", "registered"], // boilerplate trap
    ["hello world", "unverified"],
  ];
  for (const [text, expected] of cases) {
    assert.equal(classifyWhois(text), expected, `for: ${text.slice(0, 40)}`);
  }
});

test("check: gTLD available comes straight from RDAP, no WHOIS call", async (t) => {
  withInternals(t, {
    httpStatus: async () => 404,
    whoisQuery: async () => { throw new Error("WHOIS must not be called for gTLDs"); },
  });
  const r = await check("name", "com", RDAP);
  assert.deepEqual(r, { status: "available", source: RDAP.com });
});

test("check: registered returns immediately", async (t) => {
  withInternals(t, {
    httpStatus: async () => 200,
    whoisQuery: async () => { throw new Error("WHOIS must not be called"); },
  });
  const r = await check("name", "ca", RDAP);
  assert.equal(r.status, "registered");
});

test("check: .ca available is confirmed by WHOIS", async (t) => {
  withInternals(t, {
    httpStatus: async () => 404,
    whoisQuery: whoisStub("Not found: name.ca"),
  });
  const r = await check("name", "ca", RDAP);
  assert.equal(r.status, "available");
  assert.match(r.source, /whois\.fake\.test/);
});

test("check: .ca restricted overrides RDAP 404", async (t) => {
  withInternals(t, {
    httpStatus: async () => 404,
    whoisQuery: whoisStub("Error code: 01044\nusage restrictions applied"),
  });
  const r = await check("pottery", "ca", RDAP);
  assert.equal(r.status, "restricted");
});

test("check: .ca WHOIS failure degrades to available(rdap-only)", async (t) => {
  withInternals(t, {
    httpStatus: async () => 404,
    whoisQuery: whoisStub(new Error("timeout")),
  });
  const r = await check("name", "ca", RDAP);
  assert.equal(r.status, "available(rdap-only)");
});

test("check: whoisVerify=false skips the .ca cross-check", async (t) => {
  withInternals(t, {
    httpStatus: async () => 404,
    whoisQuery: async () => { throw new Error("WHOIS must not be called"); },
  });
  const r = await check("name", "ca", RDAP, { whoisVerify: false });
  assert.equal(r.status, "available(rdap-only)");
});

test("check: RDAP 429 retries until answered", async (t) => {
  const codes = [429, 429, 404];
  withInternals(t, { httpStatus: async () => codes.shift() });
  const r = await check("name", "com", RDAP);
  assert.equal(r.status, "available");
});

test("check: .dev 429 that outlasts the backoff reports 429, not no-whois-server", async (t) => {
  const rdap = { dev: "https://rdap.example/dev/" };
  const sleeps = [];
  let queries = 0;
  withInternals(t, {
    httpStatus: async () => { queries++; return 429; },
    whoisQuery: async () => "", // IANA lists no WHOIS server for .dev
    sleep: async (ms) => { sleeps.push(ms); },
  });
  const r = await check("name", "dev", rdap);
  assert.deepEqual(r, { status: "unverified(429)", source: rdap.dev });
  assert.equal(queries, RDAP_429_BACKOFF_MS.length + 1);
  for (const ms of RDAP_429_BACKOFF_MS) assert.ok(sleeps.includes(ms), `missing ${ms}ms backoff`);
});

test("check: a 429 slows later queries to that registry host only", async (t) => {
  const sleeps = [];
  const codes = [429, 404, 404, 404];
  withInternals(t, {
    httpStatus: async () => codes.shift(),
    sleep: async (ms) => { sleeps.push(ms); },
  });
  await check("a", "dev", { dev: "https://slow.example/" });
  sleeps.length = 0;
  await check("b", "dev", { dev: "https://slow.example/" });
  assert.equal(sleeps.length, 1);
  assert.ok(sleeps[0] > 0 && sleeps[0] <= 1500, `paced ${sleeps[0]}ms`);
  sleeps.length = 0;
  await check("c", "com", { com: "https://fast.example/" });
  assert.deepEqual(sleeps, []);
});

test("check: RDAP failure falls back to WHOIS", async (t) => {
  withInternals(t, {
    httpStatus: async () => 500,
    whoisQuery: whoisStub("No match for domain"),
  });
  const r = await check("name", "com", RDAP);
  assert.equal(r.status, "available");
  assert.equal(r.source, "whois.fake.test");
});

test("check: unknown TLD goes straight to WHOIS", async (t) => {
  withInternals(t, {
    httpStatus: async () => { throw new Error("RDAP must not be called"); },
    whoisQuery: whoisStub("Domain Name: NAME.ZZ\nRegistrar: X"),
  });
  const r = await check("name", "zz", RDAP);
  assert.equal(r.status, "registered");
});

test("loadRdapMap: bootstrap failure uses fallback + supplemental", async (t) => {
  const savedFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("offline"); };
  t.after(() => { globalThis.fetch = savedFetch; });
  const m = await loadRdapMap();
  assert.equal(m.com, FALLBACK_RDAP.com);
  for (const tld of Object.keys(SUPPLEMENTAL_RDAP)) assert.ok(m[tld], `missing ${tld}`);
});

test("loadRdapMap: bootstrap wins over supplemental", async (t) => {
  const savedFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    json: async () => ({ services: [[["io"], ["https://official.example/rdap"]]] }),
  });
  t.after(() => { globalThis.fetch = savedFetch; });
  const m = await loadRdapMap();
  assert.equal(m.io, "https://official.example/rdap/domain/");
  assert.equal(m.us, SUPPLEMENTAL_RDAP.us); // supplemental still fills the gaps
});

test("checkDomains: normalizes, skips comments/blanks, streams results", async (t) => {
  const savedFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("offline"); }; // fallback map
  t.after(() => { globalThis.fetch = savedFetch; });
  withInternals(t, { httpStatus: async () => 404 });

  const streamed = [];
  const records = await checkDomains(["  Alpha ", "# comment", "", "beta"], ["com"], {
    onResult: (r) => streamed.push(r.candidate),
  });
  assert.deepEqual(records.map((r) => r.candidate), ["alpha", "beta"]);
  assert.deepEqual(streamed, ["alpha", "beta"]);
  assert.equal(records[0].com, "available");
  assert.ok(records[0].checked_at);
});

test("settledCandidates: unverified results are retried, last record wins", () => {
  const lines = [
    JSON.stringify({ candidate: "taken", dev: "registered" }),
    JSON.stringify({ candidate: "throttled", dev: "unverified(429)" }),
    JSON.stringify({ candidate: "recovered", dev: "unverified(429)" }),
    JSON.stringify({ candidate: "recovered", dev: "available" }),
    JSON.stringify({ candidate: "regressed", dev: "available" }),
    JSON.stringify({ candidate: "regressed", dev: "unverified(ERR:TimeoutError)" }),
    "not json", "",
  ];
  assert.deepEqual([...settledCandidates(lines, ["dev"])].sort(), ["recovered", "taken"]);
});
