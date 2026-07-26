"""Unit tests for check_domains.py — fully offline, all network mocked.

Run:  python -m unittest -v
"""
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

import check_domains as cd


class ClassifyWhoisTests(unittest.TestCase):
    """Real-world WHOIS response dialects must classify correctly."""

    def test_cira_restricted(self):
        text = ("Error code: 01044\n"
                "Error message: The domain name requested has usage restrictions "
                "applied to it. Please see your Registrar for more details.")
        self.assertEqual(cd.classify_whois(text), "restricted")

    def test_cira_available(self):
        self.assertEqual(cd.classify_whois("Not found: xqzvkwplormtj.ca"), "available")

    def test_verisign_registered(self):
        text = "   Domain Name: GOOGLE.COM\n   Registrar: MarkMonitor Inc."
        self.assertEqual(cd.classify_whois(text), "registered")

    def test_denic_free_domain_echo_is_not_registered(self):
        # DENIC echoes "Domain: <name>" even for free domains.
        text = "Domain: xqzvkwplormtj.de\nStatus: free"
        self.assertEqual(cd.classify_whois(text), "available")

    def test_denic_registered(self):
        text = "Domain: google.de\nStatus: connect"
        self.assertEqual(cd.classify_whois(text), "registered")

    def test_it_padded_status_column(self):
        text = "Domain:             xqz.it\nStatus:             AVAILABLE"
        self.assertEqual(cd.classify_whois(text), "available")

    def test_nz_active(self):
        text = "domain_name: google.nz\nquery_status: 200 Active"
        self.assertEqual(cd.classify_whois(text), "registered")

    def test_nz_available(self):
        self.assertEqual(cd.classify_whois("query_status: 220 Available"), "available")

    def test_mx_free(self):
        self.assertEqual(cd.classify_whois("Object_Not_Found"), "available")

    def test_at_free(self):
        self.assertEqual(cd.classify_whois("% nothing found"), "available")

    def test_ch_registered(self):
        self.assertEqual(cd.classify_whois("Holder of domain name: Example LLC"), "registered")

    def test_boilerplate_restricted_word_does_not_poison_registered(self):
        # .us/.co legal boilerplate contains "restricted" — must still classify
        # as registered when registration evidence is present.
        text = ("Access to this service is restricted to query-based lookups.\n"
                "Domain Name: GOOGLE.US")
        self.assertEqual(cd.classify_whois(text), "registered")

    def test_garbage_is_unverified(self):
        self.assertEqual(cd.classify_whois("hello world"), "unverified")


class RdapCheckTests(unittest.TestCase):
    def test_404_is_available(self):
        with mock.patch.object(cd, "http_status", return_value=404):
            self.assertEqual(cd.rdap_check("https://r/", "x.com"), "available")

    def test_200_is_registered(self):
        with mock.patch.object(cd, "http_status", return_value=200):
            self.assertEqual(cd.rdap_check("https://r/", "x.com"), "registered")

    def test_429_retries_once(self):
        with mock.patch.object(cd, "http_status", side_effect=[429, 404]), \
             mock.patch.object(cd.time, "sleep"):
            self.assertEqual(cd.rdap_check("https://r/", "x.com"), "available")

    def test_error_is_unverified(self):
        with mock.patch.object(cd, "http_status", return_value="ERR:Timeout"):
            self.assertTrue(cd.rdap_check("https://r/", "x.com").startswith("unverified"))


class CheckFlowTests(unittest.TestCase):
    RDAP = {"com": "https://rdap.example/com/", "ca": "https://rdap.example/ca/"}

    def test_gtld_available_skips_whois(self):
        with mock.patch.object(cd, "rdap_check", return_value="available") as rc, \
             mock.patch.object(cd, "whois_check") as wc:
            status, source = cd.check("name", "com", self.RDAP)
        self.assertEqual(status, "available")
        self.assertEqual(source, self.RDAP["com"])
        wc.assert_not_called()

    def test_registered_returns_immediately(self):
        with mock.patch.object(cd, "rdap_check", return_value="registered"), \
             mock.patch.object(cd, "whois_check") as wc:
            status, _ = cd.check("name", "ca", self.RDAP)
        self.assertEqual(status, "registered")
        wc.assert_not_called()

    def test_ca_available_confirmed_by_whois(self):
        with mock.patch.object(cd, "rdap_check", return_value="available"), \
             mock.patch.object(cd, "whois_check", return_value=("available", "whois.cira.ca")):
            status, source = cd.check("name", "ca", self.RDAP)
        self.assertEqual(status, "available")
        self.assertIn("whois.cira.ca", source)

    def test_ca_restricted_overrides_rdap(self):
        with mock.patch.object(cd, "rdap_check", return_value="available"), \
             mock.patch.object(cd, "whois_check", return_value=("restricted", "whois.cira.ca")):
            status, _ = cd.check("pottery", "ca", self.RDAP)
        self.assertEqual(status, "restricted")

    def test_ca_whois_failure_degrades_to_rdap_only(self):
        with mock.patch.object(cd, "rdap_check", return_value="available"), \
             mock.patch.object(cd, "whois_check", return_value=("unverified", "whois.cira.ca(error)")):
            status, _ = cd.check("name", "ca", self.RDAP)
        self.assertEqual(status, "available(rdap-only)")

    def test_ca_no_verify_flag(self):
        with mock.patch.object(cd, "rdap_check", return_value="available"), \
             mock.patch.object(cd, "whois_check") as wc:
            status, _ = cd.check("name", "ca", self.RDAP, whois_verify=False)
        self.assertEqual(status, "available(rdap-only)")
        wc.assert_not_called()

    def test_rdap_unverified_falls_back_to_whois(self):
        with mock.patch.object(cd, "rdap_check", return_value="unverified(500)"), \
             mock.patch.object(cd, "whois_check", return_value=("available", "whois.x")):
            status, source = cd.check("name", "com", self.RDAP)
        self.assertEqual(status, "available")
        self.assertEqual(source, "whois.x")

    def test_unknown_tld_uses_whois(self):
        with mock.patch.object(cd, "whois_check", return_value=("registered", "whois.y")):
            status, _ = cd.check("name", "zz", self.RDAP)
        self.assertEqual(status, "registered")


class FakeResponse:
    def __init__(self, payload):
        self._body = io.BytesIO(json.dumps(payload).encode())
        self.status = 200

    def read(self, *a):
        return self._body.read(*a)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class LoadRdapMapTests(unittest.TestCase):
    def test_bootstrap_failure_uses_fallback_plus_supplemental(self):
        with mock.patch.object(cd.urllib.request, "urlopen", side_effect=OSError):
            m = cd.load_rdap_map()
        self.assertEqual(m["com"], cd.FALLBACK_RDAP["com"])
        for tld in cd.SUPPLEMENTAL_RDAP:
            self.assertIn(tld, m)

    def test_bootstrap_wins_over_supplemental(self):
        payload = {"services": [[["io"], ["https://official.example/rdap"]]]}
        with mock.patch.object(cd.urllib.request, "urlopen", return_value=FakeResponse(payload)):
            m = cd.load_rdap_map()
        self.assertEqual(m["io"], "https://official.example/rdap/domain/")
        # supplemental still fills TLDs the bootstrap lacks
        self.assertEqual(m["us"], cd.SUPPLEMENTAL_RDAP["us"])


class MainLedgerTests(unittest.TestCase):
    def test_dedup_comments_and_append(self):
        with tempfile.TemporaryDirectory() as tmp:
            names = os.path.join(tmp, "names.txt")
            out = os.path.join(tmp, "out.jsonl")
            with open(names, "w") as f:
                f.write("Alpha\nalpha\n# comment\nbeta\n")
            patches = (
                mock.patch.object(cd, "load_rdap_map", return_value={}),
                mock.patch.object(cd, "check", return_value=("available", "src")),
                mock.patch.object(cd.time, "sleep"),
                mock.patch.object(sys, "argv", ["check_domains.py", names, out]),
                mock.patch("sys.stdout", new_callable=io.StringIO),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                cd.main()
                with open(out) as f:
                    first = [json.loads(l) for l in f]
                cd.main()  # second run: everything already in the ledger
                with open(out) as f:
                    second = [json.loads(l) for l in f]
        self.assertEqual([r["candidate"] for r in first], ["alpha", "beta"])
        self.assertEqual(len(second), 2)
        for rec in first:
            self.assertEqual(rec["com"], "available")
            self.assertEqual(rec["ai"], "available")
            self.assertIn("checked_at", rec)


if __name__ == "__main__":
    unittest.main()
