"""Log scanner tests. The fixtures are HAND-WRITTEN (formats from memory, not
real captures), so these prove the logic, not compatibility with every real log."""
import tempfile
import unittest
from pathlib import Path

from mini_aibom.detect import match_ai_host
from mini_aibom.scanners.log_scanner import LogScanner

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "logs"


def scan_text(text):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "t.log"
        p.write_text(text)
        return LogScanner().scan(p)


def summary(findings):
    """{(vendor, source): count}, parsed back out of the evidence string."""
    out = {}
    for c in findings:
        count = int(c.evidence.split()[0])
        source = c.evidence.split(" from ")[1].split(" to ")[0]
        out[(c.name, source)] = count
    return out


class FixtureTests(unittest.TestCase):
    def test_dns_counts_per_source(self):
        s = summary(LogScanner().scan(FIX / "dns_sample_HANDWRITTEN.log"))
        self.assertEqual(s, {
            ("OpenAI", "192.168.1.10"): 2,
            ("Anthropic", "192.168.1.20"): 1,
            ("OpenAI", "192.168.1.30"): 1,   # only the REAL lookup, lookalikes excluded
        })

    def test_proxy_format(self):
        s = summary(LogScanner().scan(FIX / "proxy_sample_HANDWRITTEN.log"))
        self.assertEqual(s, {("OpenAI", "10.0.0.5"): 2,
                             ("Google Generative AI", "10.0.0.7"): 1})  # example.org ignored

    def test_first_line_number_recorded(self):
        f = LogScanner().scan(FIX / "dns_sample_HANDWRITTEN.log")
        first = [c for c in f if "192.168.1.10" in c.evidence][0]
        self.assertEqual(first.line, 1)


class MatchingTests(unittest.TestCase):
    def test_lookalikes_rejected(self):
        for bad in ["api.openai.com.evil.example", "myapi.openai.com",
                    "notopenai.com", "openai.com", "com"]:
            self.assertIsNone(match_ai_host(bad), bad)

    def test_subdomain_accepted(self):
        self.assertEqual(match_ai_host("eu.api.openai.com")[1], "OpenAI")

    def test_case_and_trailing_dot(self):
        self.assertEqual(len(scan_text("query API.OpenAI.COM. from 1.2.3.4\n")), 1)


class RobustnessTests(unittest.TestCase):
    def test_empty_and_garbage(self):
        self.assertEqual(scan_text(""), [])
        self.assertEqual(scan_text("\n\n???\n\x00\x01 binaryish \xff\n"), [])

    def test_unknown_source_when_no_ip(self):
        f = scan_text("lookup api.openai.com\n")
        self.assertEqual(summary(f), {("OpenAI", "unknown"): 1})

    def test_large_log_is_streamed_not_skipped(self):
        # >1 MB would be skipped by read_text_safe; a real log scanner must not.
        filler = "Oct 28 09:00:01 dnsmasq[1]: query[A] www.example.com from 10.1.1.1\n" * 30000
        text = filler + "query[A] api.openai.com from 10.9.9.9\n"
        self.assertGreater(len(text), 1_000_000)
        self.assertEqual(summary(scan_text(text)), {("OpenAI", "10.9.9.9"): 1})

    def test_many_repeats_become_one_finding(self):
        f = scan_text("q api.openai.com from 10.0.0.1\n" * 500)
        self.assertEqual(len(f), 1)
        self.assertTrue(f[0].evidence.startswith("500 hit(s)"))


if __name__ == "__main__":
    unittest.main()
