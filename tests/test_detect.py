import unittest

from mini_aibom.detect import find_endpoints, find_keys, mask


class EndpointTests(unittest.TestCase):
    def hosts(self, text):
        return [h for h, _ in find_endpoints(text)]

    def test_real_endpoint_matches(self):
        self.assertEqual(self.hosts("url = 'https://api.openai.com/v1/chat'"), ["api.openai.com"])

    def test_sentence_ending_period_still_matches(self):
        self.assertEqual(self.hosts("We call api.openai.com. Then we stop."), ["api.openai.com"])

    def test_lookalike_suffix_domain_rejected(self):
        self.assertEqual(self.hosts("https://api.openai.com.evil.example/x"), [])

    def test_lookalike_prefix_rejected(self):
        self.assertEqual(self.hosts("https://myapi.openai.com/x"), [])
        self.assertEqual(self.hosts("https://notapi.openai.com/x"), [])

    def test_hyphen_lookalike_rejected(self):
        self.assertEqual(self.hosts("https://api.openai.com-fake.io/x"), [])

    def test_local_ollama_with_port(self):
        self.assertEqual(self.hosts("http://localhost:11434/api/generate"), ["localhost:11434"])


class KeyTests(unittest.TestCase):
    def test_anthropic_not_double_counted(self):
        keys = find_keys("sk-ant-" + "A" * 30)
        self.assertEqual([p for p, _ in keys], ["Anthropic"])

    def test_mask_hides_middle(self):
        m = mask("sk-FAKEFAKEFAKEFAKEFAKEFAKE1234")
        self.assertEqual(m, "sk-FAK...34")


if __name__ == "__main__":
    unittest.main()
