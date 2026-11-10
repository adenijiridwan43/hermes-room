import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import sanitizer

FIXTURES = ROOT / "fixtures"


class SanitizerTests(unittest.TestCase):
    def test_poisoned_html_is_washed(self):
        raw = (FIXTURES / "poisoned.html").read_text(encoding="utf-8")
        out = sanitizer.sanitize_text(raw, tool_name="web_extract", args={"url": "https://example.com"})
        self.assertTrue(out.changed)
        self.assertNotIn("Ignore previous instructions", out.cleaned)
        self.assertNotIn("evil.example/collect", out.cleaned)
        self.assertIn("hidden", out.cleaned.lower())
        self.assertEqual(out.risk, "high")
        self.assertEqual(out.original_sha256, sanitizer.hashlib.sha256(raw.encode("utf-8")).hexdigest())

    def test_clean_html_is_unchanged(self):
        raw = (FIXTURES / "clean.html").read_text(encoding="utf-8")
        out = sanitizer.sanitize_text(raw, tool_name="web_extract", args={"url": "https://example.com"})
        self.assertFalse(out.changed)
        self.assertEqual(out.cleaned, raw)

    def test_hidden_unicode_removed(self):
        raw = (FIXTURES / "hidden-unicode.txt").read_text(encoding="utf-8")
        out = sanitizer.sanitize_text(raw, tool_name="read_file", args={"path": "hidden-unicode.txt"})
        self.assertTrue(out.changed)
        self.assertNotIn("\u200b", out.cleaned)
        self.assertGreaterEqual(out.removed.get("zero_width", 0), 1)

    def test_ansi_removed(self):
        raw = (FIXTURES / "terminal-ansi.txt").read_text(encoding="utf-8")
        out = sanitizer.sanitize_text(raw, tool_name="terminal", args={"command": "make"})
        self.assertTrue(out.changed)
        self.assertNotIn("\x1b", out.cleaned)
        self.assertGreaterEqual(out.removed.get("ansi_escapes", 0), 1)


    def test_secret_output_masked(self):
        raw = (FIXTURES / "secret-output.txt").read_text(encoding="utf-8")
        out = sanitizer.sanitize_text(raw, tool_name="terminal", args={"command": "env"})
        self.assertTrue(out.changed)
        self.assertEqual(out.risk, "high")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out.cleaned)
        self.assertNotIn("wJalrXUtnFEMI", out.cleaned)
        self.assertNotIn("ghp_1234567890", out.cleaned)
        self.assertNotIn("PRIVATE KEY-----", out.cleaned)
        self.assertGreaterEqual(out.removed.get("secret_aws_access_key", 0), 1)
        self.assertGreaterEqual(out.removed.get("private_key_block", 0), 1)


if __name__ == "__main__":
    unittest.main()
