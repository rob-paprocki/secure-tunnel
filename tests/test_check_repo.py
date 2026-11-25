"""Tests for scripts/check_repo.py. Run: python -I -m unittest discover -s tests"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "check_repo", Path(__file__).resolve().parent.parent / "scripts" / "check_repo.py")
check_repo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_repo)


# Bad values are assembled at run time so this file passes its own check.
PRIV_HOST = ".".join(["10", "20", "30", "40"])
PRIV_NET = ".".join(["10", "20", "30", "0"]) + "/24"
PUB_HOST = ".".join(["93", "184", "216", "34"])
BAD_EMAIL = "person" + "@" + "corp-mail.test"
BAD_MAC = ":".join(["3c", "22", "fb", "12", "34", "56"])


class CheckRepoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "wordlist.local").write_text("zzsecretterm\n", encoding="utf-8")
        os.environ.pop("PRIVATE_WORDLIST_FILE", None)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            p.write_bytes(text)
        else:
            p.write_text(text, encoding="utf-8")

    def run_check(self, publish=False):
        return check_repo.check(self.root, publish)

    def test_clean_examples_pass(self):
        self.write("a.md", "Use 192.168.100.20, 192.0.2.1, 1.1.1.1, 127.0.0.1 and 172.16.0.0/12.\n"
                           "Mail ops@example.com, noreply@github.com or x@y.invalid. MAC 00:00:5E:00:53:01.\n")
        findings, _ = self.run_check()
        self.assertEqual(findings, [])

    def test_private_host_fails_without_printing_value(self):
        self.write("a.rs", f'let ip = "{PRIV_HOST}";\n')
        findings, _ = self.run_check()
        self.assertEqual(findings, ["a.rs:1: IP address"])

    def test_small_cidr_of_private_net_fails(self):
        self.write("a.md", f"My LAN is {PRIV_NET}\n")
        findings, _ = self.run_check()
        self.assertEqual(findings, ["a.md:1: IP address"])

    def test_public_host_fails(self):
        self.write("a.md", f"server {PUB_HOST}\n")
        self.assertEqual(self.run_check()[0], ["a.md:1: IP address"])

    def test_email_and_mac_fail(self):
        self.write("a.md", f"{BAD_EMAIL}\n{BAD_MAC}\n")
        self.assertEqual(self.run_check()[0], ["a.md:1: email address", "a.md:2: MAC address"])

    def test_wordlist_in_content_and_path(self):
        self.write("docs/zzsecretterm-notes.md", "hello\n")
        self.write("b.md", "x ZZSECRETTERM y\n")
        findings, _ = self.run_check()
        self.assertIn("docs/zzsecretterm-notes.md: word list matches the file path", findings)
        self.assertIn("b.md:1: word list match", findings)
        self.assertFalse(any("zzsecretterm" in f.lower() and "notes" not in f for f in findings))

    def test_private_dir_skipped_in_dev_but_not_publish(self):
        self.write("private/notes.md", f"{BAD_EMAIL}\n")
        self.assertEqual(self.run_check()[0], [])
        self.assertEqual(self.run_check(publish=True)[0], ["private/notes.md:1: email address"])

    def test_empty_wordlist_fails_publish_only(self):
        (self.root / "wordlist.local").write_text("\n", encoding="utf-8")
        self.write("a.md", "fine\n")
        self.assertEqual(self.run_check()[0], [])
        self.assertIn("private word list is missing or empty", self.run_check(publish=True)[0])

    def test_missing_wordlist_fails_publish(self):
        (self.root / "wordlist.local").unlink()
        self.write("a.md", "fine\n")
        self.assertIn("private word list is missing or empty", self.run_check(publish=True)[0])

    def test_binary_fails_publish(self):
        self.write("x.bin", b"\xff\xfe\x00bin")
        self.assertEqual(self.run_check()[0], [])
        self.assertEqual(self.run_check(publish=True)[0],
                         ["x.bin: not UTF-8 text and not in scripts/check-binaries.txt"])

    def test_reviewed_binary_passes_only_with_matching_hash(self):
        import hashlib
        blob = b"\xff\xfe\x00img"
        self.write("x.png", blob)
        self.write("scripts/check-binaries.txt", hashlib.sha256(blob).hexdigest() + " x.png\n")
        self.assertEqual(self.run_check(publish=True)[0], [])
        self.write("x.png", blob + b"changed")
        self.assertEqual(self.run_check(publish=True)[0],
                         ["x.png: not UTF-8 text and not in scripts/check-binaries.txt"])

    def test_allow_file_and_version_strings(self):
        self.write("scripts/check-allow.txt", "3.8.2.1  # version\n")
        self.write("a.md", "Original 3.8.2.1 and installer foo-3.8.2.1.exe\n")
        self.assertEqual(self.run_check()[0], [])


if __name__ == "__main__":
    unittest.main()
