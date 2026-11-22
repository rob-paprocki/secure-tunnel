"""Tests for scripts/fetch_vendor.py (no network: download() is replaced)."""
import hashlib
import importlib.util
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "fetch_vendor", Path(__file__).resolve().parent.parent / "scripts" / "fetch_vendor.py")
fv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fv)


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


class FetchVendorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (fv.VENDOR, fv.SOURCES, fv.download)
        fv.VENDOR = Path(self.tmp.name)
        self.good = b"driver bytes"
        self.zip = make_zip({"pkg/a.dll": self.good})
        fv.SOURCES = [("https://example.invalid/pkg.zip", hashlib.sha256(self.zip).hexdigest(),
                       {"pkg/a.dll": ("x/a.dll", hashlib.sha256(self.good).hexdigest())})]
        self.calls = 0

        def fake(url):
            self.calls += 1
            return self.zip
        fv.download = fake

    def tearDown(self):
        fv.VENDOR, fv.SOURCES, fv.download = self.saved
        self.tmp.cleanup()

    def test_fetches_then_skips(self):
        self.assertEqual(fv.main(["--check"]), 1)
        self.assertEqual(fv.main([]), 0)
        self.assertEqual((fv.VENDOR / "x/a.dll").read_bytes(), self.good)
        self.assertEqual(fv.main([]), 0)
        self.assertEqual(self.calls, 1)
        self.assertEqual(fv.main(["--check"]), 0)

    def test_replaces_tampered_file(self):
        (fv.VENDOR / "x").mkdir()
        (fv.VENDOR / "x/a.dll").write_bytes(b"tampered")
        self.assertEqual(fv.main([]), 0)
        self.assertEqual((fv.VENDOR / "x/a.dll").read_bytes(), self.good)

    def test_refuses_bad_zip_hash(self):
        self.zip = make_zip({"pkg/a.dll": self.good, "extra": b"x"})
        self.assertEqual(fv.main([]), 1)
        self.assertFalse((fv.VENDOR / "x/a.dll").exists())

    def test_refuses_bad_file_hash(self):
        self.zip = make_zip({"pkg/a.dll": b"evil"})
        url, _, members = fv.SOURCES[0]
        fv.SOURCES = [(url, hashlib.sha256(self.zip).hexdigest(), members)]
        self.assertEqual(fv.main([]), 1)
        self.assertFalse((fv.VENDOR / "x/a.dll").exists())


if __name__ == "__main__":
    unittest.main()
