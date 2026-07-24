#!/usr/bin/env python3
"""gen-sbom --dep-* flags must be strictly yes/no.

A value that is neither (1, true, on, an empty string) must fail loudly rather
than be silently treated as 'no' -- a silently dropped dependency hides a
CVE-bearing component from the SBOM."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN_SBOM = os.path.join(REPO, "share", "gen-sbom")


class TestDepFlagValidation(unittest.TestCase):
    def _run(self, d, dep_value, tag):
        oh = os.path.join(d, "o.h")
        with open(oh, "w") as f:
            f.write("#define HAVE_AES 1\n")
        lib = os.path.join(d, "l.a")
        with open(lib, "wb") as f:
            f.write(b"!<arch>\n" + b"\0" * 16)
        lic = os.path.join(d, "LIC")
        with open(lic, "w") as f:
            f.write("GPL-2.0-only\n")
        cdx = os.path.join(d, f"{tag}.cdx.json")
        spdx = os.path.join(d, f"{tag}.spdx.json")
        r = subprocess.run(
            [sys.executable, GEN_SBOM, "--name", "wolfssh", "--version",
             "1.0.0", "--options-h", oh, "--lib", lib, "--license-file", lic,
             "--dep-wolfssl", dep_value, "--cdx-out", cdx, "--spdx-out", spdx],
            capture_output=True, text=True)
        return r, cdx

    def _dep_names(self, cdx):
        with open(cdx) as f:
            return {c["name"] for c in json.load(f).get("components", [])}

    def test_yes_records_dependency(self):
        with tempfile.TemporaryDirectory() as d:
            r, cdx = self._run(d, "yes", "y")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("wolfssl", self._dep_names(cdx))

    def test_no_omits_dependency(self):
        with tempfile.TemporaryDirectory() as d:
            r, cdx = self._run(d, "no", "n")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("wolfssl", self._dep_names(cdx))

    def test_bad_value_fails_loudly(self):
        # These previously coerced silently to 'no', dropping the dependency.
        for bad in ("1", "true", "on", "Y", ""):
            with tempfile.TemporaryDirectory() as d:
                r, _ = self._run(d, bad, "bad")
                self.assertNotEqual(r.returncode, 0,
                                    f"--dep-wolfssl {bad!r} was accepted")
                self.assertIn("must be 'yes' or 'no'", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
