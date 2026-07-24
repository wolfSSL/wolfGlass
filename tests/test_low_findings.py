#!/usr/bin/env python3
"""Regression tests for the low-severity review-findings bundle (gpex.20)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARE = os.path.join(REPO, "share")
GEN_SBOM = os.path.join(SHARE, "gen-sbom")
VALIDATE = os.path.join(SHARE, "validate_sbom.py")

gs = SourceFileLoader("gen_sbom", GEN_SBOM).load_module()
drv = SourceFileLoader("sbom_driver", os.path.join(SHARE, "sbom-driver.py")
                       ).load_module()
compdb = SourceFileLoader(
    "compdb_sbom", os.path.join(SHARE, "frontends", "compdb_sbom.py")
).load_module()


class TestAtomicWrite(unittest.TestCase):
    def test_writes_content_and_leaves_no_temp(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.json")
            gs.write_json_atomic({"a": 1}, p)
            with open(p) as f:
                self.assertEqual(json.load(f), {"a": 1})
            self.assertFalse(os.path.exists(p + ".tmp"))


class TestSrcsRealpathDedup(unittest.TestCase):
    def test_same_file_two_spellings_collapses(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "foo.c")
            open(f, "w").close()
            got = gs._collect_srcs([f, os.path.join(d, ".", "foo.c")], None)
            self.assertEqual(len(got), 1, got)


class TestValidateSbomRobustness(unittest.TestCase):
    def _run(self, content_or_none, name="x.cdx.json"):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, name)
            if content_or_none is not None:
                with open(p, "w") as f:
                    f.write(content_or_none)
            return subprocess.run([sys.executable, VALIDATE, p],
                                  capture_output=True, text=True)

    def test_non_dict_json_rejected_cleanly(self):
        r = self._run("[1, 2, 3]")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not an object", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_missing_file_no_traceback(self):
        r = self._run(None)  # file never created
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)


class TestScrubWindowsPath(unittest.TestCase):
    def test_windows_abs_path_redacted(self):
        out = drv.scrub_defines('#define SDK "C:\\Users\\me\\sdk"\n')
        self.assertNotIn("Users", out)
        self.assertIn("SDK", out)


class TestReadVersionEmptyMacro(unittest.TestCase):
    def test_empty_macro_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            h = os.path.join(d, "v.h")
            with open(h, "w") as f:
                f.write('#define COPYRIGHT "2026 wolfSSL"\n')
            self.assertEqual(drv.read_version(h, ""), "")


class TestCompdbUndefine(unittest.TestCase):
    def test_later_undef_cancels_define(self):
        got = compdb.extract_defines(["-DFOO", "-DBAR=1", "-UFOO"])
        self.assertIn("BAR=1", got)
        self.assertNotIn("FOO", got)

    def test_separate_arg_forms(self):
        got = compdb.extract_defines(["-D", "A=1", "-U", "A"])
        self.assertNotIn("A=1", got)


if __name__ == "__main__":
    unittest.main(verbosity=2)
