#!/usr/bin/env python3
"""Tests for tools/wolfglass-sync, focused on the --subdir containment guard.

--subdir is joined onto --dest and then written into, so an absolute value or
one containing .. must be refused rather than allowed to place/overwrite files
outside the product's vendoring path."""

import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYNC = os.path.join(REPO, "tools", "wolfglass-sync")


def _run(dest, subdir):
    return subprocess.run(
        [sys.executable, SYNC, "--dest", dest, "--subdir", subdir],
        capture_output=True, text=True)


class TestSubdirContainment(unittest.TestCase):
    def test_relative_subdir_copies_inside_dest(self):
        with tempfile.TemporaryDirectory() as dest:
            r = _run(dest, "tools/sbom")
            self.assertEqual(r.returncode, 0, r.stderr)
            # gen-sbom is part of share/, so it must land under the subdir.
            self.assertTrue(
                os.path.isfile(os.path.join(dest, "tools", "sbom", "gen-sbom")),
                os.listdir(dest))

    def test_absolute_subdir_rejected(self):
        with tempfile.TemporaryDirectory() as dest, \
                tempfile.TemporaryDirectory() as outside:
            target = os.path.join(outside, "pwned")
            r = _run(dest, target)               # absolute path
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--subdir", r.stderr)
            self.assertFalse(os.path.exists(target),
                             "absolute --subdir wrote outside --dest")

    def test_dotdot_subdir_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            dest = os.path.join(parent, "product")
            os.mkdir(dest)
            r = _run(dest, "../escape")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("escapes --dest", r.stderr)
            self.assertFalse(os.path.exists(os.path.join(parent, "escape")),
                             "../ --subdir wrote outside --dest")


if __name__ == "__main__":
    unittest.main(verbosity=2)
