#!/usr/bin/env python3
"""Tests for the IAR frontend (share/frontends/iar_sbom.py).

Focus: collect_sources must honour IAR's per-configuration <excluded> markers,
so a file excluded from the selected build configuration is not reported as a
compiled source (which would over-report the artifact's source set)."""

import importlib.util
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IAR = os.path.join(REPO, "share", "frontends", "iar_sbom.py")

_spec = importlib.util.spec_from_file_location("iar_sbom", IAR)
iar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(iar)

# a.c: compiled in every config; b.c: excluded from Release;
# c.c: excluded from Debug only.
_EWP = """<project>
  <file><name>$PROJ_DIR$/a.c</name></file>
  <file><name>$PROJ_DIR$/b.c</name>
    <excluded><configuration>Release</configuration></excluded>
  </file>
  <file><name>$PROJ_DIR$/c.c</name>
    <excluded><configuration>Debug</configuration></excluded>
  </file>
</project>"""


class TestExcludedFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = self.tmp.name
        for n in ("a.c", "b.c", "c.c"):
            open(os.path.join(self.proj, n), "w").close()
        self.root = ET.fromstring(_EWP)

    def tearDown(self):
        self.tmp.cleanup()

    def _names(self, cfg):
        present, _missing = iar.collect_sources(self.root, self.proj, cfg)
        return {os.path.basename(p) for p in present}

    def test_release_drops_file_excluded_from_release(self):
        names = self._names("Release")
        self.assertIn("a.c", names)
        self.assertIn("c.c", names)            # excluded from Debug, not Release
        self.assertNotIn("b.c", names)         # excluded from Release

    def test_debug_drops_file_excluded_from_debug(self):
        names = self._names("Debug")
        self.assertIn("a.c", names)
        self.assertIn("b.c", names)            # excluded from Release, not Debug
        self.assertNotIn("c.c", names)         # excluded from Debug


if __name__ == "__main__":
    unittest.main(verbosity=2)
