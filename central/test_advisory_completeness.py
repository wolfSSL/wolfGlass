#!/usr/bin/env python3
"""Unit tests for central/advisory-completeness (the release advisory gate).

Run:
    python3 -m unittest central/test_advisory_completeness.py
"""

import importlib.util
import json
import pathlib
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / 'advisory-completeness'


def _load():
    loader = SourceFileLoader('ac', str(SCRIPT))
    spec = importlib.util.spec_from_loader('ac', loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


ac = _load()

# A minimal ChangeLog with two releases. 5.9.1 has a normal Vulnerabilities
# section plus a second vuln-titled section, and a Bug Fixes section that
# mentions an *unrelated* CVE which must NOT be counted as fixed here.
CHANGELOG = """\
# wolfSSL Release 5.9.2 (Jun 23, 2026)
## Vulnerabilities
* [High] CVE-2026-9001
  Incomplete-fix follow-up to CVE-2026-5460 (released in 5.9.1).

# wolfSSL Release 5.9.1 (Apr. 8, 2026)
## Vulnerabilities
* [Critical] CVE-2026-5194
  A.
* [High] CVE-2026-5778
  B.
## Experimental Build Vulnerability
* [Low] CVE-2026-5507
  C.
## Bug Fixes
* Regression from the CVE-2020-0001 fix; not a new advisory.

# wolfSSL Release 5.9.0 (Mar. 18, 2026)
## Vulnerabilities
* [Low] CVE-2026-1000
  Old.
"""


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.block = ac.release_block(CHANGELOG, 'wolfSSL', '5.9.1')

    def test_block_is_scoped_to_the_release(self):
        text = '\n'.join(self.block)
        self.assertIn('CVE-2026-5194', text)
        self.assertNotIn('CVE-2026-9001', text)   # belongs to 5.9.2
        self.assertNotIn('CVE-2026-1000', text)   # belongs to 5.9.0

    def test_counts_both_vuln_sections(self):
        cves = ac.cves_fixed_in_release(self.block)
        self.assertEqual(set(cves),
                         {'CVE-2026-5194', 'CVE-2026-5778', 'CVE-2026-5507'})

    def test_excludes_non_vuln_sections(self):
        # The CVE named only under Bug Fixes must not be counted.
        self.assertNotIn('CVE-2020-0001', ac.cves_fixed_in_release(self.block))

    def test_missing_release_exits(self):
        with self.assertRaises(SystemExit):
            ac.release_block(CHANGELOG, 'wolfSSL', '9.9.9')


    def test_excludes_cve_named_only_in_bullet_body(self):
        block = ac.release_block(CHANGELOG, 'wolfSSL', '5.9.2')
        self.assertEqual(ac.cves_fixed_in_release(block), ['CVE-2026-9001'])
        self.assertNotIn('CVE-2026-5460', ac.cves_fixed_in_release(block))


class ReconcileTests(unittest.TestCase):
    def test_gap_is_reported(self):
        release = ['CVE-2026-5194', 'CVE-2026-5778', 'CVE-2026-5507']
        records = {'CVE-2026-5778'}
        overlay = {'CVE-2026-5778'}
        r = ac.build_report(release, records, overlay)
        self.assertEqual(r['missing_record'], ['CVE-2026-5194', 'CVE-2026-5507'])
        self.assertEqual(r['missing_overlay'], ['CVE-2026-5194', 'CVE-2026-5507'])

    def test_full_coverage_has_no_gap(self):
        release = ['CVE-2026-5778']
        r = ac.build_report(release, {'CVE-2026-5778'}, {'CVE-2026-5778'})
        self.assertFalse(r['missing_record'])
        self.assertFalse(r['missing_overlay'])
        self.assertFalse(r['orphan_overlay'])

    def test_orphan_overlay_detected(self):
        # An overlay entry pointing at a CVE with no record is broken input.
        release = ['CVE-2026-5778']
        r = ac.build_report(release, {'CVE-2026-5778'},
                            {'CVE-2026-5778', 'CVE-2026-0000'})
        self.assertEqual(r['orphan_overlay'], ['CVE-2026-0000'])


class OverlayLoadTests(unittest.TestCase):
    def test_comment_keys_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'overlay.json'
            p.write_text(json.dumps({
                '_comment': 'docs',
                'CVE-2026-5778': {'state': 'exploitable'},
            }))
            self.assertEqual(ac.load_overlay(str(p)), {'CVE-2026-5778'})


class Release592CatalogueTests(unittest.TestCase):
    """The committed 5.9.2 pin list must be fully covered by records+overlay."""

    def test_pinned_list_is_fully_covered(self):
        root = HERE.parent
        pin = root / 'advisories' / 'releases' / '5.9.2.cves'
        cves = ac.load_cve_list(pin)
        self.assertEqual(len(cves), 32)
        self.assertNotIn('CVE-2026-5460', cves)
        records = ac.records_present(root / 'advisories' / 'records')
        overlay = ac.load_overlay(str(root / 'advisories' / 'vex-overlay.json'))
        report = ac.build_report(cves, records, overlay)
        self.assertFalse(report['missing_record'], report['missing_record'])
        self.assertFalse(report['missing_overlay'], report['missing_overlay'])
        self.assertFalse(report['orphan_overlay'], report['orphan_overlay'])


if __name__ == '__main__':
    unittest.main()
