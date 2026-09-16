#!/usr/bin/env python3
"""Unit tests for central/advisory-completeness (the release advisory gate).

Run:
    python3 -m unittest central/test_advisory_completeness.py
"""

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / 'advisory-completeness'
ROOT = HERE.parent


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
# 5.9.2 has a body mention and a two-id bullet (strict drops the second id).
CHANGELOG = """\
# wolfSSL Release 5.9.2 (Jun 23, 2026)
## Vulnerabilities
* [High] CVE-2026-9001
  Incomplete-fix follow-up to CVE-2026-5460 (released in 5.9.1).
* [Med] CVE-2026-1111, CVE-2026-2222
  Two ids on one bullet.

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
        self.assertEqual(ac.cves_fixed_in_release(block),
                         ['CVE-2026-9001', 'CVE-2026-1111'])
        self.assertNotIn('CVE-2026-5460', ac.cves_fixed_in_release(block))

    def test_loose_set_names_ids_the_strict_rule_drops(self):
        block = ac.release_block(CHANGELOG, 'wolfSSL', '5.9.2')
        strict, loose = ac.cves_in_vuln_sections(block)
        self.assertEqual(strict, ['CVE-2026-9001', 'CVE-2026-1111'])
        self.assertEqual(loose, [
            'CVE-2026-9001', 'CVE-2026-5460', 'CVE-2026-1111', 'CVE-2026-2222',
        ])
        dropped = [c for c in loose if c not in set(strict)]
        self.assertEqual(dropped, ['CVE-2026-5460', 'CVE-2026-2222'])


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

    def test_changelog_reconcile_names_strict_drops(self):
        strict = ['CVE-2026-9001', 'CVE-2026-1111']
        loose = ['CVE-2026-9001', 'CVE-2026-5460', 'CVE-2026-1111',
                 'CVE-2026-2222']
        pin = ['CVE-2026-9001']
        prior = ['CVE-2026-1111']
        mentions = ['CVE-2026-5460', 'CVE-2026-2222']
        r = ac.reconcile_changelog(strict, loose, pin, prior, mentions)
        self.assertFalse(r['pin_missing'])
        self.assertFalse(r['pin_extra'])
        self.assertFalse(r['mentions_missing'])
        self.assertFalse(r['mentions_extra'])

    def test_changelog_reconcile_fails_unclassified_drop(self):
        strict = ['CVE-2026-9001', 'CVE-2026-1111']
        loose = ['CVE-2026-9001', 'CVE-2026-5460', 'CVE-2026-1111']
        r = ac.reconcile_changelog(strict, loose, strict, [], [])
        self.assertEqual(r['mentions_missing'], ['CVE-2026-5460'])


class OverlayLoadTests(unittest.TestCase):
    def test_comment_keys_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'overlay.json'
            p.write_text(json.dumps({
                '_comment': 'docs',
                'CVE-2026-5778': {'state': 'exploitable'},
            }))
            self.assertEqual(ac.load_overlay(str(p)), {'CVE-2026-5778'})

    def test_missing_fixed_version(self):
        overlay = {
            'CVE-2026-9001': {'fixed_versions': ['5.9.1']},
            'CVE-2026-9002': {'fixed_versions': ['5.9.2']},
        }
        bad = ac.overlay_missing_fixed_version(
            ['CVE-2026-9001', 'CVE-2026-9002'], overlay, '5.9.2')
        self.assertEqual(bad, ['CVE-2026-9001'])


class CliTests(unittest.TestCase):
    def _run(self, args):
        return subprocess.run(
            [sys.executable, str(SCRIPT)] + args,
            capture_output=True, text=True)

    def test_release_must_match_cve_list_stem(self):
        pin = ROOT / 'advisories' / 'releases' / '5.9.2.cves'
        r = self._run(['--cve-list', str(pin), '--release', '9.9.9'])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('--release 9.9.9', r.stderr)


class Release592CatalogueTests(unittest.TestCase):
    """The committed 5.9.2 pin list must be fully covered by records+overlay."""

    def test_pinned_list_is_fully_covered(self):
        pin = ROOT / 'advisories' / 'releases' / '5.9.2.cves'
        cves = ac.load_cve_list(pin)
        self.assertEqual(len(cves), 30)
        self.assertNotIn('CVE-2026-5460', cves)
        self.assertNotIn('CVE-2026-6679', cves)
        self.assertNotIn('CVE-2026-6681', cves)
        records = ac.records_present(ROOT / 'advisories' / 'records')
        overlay = ac.load_overlay(str(ROOT / 'advisories' / 'vex-overlay.json'))
        report = ac.build_report(cves, records, overlay)
        self.assertFalse(report['missing_record'], report['missing_record'])
        self.assertFalse(report['missing_overlay'], report['missing_overlay'])
        self.assertFalse(report['orphan_overlay'], report['orphan_overlay'])

    def test_overlay_fixed_versions_are_5_9_2(self):
        pin = ac.load_cve_list(ROOT / 'advisories' / 'releases' / '5.9.2.cves')
        overlay = ac.load_overlay_map(
            str(ROOT / 'advisories' / 'vex-overlay.json'))
        bad = ac.overlay_missing_fixed_version(pin, overlay, '5.9.2')
        self.assertFalse(bad, bad)

    def test_prior_release_ids_are_5_9_1_fixes(self):
        prior = ac.load_cve_list(
            ROOT / 'advisories' / 'releases' / '5.9.2.prior-release.cves')
        self.assertEqual(prior, ['CVE-2026-6679', 'CVE-2026-6681'])
        overlay = ac.load_overlay_map(
            str(ROOT / 'advisories' / 'vex-overlay.json'))
        for cve in prior:
            self.assertIn('5.9.1', overlay[cve]['fixed_versions'], cve)
            self.assertNotIn('5.9.2', overlay[cve]['fixed_versions'], cve)

    def test_pin_matches_frozen_changelog(self):
        pin = ac.load_cve_list(ROOT / 'advisories' / 'releases' / '5.9.2.cves')
        prior = ac.load_cve_list(
            ROOT / 'advisories' / 'releases' / '5.9.2.prior-release.cves')
        mentions = ac.load_cve_list(
            ROOT / 'advisories' / 'releases' / '5.9.2.mentions.cves')
        text = (HERE / 'testdata' / 'ChangeLog-5.9.2.md').read_text()
        block = ac.release_block(text, 'wolfSSL', '5.9.2')
        strict, loose = ac.cves_in_vuln_sections(block)
        r = ac.reconcile_changelog(strict, loose, pin, prior, mentions)
        self.assertFalse(r['pin_missing'], r)
        self.assertFalse(r['pin_extra'], r)
        self.assertFalse(r['mentions_missing'], r)
        self.assertFalse(r['mentions_extra'], r)
        self.assertFalse(r['prior_not_in_strict'], r)
        self.assertEqual(mentions, ['CVE-2026-5460'])


class Release592CdxRatingsTests(unittest.TestCase):
    """CycloneDX is the machine-readable CVSS v4 path (CSAF 2.0 has no v4)."""

    def test_every_pinned_cve_has_cvss_v4_rating(self):
        ga_loader = SourceFileLoader('ga', str(HERE / 'gen-advisory'))
        spec = importlib.util.spec_from_loader('ga', ga_loader)
        ga = importlib.util.module_from_spec(spec)
        ga_loader.exec_module(ga)
        pin = ac.load_cve_list(ROOT / 'advisories' / 'releases' / '5.9.2.cves')
        overlay = json.loads(
            (ROOT / 'advisories' / 'vex-overlay.json').read_text())
        rec_dir = ROOT / 'advisories' / 'records'
        advs = []
        for cve in pin:
            rec = json.loads((rec_dir / f'{cve}.json').read_text())
            advs.append(ga.parse_record(rec))
        bom = ga.generate_cdx_vex(advs, overlay, 'wolfssl-5.9.2',
                                  '2026-01-02T00:00:00Z')
        self.assertEqual(len(bom['vulnerabilities']), 30)
        missing = []
        for v in bom['vulnerabilities']:
            ratings = v.get('ratings') or []
            if not any(r.get('method') == 'CVSSv4' and r.get('score') is not None
                       for r in ratings):
                missing.append(v['id'])
        self.assertFalse(missing, missing)


if __name__ == '__main__':
    unittest.main()
