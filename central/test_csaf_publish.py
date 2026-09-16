#!/usr/bin/env python3
"""Unit tests for central/csaf-publish (unsigned directory layout).

Run:
    python3 -m unittest central/test_csaf_publish.py
"""

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

HERE = pathlib.Path(__file__).resolve().parent
PUBLISH = HERE / 'csaf-publish'
GEN = HERE / 'gen-advisory'
TESTDATA = HERE / 'testdata'
EXAMPLE_OVERLAY = HERE / 'advisory-vex-overlay.example.json'


def _load(path, name):
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


pub = _load(PUBLISH, 'csaf_publish')
ga = _load(GEN, 'ga')


def _sha(path, algo):
    return hashlib.new(algo, path.read_bytes()).hexdigest()


class CanonicalNameTests(unittest.TestCase):
    def test_cve_id(self):
        self.assertEqual(pub.canonical_filename('CVE-2026-5501'),
                         'cve-2026-5501.json')

    def test_bundle_id(self):
        self.assertEqual(pub.canonical_filename('wolfssl-5.9.2'),
                         'wolfssl-5_9_2.json')


class UnsignedPublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.docs = self.root / 'docs'
        self.out = self.root / 'publish'
        self.docs.mkdir()
        adv = ga.parse_record(json.loads(
            (TESTDATA / 'CVE-2026-5501.json').read_text()))
        ov = json.loads(EXAMPLE_OVERLAY.read_text())
        csaf = ga.generate_csaf([adv], ov, adv['cve'], '2026-01-02T00:00:00Z')
        (self.docs / 'CVE-2026-5501.csaf.json').write_text(
            json.dumps(csaf, indent=2) + '\n')

    def tearDown(self):
        self.tmp.cleanup()

    def _publish(self):
        # Drive the CLI through the same argv path CI will use.
        import sys
        argv = sys.argv
        try:
            sys.argv = [
                'csaf-publish',
                '--docs-dir', str(self.docs),
                '--out-root', str(self.out),
                '--base-url', 'https://www.wolfssl.com/.well-known/csaf',
            ]
            pub.main()
        finally:
            sys.argv = argv
        return self.out / '.well-known' / 'csaf'

    def test_layout_hashes_and_self_url(self):
        csaf_root = self._publish()
        dest = csaf_root / 'white' / '2026' / 'cve-2026-5501.json'
        self.assertTrue(dest.is_file())
        doc = json.loads(dest.read_text())
        selfs = [r['url'] for r in doc['document']['references']
                 if r.get('category') == 'self']
        self.assertEqual(
            selfs,
            ['https://www.wolfssl.com/.well-known/csaf/white/2026/cve-2026-5501.json'])
        for algo in ('sha256', 'sha512'):
            side = dest.with_name(dest.name + '.' + algo)
            want = side.read_text().split()[0]
            self.assertEqual(want, _sha(dest, algo))
        index = csaf_root.joinpath('index.txt').read_text().splitlines()
        self.assertEqual(index, ['white/2026/cve-2026-5501.json'])
        md = json.loads((csaf_root / 'provider-metadata.json').read_text())
        self.assertEqual(md['role'], 'csaf_provider')
        self.assertNotIn('public_openpgp_keys', md)

    def test_rerun_drops_stale_files(self):
        csaf_root = self._publish()
        stale = csaf_root / 'white' / '2026' / 'cve-1999-0001.json'
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text('{}\n')
        self._publish()
        self.assertFalse(stale.exists())
        json_docs = sorted(p.name for p in (csaf_root / 'white' / '2026').glob('*.json'))
        self.assertEqual(json_docs, ['cve-2026-5501.json'])


if __name__ == '__main__':
    unittest.main()
