#!/usr/bin/env python3
"""Unit tests for central/advisory-overlay-draft.

Run:
    python3 -m unittest central/test_advisory_overlay_draft.py
"""

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest
from importlib.machinery import SourceFileLoader

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / 'advisory-overlay-draft'


def _load():
    loader = SourceFileLoader('aod', str(SCRIPT))
    spec = importlib.util.spec_from_loader('aod', loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


aod = _load()

# The second paragraph names the real gate. A later sentence names a macro
# only to say the default path is not affected. The drafter must keep the
# first and drop the second. That was the 5.9.2 review miss.
CHANGELOG = textwrap.dedent("""\
    # wolfSSL Release 5.9.4 (Sep 17, 2026)
    ## Vulnerabilities
    * [High] CVE-2026-11310
      X.509 trust-chain bypass in the OpenSSL compatibility certificate verifier.

      This affects only builds with --enable-opensslextra (OPENSSL_EXTRA).
      The default wolfSSL TLS handshake (WOLFSSL_VERIFY_PEER) is not affected.
      Manual verification also requires --enable-sessioncerts.
    * [High] CVE-2026-55960
      Raw public key accepted without a chain. Only affects builds with Raw Public Key support (HAVE_RPK) enabled - disabled by default.
    * [Med] CVE-2026-1111, CVE-2026-2222
      Two ids on one bullet. Builds that define WOLFSSL_SNIFFER are affected.

    # wolfSSL Release 5.9.2 (Jun 23, 2026)
    ## Vulnerabilities
    * [Low] CVE-2026-1000
      Old.
    """)


class GuessTests(unittest.TestCase):
    def test_keeps_enable_macro_and_drops_not_affected_macro(self):
        text = (
            'This affects only builds with --enable-opensslextra (OPENSSL_EXTRA). '
            'The default wolfSSL TLS handshake (WOLFSSL_VERIFY_PEER) is not affected. '
            'Manual verification also requires --enable-sessioncerts.'
        )
        macros, flags = aod.guess_defines(text)
        self.assertEqual(macros, ['OPENSSL_EXTRA'])
        self.assertEqual(flags, ['--enable-sessioncerts'])

    def test_paren_support_macro_and_default_off(self):
        text = ('Only affects builds with Raw Public Key support (HAVE_RPK) '
                'enabled - disabled by default.')
        macros, flags = aod.guess_defines(text)
        self.assertEqual(macros, ['HAVE_RPK'])
        self.assertEqual(flags, [])
        self.assertEqual(aod.guess_default_status(text), 'off')

    def test_define_keyword_before_a_bare_macro(self):
        macros, _flags = aod.guess_defines(
            'Builds that define WOLFSSL_SNIFFER are affected.')
        self.assertEqual(macros, ['WOLFSSL_SNIFFER'])

    def test_does_not_take_a_macro_that_is_not_defined(self):
        macros, _flags = aod.guess_defines(
            'Builds where WOLFSSL_SNIFFER is not defined are safe.')
        self.assertEqual(macros, [])

    def test_unless_defined_is_not_the_gate(self):
        macros, flags = aod.guess_defines(
            'The check applies unless ALLOW_INVALID_CERTSIGN is defined. '
            'Note this only affects builds with SM2 support (--enable-sm2 or --enable-all).')
        self.assertNotIn('ALLOW_INVALID_CERTSIGN', macros)
        self.assertEqual(flags, ['--enable-sm2'])


class BulletTests(unittest.TestCase):
    def setUp(self):
        self.block = aod.ac.release_block(CHANGELOG, 'wolfSSL', '5.9.4')

    def test_strict_bullets_and_extra_id(self):
        bullets = aod.bullet_bodies(self.block)
        self.assertEqual([b['cve'] for b in bullets],
                         ['CVE-2026-11310', 'CVE-2026-55960', 'CVE-2026-1111'])
        extra = bullets[2]['extra_ids']
        self.assertEqual(extra, ['CVE-2026-2222'])

    def test_detail_is_the_first_paragraph_only(self):
        bullets = aod.bullet_bodies(self.block)
        entry, _notes = aod.draft_entry('wolfSSL', '5.9.4', bullets[0]['body'])
        self.assertEqual(
            entry['detail'],
            'X.509 trust-chain bypass in the OpenSSL compatibility certificate verifier.')
        self.assertEqual(entry['fixed_versions'], ['5.9.4'])
        self.assertEqual(entry['remediation'], 'Update to wolfSSL 5.9.4 or later.')
        self.assertEqual(entry['requires_defines'], ['OPENSSL_EXTRA'])
        self.assertNotIn('default_status', entry)

    def test_default_off_is_recorded(self):
        bullets = aod.bullet_bodies(self.block)
        entry, _notes = aod.draft_entry('wolfSSL', '5.9.4', bullets[1]['body'])
        self.assertEqual(entry['requires_defines'], ['HAVE_RPK'])
        self.assertEqual(entry['default_status'], 'off')


class SpliceTests(unittest.TestCase):
    def test_append_keeps_existing_escape_bytes(self):
        original = textwrap.dedent("""\
            {
              "_comment": "keep",
              "CVE-2026-1000": {
                "state": "exploitable",
                "detail": "API\\u2019s stay escaped"
              }
            }
            """)
        entry = {
            'state': 'exploitable',
            'response': ['update'],
            'detail': 'New.',
            'fixed_versions': ['5.9.4'],
            'remediation': 'Update to wolfSSL 5.9.4 or later.',
        }
        out = aod.splice_entries(original, [('CVE-2026-11310', entry)])
        self.assertIn('API\\u2019s stay escaped', out)
        data = json.loads(out)
        self.assertEqual(data['CVE-2026-1000']['detail'], 'API\u2019s stay escaped')
        self.assertEqual(data['CVE-2026-11310']['fixed_versions'], ['5.9.4'])
        self.assertEqual(list(data)[0], '_comment')

    def test_build_drafts_does_not_replace_an_existing_key(self):
        actions, notes = aod.build_drafts(
            CHANGELOG, 'wolfSSL', '5.9.4', {'CVE-2026-11310'}, replace=False)
        cves = [cve for cve, _entry in actions]
        self.assertNotIn('CVE-2026-11310', cves)
        self.assertIn('CVE-2026-55960', cves)
        self.assertTrue(any(line.startswith('kept ')
                            for line in notes['CVE-2026-11310']))
        self.assertTrue(any('CVE-2026-2222' in line for line in notes['CVE-2026-1111']))


class CliTests(unittest.TestCase):
    def test_dry_run_writes_nothing_and_live_run_appends(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            changelog = root / 'ChangeLog.md'
            changelog.write_text(CHANGELOG)
            overlay = root / 'vex-overlay.json'
            overlay.write_text('{}\n')
            dry = subprocess.run(
                [sys.executable, str(SCRIPT),
                 '--release', '5.9.4',
                 '--changelog', str(changelog),
                 '--overlay', str(overlay),
                 '--dry-run'],
                check=False, capture_output=True, text=True)
            self.assertEqual(dry.returncode, 0, dry.stderr)
            self.assertIn('dry run: file not written', dry.stdout)
            self.assertIn('REVIEW', dry.stdout)
            self.assertEqual(overlay.read_text(), '{}\n')

            live = subprocess.run(
                [sys.executable, str(SCRIPT),
                 '--release', '5.9.4',
                 '--changelog', str(changelog),
                 '--overlay', str(overlay)],
                check=False, capture_output=True, text=True)
            self.assertEqual(live.returncode, 0, live.stderr)
            data = json.loads(overlay.read_text())
            self.assertIn('CVE-2026-11310', data)
            self.assertNotIn('CVE-2026-2222', data)
            self.assertNotIn('CVE-2026-1000', data)

            again = subprocess.run(
                [sys.executable, str(SCRIPT),
                 '--release', '5.9.4',
                 '--changelog', str(changelog),
                 '--overlay', str(overlay)],
                check=False, capture_output=True, text=True)
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertIn('nothing to add', again.stdout)
            self.assertEqual(json.loads(overlay.read_text()), data)


if __name__ == '__main__':
    unittest.main()
