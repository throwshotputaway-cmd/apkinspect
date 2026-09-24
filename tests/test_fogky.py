#!/usr/bin/env python3
"""Effectiveness checks for the fogky MSZ1 container path, using a local carrier.

The carrier is an MSZ1-line sample (assets/dnshz4t XOR-pad/RC4x4/AES-GCM
blob wrapping a zlib+MSP1 container that holds an APK split set). It is NOT
part of this repo - point --apk at your local copy.

Run:  python -m unittest discover -s tests
      python tests/test_fogky.py [--apk PATH]
"""
import argparse
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

APK = os.environ.get('APKINSPECT_FOGKY_APK',
                     r'C:\projects\apks\NextGen_mParivahan_Official.apk')
KEY = ('4345f79c3daab6bc3ddeaae19e8c5f451290e1f679a7b0136403d0b28808988d')
ASSET = 'assets/dnshz4t'
CLI = [sys.executable, '-m', 'apkinspect']


def run_cli(*argv):
    return subprocess.run(CLI + list(argv), capture_output=True, text=True)


class FogkyContainerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(APK):
            raise unittest.SkipTest('fogky carrier not found: %s' % APK)
        cls.tmp = tempfile.TemporaryDirectory()

    def out(self, name):
        return os.path.join(self.tmp.name, name)

    def test_container_entries_are_valid_apks(self):
        """MSZ1 plaintext must extract base.apk + split as healthy ZIPs."""
        d = self.out('split')
        r = run_cli('fogky', APK, ASSET, '-o', d, '--key', KEY)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('MSZ1 container: 2 entries', r.stdout)
        names = sorted(os.listdir(d))
        self.assertEqual(names, ['base.apk', 'split_config.dex.apk'])
        for n in names:
            with zipfile.ZipFile(os.path.join(d, n)) as z:
                self.assertIsNone(z.testzip())
                self.assertGreater(len(z.namelist()), 0)

    def test_raw_matches_container_path(self):
        """--raw writes the untouched MSZ1 plaintext (same GCM plaintext)."""
        raw = self.out('raw.bin')
        r = run_cli('fogky', APK, ASSET, '-o', raw, '--key', KEY, '--raw')
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(raw, 'rb') as fh:
            head = fh.read(4)
        self.assertEqual(head, b'MSZ1')

    def test_odd_length_key_is_clean_error(self):
        r = run_cli('fogky', APK, ASSET, '-o', self.out('x'), '--key', 'abc')
        self.assertEqual(r.returncode, 1)
        self.assertIn('must be hex', r.stderr)
        self.assertNotIn('Traceback', r.stderr)

    def test_wrong_key_length_is_clean_error(self):
        r = run_cli('fogky', APK, ASSET, '-o', self.out('x'), '--key', 'aabbcc')
        self.assertEqual(r.returncode, 1)
        self.assertIn('16, 24 or 32 bytes', r.stderr)
        self.assertNotIn('Traceback', r.stderr)

    def test_wrong_key_fails_gcm_tag(self):
        r = run_cli('fogky', APK, ASSET, '-o', self.out('x'),
                    '--key', '00' * 32)
        self.assertEqual(r.returncode, 1)
        self.assertIn('GCM tag failure', r.stderr)
        self.assertNotIn('Traceback', r.stderr)

    def test_missing_asset_is_clean_error(self):
        r = run_cli('fogky', APK, 'assets/nope', '-o', self.out('x'),
                    '--key', KEY)
        self.assertEqual(r.returncode, 1)
        self.assertIn('not found', r.stderr)
        self.assertNotIn('Traceback', r.stderr)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--apk', default=APK)
    ns, rest = ap.parse_known_args()
    APK = ns.apk
    unittest.main(argv=[sys.argv[0]] + rest)
