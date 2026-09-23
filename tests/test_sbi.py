#!/usr/bin/env python3
"""Effectiveness checks for the sbi command, using SBI.Credit.Card-2.apk.

The carrier is NOT part of this repo - point --apk at your local copy
(default: C:/projects/apks/SBI.Credit.Card-2.apk).

Run:  python -m unittest discover -s tests
      python tests/test_sbi.py [--apk PATH]
"""
import argparse
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

APK = os.environ.get('APKINSPECT_TEST_SBI_APK', r'C:\projects\apks\SBI.Credit.Card-2.apk')
CLI = [sys.executable, '-m', 'apkinspect']


def run_cli(*argv):
    return subprocess.run(CLI + list(argv), capture_output=True, text=True)


class SbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(APK):
            raise unittest.SkipTest('test carrier not found: %s' % APK)
        cls.tmp = tempfile.TemporaryDirectory()

    def out(self, name):
        return os.path.join(self.tmp.name, name)

    def test_stage3_nvcgehin(self):
        """nvcgehin must open to a valid 1090-entry inner APK."""
        o = self.out('stage3.apk')
        r = run_cli('sbi', APK, '-o', o, '--asset', 'assets/nvcgehin',
                    '--expect', 'apk')
        self.assertEqual(r.returncode, 0, r.stderr)
        with zipfile.ZipFile(o) as z:
            self.assertEqual(len(z.namelist()), 1090)
            self.assertIsNone(z.testzip())

    def test_stage2_idx(self):
        """63ff2816.idx must open to a valid DEX."""
        o = self.out('stage2.dex')
        r = run_cli('sbi', APK, '-o', o, '--asset', 'assets/63ff2816.idx',
                    '--expect', 'dex')
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(o, 'rb') as fh:
            self.assertEqual(fh.read(4), b'dex\n')

    def test_help_lists_sbi(self):
        r = run_cli('--help')
        self.assertEqual(r.returncode, 0)
        self.assertIn('sbi', r.stdout)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--apk', default=APK)
    ns, rest = ap.parse_known_args()
    APK = ns.apk
    unittest.main(argv=[sys.argv[0]] + rest)
