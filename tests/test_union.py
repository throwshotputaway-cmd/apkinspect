#!/usr/bin/env python3
"""Effectiveness checks for apkinspect, using union.apk as the test carrier.

union.apk is an update.enc-line sample (assets/update.enc XOR-encrypted,
key in libpayload.so rodata). It is NOT part of this repo - point
--apk at your local copy (default: C:/projects/apks/union.apk).

Run:  python -m unittest discover -s tests
      python tests/test_union.py [--apk PATH]
"""
import argparse
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

APK = os.environ.get('APKINSPECT_TEST_APK', r'C:\projects\apks\union.apk')
CLI = [sys.executable, '-m', 'apkinspect']


def run_cli(*argv):
    return subprocess.run(CLI + list(argv), capture_output=True, text=True)


class UnionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(APK):
            raise unittest.SkipTest('test carrier not found: %s' % APK)
        cls.tmp = tempfile.TemporaryDirectory()

    def out(self, name):
        return os.path.join(self.tmp.name, name)

    def test_upd_decrypts_update_enc(self):
        """Primary test: update.enc must XOR-decrypt to a valid ZIP."""
        o = self.out('update.apk')
        r = run_cli('upd', APK, '-o', o)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(o, 'rb') as fh:
            head = fh.read(4)
        self.assertEqual(head, b'PK\x03\x04')
        with zipfile.ZipFile(o) as z:
            self.assertIsNone(z.testzip())
            self.assertGreater(len(z.namelist()), 0)

    def test_signed_fails_gracefully(self):
        """union.apk has no signed-line assets: clean error, no traceback."""
        r = run_cli('signed', APK, '--outdir', self.out('s'))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('not found', r.stderr)
        self.assertNotIn('Traceback', r.stderr)

    def test_icici_ctr_fails_gracefully(self):
        r = run_cli('icici-ctr', APK, '-o', self.out('x.apk'),
                    '--key', 'f5090d29cc4f11df7bca1e813d68600f')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('not found', r.stderr)
        self.assertNotIn('Traceback', r.stderr)

    def test_dpt_fails_gracefully(self):
        r = run_cli('dpt', APK, '-o', self.out('u'))
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn('Traceback', r.stderr)

    def test_lcg_rejects_non_lcg(self):
        """update.enc is not an LCG blob: must report invalid ZIP, rc=1."""
        blob = os.path.join(self.tmp.name, 'blob.dat')
        with zipfile.ZipFile(APK) as z:
            with open(blob, 'wb') as fh:
                fh.write(z.read('assets/update.enc'))
        r = run_cli('lcg', blob, '-o', self.out('l.apk'))
        self.assertEqual(r.returncode, 1)
        self.assertTrue('not a valid ZIP' in r.stderr
                        or 'does not start with PK' in r.stderr, r.stderr)

    def test_oracle_method_absent(self):
        """union.apk is not an oracle-line sample: clean error."""
        dex = os.path.join(self.tmp.name, 'classes.dex')
        with zipfile.ZipFile(APK) as z:
            with open(dex, 'wb') as fh:
                fh.write(z.read('classes.dex'))
        r = run_cli('oracle', dex)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('not found', r.stderr)
        self.assertNotIn('Traceback', r.stderr)

    def test_help_lists_all_commands(self):
        r = run_cli('--help')
        self.assertEqual(r.returncode, 0)
        for cmd in ('lcg', 'upd', 'shard', 'spk', 'staged', 'fogky',
                    'signed', 'oracle', 'splitkey', 'elforacle',
                    'icici-ctr', 'dpt', 'axml-trim'):
            self.assertIn(cmd, r.stdout)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--apk', default=APK)
    ns, rest = ap.parse_known_args()
    APK = ns.apk
    unittest.main(argv=[sys.argv[0]] + rest)
