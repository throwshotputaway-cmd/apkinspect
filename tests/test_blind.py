import argparse
import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
import zipfile

from apkinspect import blind
from apkinspect.__main__ import normalize_argv


def make_manifest():
    return b'\x03\x00\x08\x00' + b'\x00' * 4 + struct.pack('<HHI', 0x0101, 0, 8)


def make_dex():
    data = bytearray(112)
    data[:8] = b'dex\n035\0'
    struct.pack_into('<I', data, 32, len(data))
    struct.pack_into('<I', data, 36, 112)
    struct.pack_into('<I', data, 40, 0x12345678)
    return bytes(data)


def write_zip(path, entries):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


class BlindTests(unittest.TestCase):
    def test_final_apk_requires_manifest_and_dex(self):
        with tempfile.TemporaryDirectory() as directory:
            complete = os.path.join(directory, 'complete.apk')
            missing_dex = os.path.join(directory, 'missing-dex.apk')
            write_zip(complete, {
                'AndroidManifest.xml': make_manifest(),
                'classes.dex': make_dex(),
            })
            write_zip(missing_dex, {'AndroidManifest.xml': make_manifest()})
            self.assertTrue(blind.is_final_apk(complete))
            self.assertFalse(blind.is_final_apk(missing_dex))

    def test_existing_final_apk_is_copied_and_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, 'source.apk')
            output = os.path.join(directory, 'output')
            write_zip(source, {
                'AndroidManifest.xml': make_manifest(),
                'classes.dex': make_dex(),
            })
            args = argparse.Namespace(
                apk=source,
                outdir=output,
                max_depth=2,
                max_attempts=4,
                max_assets=0,
            )
            with contextlib.redirect_stdout(io.StringIO()):
                result = blind.run(args)
            self.assertEqual(result, 0)
            self.assertTrue(os.path.isfile(os.path.join(output, 'final.apk')))
            with open(os.path.join(output, 'report.json'), encoding='utf-8') as stream:
                report = json.load(stream)
            self.assertEqual(report['final'], os.path.join(output, 'final.apk'))
            self.assertTrue(any(profile['name'] == 'fogky' for profile in report['profiles']))

    def test_nested_apk_is_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            inner = os.path.join(directory, 'inner.apk')
            outer = os.path.join(directory, 'outer.zip')
            output = os.path.join(directory, 'output')
            write_zip(inner, {
                'AndroidManifest.xml': make_manifest(),
                'classes.dex': make_dex(),
            })
            with open(inner, 'rb') as stream:
                inner_data = stream.read()
            write_zip(outer, {'payload.apk': inner_data})
            args = argparse.Namespace(
                apk=outer,
                outdir=output,
                max_depth=2,
                max_attempts=4,
                max_assets=0,
            )
            with contextlib.redirect_stdout(io.StringIO()):
                result = blind.run(args)
            self.assertEqual(result, 0)
            self.assertTrue(os.path.isfile(os.path.join(output, 'final.apk')))

    def test_blind_alias_is_normalized(self):
        self.assertEqual(normalize_argv(['--blind', 'sample.apk']),
                         ['blind', 'sample.apk'])


if __name__ == '__main__':
    unittest.main()
