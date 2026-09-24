import argparse
import contextlib
import io
import os
import struct
import tempfile
import unittest
from unittest import mock
import zipfile

from apkinspect import blind
from apkinspect.__main__ import build_parser, normalize_argv
from apkinspect.profiles import profile_by_name


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

    def test_existing_final_apk_is_copied(self):
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
            self.assertFalse(os.path.exists(os.path.join(output, 'report.json')))

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

    def test_encrypted_member_is_left_for_adapters(self):
        class Info:
            filename = 'assets/protected.bin'
            external_attr = 0
            flag_bits = 1
            file_size = 1
            compress_size = 1

        class Archive:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def infolist(self):
                return [Info()]

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'carrier.zip')
            with open(path, 'wb') as stream:
                stream.write(b'PK')
            with mock.patch('apkinspect.blind.zipfile.ZipFile', return_value=Archive()):
                infos = blind._archive_info(path)
        self.assertIn('assets/protected.bin', infos)

    def test_known_variant_matrix_is_present(self):
        for command in ('upd', 'staged', 'signed', 'spk', 'fogky', 'shard', 'cloak'):
            self.assertTrue(profile_by_name(command).variants)
        self.assertEqual(blind.KNOWN_VARIANTS['upd'],
                         profile_by_name('upd').variants)

    def test_profile_filter_limits_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, 'carrier.zip')
            output = os.path.join(directory, 'output')
            write_zip(source, {'assets/update.enc': b'not-a-payload'})
            args = argparse.Namespace(
                apk=source,
                outdir=output,
                max_depth=1,
                max_attempts=4,
                max_assets=0,
                profiles=['fogky'],
            )
            with mock.patch.object(blind, '_invoke', return_value=(1, 'blocked')) as invoke:
                with contextlib.redirect_stdout(io.StringIO()):
                    result = blind.run(args)
            self.assertEqual(result, 1)
            invoke.assert_not_called()
            self.assertFalse(os.path.exists(os.path.join(output, 'report.json')))

    def test_profile_option_is_repeatable(self):
        args = build_parser().parse_args([
            'blind', 'sample.apk', '--profile', 'fogky', '--profile', 'upd'])
        self.assertEqual(args.profiles, ['fogky', 'upd'])

    def test_blind_alias_is_normalized(self):
        self.assertEqual(normalize_argv(['--blind', 'sample.apk']),
                         ['blind', 'sample.apk'])


if __name__ == '__main__':
    unittest.main()
