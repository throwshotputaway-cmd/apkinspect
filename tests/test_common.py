import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
import zipfile
import zlib

from apkinspect import fogky
from apkinspect.__main__ import build_parser, main
from apkinspect.common import ToolError, pkcs7_unpad, read_asset, safe_basename, safe_output_path, verify_zip, write_file


class CommonTests(unittest.TestCase):
    def test_verify_empty_zip(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w'):
            pass
        self.assertEqual(verify_zip(buffer.getvalue()), 0)

    def test_read_asset_rejects_oversized_asset(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = os.path.join(directory, 'carrier.apk')
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('assets/payload.bin', b'abc')
            self.assertEqual(read_asset(apk, 'assets/payload.bin', max_bytes=3), b'abc')
            with self.assertRaisesRegex(ToolError, 'exceeds the 2-byte limit'):
                read_asset(apk, 'assets/payload.bin', max_bytes=2)

    def test_safe_output_path_rejects_traversal(self):
        with self.assertRaises(ToolError):
            safe_output_path('out', '../outside.dex')
        with self.assertRaises(ToolError):
            safe_output_path('out', '/absolute.dex')

    def test_safe_basename(self):
        self.assertEqual(safe_basename('a/b/file.dex'), 'file.dex')
        with self.assertRaises(ToolError):
            safe_basename('../')

    def test_pkcs7_unpad(self):
        self.assertEqual(pkcs7_unpad(b'abc' + b'\x04' * 4), b'abc')
        with self.assertRaises(ToolError):
            pkcs7_unpad(b'abc\x04')

    def test_write_file_replaces_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'nested', 'output.bin')
            write_file(path, b'new')
            with open(path, 'rb') as fh:
                self.assertEqual(fh.read(), b'new')
            self.assertFalse(any(name.startswith('.apkinspect-')
                                 for name in os.listdir(os.path.dirname(path))))


class FogkyTests(unittest.TestCase):
    def test_parse_msz1_container(self):
        name = b'base.apk'
        entry = struct.pack('<H', len(name)) + name + struct.pack('<I', 3) + b'abc'
        raw = struct.pack('<II', fogky.MSP1_MAGIC, 1) + entry
        entries = fogky.parse_container(fogky.MSZ1_MAGIC + zlib.compress(raw))
        self.assertEqual(entries, [('base.apk', b'abc')])

    def test_rejects_truncated_container(self):
        with self.assertRaises(ToolError):
            fogky.parse_container(fogky.MSZ1_MAGIC + zlib.compress(b'abc'))


class CliTests(unittest.TestCase):
    def test_elforacle_function_option_does_not_replace_handler(self):
        args = build_parser().parse_args([
            'elforacle', 'library.so', '-o', 'strings.txt', '--func', 'nativeOracle'])
        self.assertEqual(args.symbol, 'nativeOracle')
        self.assertTrue(callable(args.func))

    def test_profiles_json_lists_builtin_metadata(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = main(['profiles', '--json'])
        self.assertEqual(result, 0)
        profiles = json.loads(stdout.getvalue())
        names = {profile['name'] for profile in profiles}
        self.assertIn('fogky', names)
        self.assertIn('aes-gcm-hkdf', names)

    def test_missing_file_is_clean_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = main(['axml-trim', 'missing.apk', '-o', 'out.apk'])
        self.assertEqual(result, 1)
        self.assertNotIn('Traceback', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
