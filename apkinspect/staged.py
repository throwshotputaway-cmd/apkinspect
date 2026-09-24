#!/usr/bin/env python3
"""Staged-shard reassembler for meta.json-driven multi-part payloads.

Scheme (recovered from loader disassembly): meta.json lists parts in order;
each part is AES-CBC with key SHA-256(password) and the part's first 16 bytes
as IV; plaintexts are PKCS5-unpadded and concatenated to a gzip verified by
compressedSha256, which inflates to the APK verified by originalSha256.
"""
import gzip
import hashlib
import io
import json
import posixpath
import zipfile
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .common import ToolError, pkcs7_unpad, read_asset, report_plain, write_file
from .ui import ui_for

DEFAULT_PASSWORD = '0oP#4mKl1X3'


def register(sub):
    p = sub.add_parser('staged', help='reassemble meta.json-driven staged payloads')
    p.add_argument('apk', help='carrier APK')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--password', default=DEFAULT_PASSWORD,
                   help='password baked into the loader (try builder defaults first)')
    p.add_argument('--asset-dir', default='assets/packed')
    p.add_argument('--meta', default='meta.json')
    p.set_defaults(func=run)


def run(args) -> int:
    meta_path = posixpath.join(args.asset_dir, args.meta)
    raw_meta = read_asset(args.apk, meta_path)
    try:
        meta = json.loads(raw_meta)
    except (TypeError, ValueError) as e:
        raise ToolError('invalid metadata JSON: %s' % e)
    if not isinstance(meta, dict) or not isinstance(meta.get('files'), list):
        raise ToolError('metadata must contain a files list')
    expected_compressed = meta.get('compressedSha256')
    expected_original = meta.get('originalSha256')
    if not isinstance(expected_compressed, str) or not isinstance(expected_original, str):
        raise ToolError('metadata is missing SHA-256 fields')

    key = hashlib.sha256(args.password.encode()).digest()
    parts = []
    ui = ui_for(args)
    with ui.progress('Decrypting staged parts', len(meta['files'])) as progress:
        for part in meta['files']:
            if not isinstance(part, dict) or not isinstance(part.get('file'), str):
                raise ToolError('metadata contains an invalid file entry')
            name = part['file']
            if name.startswith('/') or '..' in name.split('/'):
                raise ToolError('unsafe metadata asset path: %s' % name)
            data = read_asset(args.apk, posixpath.join(args.asset_dir, name))
            if len(data) < 32 or (len(data) - 16) % 16:
                raise ToolError('part %s has an invalid AES-CBC length' % name)
            iv, ct = data[:16], data[16:]
            try:
                dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                pt = dec.update(ct) + dec.finalize()
            except Exception as e:
                raise ToolError('part %s could not be decrypted: %s' % (name, e))
            try:
                pt = pkcs7_unpad(pt)
            except ToolError as e:
                raise ToolError('part %s: %s' % (name, e))
            parts.append(pt)
            print('%s: %d -> %d' % (name, len(data), len(pt)))
            progress.advance(detail=name)

    blob = b''.join(parts)
    if hashlib.sha256(blob).hexdigest().lower() != expected_compressed.lower():
        raise ToolError('compressed hash mismatch - wrong password or part order?')
    try:
        out = gzip.decompress(blob)
    except (OSError, EOFError, ValueError, zlib.error) as e:
        raise ToolError('reassembled payload is not valid gzip: %s' % e)
    if hashlib.sha256(out).hexdigest().lower() != expected_original.lower():
        raise ToolError('decompressed hash mismatch')
    try:
        with zipfile.ZipFile(io.BytesIO(out)) as archive:
            bad = archive.testzip()
            if bad is not None:
                raise ToolError('reassembled payload is corrupt (first bad entry: %s)' % bad)
            print('zip entries %d, testzip: %s' % (len(archive.namelist()), bad))
    except ToolError:
        raise
    except Exception as e:
        raise ToolError('reassembled payload is not a ZIP: %s' % e)
    write_file(args.output, out)
    report_plain(args.output, out)
    return 0
