#!/usr/bin/env python3
"""Staged-shard reassembler for meta.json-driven multi-part payloads.

Scheme (recovered from loader disassembly): meta.json lists parts in order;
each part is AES-CBC with key SHA-256(password) and the part's first 16 bytes
as IV; plaintexts are PKCS5-unpadded and concatenated to a gzip verified by
compressedSha256, which inflates to the APK verified by originalSha256.
"""
import argparse
import gzip
import hashlib
import io
import json
import zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .common import ToolError, read_asset, report_plain, write_file


def register(sub):
    p = sub.add_parser('staged', help='reassemble meta.json-driven staged payloads')
    p.add_argument('apk', help='carrier APK')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--password', default='0oP#4mKl1X3',
                   help='password baked into the loader (try builder defaults first)')
    p.add_argument('--asset-dir', default='assets/packed')
    p.add_argument('--meta', default='meta.json')
    p.set_defaults(func=run)


def run(args) -> int:
    meta = json.loads(read_asset(args.apk, '%s/%s' % (args.asset_dir, args.meta)))
    key = hashlib.sha256(args.password.encode()).digest()
    print('key: %s' % key.hex())
    print('parts: %s' % [f['file'] for f in meta['files']])

    blob = b''
    for f in meta['files']:
        data = read_asset(args.apk, '%s/%s' % (args.asset_dir, f['file']))
        iv, ct = data[:16], data[16:]
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        pt = pt[:-pt[-1]]  # PKCS5 unpad
        blob += pt
        print('%s: %d -> %d' % (f['file'], len(data), len(pt)))

    if hashlib.sha256(blob).hexdigest() != meta['compressedSha256']:
        raise ToolError('compressed hash mismatch - wrong password or part order?')
    out = gzip.decompress(blob)
    if hashlib.sha256(out).hexdigest() != meta['originalSha256']:
        raise ToolError('decompressed hash mismatch')
    try:
        with zipfile.ZipFile(io.BytesIO(out)) as zz:
            bad = zz.testzip()
            print('zip entries %d, testzip: %s' % (len(zz.namelist()), bad))
            if bad is not None:
                raise ToolError('reassembled payload is corrupt')
    except ToolError:
        raise
    except Exception as e:
        raise ToolError('reassembled payload is not a ZIP: %s' % e)
    write_file(args.output, out)
    report_plain(args.output, out)
    return 0
