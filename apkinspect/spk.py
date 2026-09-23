#!/usr/bin/env python3
"""Decrypt the SPK mystery-line .bin blobs (sewa generation).

Outer layer: repeating XOR with the 44-char getSecretKey rodata string.
Inner layer: b'SPKZ' + raw DEFLATE of b'SPK1' + u32 + u16 + name + body,
where body is a shell ZIP (5 entries, decoy central directory with
'Block 42' prefix and fnl=0 junk entries) with carved DEX/container
data trailing it. DEX files carve cleanly by their header file_size.
"""
import argparse
import hashlib
import zipfile
import zlib

from .common import ToolError, read_asset, report_plain, write_file

DEFAULT_KEY = b'fLSUt5bSI0xpWOYLUmVTUSinuMrnJrxszvOp5wXF'


def pick_asset(apk_path: str) -> str:
    with zipfile.ZipFile(apk_path) as z:
        cands = [(n, z.getinfo(n).file_size) for n in z.namelist()
                 if n.startswith('assets/') and n.endswith('.bin')]
    if not cands:
        raise ToolError('no assets/*.bin blob found in %s' % apk_path)
    return max(cands, key=lambda x: x[1])[0]


def register(sub):
    p = sub.add_parser('spk', help='decrypt SPK-line .bin blobs')
    p.add_argument('apk', help='carrier APK')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--key', default=None)
    p.add_argument('--asset', default=None,
                   help='asset path (default: largest assets/*.bin)')
    p.set_defaults(func=run)


def run(args) -> int:
    aname = args.asset or pick_asset(args.apk)
    blob = read_asset(args.apk, aname)
    print('asset %s len %d' % (aname, len(blob)))
    key = args.key.encode() if args.key else DEFAULT_KEY
    pt = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))
    if pt[:4] != b'SPKZ':
        raise ToolError('not an SPK container (bad key?)')
    do = zlib.decompressobj()
    try:
        body = do.decompress(pt[4:])
    except zlib.error as e:
        raise ToolError('SPKZ DEFLATE failed: %s' % e)
    if do.unused_data:
        raise ToolError('trailing data after SPKZ stream')
    if body[:4] != b'SPK1':
        raise ToolError('bad SPK1 magic')
    print('body sha256: %s' % hashlib.sha256(body).hexdigest())
    write_file(args.output, body)
    report_plain(args.output, body)
    print('hint: carve DEXes by scanning for b\'dex\\n035\' + u32 size at +32')
    return 0
