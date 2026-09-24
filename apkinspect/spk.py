#!/usr/bin/env python3
"""Decrypt the SPK mystery-line .bin blobs (sewa generation).

Outer layer: repeating XOR with the 44-char getSecretKey rodata string.
Inner layer: b'SPKZ' + raw DEFLATE of b'SPK1' + u32 + u16 + name + body,
where body is a shell ZIP (5 entries, decoy central directory with
'Block 42' prefix and fnl=0 junk entries) with carved DEX/container
data trailing it. DEX files carve cleanly by their header file_size.
"""
import hashlib
import zipfile
import zlib

from .common import ToolError, read_asset, report_plain, write_file

DEFAULT_KEY = b'fLSUt5bSI0xpWOYLUmVTUSinuMrnJrxszvOp5wXF'


def pick_asset(apk_path: str) -> str:
    try:
        with zipfile.ZipFile(apk_path) as archive:
            candidates = [(name, archive.getinfo(name).file_size)
                          for name in archive.namelist()
                          if name.startswith('assets/') and name.endswith('.bin')]
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile) as e:
        raise ToolError('could not read APK %s: %s' % (apk_path, e))
    if not candidates:
        raise ToolError('no assets/*.bin blob found in %s' % apk_path)
    return max(candidates, key=lambda item: item[1])[0]


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
    if not key:
        raise ToolError('key must not be empty')
    pt = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))
    if pt[:4] != b'SPKZ':
        raise ToolError('not an SPK container (bad key?)')
    body = None
    for window in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        stream = zlib.decompressobj(window)
        try:
            candidate = stream.decompress(pt[4:])
        except zlib.error as e:
            if window == zlib.MAX_WBITS:
                continue
            raise ToolError('SPKZ DEFLATE failed: %s' % e)
        if not stream.eof:
            if window == zlib.MAX_WBITS:
                continue
            raise ToolError('SPKZ DEFLATE stream is truncated')
        if stream.unused_data:
            raise ToolError('trailing data after SPKZ stream')
        body = candidate
        break
    if body is None:
        raise ToolError('SPKZ DEFLATE failed for wrapped and raw streams')
    if body[:4] != b'SPK1':
        raise ToolError('bad SPK1 magic')
    print('body sha256: %s' % hashlib.sha256(body).hexdigest())
    write_file(args.output, body)
    report_plain(args.output, body)
    print('hint: carve DEXes by scanning for b\'dex\\n035\' + u32 size at +32')
    return 0
