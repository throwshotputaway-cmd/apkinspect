#!/usr/bin/env python3
"""Static unpacker for dpt-shell (luoyesiqiu/dpt-shell) packed APKs.

dpt-shell strips every method's Dalvik bytecode from the DEX, stores the
bodies in assets/OoooooOooo, and appends the gutted DEXes as a ZIP on the
tail of the stub classes.dex (size in the last 4 bytes, big-endian).
At runtime the native lib restores bodies via ART hooks; here we patch
them statically and fix the DEX SHA-1/Adler32 headers.

OoooooOooo layouts handled:
- standard: u16 version, u16 dexCount, u32 offsets[]; per section u16
  methodCount then (u32 methodIndex, u32 insnsSizeBytes, bytes)
- size-first XOR variant: (u32 insnsSize, u32 methodIndex, bytes ^ 0x6f)
Sections are matched to DEX files by exact code-capacity fit, so no
hardcoded dex ordering is assumed.

Requires: androguard
"""
import argparse
import hashlib
import io
import os
import struct
import zipfile
import zlib

from .common import ToolError, read_asset


def parse_standard(oo):
    ver, ndex = struct.unpack('<HH', oo[:4])
    if ndex > 32:
        raise ValueError('implausible dexCount')
    offs = struct.unpack('<%dI' % ndex, oo[4:4 + 4 * ndex])
    if any(o >= len(oo) for o in offs) or list(offs) != sorted(offs):
        raise ValueError('bad section offsets')
    maps = []
    for off in offs:
        mcount = struct.unpack('<H', oo[off:off + 2])[0]
        p = off + 2
        m = {}
        for _ in range(mcount):
            if p + 8 > len(oo):
                raise ValueError('record overruns file')
            midx, sz = struct.unpack('<II', oo[p:p + 8])
            p += 8
            if sz > 0x10000 or p + sz > len(oo):
                raise ValueError('bad insns size')
            m[midx] = oo[p:p + sz]
            p += sz
        maps.append(m)
    return maps


def parse_xor_variant(oo):
    ver, ndex = struct.unpack('<HH', oo[:4])
    if ndex > 32:
        raise ValueError('implausible dexCount')
    offs = struct.unpack('<%dI' % ndex, oo[4:4 + 4 * ndex])
    maps = []
    for off in offs:
        mcount = struct.unpack('<H', oo[off:off + 2])[0]
        p = off + 2
        m = {}
        for _ in range(mcount):
            if p + 8 > len(oo):
                raise ValueError('record overruns file')
            sz, midx = struct.unpack('<II', oo[p:p + 8])
            p += 8
            if sz > 0x10000 or p + sz > len(oo):
                raise ValueError('bad insns size')
            m[midx] = bytes(b ^ 0x6F for b in oo[p:p + sz])
            p += sz
        maps.append(m)
    return maps


def fix_headers(d: bytearray) -> None:
    d[12:32] = hashlib.sha1(bytes(d[32:])).digest()
    d[8:12] = struct.pack('<I', zlib.adler32(bytes(d[12:])) & 0xFFFFFFFF)


def register(sub):
    p = sub.add_parser('dpt', help='statically unpack dpt-shell packed APKs')
    p.add_argument('apk', help='packed APK')
    p.add_argument('-o', '--outdir', default='unpacked',
                   help='where to write restored classes*.dex')
    p.add_argument('--oooo', default='assets/OoooooOooo',
                   help='bytecode-store asset path')
    p.set_defaults(func=run)


def run(args) -> int:
    try:
        from androguard.core.dex import DEX
    except ImportError:
        raise ToolError('androguard is required: pip install androguard')

    oo = read_asset(args.apk, args.oooo)
    maps = None
    for name, fn in (('standard', parse_standard), ('xor-0x6f', parse_xor_variant)):
        try:
            maps = fn(oo)
        except (ValueError, struct.error):
            continue
        print('OoooooOooo layout: %s (%s)' % (
            name, [(len(m), max(m) if m else None) for m in maps]))
        break
    if maps is None:
        raise ToolError('could not parse bytecode store (unknown variant?)')

    with zipfile.ZipFile(args.apk) as z:
        try:
            stub = z.read('classes.dex')
        except KeyError:
            raise ToolError('no classes.dex with appended payload found')
    if len(stub) < 8:
        raise ToolError('classes.dex too small for appended ZIP')
    zsize = struct.unpack('>I', stub[-4:])[0]
    if zsize > len(stub) - 4 or stub[len(stub) - 4 - zsize:len(stub) - 4 - zsize + 2] != b'PK':
        raise ToolError('no appended ZIP on classes.dex tail')
    inner = zipfile.ZipFile(io.BytesIO(stub[len(stub) - 4 - zsize:len(stub) - 4]))
    names = [n for n in inner.namelist() if n.endswith('.dex')]
    if not names:
        raise ToolError('appended ZIP holds no .dex files')
    print('appended dexes: %s' % names)
    raw = {n: bytearray(inner.read(n)) for n in names}

    cmap = {}
    for n, d in raw.items():
        dx = DEX(bytes(d))
        c = {}
        for cls in dx.get_classes():
            for m in cls.get_methods():
                if m.get_code_off():
                    c[m.get_method_idx()] = m.get_code_off()
        cmap[n] = c

    def exact(m, d, c):
        return sum(1 for midx, ins in m.items()
                   if c.get(midx)
                   and struct.unpack('<I', d[c[midx] + 12:c[midx] + 16])[0] * 2 == len(ins))

    resolved = {}
    for di, m in enumerate(maps):
        if not m:
            continue
        scored = sorted(((exact(m, raw[n], cmap[n]), n) for n in names),
                        reverse=True)
        if scored[0][0] != len(m) or (len(scored) > 1 and scored[1][0] == len(m)):
            raise ToolError('Oooo section %d (%d methods) has no unique '
                            'exact-fit DEX (best: %s)' % (di, len(m), scored[:3]))
        resolved[di] = scored[0][1]
        print('Oooo[%d] (%d methods) -> %s' % (di, len(m), scored[0][1]))

    os.makedirs(args.outdir, exist_ok=True)
    total = 0
    for di, n in resolved.items():
        d, c, m = raw[n], cmap[n], maps[di]
        for midx, ins in m.items():
            co = c[midx]
            d[co + 16:co + 16 + len(ins)] = ins
            total += 1
        fix_headers(d)
        with open(os.path.join(args.outdir, n), 'wb') as fh:
            fh.write(d)
        print('%s: patched %d methods' % (n, len(m)))
    for n in names:
        if n not in resolved.values():
            fix_headers(raw[n])
            with open(os.path.join(args.outdir, n), 'wb') as fh:
                fh.write(raw[n])
            print('%s: copied (no extracted methods)' % n)
    print('TOTAL patched methods: %d -> %s' % (total, args.outdir))
    return 0
