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
import hashlib
import io
import struct
import zipfile
import zlib

from .common import ToolError, read_asset, safe_output_path, write_file
from .ui import ui_for


def parse_standard(oo):
    if len(oo) < 4:
        raise ValueError('bytecode store header truncated')
    ver, ndex = struct.unpack('<HH', oo[:4])
    if ndex > 32 or len(oo) < 4 + 4 * ndex:
        raise ValueError('implausible dexCount')
    offs = struct.unpack('<%dI' % ndex, oo[4:4 + 4 * ndex])
    if any(o < 4 + 4 * ndex or o >= len(oo) for o in offs) or list(offs) != sorted(offs):
        raise ValueError('bad section offsets')
    maps = []
    previous_end = 4 + 4 * ndex
    for off in offs:
        if off < previous_end or off + 2 > len(oo):
            raise ValueError('bad section start')
        mcount = struct.unpack('<H', oo[off:off + 2])[0]
        p = off + 2
        m = {}
        for _ in range(mcount):
            if p + 8 > len(oo):
                raise ValueError('record overruns file')
            midx, size = struct.unpack('<II', oo[p:p + 8])
            p += 8
            if size > 0x10000 or p + size > len(oo):
                raise ValueError('bad insns size')
            if midx in m:
                raise ValueError('duplicate method index')
            m[midx] = oo[p:p + size]
            p += size
        maps.append(m)
        previous_end = p
    return maps


def parse_xor_variant(oo):
    if len(oo) < 4:
        raise ValueError('bytecode store header truncated')
    ver, ndex = struct.unpack('<HH', oo[:4])
    if ndex > 32 or len(oo) < 4 + 4 * ndex:
        raise ValueError('implausible dexCount')
    offs = struct.unpack('<%dI' % ndex, oo[4:4 + 4 * ndex])
    if any(o < 4 + 4 * ndex or o >= len(oo) for o in offs) or list(offs) != sorted(offs):
        raise ValueError('bad section offsets')
    maps = []
    previous_end = 4 + 4 * ndex
    for off in offs:
        if off < previous_end or off + 2 > len(oo):
            raise ValueError('bad section start')
        mcount = struct.unpack('<H', oo[off:off + 2])[0]
        p = off + 2
        m = {}
        for _ in range(mcount):
            if p + 8 > len(oo):
                raise ValueError('record overruns file')
            size, midx = struct.unpack('<II', oo[p:p + 8])
            p += 8
            if size > 0x10000 or p + size > len(oo):
                raise ValueError('bad insns size')
            if midx in m:
                raise ValueError('duplicate method index')
            m[midx] = bytes(b ^ 0x6F for b in oo[p:p + size])
            p += size
        maps.append(m)
        previous_end = p
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

    try:
        with zipfile.ZipFile(args.apk) as archive:
            try:
                stub = archive.read('classes.dex')
            except KeyError:
                raise ToolError('no classes.dex with appended payload found')
    except ToolError:
        raise
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile, zlib.error) as e:
        raise ToolError('could not read packed APK: %s' % e)
    if len(stub) < 8:
        raise ToolError('classes.dex too small for appended ZIP')
    zsize = struct.unpack('>I', stub[-4:])[0]
    if zsize > len(stub) - 4 or stub[len(stub) - 4 - zsize:len(stub) - 4 - zsize + 2] != b'PK':
        raise ToolError('no appended ZIP on classes.dex tail')
    try:
        with zipfile.ZipFile(io.BytesIO(stub[len(stub) - 4 - zsize:len(stub) - 4])) as inner:
            all_names = inner.namelist()
            names = [n for n in all_names if n.endswith('.dex')]
            if len(names) != len(set(names)):
                raise ToolError('appended ZIP contains duplicate DEX names')
            if not names:
                raise ToolError('appended ZIP holds no .dex files')
            for name in names:
                if (name.startswith('/') or '\\' in name
                        or any(part in ('', '.', '..') for part in name.split('/'))):
                    raise ToolError('unsafe DEX name in appended ZIP: %r' % name)
            raw = {name: bytearray(inner.read(name)) for name in names}
    except ToolError:
        raise
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile, zlib.error) as e:
        raise ToolError('could not read appended DEX ZIP: %s' % e)
    print('appended dexes: %s' % names)

    cmap = {}
    for name, dex_data in raw.items():
        try:
            dx = DEX(bytes(dex_data))
            methods = {}
            for cls in dx.get_classes():
                for method in cls.get_methods():
                    code_off = method.get_code_off()
                    if code_off:
                        methods[method.get_method_idx()] = code_off
            cmap[name] = methods
        except Exception as e:
            raise ToolError('could not parse %s: %s' % (name, e))

    def exact(methods, dex_data, code_offsets):
        matches = 0
        for method_index, instructions in methods.items():
            code_off = code_offsets.get(method_index)
            if code_off is None or code_off + 16 > len(dex_data):
                continue
            size = struct.unpack('<I', dex_data[code_off + 12:code_off + 16])[0]
            if size * 2 == len(instructions):
                matches += 1
        return matches

    resolved = {}
    for section_index, methods in enumerate(maps):
        if not methods:
            continue
        scored = sorted(((exact(methods, raw[name], cmap[name]), name)
                         for name in names), reverse=True)
        if scored[0][0] != len(methods) or (len(scored) > 1 and scored[1][0] == len(methods)):
            raise ToolError('Oooo section %d (%d methods) has no unique '
                            'exact-fit DEX (best: %s)'
                            % (section_index, len(methods), scored[:3]))
        resolved[section_index] = scored[0][1]
        print('Oooo[%d] (%d methods) -> %s'
              % (section_index, len(methods), scored[0][1]))

    targets = {name: safe_output_path(args.outdir, name) for name in names}
    total = 0
    ui = ui_for(args)
    with ui.progress('Writing restored DEX files', len(names)) as progress:
        for section_index, name in resolved.items():
            dex_data, code_offsets, methods = raw[name], cmap[name], maps[section_index]
            for method_index, instructions in methods.items():
                code_off = code_offsets[method_index]
                if code_off + 16 + len(instructions) > len(dex_data):
                    raise ToolError('method body exceeds DEX bounds in %s' % name)
                dex_data[code_off + 16:code_off + 16 + len(instructions)] = instructions
                total += 1
            fix_headers(dex_data)
            write_file(targets[name], bytes(dex_data))
            print('%s: patched %d methods' % (name, len(methods)))
            progress.advance(detail=name)
        for name in names:
            if name not in resolved.values():
                fix_headers(raw[name])
                write_file(targets[name], bytes(raw[name]))
                print('%s: copied (no extracted methods)' % name)
                progress.advance(detail=name)
    print('TOTAL patched methods: %d -> %s' % (total, args.outdir))
    return 0
