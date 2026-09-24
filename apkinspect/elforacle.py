#!/usr/bin/env python3
"""Native string-oracle extractor for protector .so files (x86_64).

Targets the indexed-string switch pattern: a bounds-checked jump table where
each case sets (data ptr, key ptr, lengths) via RIP-relative lea, then jumps
to a shared repeating-XOR decoder ending in NewStringUTF.

Learnings baked in:
- default key length may come from the function prelude (not the case block)
- data/key registers may be MIRRORED between builder versions: both
  conventions are tried, keeping the most readable output
- decoded lengths can overshoot: output is truncated at the first NUL
- some cases derive key length from the index argument itself

Requires: lief, capstone
"""
import re
import struct
from typing import Dict, Optional, Tuple

from .common import ToolError, read_file, write_file


def section_map(raw):
    if len(raw) < 64 or raw[:4] != b'\x7fELF':
        raise ToolError('not an ELF file')
    if raw[4] != 2 or raw[5] != 1:
        raise ToolError('ELF must be 64-bit little-endian')
    if struct.unpack('<H', raw[18:20])[0] != 62:
        raise ToolError('ELF architecture is not x86_64')
    e_shoff = struct.unpack('<Q', raw[0x28:0x30])[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHH', raw[0x3A:0x40])
    if e_shoff == 0 or e_shnum == 0 or e_shentsize < 64:
        raise ToolError('no usable section headers (stripped?)')
    if e_shoff + e_shentsize * e_shnum > len(raw) or e_shstrndx >= e_shnum:
        raise ToolError('ELF section table is out of bounds')
    string_header = e_shoff + e_shstrndx * e_shentsize
    _, _, _, _, string_offset, string_size, _, _, _, _ = struct.unpack(
        '<IIQQQQIIQQ', raw[string_header:string_header + 64])
    if string_offset + string_size > len(raw):
        raise ToolError('ELF section-name table is out of bounds')
    names = raw[string_offset:string_offset + string_size]
    out = {}
    for index in range(e_shnum):
        offset = e_shoff + index * e_shentsize
        name, section_type, _, address, file_offset, size, _, _, _, _ = struct.unpack(
            '<IIQQQQIIQQ', raw[offset:offset + 64])
        if name >= len(names) or (section_type != 8 and file_offset + size > len(raw)):
            raise ToolError('ELF section table entry is out of bounds')
        end = names.find(b'\x00', name)
        if end < 0:
            raise ToolError('ELF section name is not NUL terminated')
        out[names[name:end].decode()] = (address, file_offset, size)
    return out


def readability(buf: bytes) -> float:
    if not buf:
        return 0.0
    text = sum(1 for b in buf if 32 <= b < 127 or b in (10, 13))
    return text / len(buf)


def register(sub):
    p = sub.add_parser('elforacle',
                       help='extract encrypted string tables from protector .so (x86_64)')
    p.add_argument('sofile', help='native library (prefer x86_64 slice)')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--func', dest='symbol', default='getNativeStr',
                   help='JNI oracle function substring')
    p.add_argument('--bound', type=lambda x: int(x, 0), default=None,
                   help='max index (auto-read from cmp if omitted)')
    p.add_argument('--default-keylen', type=int, default=12)
    p.set_defaults(func=run)


def run(args) -> int:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError:
        raise ToolError('capstone is required: pip install capstone')
    try:
        import lief
    except ImportError:
        raise ToolError('lief is required: pip install lief')

    raw = read_file(args.sofile, 'ELF file')
    if args.default_keylen < 1:
        raise ToolError('default key length must be positive')
    if args.bound is not None and args.bound < 0:
        raise ToolError('bound must not be negative')
    secs = section_map(raw)
    if '.text' not in secs or '.rodata' not in secs:
        raise ToolError('need .text and .rodata sections')
    TVA, TOFF, TSZ = secs['.text']
    RVA, ROFF, RSZ = secs['.rodata']
    code = raw[TOFF:TOFF + TSZ]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    insns = list(md.disasm(code, TVA))
    byaddr = {i.address: i for i in insns}

    b = lief.parse(args.sofile)
    if b is None:
        raise ToolError('LIEF could not parse ELF file')
    dynamic_symbols = getattr(b, 'dynamic_symbols', None)
    if dynamic_symbols is None:
        raise ToolError('LIEF did not return an ELF binary')
    syms = [s for s in dynamic_symbols if s.value and args.symbol in s.name]
    if not syms:
        raise ToolError("no dynamic symbol matching '%s'" % args.symbol)
    fva = syms[0].value
    bound = args.bound
    table_va = None
    for i in insns:
        if i.address < fva:
            continue
        if i.mnemonic == 'cmp' and 'edx' in i.op_str and bound is None:
            try:
                bound = int(i.op_str.split(',')[1].strip(), 0)
            except ValueError:
                pass
        if i.mnemonic == 'lea' and i.op_str.startswith('rcx') and 'rip' in i.op_str:
            disp = int(i.op_str.split('rip', 1)[1].replace(' ', '').strip('[]'), 0)
            table_va = i.address + i.size + disp
            break
    if table_va is None or bound is None:
        raise ToolError('could not locate jump table/bound (use --bound)')
    print('oracle @%#x bound=%d table=%#x' % (fva, bound, table_va))

    def u32(va):
        offset = ROFF + va - RVA
        if offset < ROFF or offset + 4 > ROFF + RSZ:
            raise ToolError('ELF jump-table offset is out of bounds')
        return struct.unpack('<i', raw[offset:offset + 4])[0]

    def rd(va, n):
        offset = ROFF + va - RVA
        if offset < ROFF or n < 0 or offset + n > ROFF + RSZ:
            raise ToolError('ELF data offset is out of bounds')
        return raw[offset:offset + n]

    def walk(tgt):
        r15, r12, flag, r13, rbp = None, None, None, None, None
        a = tgt
        for _ in range(30):
            i = byaddr.get(a)
            if i is None:
                break
            m, o = i.mnemonic, i.op_str
            try:
                if m == 'mov' and o.startswith('r15d'):
                    r15 = int(o.split(',')[1].strip(), 0)
                elif m == 'mov' and o.startswith('r12d'):
                    r12 = int(o.split(',')[1].strip(), 0)
                elif m == 'mov' and 'dword ptr [rsp + 4]' in o:
                    try:
                        flag = int(o.split(',')[1].strip(), 0)
                    except ValueError:
                        flag = 1
                elif m == 'lea' and o.startswith('r13') and 'rip' in o:
                    r13 = i.address + i.size + int(o.split('rip', 1)[1].replace(' ', '').strip('[]'), 0)
                elif m == 'lea' and o.startswith('rbp') and 'rip' in o:
                    rbp = i.address + i.size + int(o.split('rip', 1)[1].replace(' ', '').strip('[]'), 0)
                elif m == 'xor' and o.startswith('r12d'):
                    r12 = 0
                elif m == 'mov' and re.match(r'r15d,\s*edx', o):
                    r15 = 'dyn'
                elif m == 'mov' and re.match(r'r12d,\s*edx', o):
                    r12 = 'dyn'
            except ValueError:
                pass
            if m == 'jmp':
                break
            a += i.size
        return r15, r12, flag, r13, rbp

    results: Dict[int, Tuple[Optional[bytes], str]] = {}
    for idx in range(bound + 1):
        tgt = table_va + u32(table_va + idx * 4)
        r15, r12, flag, r13, rbp = walk(tgt)
        if r15 is None:
            r15 = args.default_keylen
        if r15 == 'dyn' or r12 == 'dyn':
            results[idx] = (None, 'dynamic-regs')
            continue
        if not isinstance(r12, int) or not isinstance(rbp, int) or not isinstance(r13, int) \
                or not isinstance(r15, int) or not flag:
            results[idx] = (None, 'unparsed')
            continue
        cands = []
        for dptr, kptr in ((rbp, r13), (r13, rbp)):
            try:
                data, key = rd(dptr, r12), rd(kptr, r15 or 1)
            except Exception:
                continue
            dec = bytes(x ^ key[j % len(key)] for j, x in enumerate(data)).split(b'\x00')[0]
            cands.append((readability(dec), dec))
        best = max(cands, key=lambda c: c[0]) if cands else (0, b'')
        results[idx] = (best[1], 'score=%.2f' % best[0])

    lines = []
    for idx in sorted(results):
        value, note = results[idx]
        lines.append('%d: %r  [%s]\n' % (idx, value, note))
    write_file(args.output, ''.join(lines).encode('utf-8', errors='replace'))
    ok = sum(1 for v, _ in results.values() if v)
    print('decoded %d/%d -> %s' % (ok, len(results), args.output))
    for idx in sorted(results):
        v, note = results[idx]
        print(idx, '->', repr(v[:100]) if v else None)
    return 0
