#!/usr/bin/env python3
"""Break numeric string oracles (signed(46) mfEauTFiO4iBZizsu9 family).

The protector hides strings behind three primitives (mixer, charAt extractor,
string builder) indexed by a 64-bit seed and a blob string. This tool
reimplements them from dexdump disassembly, finds every `const-wide` seed
feeding the oracle method, and decodes each one.

Two DEX string-table bugs this avoids (learned the hard way):
- Q91iGS5B return is (x >> 32) & M, not the full 64-bit pair
- string_data_item length is a UTF-16 char count, not a byte count: strings
  must be read up to the NUL terminator, not by length prefix
"""
import argparse
import struct

from .common import ToolError, warn

M = (1 << 64) - 1


def to_short(x):
    x &= 0xFFFF
    return x - 0x10000 if x >= 0x8000 else x


def rotl16(s, n):
    # Dalvik: shl-int + rsub + ushr-int + or-int on the SIGN-EXTENDED 32-bit
    # value, then int-to-short. Emulate exactly (differs from a clean 16-bit
    # rotate when s < 0 because ushr drags in sign bits).
    sx = s & 0xFFFFFFFF
    n &= 31
    if n == 0:
        return to_short(sx)
    return to_short((sx << n) | (sx >> (32 - n)))


def Q91(x):
    x &= M
    x ^= (x >> 33)
    x = (x * 0x62a9d9ed799705f5) & M
    x ^= (x >> 28)
    x = (x * 0xcb24d0a5c88c35b3) & M
    # return ((j2 ^ (j2 >>> 28)) * C2) >>> 32  (plain logical shift value)
    return (x >> 32) & M


def q2sx(x):
    x &= M
    a = to_short(x & 0xFFFF)
    b = to_short((x >> 16) & 0xFFFF)
    s5 = to_short(a + b)
    s5 = rotl16(s5, 9)
    if s5 >= 0x8000:
        s5 -= 0x10000
    t = to_short(s5 + a)
    u = to_short(b ^ a)
    v0 = rotl16(a, 13)
    if v0 >= 0x8000:
        v0 -= 0x10000
    v0 = to_short(v0 ^ u)
    v0 = to_short(v0 ^ ((u << 5) & 0xFFFFFFFF))
    r = rotl16(u, 10)
    if r >= 0x8000:
        r -= 0x10000
    # ((((long)r) | (((long)t) << 16)) << 16) | (long)v0  -- Java sign-extends
    # each short to long before assembling (jadx ground truth).
    t64 = t & M
    r64 = r & M
    v064 = v0 & M
    return ((((r64 | ((t64 << 16) & M)) & M) << 16) | v064) & M


def xgv_q2sx(i, blob, seed):
    h = q2sx(seed)
    s = blob[i // 8191]
    c = ord(s[i % 8191])
    return (((c & 0xFFFF) << 32) ^ h) & M


def wZFA(seed, blob):
    t = seed & 0xFFFFFFFF
    t = Q91(t)
    t = q2sx(t)
    hi = (t >> 32) & 0xFFFF
    t = q2sx(t)
    mid = (t >> 16) & 0xFFFF0000
    s2 = ((seed >> 32) & M) ^ hi ^ mid
    s2 &= M
    n = s2 & 0xFFFFFFFF
    if n >= 0x80000000:
        n -= 0x100000000
    out = xgv_q2sx(n, blob, t)
    strlen = (out >> 32) & 0xFFFF
    chars = []
    for k in range(strlen):
        c = xgv_q2sx(n + k + 1, blob, out)
        chars.append(chr((c >> 32) & 0xFFFF))
    return ''.join(chars)


def read_uleb(d, o):
    r = 0
    s = 0
    while True:
        b = d[o]
        o += 1
        r |= (b & 0x7f) << s
        s += 7
        if not b & 0x80:
            return r, o


def get_strings(dex):
    ns, off = struct.unpack('<II', dex[56:64])
    so = struct.unpack('<%dI' % ns, dex[off:off + 4 * ns])
    out = []
    for a in so:
        _, p = read_uleb(dex, a)
        e = dex.index(b'\x00', p)
        out.append(dex[p:e].decode('utf-8', errors='replace'))
    return out


def find_oracle_idx(dex, strings, method_name):
    nm = struct.unpack('<I', dex[88:92])[0]
    moff = struct.unpack('<I', dex[92:96])[0]
    hits = []
    for i in range(nm):
        _, _, name = struct.unpack('<HHI', dex[moff + 8 * i:moff + 8 * i + 8])
        if strings[name] == method_name:
            hits.append(i)
    return hits


def scan_seeds(dex, oracle_idx):
    """Find const-wide literals feeding invoke-static to the oracle method.

    const-wide is opcode 0x19 (5 code units); the oracle call must appear
    within the following units. Yields distinct seeds in file order.
    """
    seeds = []
    seen = set()
    mv = memoryview(dex)
    for o in range(0, len(dex) - 10, 2):
        if mv[o] != 0x19:
            continue
        seed = struct.unpack('<Q', dex[o + 2:o + 10])[0]
        if seed in seen:
            continue
        # look ahead for invoke-static to the oracle (format 35c: op=0x71,
        # AA|count, then method_idx u16 in the next unit)
        units = struct.unpack('<13H', dex[o:o + 26])
        ok = False
        for k in range(5, 12):
            if (units[k] & 0xFF) == 0x71 and units[k + 1] == oracle_idx:
                ok = True
                break
        if ok:
            seen.add(seed)
            seeds.append(seed)
    return seeds


def readability(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for ch in s if 32 <= ord(ch) < 127 or ch in '\n\r\t')
    return ok / len(s)


def register(sub):
    p = sub.add_parser('oracle', help='decode numeric string-oracle call sites')
    p.add_argument('dex', help='classes.dex (extract from APK first)')
    p.add_argument('--method', default='q2sx0mC159653E9dHg',
                   help='oracle method name')
    p.add_argument('--min-score', type=float, default=0.0,
                   help='only show decodes with readability >= this')
    p.add_argument('-o', '--output', help='write decoded strings here')
    p.set_defaults(func=run)


def run(args) -> int:
    with open(args.dex, 'rb') as fh:
        dex = fh.read()
    if dex[:4] != b'dex\n':
        raise ToolError('not a DEX file: %s' % args.dex)
    strings = get_strings(dex)
    blob = max(strings, key=len)
    print('strings=%d blob_chars=%d' % (len(strings), len(blob)))
    hits = find_oracle_idx(dex, strings, args.method)
    if not hits:
        raise ToolError("oracle method '%s' not found (wrong family?)" % args.method)
    if len(hits) > 1:
        warn('multiple methods named %s: %s (using first)' % (args.method, hits))
    seeds = scan_seeds(dex, hits[0])
    print('seeds found: %d' % len(seeds))
    lines = []
    for s in seeds:
        try:
            txt = wZFA(s, [blob])
        except Exception:
            continue
        score = readability(txt)
        if score >= args.min_score:
            lines.append('0x%016x -> %r [%.2f]' % (s, txt, score))
    for ln in lines:
        print(ln)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(lines) + '\n')
        print('written to %s' % args.output)
    return 0
