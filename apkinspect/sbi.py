#!/usr/bin/env python3
"""Decryptor for the SBI credit-card dropper line (ixrxty/vvcym/cgifamily).

Each asset is wrapped in the same onion (recovered from cgiyd disassembly):

1. unshell:  AES-GCM, key = SHA-256(blob[0:32] + xb(tag)),
             nonce = blob[32:44], AAD = xb(tag)
2. uncloak:  LCG un-permute (seed from SHA-256 halves) + nibble swap +
             SHA-256-CTR keystream XOR
3. pull:     HKDF-SHA256(key_bytes, salt, kind) -> AES-GCM
             (nonce = uncloaked[16:28], AAD = salt + kind),
             flag byte selects raw-DEFLATE inflation
4. unwrap:   if the result is not already PK/DEX, one more AES-GCM round
             (key = SHA-256(nonce + pepper), AAD = xb_pay)

`.idx` assets yield a DEX (stage 2); `nvcgehin` yields the inner APK
(stage 3). The HK/PK hex master keys below are builder defaults -
override per sample via --hk/--pk.
"""
import argparse
import hashlib
import hmac
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .common import ToolError, read_asset, report_plain, verify_zip, write_file

K = (-91) & 0xFF

DEFAULT_HK = ('e3d2d086d4d5818582d7d28282d4d685da86da82da81d68087d38685d6'
              'dad485d282d1d4d0d3d6d1d1d7dbd1dad7d3d0db82d1d7d08180dbd4d08085'
              '8681d0d5db')
DEFAULT_PK = ('9cabaea9a9afa8aaf8fdadaaf9a4fffea5ada8f8aaf8a9afaba4fea5acfdaf'
              'aafeacada5a9f8abadaffafefaa5aea8aea9fafaaba8a8fea4afffacadf8ab'
              'aaafaf')

_PEPPER = [97, 76, -65, -34, -54, -123, 125, -101, -16, 4, 28, 101, -37,
           -111, 115, 87, 47, -71, 59, -30, 16, 117, -102, -49, -67, 71,
           98, 124, -18, -86, -1, -109]
_XB_PAY = [-43, -60, -36]


def xb(arr):
    return bytes([(b & 0xFF) ^ K for b in arr])


def hx(s):
    n = len(s) // 2
    if n < 2:
        return ''
    k = int(s[0:2], 16)
    return ''.join(chr(int(s[i * 2:(i + 1) * 2], 16) ^ k) for i in range(1, n))


def key_from_hex(s):
    h = hx(s)
    return bytes(int(h[i * 2:(i + 1) * 2], 16) for i in range(len(h) // 2))


def unshell(data: bytes) -> bytes:
    if len(data) < 60:
        raise ToolError('blob too short for unshell (%d bytes)' % len(data))
    s1, nonce, ct = data[0:32], data[32:44], data[44:]
    md = hashlib.sha256()
    md.update(s1)
    md.update(xb([-10 & 0xFF, -109 & 0xFF]))
    try:
        return AESGCM(md.digest()).decrypt(nonce, ct, xb([-10 & 0xFF, -110 & 0xFF]))
    except Exception as e:
        raise ToolError('unshell AES-GCM failed: %s' % e)


def lcg_seed(b1, b2):
    md = hashlib.sha256()
    md.update(b1)
    md.update(b2)
    d = md.digest()
    val = (d[3] & 0xFF) | ((d[0] & 0xFF) << 24) | ((d[1] & 0xFF) << 16) | ((d[2] & 0xFF) << 8) | 1
    return val - 0x100000000 if val >= 0x80000000 else val


def lcg_unpermute(arr, b2, b3):
    out = bytearray(arr)
    if len(out) < 2:
        return out
    seed = lcg_seed(b2, b3) & 0xFFFFFFFF
    idx, perm = [], []
    i = len(out) - 1
    while i > 0:
        seed = ((seed * 1103515245) + 12345) & 0xFFFFFFFF
        idx.append(i)
        perm.append(int(seed % (i + 1)))
        i -= 1
    for a, b in zip(reversed(idx), reversed(perm)):
        out[a], out[b] = out[b], out[a]
    return out


def keystream(b1, b2, length, b3):
    out = bytearray()
    i = 0
    while len(out) < length:
        md = hashlib.sha256()
        md.update(b1)
        md.update(b2)
        md.update(b3)
        md.update(bytes([(i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF]))
        d = md.digest()
        out.extend(d[:min(len(d), length - len(out))])
        i += 1
    return bytes(out)


def uncloak(data: bytes) -> bytes:
    u = unshell(data)
    if len(u) < 17:
        raise ToolError('unshelled blob too short')
    b2, rest = u[:16], bytearray(u[16:])
    tag1 = xb([-14 & 0xFF, -112 & 0xFF])
    unp = lcg_unpermute(rest, b2, tag1)
    for i in range(len(unp)):
        unp[i] = ((unp[i] >> 4) | (unp[i] << 4)) & 0xFF
    tag2 = xb([-14 & 0xFF, -111 & 0xFF])
    ks = keystream(b2, b2[::-1], len(unp), tag2)
    return bytes(x ^ y for x, y in zip(bytes(unp), ks))


def hkdf(key_bytes, salt, kind):
    prk = hmac.new(salt, key_bytes, hashlib.sha256).digest()
    return hmac.new(prk, kind + bytes([1]), hashlib.sha256).digest()


def pull_kind(data: bytes, key_bytes: bytes, kind: bytes) -> bytes:
    u = uncloak(data)
    if len(u) < 45:
        raise ToolError('uncloaked blob too short')
    salt, nonce, ct = u[:16], u[16:28], u[28:]
    try:
        dec = AESGCM(hkdf(key_bytes, salt, kind)).decrypt(nonce, ct, salt + kind)
    except Exception as e:
        raise ToolError('pull AES-GCM failed (wrong kind/master key?): %s' % e)
    if not dec:
        raise ToolError('pull decrypted empty')
    payload = dec[1:]
    if dec[0] & 1:
        try:
            return zlib.decompress(payload)
        except zlib.error:
            return zlib.decompress(payload, -zlib.MAX_WBITS)
    return payload


def unwrap_pay(data: bytes) -> bytes:
    if data[:2] == b'PK' or data[:4] == b'dex\n':
        return data
    if len(data) < 28:
        raise ToolError('payload too short for unwrap (%d bytes)' % len(data))
    nonce, ct = data[:12], data[12:]
    md = hashlib.sha256()
    md.update(nonce)
    md.update(bytes([(b & 0xFF) ^ K for b in _PEPPER]))
    try:
        return AESGCM(md.digest()).decrypt(nonce, ct, xb(_XB_PAY))
    except Exception as e:
        raise ToolError('unwrap AES-GCM failed: %s' % e)


def parse_kind(s: str) -> bytes:
    s = s.upper()
    if s == 'H':
        return bytes([(-51 & 0xFF) ^ K])
    if s == 'P':
        return bytes([(-43 & 0xFF) ^ K])
    v = int(s, 0)
    if not 0 <= v <= 255:
        raise ToolError('kind byte out of range: %s' % s)
    return bytes([v])


def register(sub):
    p = sub.add_parser('sbi', help='decrypt SBI-line GCM/LCG assets')
    p.add_argument('apk', help='carrier APK')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--asset', default='assets/nvcgehin')
    p.add_argument('--hk', default=DEFAULT_HK, help='master key hex (idx stage)')
    p.add_argument('--pk', default=DEFAULT_PK, help='master key hex (apk stage)')
    p.add_argument('--kind', default=None,
                   help='kind byte: H, P, or 0xNN (default: try P then H)')
    p.add_argument('--expect', choices=('auto', 'apk', 'dex'), default='auto')
    p.set_defaults(func=run)


def run(args) -> int:
    data = read_asset(args.apk, args.asset)
    kinds = [parse_kind(args.kind)] if args.kind else [parse_kind('P'), parse_kind('H')]
    # HK opens .idx stages, PK opens nvcgehin; try both pairings
    combos = ([(args.hk, k) for k in kinds] + [(args.pk, k) for k in kinds]
              if not args.kind else
              [(args.hk, kinds[0]), (args.pk, kinds[0])])
    pt, used = None, None
    errors = []
    for master_hex, kind in combos:
        try:
            pt = pull_kind(data, key_from_hex(master_hex), kind)
            used = (master_hex[:12] + '...', kind.hex())
            break
        except ToolError as e:
            errors.append(str(e))
    if pt is None:
        raise ToolError('no master-key/kind combo opened the asset (%s)'
                        % ' | '.join(errors[:2]))
    print('opened with master=%s kind=%s' % used)
    try:
        out = unwrap_pay(pt)
    except ToolError as e:
        raise ToolError('%s' % e)
    if args.expect == 'apk':
        n = verify_zip(out)
        print('zip entries: %d' % n)
    elif args.expect == 'dex':
        if out[:4] != b'dex\n':
            raise ToolError('not a DEX file (wrong kind?)')
    write_file(args.output, out)
    report_plain(args.output, out)
    return 0
