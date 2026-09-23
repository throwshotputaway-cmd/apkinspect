#!/usr/bin/env python3
"""Full fogky3f0e pipeline from ba.ac6bHdI: XOR-pad -> RC4(x4 KSA) -> AES-GCM.

The blob layout is [16B xor-pad][16B rc4-key][RC4(XOR(blob[32:], xor-pad))]
and the RC4 output is [12B IV][GCM ciphertext+tag], decrypted with the
abm4() split-array key (use `splitkey` to re-derive it per sample).
"""
import argparse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .common import ToolError, read_asset, report_plain, write_file

# abm4() split-array key for the reference sample (signed bytes -> XOR halves)
_A = [120, 71, -126, 123, 69, -16, -26, -59, 114, -11, 84, 124, -83, -79,
      55, 106, 43, 63, 99, -115, -55, 16, 95, -71, 37, 62, 40, 126, -53,
      101, -111, 126]
_B = [-85, -120, 88, -106, -83, -82, -87, 34, 20, 33, 6, -95, 94, -98,
      12, -62, 14, -108, 105, -79, 80, 26, -85, -90, -96, -60, 69, -103,
      -36, -114, 16, 122]
DEFAULT_KEY = bytes((a & 0xFF) ^ (b & 0xFF) for a, b in zip(_A, _B))


def rc4x4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    for _ in range(4):  # NOTE: 4 KSA rounds, not the usual 1
        j = 0
        for i in range(256):
            si = s[i]
            j = (j + si + (key[i % 16] & 0xFF)) & 0xFF
            s[i] = s[j]
            s[j] = si
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        si = s[i]
        j = (j + si) & 0xFF
        s[i] = s[j]
        s[j] = si
        out.append(byte ^ (s[(s[i] + si) & 0xFF] & 0xFF))
    return bytes(out)


def register(sub):
    p = sub.add_parser('fogky', help='decrypt fogky XOR+RC4x4+AES-GCM blobs')
    p.add_argument('apk', help='carrier APK')
    p.add_argument('asset', help='asset path inside the APK')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--key', default=None,
                   help='AES-GCM key as hex (default: reference abm4 key)')
    p.set_defaults(func=run)


def run(args) -> int:
    key = bytes.fromhex(args.key) if args.key else DEFAULT_KEY
    blob = read_asset(args.apk, args.asset)
    if len(blob) < 32 + 12 + 16:
        raise ToolError('blob too short (%d bytes)' % len(blob))
    xpad, rkey, rest = blob[:16], blob[16:32], blob[32:]
    stage2 = rc4x4(bytes(b ^ xpad[i % 16] for i, b in enumerate(rest)), rkey)
    iv, ct = stage2[:12], stage2[12:]
    try:
        dec = Cipher(algorithms.AES(key), modes.GCM(iv, ct[-16:])).decryptor()
        pt = dec.update(ct[:-16]) + dec.finalize()
    except Exception as e:
        raise ToolError('AES-GCM tag failure - wrong key or blob? (%s)' % e)
    write_file(args.output, pt)
    report_plain(args.output, pt)
    return 0
