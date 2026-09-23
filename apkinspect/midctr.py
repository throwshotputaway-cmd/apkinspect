#!/usr/bin/env python3
"""AES-CTR payload decryptor for the native-loader dropper line.

The native loop (oP7cJ in the bundled .so) builds each 16-byte counter block as:
  bytes 0-7 : 8-byte constant (LE of the inline immediate)
  bytes 8-11: block number (byte_index >> 4) as 28-bit LE
  bytes 12-15: zero
and keystream = AES-128-ECB(key, counter_block). Standard AES; the only
quirk is the counter living in the MIDDLE of the block (byte 8 first),
so stock CTR tooling decrypts block 0 correctly and garbage afterwards.
"""
import argparse
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .common import ToolError, read_asset, report_plain, verify_zip, write_file


def decrypt_blob(ct: bytes, key: bytes, const8: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = bytearray(len(ct))
    for blk in range((len(ct) + 15) // 16):
        ctr = const8 + struct.pack('<Q', blk & 0x0FFFFFFF)
        ks = enc.update(ctr)
        s = blk * 16
        chunk = ct[s:s + 16]
        for i in range(len(chunk)):
            out[s + i] = chunk[i] ^ ks[i]
    return bytes(out)


def key_from_so(path: str, offset: int) -> bytes:
    with open(path, 'rb') as fh:
        fh.seek(offset)
        key = fh.read(16)
    if len(key) != 16:
        raise ToolError('could not read 16-byte key at %#x of %s' % (offset, path))
    return key


def register(sub):
    p = sub.add_parser('midctr', help='decrypt mid-counter AES-CTR assets')
    p.add_argument('apk', help='carrier APK')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--asset', default='assets/nvcgehin')
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument('--key', help='AES-128 key as hex')
    src.add_argument('--so', help='native .so holding the key in .data')
    p.add_argument('--key-off', type=lambda x: int(x, 0), default=0x17440,
                   help='key file offset inside --so')
    p.add_argument('--const', type=lambda x: int(x, 0),
                   default=0x6b71def9b8938f83,
                   help='8-byte counter constant (native immediate)')
    p.add_argument('--no-verify', action='store_true')
    p.set_defaults(func=run)


def run(args) -> int:
    key = bytes.fromhex(args.key) if args.key else key_from_so(args.so, args.key_off)
    const8 = struct.pack('<Q', args.const)
    print('key=%s const8=%s' % (key.hex(), const8.hex()))
    ct = read_asset(args.apk, args.asset)
    pt = decrypt_blob(ct, key, const8)
    if not args.no_verify:
        try:
            n = verify_zip(pt)
        except ToolError as e:
            raise ToolError('%s (wrong key/const?)' % e)
        print('zip entries: %d' % n)
    write_file(args.output, pt)
    report_plain(args.output, pt)
    return 0
