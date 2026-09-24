#!/usr/bin/env python3
"""Two-stage decryptor for the signed(46) dictionary-name asset line.

Stage 1: asset 0uym5nunf4giud61 is repeating-XOR with the 64-char key from
  the native string table (emulated from libnapoli.so prologues).
  -> valid DEX (com.example.virusscanbypassbootstrapper.DexLoader).
Stage 2: DexLoader.openAssets() decrypts assets with AES/CBC/PKCS5Padding,
  key = SHA-1(asset_basename)[..16], IV = zeros; applied here to
  bvxg8rspej6aqybh/u0w4uogp -> ZIP with classes.dex (com.hv.nodulized).
Other assets (aeromarine, aliner, oversettlement, sophisticallycenses,
unionization + small ones) do NOT open under this scheme; they are
consumed by stage-2 code behind the numeric string oracle
(see `oracle`) - dynamic or deeper RE required.
"""
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .common import ToolError, pkcs7_unpad, read_asset, verify_zip, write_file

DEFAULT_XOR64 = b'hgwsldiyf7oxls3fm5dxmvrfpcaimougsvrxujztomip20cinmhna1cnghwxcdgc'
DEFAULT_STAGE1 = 'assets/0uym5nunf4giud61'
DEFAULT_STAGE2 = 'assets/bvxg8rspej6aqybh/u0w4uogp'


def register(sub):
    p = sub.add_parser('signed', help='decrypt signed(46)-line two-stage assets')
    p.add_argument('apk')
    p.add_argument('--outdir', default='.')
    p.add_argument('--stage1', default=DEFAULT_STAGE1)
    p.add_argument('--stage2', default=DEFAULT_STAGE2)
    p.add_argument('--xor-key', default=None,
                   help='stage-1 XOR key text (default: builder key)')
    p.set_defaults(func=run)


def run(args) -> int:
    os.makedirs(args.outdir, exist_ok=True)
    xor64 = args.xor_key.encode() if args.xor_key else DEFAULT_XOR64
    if not xor64:
        raise ToolError('XOR key must not be empty')
    enc = read_asset(args.apk, args.stage1)
    dex = bytes(b ^ xor64[i % len(xor64)] for i, b in enumerate(enc))
    if not dex.startswith(b'dex\n'):
        raise ToolError('stage-1 XOR failed (no dex magic - wrong key?)')
    p1 = os.path.join(args.outdir, 'stage1.dex')
    write_file(p1, dex)
    print('stage1.dex OK (%d bytes) -> %s' % (len(dex), p1))

    enc2 = read_asset(args.apk, args.stage2)
    base = args.stage2.replace('\\', '/').rsplit('/', 1)[-1].encode()
    key = hashlib.sha1(base).digest()[:16]
    try:
        dec = Cipher(algorithms.AES(key), modes.CBC(b'\x00' * 16)).decryptor()
        pt = dec.update(enc2) + dec.finalize()
    except Exception as e:
        raise ToolError('stage-2 AES-CBC failed: %s' % e)
    try:
        pt = pkcs7_unpad(pt)
    except ToolError as e:
        raise ToolError('stage-2 %s' % e)
    n = verify_zip(pt, 'stage-2 output')
    print('stage2.zip entries: %d' % n)
    p2 = os.path.join(args.outdir, 'stage2.zip')
    write_file(p2, pt)
    print('stage2.zip OK (%d bytes) -> %s' % (len(pt), p2))
    return 0
