#!/usr/bin/env python3
"""LCG stream-cipher decryptor for GhostBat-style .dat dropper payloads.

Scheme: skip HEADER bytes, then per byte
    state = (state * A + C) & 0xFFFFFFFF
    out   = in ^ ((state >> 24) & 0xFF)
(validated against InstallHelper.writeAssetToFile disassembly)
"""
import argparse

from .common import ToolError, report_plain, verify_zip, warn, write_file

A = 0x0019660D  # 1664525 (Numerical Recipes LCG)
C = 0x3C6EF35F  # 1013904223
MASK = 0xFFFFFFFF


def decrypt(data: bytes, seed: int = 0x4394D, header: int = 16) -> bytes:
    enc = data[header:]
    state = seed
    out = bytearray(len(enc))
    for i, b in enumerate(enc):
        state = ((state * A) + C) & MASK
        out[i] = b ^ ((state >> 24) & 0xFF)
    return bytes(out)


def looks_like_lcg_blob(data: bytes) -> bool:
    """16 zero-byte header + high entropy body is the family tell."""
    return data[:16] == b'\x00' * 16


def register(sub):
    p = sub.add_parser('lcg', help='decrypt LCG-stream .dat dropper payloads')
    p.add_argument('input', help='encrypted blob (.dat asset or standalone file)')
    p.add_argument('-o', '--output', required=True, help='where to write plaintext')
    p.add_argument('--seed', type=lambda x: int(x, 0), default=0x4394D)
    p.add_argument('--header', type=int, default=16)
    p.add_argument('--no-verify', action='store_true')
    p.set_defaults(func=run)


def run(args) -> int:
    with open(args.input, 'rb') as fh:
        data = fh.read()
    if not looks_like_lcg_blob(data):
        warn('no 16-zero-byte header; trying anyway')
    pt = decrypt(data, args.seed, args.header)
    if not args.no_verify:
        try:
            verify_zip(pt)
        except ToolError as e:
            raise ToolError('%s (wrong seed/header?)' % e)
    write_file(args.output, pt)
    report_plain(args.output, pt)
    return 0
