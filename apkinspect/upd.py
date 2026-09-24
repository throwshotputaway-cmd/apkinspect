#!/usr/bin/env python3
"""Repeating-XOR decryptor for the update.enc builder line.

Scheme: out[i] = in[i] ^ key[i % len(key)] with the builder key taken from
the libpayload.so rodata (getSecretKey return). Same key across all observed
samples - try it first on any new update.enc carrier before deeper RE.
"""

from .common import ToolError, read_asset, report_plain, verify_zip, write_file

DEFAULT_KEY = b'PayloadSecure2026_ProtectionKey'


def register(sub):
    p = sub.add_parser('upd', help='XOR-decrypt update.enc payloads')
    p.add_argument('apk', help='carrier APK')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--key', default=None, help='key text (default: builder key)')
    p.add_argument('--asset', default='assets/update.enc')
    p.add_argument('--no-verify', action='store_true')
    p.set_defaults(func=run)


def run(args) -> int:
    key = args.key.encode() if args.key else DEFAULT_KEY
    if not key:
        raise ToolError('key must not be empty')
    data = read_asset(args.apk, args.asset)
    pt = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    if not args.no_verify:
        try:
            n = verify_zip(pt)
        except ToolError as e:
            raise ToolError('%s (wrong key?)' % e)
        print('zip entries: %d' % n)
    write_file(args.output, pt)
    report_plain(args.output, pt)
    return 0
