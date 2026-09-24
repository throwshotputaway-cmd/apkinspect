#!/usr/bin/env python3
"""Single-blob repeating-XOR decryptor for staged-payload .raw assets.

Scheme: out[i] = in[i] ^ key[(i + offset) % len(key)], usually offset 0.
The halves password is builder-wide, not per-build - try it first on any
new sharded sample before deeper RE.
"""

from .common import ToolError, read_asset, report_plain, verify_zip, write_file

DEFAULT_KEY = b'oB1xhjKSLwPMX7FUGjsahD0gWzD0W3v7UWOtiPtw'


def register(sub):
    p = sub.add_parser('shard', help='XOR-decrypt single-blob staged assets')
    p.add_argument('apk', help='carrier APK')
    p.add_argument('asset', help='asset path inside the APK')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--key', default=None,
                   help='key text (default: builder halves password)')
    p.add_argument('--offset', type=int, default=0,
                   help='cumulative stream offset for multi-shard chains')
    p.add_argument('--no-verify', action='store_true')
    p.set_defaults(func=run)


def run(args) -> int:
    key = args.key.encode() if args.key else DEFAULT_KEY
    if not key:
        raise ToolError('key must not be empty')
    if args.offset < 0:
        raise ToolError('offset must not be negative')
    data = read_asset(args.apk, args.asset)
    pt = bytes(b ^ key[(i + args.offset) % len(key)] for i, b in enumerate(data))
    if not args.no_verify:
        try:
            n = verify_zip(pt)
        except ToolError as e:
            raise ToolError('%s (wrong key/offset?)' % e)
        print('zip entries: %d' % n)
    write_file(args.output, pt)
    report_plain(args.output, pt)
    return 0
