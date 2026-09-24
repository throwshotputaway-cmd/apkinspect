import gzip
import zlib

from .common import ToolError, read_asset, read_key, report_plain, validate_payload, write_file


def decrypt_blob(data: bytes, key: bytes) -> bytes:
    if not data:
        raise ToolError('XOR-gzip payload is empty')
    if not key:
        raise ToolError('XOR key must not be empty')
    transformed = bytes(value ^ key[index % len(key)]
                        for index, value in enumerate(data))
    try:
        return gzip.decompress(transformed)
    except (OSError, EOFError, ValueError, zlib.error) as e:
        raise ToolError('XOR-gzip payload is not valid gzip: %s' % e)


def register(sub):
    parser = sub.add_parser('xor-gzip', help='decrypt repeating-XOR plus gzip assets')
    parser.add_argument('apk', help='carrier APK')
    parser.add_argument('asset', nargs='?', default='assets/f89710c8', help='encrypted asset path')
    parser.add_argument('-o', '--output', required=True, help='output file')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--key', help='XOR key as hex')
    source.add_argument('--key-file', help='file containing XOR key hex')
    parser.add_argument('--expect', choices=('auto', 'apk', 'dex'), default='dex')
    parser.set_defaults(func=run)


def run(args) -> int:
    key = read_key(args.key, args.key_file, 'key')
    data = read_asset(args.apk, args.asset)
    plaintext = decrypt_blob(data, key)
    entries = validate_payload(plaintext, args.expect, 'XOR-gzip output')
    write_file(args.output, plaintext)
    if entries:
        print('zip entries: %d' % entries)
    report_plain(args.output, plaintext)
    return 0
