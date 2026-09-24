import gzip
import hashlib
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .common import ToolError, pkcs7_unpad, read_asset, read_key, report_plain, validate_payload, write_file
from .ui import ui_for


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ToolError('XOR key must not be empty')
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def decrypt_chunks(chunks, key: bytes) -> bytes:
    if not chunks:
        raise ToolError('no encrypted chunks supplied')
    if len(key) not in (16, 24, 32):
        raise ToolError('chunked AES/gzip key must be 16, 24 or 32 bytes')
    encrypted = b''.join(chunks)
    if len(encrypted) < 32:
        raise ToolError('chunked AES/gzip payload is too short (%d bytes)' % len(encrypted))
    transformed = xor_bytes(encrypted, hashlib.sha256(key).digest())
    iv = transformed[:16]
    ciphertext = transformed[16:]
    if not ciphertext or len(ciphertext) % 16:
        raise ToolError('chunked AES/gzip ciphertext has an invalid AES-CBC length')
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise ToolError('chunked AES/gzip AES-CBC decryption failed: %s' % e)
    plaintext = pkcs7_unpad(padded)
    try:
        return gzip.decompress(plaintext)
    except (OSError, EOFError, ValueError, zlib.error) as e:
        raise ToolError('chunked AES/gzip plaintext is not valid gzip: %s' % e)


def register(sub):
    parser = sub.add_parser('chunked-aes-gzip', help='decrypt numbered chunk payloads with SHA-256-XOR, AES-CBC and gzip')
    parser.add_argument('apk', help='carrier APK')
    parser.add_argument('-o', '--output', required=True, help='output file')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--key', help='AES key as hex')
    source.add_argument('--key-file', help='file containing AES key hex')
    parser.add_argument('--prefix', default='assets/vbfk/iyxu_', help='chunk path prefix')
    parser.add_argument('--suffix', default='.png', help='chunk path suffix')
    parser.add_argument('--start', type=int, default=0, help='first chunk index')
    parser.add_argument('--count', type=int, default=10, help='number of chunks')
    parser.add_argument('--expect', choices=('auto', 'apk', 'dex'), default='apk')
    parser.set_defaults(func=run)


def run(args) -> int:
    if args.start < 0 or args.count < 1:
        raise ToolError('chunk start must be non-negative and count must be positive')
    key = read_key(args.key, args.key_file, 'key', (16, 24, 32))
    chunks = []
    ui = ui_for(args)
    with ui.progress('Reading encrypted chunks', args.count) as progress:
        for index in range(args.count):
            name = '%s%d%s' % (args.prefix, args.start + index, args.suffix)
            chunks.append(read_asset(args.apk, name))
            progress.advance(detail=name)
    plaintext = decrypt_chunks(chunks, key)
    entries = validate_payload(plaintext, args.expect, 'chunked AES/gzip output')
    write_file(args.output, plaintext)
    if entries:
        print('zip entries: %d' % entries)
    report_plain(args.output, plaintext)
    return 0
