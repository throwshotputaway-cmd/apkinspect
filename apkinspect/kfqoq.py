import gzip
import hashlib
import hmac
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .common import ToolError, read_asset, read_file, report_plain, validate_payload, write_file


def decode_key(encoded: str) -> bytes:
    encoded = encoded.strip()
    if len(encoded) < 4 or len(encoded) % 2:
        raise ToolError('AES-GCM/HKDF key must be even-length hex text')
    try:
        prefix = int(encoded[:2], 16)
        decoded = ''.join(chr(int(encoded[index:index + 2], 16) ^ prefix)
                           for index in range(2, len(encoded), 2))
        key = bytes(int(decoded[index:index + 2], 16)
                    for index in range(0, len(decoded), 2))
    except ValueError:
        raise ToolError('AES-GCM/HKDF key must be valid hex text')
    if len(key) not in (16, 24, 32):
        raise ToolError('AES-GCM/HKDF key must decode to 16, 24 or 32 bytes')
    return key


def load_key(hk: str, hk_file: str) -> bytes:
    if (hk is None) == (hk_file is None):
        raise ToolError('provide exactly one of --hk or --hk-file')
    if hk_file is not None:
        try:
            hk = read_file(hk_file, 'AES-GCM/HKDF key file').decode('ascii').strip()
        except UnicodeDecodeError:
            raise ToolError('AES-GCM/HKDF key file is not ASCII hex text')
    return decode_key(hk)


def kind_byte(value: str) -> bytes:
    value = value.upper()
    if value == 'H':
        return bytes([((-51) & 0xFF) ^ 0xA5])
    if value == 'P':
        return bytes([((-43) & 0xFF) ^ 0xA5])
    try:
        parsed = int(value, 0)
    except ValueError:
        raise ToolError('kind must be H, P, or an integer byte')
    if not 0 <= parsed <= 255:
        raise ToolError('kind byte out of range: %s' % value)
    return bytes([parsed])


def decrypt_blob(data: bytes, key: bytes, kind: bytes) -> bytes:
    if len(data) < 45:
        raise ToolError('AES-GCM/HKDF blob is too short (%d bytes)' % len(data))
    if len(kind) != 1:
        raise ToolError('AES-GCM/HKDF kind must be one byte')
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    prk = hmac.new(salt, key, hashlib.sha256).digest()
    derived = hmac.new(prk, kind + b'\x01', hashlib.sha256).digest()
    try:
        plaintext = AESGCM(derived).decrypt(nonce, ciphertext, salt + kind)
    except Exception as e:
        raise ToolError('AES-GCM/HKDF AES-GCM decryption failed: %s' % e)
    if not plaintext:
        raise ToolError('AES-GCM/HKDF payload is empty')
    payload = plaintext[1:]
    if plaintext[0] & 1:
        for decompressor in (gzip.decompress,
                            lambda data: zlib.decompress(data, zlib.MAX_WBITS),
                            lambda data: zlib.decompress(data, -zlib.MAX_WBITS)):
            try:
                return decompressor(payload)
            except (OSError, EOFError, ValueError, zlib.error):
                continue
        raise ToolError('AES-GCM/HKDF compressed payload is invalid')
    return payload


def register(sub):
    parser = sub.add_parser('aes-gcm-hkdf', help='decrypt direct AES-GCM/HKDF loader assets')
    parser.add_argument('apk', help='carrier APK')
    parser.add_argument('asset', help='encrypted asset path')
    parser.add_argument('-o', '--output', required=True, help='output file')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--hk', help='obfuscated AES-GCM/HKDF key text')
    source.add_argument('--hk-file', help='file containing obfuscated AES-GCM/HKDF key text')
    parser.add_argument('--kind', default='H', help='kind byte: H, P, or 0xNN')
    parser.add_argument('--expect', choices=('auto', 'apk', 'dex'), default='dex')
    parser.set_defaults(func=run)


def run(args) -> int:
    key = load_key(args.hk, args.hk_file)
    data = read_asset(args.apk, args.asset)
    plaintext = decrypt_blob(data, key, kind_byte(args.kind))
    entries = validate_payload(plaintext, args.expect, 'AES-GCM/HKDF output')
    write_file(args.output, plaintext)
    if entries:
        print('zip entries: %d' % entries)
    report_plain(args.output, plaintext)
    return 0
