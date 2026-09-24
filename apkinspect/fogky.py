#!/usr/bin/env python3
"""Full fogky3f0e pipeline from ba.ac6bHdI: XOR-pad -> RC4(x4 KSA) -> AES-GCM.

The blob layout is [16B xor-pad][16B rc4-key][RC4(XOR(blob[32:], xor-pad))]
and the RC4 output is [12B IV][GCM ciphertext+tag], decrypted with the
abm4() split-array key (use `splitkey` to re-derive it per sample).

Plaintext can be an MSZ1 container: 'MSZ1' + zlib stream wrapping an MSP1
entry table (count, then name_len/name/size/data records). This builder line
ships an APK split set that way, so container entries are extracted as files
and -o is treated as a directory. Use --raw to write the decrypted bytes
untouched instead.
"""
import io
import os
import struct
import zipfile
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .common import ToolError, read_asset, report_plain, safe_basename, safe_output_path, sha256, write_file
from .ui import ui_for

# abm4() split-array key for the reference sample (signed bytes -> XOR halves)
_A = [120, 71, -126, 123, 69, -16, -26, -59, 114, -11, 84, 124, -83, -79,
      55, 106, 43, 63, 99, -115, -55, 16, 95, -71, 37, 62, 40, 126, -53,
      101, -111, 126]
_B = [-85, -120, 88, -106, -83, -82, -87, 34, 20, 33, 6, -95, 94, -98,
      12, -62, 14, -108, 105, -79, 80, 26, -85, -90, -96, -60, 69, -103,
      -36, -114, 16, 122]
DEFAULT_KEY = bytes((a & 0xFF) ^ (b & 0xFF) for a, b in zip(_A, _B))

MSZ1_MAGIC = b'MSZ1'
MSP1_MAGIC = 827347789
MAX_ENTRIES = 64


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


def parse_key(hexstr):
    """Return the AES-GCM key from a hex string, or the reference default."""
    if not hexstr:
        return DEFAULT_KEY
    cleaned = hexstr.replace(' ', '').replace('0x', '').replace(':', '')
    try:
        key = bytes.fromhex(cleaned)
    except ValueError:
        raise ToolError('--key must be hex (got %r)' % hexstr)
    if len(key) not in (16, 24, 32):
        raise ToolError('--key must be 16, 24 or 32 bytes, got %d' % len(key))
    return key


def parse_container(data: bytes):
    """Return [(name, bytes)] for an MSZ1/MSP1 payload, else None."""
    if data[:4] != MSZ1_MAGIC:
        return None
    try:
        raw = zlib.decompress(data[4:])
    except zlib.error:
        try:
            raw = zlib.decompress(data[4:], -15)
        except zlib.error:
            raise ToolError('MSZ1 payload is neither zlib nor raw deflate')
    if len(raw) < 8:
        raise ToolError('MSP1 header truncated (%d bytes)' % len(raw))
    magic, count = struct.unpack('<II', raw[:8])
    if magic != MSP1_MAGIC:
        raise ToolError('MSP1 bad magic 0x%08x' % magic)
    if count < 1 or count > MAX_ENTRIES:
        raise ToolError('MSP1 bad entry count: %d' % count)
    off = 8
    entries = []
    for _ in range(count):
        if len(raw) - off < 2:
            raise ToolError('MSP1 truncated name_len')
        nlen, = struct.unpack('<H', raw[off:off + 2])
        off += 2
        if nlen < 1 or nlen > 4096 or off + nlen > len(raw):
            raise ToolError('MSP1 bad name_len: %d' % nlen)
        try:
            name = raw[off:off + nlen].decode('utf-8')
        except UnicodeDecodeError as e:
            raise ToolError('MSP1 entry name is not UTF-8: %s' % e)
        off += nlen
        if len(raw) - off < 4:
            raise ToolError('MSP1 truncated size for %s' % name)
        size, = struct.unpack('<I', raw[off:off + 4])
        off += 4
        if off + size > len(raw):
            raise ToolError('MSP1 bad size %d for %s' % (size, name))
        entries.append((name, raw[off:off + size]))
        off += size
    if off != len(raw):
        raise ToolError('MSP1 has %d trailing bytes' % (len(raw) - off))
    return entries


def register(sub):
    p = sub.add_parser('fogky', help='decrypt fogky XOR+RC4x4+AES-GCM blobs')
    p.add_argument('apk', help='carrier APK')
    p.add_argument('asset', help='asset path inside the APK')
    p.add_argument('-o', '--output', required=True,
                   help='output file, or directory for MSZ1 container entries')
    p.add_argument('--key', default=None,
                   help='AES-GCM key as hex (default: reference abm4 key)')
    p.add_argument('--raw', action='store_true',
                   help='write decrypted bytes as-is, skip MSZ1 container')
    p.set_defaults(func=run)


def run(args) -> int:
    key = parse_key(args.key)
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
    entries = None if getattr(args, 'raw', False) else parse_container(pt)
    if entries is None:
        write_file(args.output, pt)
        report_plain(args.output, pt)
        return 0
    targets = []
    seen = set()
    for name, _ in entries:
        basename = safe_basename(name)
        if basename in seen:
            raise ToolError('duplicate output name: %s' % basename)
        seen.add(basename)
        targets.append(safe_output_path(args.output, basename))
    os.makedirs(args.output, exist_ok=True)
    print('MSZ1 container: %d entries, %d bytes -> %s'
          % (len(entries), len(pt), args.output))
    ui = ui_for(args)
    with ui.progress('Extracting MSZ1 entries', len(entries)) as progress:
        for (name, data), target in zip(entries, targets):
            write_file(target, data)
            extra = ''
            if data[:4] == b'PK':
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as archive:
                        bad = archive.testzip()
                        extra = (' zip_ok entries=%d' % len(archive.namelist())
                                 if bad is None else ' zip_corrupt')
                except Exception:
                    extra = ' zip_corrupt'
            print('  %-32s len=%-9d sha256=%s%s'
                  % (name, len(data), sha256(data)[:32], extra))
            progress.advance(detail=name)
    return 0
