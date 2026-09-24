#!/usr/bin/env python3
"""Trim trailing filler from binary AndroidManifest.xml entries.

Some protectors pad the manifest far beyond its real AXML length (tens of MB
of filler after the END_NAMESPACE chunk). The archive stays CRC-valid so
zipfile/aapt tolerate it, but jadx/apktool manifest parsing breaks. This
rebuilds the APK with the manifest truncated to its true end.
"""
import io
import struct
import zipfile

from .common import ToolError, write_file
from .ui import ui_for

END_NAMESPACE = 0x0101


def real_axml_len(data: bytes) -> int:
    if data[:4] != b'\x03\x00\x08\x00':
        raise ToolError('not a binary AXML file (bad magic)')
    off = 8
    while off + 8 <= len(data):
        typ, _, size = struct.unpack('<HHI', data[off:off + 8])
        if size < 8 or off + size > len(data):
            raise ToolError('bad AXML chunk at offset %d' % off)
        off += size
        if typ == END_NAMESPACE:
            return off
    raise ToolError('END_NAMESPACE chunk not found')


def register(sub):
    p = sub.add_parser('axml-trim', help='rebuild APK with filler-free manifest')
    p.add_argument('apk', help='input APK')
    p.add_argument('-o', '--output', required=True, help='output APK path')
    p.add_argument('--entry', default='AndroidManifest.xml')
    p.set_defaults(func=run)


def run(args) -> int:
    with zipfile.ZipFile(args.apk) as zin:
        try:
            raw = zin.read(args.entry)
        except KeyError:
            raise ToolError("entry '%s' not found" % args.entry)
        real = real_axml_len(raw)
        print('manifest: declared=%d real=%d (truncating %d filler bytes)'
              % (len(raw), real, len(raw) - real))
        buf = io.BytesIO()
        ui = ui_for(args)
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zout:
            with ui.progress('Rebuilding APK entries', len(zin.infolist())) as progress:
                for info in zin.infolist():
                    data = zin.read(info.filename)
                    if info.filename == args.entry:
                        data = raw[:real]
                    zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                    zi.compress_type = info.compress_type
                    zi.external_attr = info.external_attr
                    zi.create_system = info.create_system
                    zout.writestr(zi, data)
                    progress.advance(detail=info.filename)
    out = buf.getvalue()
    write_file(args.output, out)
    print('wrote %s (%d bytes)' % (args.output, len(out)))
    return 0
