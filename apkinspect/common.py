"""Shared helpers for apkinspect subcommands."""
import hashlib
import io
import os
import re
import sys
import tempfile
import zipfile
import zlib


MAX_ASSET_BYTES = 256 * 1024 * 1024


class ToolError(Exception):
    """Fatal, user-facing tool failure (mapped to a non-zero exit code)."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_file(path: str, what: str = 'input') -> bytes:
    try:
        with open(os.fspath(path), 'rb') as fh:
            return fh.read()
    except OSError as e:
        raise ToolError("cannot read %s '%s': %s" % (what, path, e))


def parse_hex(value: str, name: str = 'value', lengths=None) -> bytes:
    if not isinstance(value, str):
        raise ToolError('%s must be hex text' % name)
    cleaned = ''.join(value.split()).replace(':', '')
    if cleaned.lower().startswith('0x'):
        cleaned = cleaned[2:]
    try:
        parsed = bytes.fromhex(cleaned)
    except ValueError:
        raise ToolError('%s must be hex text' % name)
    if lengths is not None and len(parsed) not in lengths:
        expected = ', '.join(str(length) for length in lengths)
        raise ToolError('%s must be %s bytes, got %d' % (name, expected, len(parsed)))
    return parsed


def read_key(key: str, key_file: str, name: str = 'key', lengths=None) -> bytes:
    if (key is None) == (key_file is None):
        raise ToolError('provide exactly one of --%s or --%s-file' % (name, name))
    if key_file is not None:
        try:
            key = read_file(key_file, '%s file' % name).decode('ascii').strip()
        except UnicodeDecodeError:
            raise ToolError('%s file is not ASCII hex text' % name)
    return parse_hex(key, name, lengths)


def read_asset(apk_path: str, asset: str,
               max_bytes: int = MAX_ASSET_BYTES) -> bytes:
    """Read an asset from a carrier APK, with clean errors."""
    try:
        with zipfile.ZipFile(os.fspath(apk_path)) as archive:
            try:
                info = archive.getinfo(asset)
            except KeyError:
                raise ToolError(
                    "asset '%s' not found in %s (this carrier is not from "
                    "the matching builder line?)" % (asset, apk_path))
            if info.file_size > max_bytes:
                raise ToolError("asset '%s' exceeds the %d-byte limit" % (asset, max_bytes))
            data = archive.read(asset)
            if len(data) > max_bytes:
                raise ToolError("asset '%s' exceeds the %d-byte limit" % (asset, max_bytes))
            return data
    except ToolError:
        raise
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile, zlib.error) as e:
        raise ToolError("not a valid ZIP/APK: %s (%s)" % (apk_path, e))


def verify_zip(data: bytes, what: str = 'output') -> int:
    """Return entry count if data is a healthy ZIP, else raise ToolError."""
    if len(data) < 4 or data[:2] != b'PK':
        raise ToolError('%s is not a valid ZIP (wrong key/params?)' % what)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            bad = archive.testzip()
            if bad is not None:
                raise ToolError('%s is corrupt (first bad entry: %s)' % (what, bad))
            return len(archive.namelist())
    except ToolError:
        raise
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile, zlib.error,
            NotImplementedError) as e:
        raise ToolError('%s is not a valid ZIP: %s' % (what, e))


def validate_payload(data: bytes, expect: str = 'auto', what: str = 'output') -> int:
    if expect in ('apk', 'zip'):
        return verify_zip(data, what)
    if expect == 'dex':
        if data[:4] != b'dex\n':
            raise ToolError('%s is not a DEX file' % what)
        return 0
    if data[:2] == b'PK':
        return verify_zip(data, what)
    if data[:4] != b'dex\n':
        raise ToolError('%s has unknown magic %s' % (what, data[:4].hex()))
    return 0


def write_file(path: str, data: bytes) -> None:
    path = os.fspath(path)
    parent = os.path.dirname(os.path.abspath(path)) or '.'
    os.makedirs(parent, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.apkinspect-', dir=parent)
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def safe_basename(name: str) -> str:
    normalized = os.fspath(name).replace('\\', '/')
    if '\x00' in normalized:
        raise ToolError('output name contains a NUL byte')
    basename = normalized.rsplit('/', 1)[-1]
    if basename in ('', '.', '..'):
        raise ToolError('unsafe output name: %r' % name)
    return basename


def safe_output_path(root: str, name: str) -> str:
    relative = os.fspath(name).replace('\\', '/')
    if not relative or '\x00' in relative or relative.startswith('/'):
        raise ToolError('unsafe output path: %r' % name)
    if re.match(r'^[A-Za-z]:', relative):
        raise ToolError('unsafe output path: %r' % name)
    parts = relative.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ToolError('unsafe output path: %r' % name)
    root_path = os.path.abspath(os.fspath(root))
    candidate = os.path.abspath(os.path.join(root_path, *parts))
    root_real = os.path.realpath(root_path)
    candidate_real = os.path.realpath(candidate)
    try:
        contained = os.path.commonpath((root_real, candidate_real)) == root_real
    except ValueError:
        contained = False
    if not contained or os.path.islink(candidate):
        raise ToolError('output path escapes destination: %r' % name)
    return candidate


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise ToolError('padded data is empty')
    pad = data[-1]
    if pad < 1 or pad > block_size or pad > len(data):
        raise ToolError('invalid PKCS7 padding')
    if data[-pad:] != bytes((pad,)) * pad:
        raise ToolError('invalid PKCS7 padding')
    return data[:-pad]


def report_plain(path: str, data: bytes) -> None:
    print('len=%d sha256=%s magic=%s -> %s'
          % (len(data), sha256(data), data[:4].hex(), path))


def warn(msg: str) -> None:
    print('warning: %s' % msg, file=sys.stderr)
