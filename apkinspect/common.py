"""Shared helpers for apkinspect subcommands."""
import hashlib
import io
import sys
import zipfile


class ToolError(Exception):
    """Fatal, user-facing tool failure (mapped to a non-zero exit code)."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_asset(apk_path: str, asset: str) -> bytes:
    """Read an asset from a carrier APK, with clean errors."""
    try:
        with zipfile.ZipFile(apk_path) as z:
            try:
                return z.read(asset)
            except KeyError:
                raise ToolError(
                    "asset '%s' not found in %s (this carrier is not from "
                    "the matching builder line?)" % (asset, apk_path))
    except zipfile.BadZipFile as e:
        raise ToolError("not a valid ZIP/APK: %s (%s)" % (apk_path, e))


def verify_zip(data: bytes, what: str = 'output') -> int:
    """Return entry count if data is a healthy ZIP, else raise ToolError."""
    if data[:4] != b'PK\x03\x04':
        raise ToolError('%s does not start with PK\\x03\\x04 (wrong key/params?)'
                        % what)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            bad = z.testzip()
            if bad is not None:
                raise ToolError('%s is corrupt (first bad entry: %s)' % (what, bad))
            return len(z.namelist())
    except ToolError:
        raise
    except Exception as e:
        raise ToolError('%s is not a valid ZIP: %s' % (what, e))


def write_file(path: str, data: bytes) -> None:
    with open(path, 'wb') as fh:
        fh.write(data)


def report_plain(path: str, data: bytes) -> None:
    print('len=%d sha256=%s magic=%s -> %s'
          % (len(data), sha256(data), data[:4].hex(), path))


def warn(msg: str) -> None:
    print('warning: %s' % msg, file=sys.stderr)
