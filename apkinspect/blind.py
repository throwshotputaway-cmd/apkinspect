"""Bounded static APK discovery across supported payload families."""
import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import struct
import tempfile
import zipfile
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Sequence, Set, Tuple

from . import axml, cloak, dpt, fogky, lcg, shard, signed, spk, staged, upd
from .common import ToolError, read_file, write_file
from .profiles import AdapterProfile, BUILTIN_PROFILES, profile_by_name
from .ui import UI

MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_ENTRY_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 50000
MAX_RATIO = 500
MAX_PARTS = 64
MAX_REPORTED_ERROR = 240
_ATTEMPT_TOKEN = '__APKINSPECT_ATTEMPT_DIR__'

KNOWN_VARIANTS = {
    profile.name: profile.variants
    for profile in BUILTIN_PROFILES
    if profile.variants
}


def _nonnegative(value: str) -> int:
    parsed = int(value, 0)
    if parsed < 0:
        raise argparse.ArgumentTypeError('value must be non-negative')
    return parsed


def _positive(value: str) -> int:
    parsed = int(value, 0)
    if parsed < 1:
        raise argparse.ArgumentTypeError('value must be positive')
    return parsed


def _safe_error(error: Exception) -> str:
    message = ' '.join(str(error).split())
    message = re.sub(r'(?i)\b[0-9a-f]{24,}\b', '<redacted>', message)
    message = re.sub(r"assets/[^\s'\"]+", 'assets/<redacted>', message)
    return message[:MAX_REPORTED_ERROR] or type(error).__name__


def _safe_member_name(name: str) -> str:
    normalized = name.replace('\\', '/')
    if not normalized or '\x00' in normalized:
        raise ToolError('unsafe archive member name')
    if normalized.startswith('/') or re.match(r'^[A-Za-z]:', normalized):
        raise ToolError('unsafe archive member path')
    parts = normalized.rstrip('/').split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ToolError('unsafe archive member path')
    return normalized


def _regular_file(path: str) -> bool:
    return os.path.isfile(path) and not os.path.islink(path)


def _archive_info(path: str) -> Dict[str, zipfile.ZipInfo]:
    if not _regular_file(path):
        raise ToolError('input is not a regular file')
    size = os.path.getsize(path)
    if size > MAX_INPUT_BYTES:
        raise ToolError('APK exceeds the %d-byte input limit' % MAX_INPUT_BYTES)
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES:
                raise ToolError('archive has too many entries')
            result: Dict[str, zipfile.ZipInfo] = {}
            total = 0
            for info in infos:
                name = _safe_member_name(info.filename)
                if name in result:
                    raise ToolError('archive has duplicate member names')
                mode = (info.external_attr >> 16) & 0o170000
                if stat.S_ISLNK(mode):
                    raise ToolError('archive contains a symbolic link')
                if info.file_size > MAX_ENTRY_BYTES:
                    raise ToolError('archive member exceeds the size limit')
                if info.compress_size and info.file_size > max(
                        MAX_ENTRY_BYTES, info.compress_size * MAX_RATIO):
                    raise ToolError('archive member compression ratio is too high')
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise ToolError('archive expanded size exceeds the limit')
                result[name] = info
            return result
    except ToolError:
        raise
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile) as error:
        raise ToolError('not a valid ZIP/APK: %s' % error)


def _read_member(path: str, name: str) -> bytes:
    _archive_info(path)
    try:
        with zipfile.ZipFile(path) as archive:
            return archive.read(name)
    except (KeyError, OSError, RuntimeError, EOFError, zipfile.BadZipFile) as error:
        raise ToolError('could not read archive member: %s' % error)


def _valid_dex(data: bytes) -> bool:
    if len(data) < 112 or data[:4] != b'dex\n':
        return False
    file_size, header_size, endian = struct.unpack('<III', data[32:44])
    return (header_size == 112 and endian == 0x12345678
            and 112 <= file_size <= len(data))


def _valid_manifest(data: bytes) -> bool:
    try:
        axml.real_axml_len(data)
    except (ToolError, struct.error):
        return False
    return True


def is_final_apk(path: str) -> bool:
    try:
        infos = _archive_info(path)
        names = set(infos)
        if 'AndroidManifest.xml' not in names or 'classes.dex' not in names:
            return False
        with zipfile.ZipFile(path) as archive:
            manifest = archive.read('AndroidManifest.xml')
            if not _valid_manifest(manifest):
                return False
            for name in names:
                if not re.fullmatch(r'classes(?:\d+)?\.dex', name):
                    continue
                if not _valid_dex(archive.read(name)):
                    return False
            bad = archive.testzip()
            return bad is None
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile, KeyError, ToolError):
        return False


def _file_digest(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _candidate_assets(infos: Dict[str, zipfile.ZipInfo], limit: int) -> List[str]:
    preferred = {'assets/update.enc', 'assets/nvcgehin'}
    candidates = []
    for name, info in infos.items():
        if name.endswith('/') or not name.startswith('assets/'):
            continue
        if name.endswith(('.json', '.arsc')) or name.startswith('assets/packed/'):
            continue
        priority = 0 if name in preferred else 1
        candidates.append((priority, -info.file_size, name))
    candidates.sort()
    return [name for _, _, name in candidates[:limit]]


def _collect_files(root: str, limit: int = 128) -> List[str]:
    if _regular_file(root):
        return [root] if os.path.getsize(root) <= MAX_ENTRY_BYTES else []
    if not os.path.isdir(root) or os.path.islink(root):
        return []
    result = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(directory, name))]
        for name in files:
            path = os.path.join(directory, name)
            if _regular_file(path) and os.path.getsize(path) <= MAX_ENTRY_BYTES:
                result.append(path)
                if len(result) > limit:
                    raise ToolError('command produced too many output files')
    return sorted(result)


def _nested_apks(path: str, artifact_root: str, index: int) -> List[str]:
    try:
        infos = _archive_info(path)
    except ToolError:
        return []
    candidates = sorted(name for name in infos if name.lower().endswith('.apk'))
    output = []
    for offset, name in enumerate(candidates[:MAX_PARTS]):
        try:
            data = _read_member(path, name)
            target = os.path.join(artifact_root, 'nested-%04d-%02d.apk'
                                  % (index, offset))
            write_file(target, data)
            output.append(target)
        except ToolError:
            continue
    return output


def _adapter_args(module: Any, argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    sub = parser.add_subparsers(dest='command')
    module.register(sub)
    args = parser.parse_args(list(argv))
    args.ui = UI(quiet=True, color=False, progress='never', stream=io.StringIO())
    return args


def _invoke(module: Any, argv: Sequence[str]) -> Tuple[int, str]:
    try:
        args = _adapter_args(module, argv)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = args.func(args)
        return int(result), ''
    except SystemExit:
        return 1, 'adapter arguments were invalid'
    except Exception as error:
        return 1, _safe_error(error)


class BlindRunner:
    def __init__(self, input_path: str, outdir: str, max_depth: int,
                 max_attempts: int, max_assets: int,
                 requested_profiles: Optional[Sequence[str]] = None):
        self.input_path = os.path.abspath(input_path)
        self.outdir = os.path.abspath(outdir)
        self.max_depth = max_depth
        self.max_attempts = max_attempts
        self.max_assets = max_assets
        self.requested_profiles = set(requested_profiles) if requested_profiles else None
        self.queue: Deque[Tuple[str, int]] = deque()
        self.queued: Set[str] = set()
        self.processed: Set[str] = set()
        self.attempted: Set[Tuple[str, str, str, str]] = set()
        self.attempt_count = 0
        self.artifact_count = 0
        self.final_path: Optional[str] = None
        os.makedirs(os.path.join(self.outdir, 'attempts'), exist_ok=True)
        os.makedirs(os.path.join(self.outdir, 'artifacts'), exist_ok=True)

    def _queue(self, path: str, depth: int) -> bool:
        if not _regular_file(path) or os.path.getsize(path) > MAX_ENTRY_BYTES:
            return False
        digest = _file_digest(path)
        if digest in self.queued:
            return False
        self.queued.add(digest)
        self.queue.append((path, depth))
        return True

    def _queue_nested(self, path: str, depth: int) -> None:
        self.artifact_count += 1
        nested = _nested_apks(
            path, os.path.join(self.outdir, 'artifacts'), self.artifact_count)
        for candidate in nested:
            self._queue(candidate, depth + 1)

    def _artifact_path(self, suffix: str) -> str:
        self.artifact_count += 1
        return os.path.join(self.outdir, 'artifacts', 'artifact-%04d-%s'
                            % (self.artifact_count, suffix))

    def _attempt_output(self, *parts: str) -> str:
        return os.path.join(_ATTEMPT_TOKEN, *parts)

    def _staged_safe(self, path: str) -> bool:
        try:
            data = _read_member(path, 'assets/packed/meta.json')
            metadata = json.loads(data.decode('utf-8'))
            files = metadata.get('files')
            return (isinstance(metadata, dict) and isinstance(files, list)
                    and 1 <= len(files) <= MAX_PARTS
                    and all(isinstance(item, dict) and isinstance(item.get('file'), str)
                            and _safe_member_name(item['file']) for item in files))
        except (ToolError, UnicodeDecodeError, ValueError, TypeError):
            return False

    def _profile_enabled(self, name: str) -> bool:
        return self.requested_profiles is None or name in self.requested_profiles

    def _try(self, name: str, module: Any, depth: int, input_digest: str,
             asset: str, argv: List[str], variant: str = 'default') -> bool:
        marker = (name, input_digest, asset, variant)
        if marker in self.attempted:
            return False
        self.attempted.add(marker)
        if self.attempt_count >= self.max_attempts:
            return False
        self.attempt_count += 1
        attempt_dir = os.path.join(self.outdir, 'attempts', 'attempt-%04d'
                                   % self.attempt_count)
        os.makedirs(attempt_dir, exist_ok=True)
        scoped_argv = [
            argument.replace(_ATTEMPT_TOKEN, attempt_dir)
            if isinstance(argument, str) else argument
            for argument in argv
        ]
        result, _ = _invoke(module, scoped_argv)
        outputs: List[str] = []
        if result == 0:
            try:
                outputs = _collect_files(attempt_dir)
            except ToolError:
                result = 1
        if result != 0:
            return False
        for output in outputs:
            if is_final_apk(output):
                self._finish(output)
                return True
            if _regular_file(output) and zipfile.is_zipfile(output):
                self._queue_nested(output, depth)
                if depth < self.max_depth:
                    self._queue(output, depth + 1)
        return False

    def _try_variants(self, profile: AdapterProfile, module: Any, depth: int,
                      input_digest: str, asset: str, argv_builder: Any) -> bool:
        for variant, value in profile.variants or (('default', ''),):
            if self._try(profile.name, module, depth, input_digest, asset,
                         argv_builder(value), variant=variant):
                return True
        return False

    def _finish(self, source: str) -> None:
        if self.final_path is not None:
            return
        target = os.path.join(self.outdir, 'final.apk')
        write_file(target, read_file(source, 'final APK'))
        self.final_path = target

    def _try_adapters(self, path: str, depth: int, digest: str,
                      infos: Dict[str, zipfile.ZipInfo]) -> None:
        self._queue_nested(path, depth)
        names = set(infos)
        if (self._profile_enabled('axml-trim')
                and 'AndroidManifest.xml' in names
                and self._try(
                    'axml-trim', axml, depth, digest, '',
                    ['axml-trim', path, '-o', self._attempt_output('axml.apk')])):
            return
        if (self._profile_enabled('upd')
                and 'assets/update.enc' in names
                and self._try_variants(
                    profile_by_name('upd'), upd, depth, digest, 'assets/update.enc',
                    lambda key: ['upd', path, '-o', self._attempt_output('upd.payload'),
                                 '--key', key])):
            return
        if (self._profile_enabled('staged')
                and 'assets/packed/meta.json' in names
                and self._staged_safe(path)
                and self._try_variants(
                    profile_by_name('staged'), staged, depth, digest,
                    'assets/packed/meta.json',
                    lambda password: ['staged', path,
                                      '-o', self._attempt_output('staged.payload'),
                                      '--password', password])):
            return
        if (self._profile_enabled('signed')
                and {'assets/0uym5nunf4giud61',
                     'assets/bvxg8rspej6aqybh/u0w4uogp'} <= names
                and self._try_variants(
                    profile_by_name('signed'), signed, depth, digest, 'signed-family',
                    lambda key: ['signed', path, '--outdir',
                                 self._attempt_output('signed'), '--xor-key', key])):
            return
        if (self._profile_enabled('cloak')
                and 'assets/nvcgehin' in names
                and self._try_variants(
                    profile_by_name('cloak'), cloak, depth, digest, 'assets/nvcgehin',
                    lambda key: ['cloak', path, '-o',
                                 self._attempt_output('cloak.payload')])):
            return
        binary_assets = sorted(
            (name for name in names if name.startswith('assets/') and name.endswith('.bin')),
            key=lambda name: (-infos[name].file_size, name))
        if (self._profile_enabled('spk')
                and binary_assets
                and self._try_variants(
                    profile_by_name('spk'), spk, depth, digest, binary_assets[0],
                    lambda key: ['spk', path, '-o', self._attempt_output('spk.body'),
                                 '--asset', binary_assets[0], '--key', key])):
            return
        for asset in _candidate_assets(infos, self.max_assets):
            if (self._profile_enabled('fogky')
                    and self._try_variants(
                        profile_by_name('fogky'), fogky, depth, digest, asset,
                        lambda key, asset=asset: [
                            'fogky', path, asset,
                            '-o', self._attempt_output('fogky-%d' % len(asset)),
                            '--key', key])):
                return
            if (self._profile_enabled('shard')
                    and self._try_variants(
                        profile_by_name('shard'), shard, depth, digest, asset,
                        lambda key, asset=asset: [
                            'shard', path, asset,
                            '-o', self._attempt_output('shard-%d' % len(asset)),
                            '--key', key])):
                return
            if self._profile_enabled('lcg') and asset.lower().endswith('.dat'):
                try:
                    data = _read_member(path, asset)
                except ToolError:
                    continue
                lcg_input = None
                try:
                    with tempfile.NamedTemporaryFile(
                            prefix='apkinspect-blind-', suffix='.dat', delete=False) as stream:
                        lcg_input = stream.name
                        stream.write(data)
                    if self._try(
                            'lcg', lcg, depth, digest, asset,
                            ['lcg', lcg_input,
                             '-o', self._attempt_output('lcg.payload')]):
                        return
                finally:
                    if lcg_input:
                        try:
                            os.unlink(lcg_input)
                        except OSError:
                            pass
        if (self._profile_enabled('dpt')
                and 'assets/OoooooOooo' in names):
            self._try('dpt', dpt, depth, digest, 'assets/OoooooOooo',
                      ['dpt', path, '-o', self._attempt_output('dpt')])

    def run(self) -> int:
        if not _regular_file(self.input_path):
            raise ToolError('input APK is not a regular file')
        if os.path.getsize(self.input_path) > MAX_INPUT_BYTES:
            raise ToolError('input APK exceeds the size limit')
        if is_final_apk(self.input_path):
            self._finish(self.input_path)
        else:
            self._queue(self.input_path, 0)
            while self.queue and self.final_path is None:
                path, depth = self.queue.popleft()
                if depth > self.max_depth:
                    continue
                digest = _file_digest(path)
                if digest in self.processed:
                    continue
                self.processed.add(digest)
                try:
                    infos = _archive_info(path)
                except ToolError:
                    continue
                self._try_adapters(path, depth, digest, infos)
                if self.attempt_count >= self.max_attempts and self.queue:
                    self.queue.clear()
        if self.final_path is None:
            print('blind: no structurally complete APK found')
            return 1
        print('blind: final APK %s' % self.final_path)
        return 0


def register(sub):
    parser = sub.add_parser(
        'blind',
        help='try compatible static unpackers and follow payloads to a final APK',
    )
    parser.add_argument('apk', help='input APK or carrier ZIP')
    parser.add_argument('-o', '--outdir', default='blind-output',
                        help='directory for final.apk and artifacts')
    parser.add_argument('--max-depth', type=_nonnegative, default=4,
                        help='maximum recursive payload depth (default: 4)')
    parser.add_argument('--max-attempts', type=_positive, default=64,
                        help='maximum command attempts (default: 64)')
    parser.add_argument('--max-assets', type=_nonnegative, default=16,
                        help='maximum ranked assets per decryptor (default: 16)')
    profile_choices = tuple(profile.name for profile in BUILTIN_PROFILES
                            if profile.blind_compatible)
    parser.add_argument('--profile', action='append', choices=profile_choices,
                        dest='profiles',
                        help='limit blind discovery to a profile; repeat for multiple profiles')
    parser.set_defaults(func=run)


def run(args) -> int:
    runner = BlindRunner(args.apk, args.outdir, args.max_depth,
                         args.max_attempts, args.max_assets,
                         getattr(args, 'profiles', None))
    return runner.run()
