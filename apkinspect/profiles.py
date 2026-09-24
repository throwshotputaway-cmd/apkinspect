"""Declarative metadata for built-in APK adapter families."""
import json
from dataclasses import asdict, dataclass
from typing import Tuple


@dataclass(frozen=True)
class AdapterProfile:
    name: str
    module: str
    trigger: str
    command: Tuple[str, ...] = ()
    asset: str = ''
    required_assets: Tuple[str, ...] = ()
    description: str = ''
    blind_compatible: bool = True


BUILTIN_PROFILES = (
    AdapterProfile(
        'axml-trim', 'axml', 'manifest',
        ('axml-trim', '{apk}', '-o', '{output}'),
        description='trim and rebuild a binary Android manifest',
    ),
    AdapterProfile(
        'upd', 'upd', 'asset',
        ('upd', '{apk}', '-o', '{output}'),
        asset='assets/update.enc',
        description='repeating-XOR update.enc carrier',
    ),
    AdapterProfile(
        'staged', 'staged', 'staged',
        ('staged', '{apk}', '-o', '{output}'),
        asset='assets/packed/meta.json',
        description='metadata-described AES-CBC staged payload',
    ),
    AdapterProfile(
        'signed', 'signed', 'assets',
        ('signed', '{apk}', '--outdir', '{output}'),
        required_assets=(
            'assets/0uym5nunf4giud61',
            'assets/bvxg8rspej6aqybh/u0w4uogp',
        ),
        description='two-stage signed-family payload',
    ),
    AdapterProfile(
        'cloak', 'cloak', 'asset',
        ('cloak', '{apk}', '-o', '{output}'),
        asset='assets/nvcgehin',
        description='layered AES-GCM/LCG/HKDF carrier',
    ),
    AdapterProfile(
        'spk', 'spk', 'binary',
        ('spk', '{apk}', '-o', '{output}', '--asset', '{asset}'),
        description='SPKZ/SPK1 repeating-XOR container',
    ),
    AdapterProfile(
        'fogky', 'fogky', 'ranked',
        ('fogky', '{apk}', '{asset}', '-o', '{output}'),
        description='Fogky XOR/RC4/AES-GCM carrier',
    ),
    AdapterProfile(
        'shard', 'shard', 'ranked',
        ('shard', '{apk}', '{asset}', '-o', '{output}'),
        description='single-blob repeating-XOR shard',
    ),
    AdapterProfile(
        'lcg', 'lcg', 'dat',
        ('lcg', '{input}', '-o', '{output}'),
        description='standalone LCG stream-cipher blob',
    ),
    AdapterProfile(
        'dpt', 'dpt', 'asset',
        ('dpt', '{apk}', '-o', '{output}'),
        asset='assets/OoooooOooo',
        description='restore dpt-shell method bodies',
    ),
    AdapterProfile(
        'aes-gcm-hkdf', 'kfqoq', 'manual',
        description='requires a sample-specific HK key',
        blind_compatible=False,
    ),
    AdapterProfile(
        'chunked-aes-gzip', 'vbfk', 'manual',
        description='requires sample-specific chunk parameters',
        blind_compatible=False,
    ),
    AdapterProfile(
        'xor-gzip', 'xor_gzip', 'manual',
        description='requires a sample-specific XOR key',
        blind_compatible=False,
    ),
    AdapterProfile(
        'midctr', 'midctr', 'manual',
        description='requires a sample-specific key or native offset',
        blind_compatible=False,
    ),
)


def profile_report() -> list:
    return [asdict(profile) for profile in BUILTIN_PROFILES]


def register(sub):
    parser = sub.add_parser(
        'profiles',
        help='list built-in adapter profiles and discovery metadata',
    )
    parser.add_argument('--json', action='store_true', dest='as_json',
                        help='emit machine-readable JSON')
    parser.set_defaults(func=run)


def run(args) -> int:
    if args.as_json:
        print(json.dumps(profile_report(), indent=2, sort_keys=True))
        return 0
    print('%-18s %-10s %-8s %s' % ('PROFILE', 'TRIGGER', 'BLIND', 'DESCRIPTION'))
    for profile in BUILTIN_PROFILES:
        blind = 'yes' if profile.blind_compatible else 'no'
        print('%-18s %-10s %-8s %s'
              % (profile.name, profile.trigger, blind, profile.description))
    return 0
