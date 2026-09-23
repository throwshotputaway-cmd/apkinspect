#!/usr/bin/env python3
"""apkinspect - static decryptors and unpackers for packed Android APKs."""
import argparse
import sys

from . import __version__
from .common import ToolError
from . import axml, dpt, elforacle, fogky, icici_ctr, lcg
from . import oracle, sbi, shard, signed, spk, splitkey, staged, upd

MODULES = (axml, dpt, elforacle, fogky, icici_ctr, lcg, oracle, sbi,
           shard, signed, spk, splitkey, staged, upd)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog='apkinspect',
        description='Static decryptors/unpackers for packed Android APKs.')
    ap.add_argument('--version', action='version', version=__version__)
    sub = ap.add_subparsers(dest='command', metavar='<command>')
    for mod in MODULES:
        mod.register(sub)
    args = ap.parse_args(argv)
    if not getattr(args, 'command', None):
        ap.print_help()
        return 2
    try:
        return args.func(args)
    except ToolError as e:
        print('ERROR: %s' % e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('interrupted', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
