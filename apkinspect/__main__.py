#!/usr/bin/env python3
"""apkinspect - static decryptors and unpackers for packed Android APKs."""
import argparse
import sys
import time

from . import __version__
from .common import ToolError
from .ui import UI
from . import axml, blind, cloak, dpt, elforacle, fogky, kfqoq, lcg, midctr
from . import oracle, profiles, shard, signed, spk, splitkey, staged, upd, vbfk, xor_gzip

MODULES = (axml, blind, cloak, dpt, elforacle, fogky, kfqoq, lcg, midctr, oracle,
           profiles, shard, signed, spk, splitkey, staged, upd, vbfk, xor_gzip)


def add_ui_options(parser, suppress: bool = False) -> None:
    default = argparse.SUPPRESS if suppress else False
    parser.add_argument('--no-color', action='store_true', default=default,
                        help='disable ANSI colors')
    parser.add_argument('-q', '--quiet', action='store_true', default=default,
                        help='suppress status and progress output')
    progress_default = argparse.SUPPRESS if suppress else 'auto'
    parser.add_argument('--progress', choices=('auto', 'always', 'never'),
                        default=progress_default,
                        help='progress display mode')


def normalize_argv(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    for index, value in enumerate(values):
        if value == '--blind':
            values[index] = 'blind'
            break
    return values


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='apkinspect',
        description='Static decryptors/unpackers for packed Android APKs.')
    parser.add_argument('--version', action='version', version=__version__)
    add_ui_options(parser)
    sub = parser.add_subparsers(dest='command', metavar='<command>')
    for module in MODULES:
        module.register(sub)
    for command_parser in sub.choices.values():
        add_ui_options(command_parser, suppress=True)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(normalize_argv(argv))
    if not getattr(args, 'command', None):
        parser.print_help()
        return 2
    ui = UI(quiet=args.quiet, color=not args.no_color, progress=args.progress)
    args.ui = ui
    started = time.monotonic()
    ui.command_start(args.command)
    try:
        result = args.func(args)
    except ToolError as e:
        ui.error(str(e))
        return 1
    except KeyboardInterrupt:
        ui.interrupted()
        return 130
    except Exception as e:
        ui.error(str(e))
        return 1
    if result == 0:
        ui.command_done(args.command, time.monotonic() - started)
    return result


if __name__ == '__main__':
    sys.exit(main())
