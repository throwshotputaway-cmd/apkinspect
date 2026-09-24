#!/usr/bin/env python3
"""Split-array AES-key extractor from dexdump disassembly.

Targets the protector pattern where a key-builder method constructs two
byte arrays from scattered immediate constants (const/16 + aput-byte) and
returns array1[i] ^ array2[i]. Per-build keys are the norm - re-run per sample.
"""
import re
from typing import List, Optional, cast

from .common import ToolError, read_file, write_file


def register(sub):
    p = sub.add_parser('splitkey',
                       help='extract split-array AES keys from dexdump output')
    p.add_argument('dump', help='dexdump -d output file')
    p.add_argument('--class', dest='cls', required=True,
                   help='class descriptor substring, e.g. MainActivity')
    p.add_argument('--method', required=True, help='key-builder method name')
    p.add_argument('--size', type=int, default=32, help='key length in bytes')
    p.add_argument('-o', '--output', help='write raw key bytes here')
    p.set_defaults(func=run)


def run(args) -> int:
    if args.size < 1:
        raise ToolError('size must be positive')
    try:
        text = read_file(args.dump, 'dexdump file').decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        raise ToolError('dexdump file is not valid UTF-8')
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines)
                     if 'Class descriptor' in line and args.cls in line)
    except StopIteration:
        raise ToolError("class '%s' not found in dump" % args.cls)
    try:
        end = next(i for i in range(start + 10, len(lines))
                   if 'Class descriptor' in lines[i])
    except StopIteration:
        end = len(lines)
    seg = lines[start:end]
    try:
        d0 = next(i for i, line in enumerate(seg)
                  if line.strip() == "name          : '%s'" % args.method)
    except StopIteration:
        raise ToolError("method '%s' not found in class '%s'"
                        % (args.method, args.cls))
    j = d0
    while j < len(seg) and 'catches' not in seg[j]:
        j += 1
    body = seg[d0:j]

    a1: List[Optional[int]] = [None] * args.size
    a2: List[Optional[int]] = [None] * args.size
    cur = {}
    for line in body:
        match = re.search(r'const/(?:16|4) v(\d+), #int (-?\d+)', line)
        if match:
            cur[int(match.group(1))] = int(match.group(2)) & 0xFF
            continue
        match = re.search(r'aput-byte v(\d+), v(\d+), v(\d+)', line)
        if match:
            value_reg, array_reg, index_reg = (int(match.group(i)) for i in (1, 2, 3))
            if value_reg not in cur or index_reg not in cur:
                raise ToolError('splitkey could not resolve a register value')
            index = cur[index_reg]
            if not 0 <= index < args.size:
                raise ToolError('splitkey index out of range: %d' % index)
            value = cur[value_reg]
            if array_reg == 1:
                a1[index] = value
            elif array_reg == 2:
                a2[index] = value
    a1_bytes = bytearray(args.size)
    a2_bytes = bytearray(args.size)
    for position, entry in enumerate(a1):
        if entry is None:
            raise ToolError('splitkey did not find a complete key')
        a1_bytes[position] = cast(int, entry)
    for position, entry in enumerate(a2):
        if entry is None:
            raise ToolError('splitkey did not find a complete key')
        a2_bytes[position] = cast(int, entry)
    key = bytes(x ^ y for x, y in zip(a1_bytes, a2_bytes))
    print('AES key: %s' % key.hex())
    if args.output:
        write_file(args.output, key)
        print('written to %s' % args.output)
    return 0
