#!/usr/bin/env python3
"""Split-array AES-key extractor from dexdump disassembly.

Targets the protector pattern where a key-builder method constructs two
byte arrays from scattered immediate constants (const/16 + aput-byte) and
returns array1[i] ^ array2[i]. Per-build keys are the norm - re-run per sample.
"""
import argparse
import re

from .common import ToolError


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
    with open(args.dump, encoding='utf-8', errors='ignore') as fh:
        lines = fh.read().splitlines()
    try:
        start = next(i for i, l in enumerate(lines)
                     if 'Class descriptor' in l and args.cls in l)
    except StopIteration:
        raise ToolError("class '%s' not found in dump" % args.cls)
    try:
        end = next(i for i in range(start + 10, len(lines))
                   if 'Class descriptor' in lines[i])
    except StopIteration:
        end = len(lines)
    seg = lines[start:end]
    try:
        d0 = next(i for i, l in enumerate(seg)
                  if l.strip() == "name          : '%s'" % args.method)
    except StopIteration:
        raise ToolError("method '%s' not found in class '%s'"
                        % (args.method, args.cls))
    j = d0
    while j < len(seg) and 'catches' not in seg[j]:
        j += 1
    body = seg[d0:j]

    a1, a2 = [0] * args.size, [0] * args.size
    cur = {}
    for l in body:
        m = re.search(r'const/(?:16|4) v(\d+), #int (-?\d+)', l)
        if m:
            cur[int(m.group(1))] = int(m.group(2)) & 0xFF
            continue
        m = re.search(r'aput-byte v(\d+), v(\d+), v(\d+)', l)
        if m:
            v, arr, idx = int(m.group(1)), int(m.group(2)), int(m.group(3))
            # NOTE: straight-line code assumed; verify the method has no
            # branches between const and aput if output looks wrong
            if arr == 1:
                a1[cur.get(idx, 0)] = cur.get(v, 0)
            elif arr == 2:
                a2[cur.get(idx, 0)] = cur.get(v, 0)
    key = bytes(x ^ y for x, y in zip(a1, a2))
    print('AES key: %s' % key.hex())
    if args.output:
        with open(args.output, 'wb') as fh:
            fh.write(key)
        print('written to %s' % args.output)
    return 0
