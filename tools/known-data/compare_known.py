#!/usr/bin/env python3
"""Check regfprobe against what Windows itself enumerated for the same key.

    python3 tools/known-data/compare_known.py known.hiv known.tsv [--reg known.reg] [--plant]

known.tsv and known.hiv come from make_known_hive.ps1. Every key is matched by path and every
value by (key path, value name), never by position. Checked: the set of keys and values, each
key's last-write FILETIME (to the 100 ns), class name and counts, and each value's type number
and data bytes. --reg also reads Windows' reg export and checks regfprobe's own .reg export says
the same thing (values compared as type and bytes once both files are parsed).

--plant flips one byte of one value on regfprobe's side first, a positive control: the run
must then report exactly one difference.
"""

import argparse
import base64
import io
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', '..'))
import regfprobe  # noqa: E402  pylint: disable=wrong-import-position


def _text(b64):
    return base64.b64decode(b64).decode('utf-16-le')


def read_tsv(path):
    keys, values = {}, {}
    with open(path, encoding='utf-8') as handle:
        for line in handle:
            parts = line.rstrip('\n').split('\t')
            if parts[0] == 'K':
                keys[_text(parts[1]).upper()] = (int(parts[2]), _text(parts[3]), int(parts[4]), int(parts[5]))
            elif parts[0] == 'V':
                values[(_text(parts[1]).upper(), _text(parts[2]).upper())] = (int(parts[3]), base64.b64decode(parts[4]))
    return keys, values


def read_hive(path, plant):
    hive = regfprobe.Hive(path)
    keys, values, planted = {}, {}, None
    for key in hive.walk():
        keys[key.path.upper()] = (key.last_written_raw, key.class_name, key.subkey_count, key.value_count)
        for value in key.values():
            raw = value.raw
            if plant and planted is None and len(raw) > 2:
                raw = raw[:1] + bytes([raw[1] ^ 0xFF]) + raw[2:]
                planted = f'{key.path} : {value.name}'
            values[(key.path.upper(), value.name.upper())] = (value.type, raw)
    return hive, keys, values, planted


_REG_LINE = re.compile(r'^(@|"(?:[^"\\]|\\.)*")=(.*)$', re.S)


def parse_reg(text):
    """{(key path below the first path, value name upper): (type, bytes)} from regedit's format."""
    lines = text.replace('\r\n', '\n').split('\n')
    joined, current = [], ''
    for line in lines:
        if current:
            current += line.lstrip()
        else:
            current = line
        if current.endswith('\\') and not current.startswith('['):
            current = current[:-1]
            continue
        joined.append(current)
        current = ''
    result, base, path = {}, None, None
    for line in joined:
        if line.startswith('[') and line.endswith(']'):
            full = line[1:-1]
            if base is None:
                base = full
            path = full[len(base):].lstrip('\\').upper()
            continue
        match = _REG_LINE.match(line)
        if not match or path is None:
            continue
        name = '' if match.group(1) == '@' else re.sub(r'\\(.)', r'\1', match.group(1)[1:-1])
        data = match.group(2)
        if data.startswith('"'):
            text_value = re.sub(r'\\(.)', r'\1', data[1:-1])
            kind, raw = 1, (text_value + '\x00').encode('utf-16-le')
        elif data.startswith('dword:'):
            kind, raw = 4, int(data[6:], 16).to_bytes(4, 'little')
        elif data.startswith('hex:'):
            kind, raw = 3, bytes.fromhex(data[4:].replace(',', ''))
        else:
            m = re.match(r'hex\(([0-9a-fA-F]+)\):(.*)', data)
            kind, raw = int(m.group(1), 16), bytes.fromhex(m.group(2).replace(',', ''))
        result[(path, name.upper())] = (kind, raw)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('hive')
    parser.add_argument('tsv')
    parser.add_argument('--reg')
    parser.add_argument('--plant', action='store_true')
    parser.add_argument('--details', type=int, default=10)
    args = parser.parse_args()

    tkeys, tvalues = read_tsv(args.tsv)
    hive, rkeys, rvalues, planted = read_hive(args.hive, args.plant)
    found, shown = Counter(), Counter()

    def report(kind, text):
        found[kind] += 1
        if shown[kind] < args.details:
            shown[kind] += 1
            print(f'  {kind}: {text[:200]}')

    for path in sorted(set(tkeys) | set(rkeys)):
        a, b = rkeys.get(path), tkeys.get(path)
        if a is None or b is None:
            report('key missing on one side', f'{path!r} regfprobe={a is not None} windows={b is not None}')
            continue
        if a[0] != b[0]:
            report('key last-write differs', f'{path!r} {a[0]} vs {b[0]}')
        if a[1] != b[1]:
            report('class name differs', f'{path!r} {a[1]!r} vs {b[1]!r}')
        if a[2:] != b[2:]:
            report('key counts differ', f'{path!r} {a[2:]} vs {b[2:]}')
    for name in sorted(set(tvalues) | set(rvalues)):
        a, b = rvalues.get(name), tvalues.get(name)
        label = f'{name[0]!r} : {name[1][:40]!r}'
        if a is None or b is None:
            report('value missing on one side', f'{label} regfprobe={a is not None} windows={b is not None}')
            continue
        if a[0] != b[0]:
            report('value type differs', f'{label} {a[0]} vs {b[0]}')
        if a[1] != b[1]:
            report('value bytes differ', f'{label} {len(a[1])} vs {len(b[1])} bytes')
    print(f'Windows enumerated {len(tkeys)} keys and {len(tvalues)} values; regfprobe read '
          f'{len(rkeys)} keys and {len(rvalues)} values; faults {dict(hive.faults) or "none"}')
    if planted:
        print(f'planted a change in {planted}')

    if args.reg:
        with open(args.reg, 'rb') as handle:
            theirs = parse_reg(handle.read().decode('utf-16'))
        stream = io.StringIO()
        regfprobe.export_key(hive, hive.root(), 'reg', stream, prefix='X')
        mine = parse_reg(stream.getvalue())
        for name in sorted(set(theirs) | set(mine)):
            a, b = mine.get(name), theirs.get(name)
            label = f'{name[0]!r} : {name[1][:40]!r}'
            if a != b:
                report('.reg export differs', f'{label} regfprobe={a and (a[0], len(a[1]))} reg.exe={b and (b[0], len(b[1]))}')
        print(f'.reg: reg.exe wrote {len(theirs)} values, regfprobe {len(mine)}')

    for kind, count in sorted(found.items()):
        print(f'{kind}: {count}')
    print('no differences' if not found else f'TOTAL {sum(found.values())}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
