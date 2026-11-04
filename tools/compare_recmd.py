#!/usr/bin/env python3
"""Compare regfprobe with Eric Zimmerman's RECmd on the same hive.

    RECmd.exe -f HIVE --kn ROOT --recover false --nl --json OUTDIR --jsonf HIVE.json
    python3 tools/compare_recmd.py HIVE HIVE.json [--details N] [--plant]

RECmd's JSON dump nests each key with its path, its last-write time (to the 100 ns) and its
values with their type name and raw bytes (DataRaw, base64). Keys are matched by path and values
by (key path, value name), never by position. Compared: the set of keys, each key's last-write
time to the 100 ns, the set of values, each value's raw bytes, and for the standard REG_* types
the type. Logs are not replayed on either side (RECmd's --nl with no logs beside the hive,
regfprobe's recover=False). Prints counts and paths only, never value data.

--plant changes one value's bytes on regfprobe's side, a positive control.
"""

import argparse
import base64
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import regfprobe  # noqa: E402  pylint: disable=wrong-import-position

# RECmd's type names for the REG_* numbers, as its JSON writes them
RECMD_TYPES = {'RegNone': 0, 'RegSz': 1, 'RegExpandSz': 2, 'RegBinary': 3, 'RegDword': 4,
               'RegDwordBigEndian': 5, 'RegLink': 6, 'RegMultiSz': 7, 'RegResourceList': 8,
               'RegFullResourceDescription': 9, 'RegResourceRequirementsList': 10, 'RegQword': 11}
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _ticks(text):
    """RECmd's 'YYYY-MM-DDTHH:MM:SS.fffffffZ' as a FILETIME count."""
    head, _, frac = text.rstrip('Z').partition('.')
    stamp = datetime.strptime(head, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    delta = stamp - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + int((frac + '0000000')[:7])


def recmd_side(path):
    with open(path, encoding='utf-8-sig') as handle:
        root = json.load(handle)
    keys, values = {}, {}
    stack = [root]
    while stack:
        key = stack.pop()
        # KeyPath begins with the hive's root key name. --kn ROOT dumps the first key named
        # Root, which is the hive root except where a subkey has that name (Amcache.hve), so
        # paths are taken below the root name, never relative to the dumped key
        rel = key['KeyPath'].partition('\\')[2].upper()
        keys[rel] = (_ticks(key['LastWriteTimestamp']), len(key.get('SubKeys') or []), len(key.get('Values') or []))
        for value in key.get('Values') or []:
            name = value.get('ValueName') or ''
            name = '' if name == '(default)' else name
            raw = base64.b64decode(value.get('DataRaw') or '')
            values[(rel, name.upper())] = (value.get('ValueType'), raw)
        stack.extend(key.get('SubKeys') or [])
    top = root['KeyPath'].partition('\\')[2].upper()
    return keys, values, top


def regf_side(path, plant):
    hive = regfprobe.Hive(path, recover=False)
    keys, values, planted = {}, {}, None
    for key in hive.walk():
        keys[key.path.upper()] = (key.last_written_raw, len(key.subkeys()), len(key.values()))
        for value in key.values():
            raw = value.raw
            if plant and planted is None and raw:
                raw, planted = bytes([raw[0] ^ 0xFF]) + raw[1:], f'{key.path} : {value.name}'
            values[(key.path.upper(), value.name.upper())] = (value.type, raw)
    return hive, keys, values, planted


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('hive')
    parser.add_argument('recmd_json')
    parser.add_argument('--details', type=int, default=5)
    parser.add_argument('--plant', action='store_true')
    args = parser.parse_args()
    hive, rkeys, rvalues, planted = regf_side(args.hive, args.plant)
    tkeys, tvalues, top = recmd_side(args.recmd_json)
    if top:
        # RECmd dumped a subtree: compare that subtree only
        def inside(path):
            return path == top or path.startswith(top + '\\')
        rkeys = {k: v for k, v in rkeys.items() if inside(k)}
        rvalues = {k: v for k, v in rvalues.items() if inside(k[0])}
        print(f'  RECmd dumped the subtree {top}; comparing that subtree')
    found, shown = Counter(), Counter()

    def report(kind, text):
        found[kind] += 1
        if shown[kind] < args.details:
            shown[kind] += 1
            print(f'    {kind}: {text[:180]}')

    print(args.hive)
    for name in sorted(set(rkeys) | set(tkeys)):
        a, b = rkeys.get(name), tkeys.get(name)
        if a is None or b is None:
            report('key on one side only', f'{name} regfprobe={a is not None} RECmd={b is not None}')
            continue
        if a[0] != b[0]:
            report('key last-write differs', f'{name} {a[0]} vs {b[0]}')
        if a[1:] != b[1:]:
            report('key counts differ', f'{name} {a[1:]} vs {b[1:]}')
    for name in sorted(set(rvalues) | set(tvalues)):
        a, b = rvalues.get(name), tvalues.get(name)
        label = f'{name[0]} : {name[1] or "(default)"}'
        if a is None or b is None:
            report('value on one side only', f'{label} regfprobe={a is not None} RECmd={b is not None}')
            continue
        if b[0] in RECMD_TYPES and RECMD_TYPES[b[0]] != a[0]:
            report('value type differs', f'{label} {a[0]} vs {b[0]}')
        if a[1] != b[1]:
            report('value bytes differ', f'{label} {len(a[1])} vs {len(b[1])} bytes, type {a[0]}')
    print(f'  keys regfprobe {len(rkeys)}, RECmd {len(tkeys)}; values regfprobe {len(rvalues)}, '
          f'RECmd {len(tvalues)}; regfprobe faults {dict(hive.faults) or "none"}')
    if planted:
        print(f'  planted a change in {planted}')
    for kind, count in sorted(found.items()):
        print(f'  {kind}: {count}')
    print('  no differences' if not found else f'  TOTAL {sum(found.values())}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
