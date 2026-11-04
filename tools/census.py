#!/usr/bin/env python3
"""Count which parts of the format a set of hives exercises. Counts only, never names or data.

    python3 tools/census.py HIVE [HIVE ...]

Per hive and in total: format version, dirty or clean and what replay did, keys, values,
compressed and UTF-16 names, resident, cell and big-data values, index list kinds, value types,
decoding notes by kind, and faults by kind. A feature the total shows as 0 is not exercised by
these hives, whatever the unit tests cover.
"""

import os
import re
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import regfprobe  # noqa: E402  pylint: disable=wrong-import-position


def census(path):
    hive = regfprobe.Hive(path)
    c = Counter()
    c[f'version {hive.version}'] += 1
    c[f'recovery {hive.recovery["state"]}'] += 1
    for key in hive.walk():
        c['keys'] += 1
        c['key name compressed' if key.flags & 0x20 else 'key name UTF-16'] += 1
        if key.class_length:
            c['keys with class name'] += 1
        if key.subkey_count and key.subkeys_offset != 0xFFFFFFFF:
            try:
                sig = bytes(hive.cell(key.subkeys_offset)[:2]).decode('latin-1')
                c[f'index {sig}'] += 1
            except regfprobe.RegfError:
                pass
        for value in key.values():
            c['values'] += 1
            c['value name compressed' if value.flags & 1 else 'value name UTF-16'] += 1
            _ = value.data
            c['big data' if value.big_data else 'resident' if value.resident else 'cell data'] += 1
            c[f'type {regfprobe.REG_TYPES.get(value.type, "other")}'] += 1
            if value.tombstone:
                c['tombstone flag'] += 1
            for note in value.notes:
                c['note: ' + re.sub(r'\d+', 'N', note)] += 1
    for kind, count in hive.faults.items():
        c[f'fault {kind}'] += count
    return c


def main():
    total = Counter()
    for path in sys.argv[1:]:
        try:
            total.update(census(path))
            total['hives'] += 1
        except regfprobe.RegfError:
            total['not a hive'] += 1
    for name, count in sorted(total.items()):
        print(f'{count:>10}  {name}')
    return 0


if __name__ == '__main__':
    struct.calcsize('<I')
    sys.exit(main())
