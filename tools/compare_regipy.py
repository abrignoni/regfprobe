#!/usr/bin/env python3
"""Read hives with regfprobe and with regipy, and diff what each reports.

    python3 tools/compare_regipy.py HIVE [HIVE ...] [--details N] [--plant]

Run it with a Python that has regipy installed (it is not a regfprobe dependency). Keys are
matched by path and values by (key path, value name), never by position. Compared: the set of
keys, each key's last-written time (within one microsecond, since regipy rounds the FILETIME
and regfprobe truncates it), the set of value names, each value's type name, and for REG_SZ,
REG_EXPAND_SZ, REG_DWORD, REG_QWORD and REG_MULTI_SZ the decoded data. Logs are not replayed
on either side. Prints counts and paths only, never value data.

--plant changes one REG_SZ value on regfprobe's side, a positive control: the run must report it.
"""

import argparse
import os
import sys
from collections import Counter, defaultdict
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import regfprobe  # noqa: E402  pylint: disable=wrong-import-position

from regipy.registry import NKRecord, RegistryHive  # noqa: E402  pylint: disable=wrong-import-position,import-error

# regipy's recurse_subkeys reads values through NKRecord.iter_values, which trims data to 256
# characters unless trim_values=False (regipy 6.5.0). Compare whole values.
_ITER_VALUES = NKRecord.iter_values
NKRecord.iter_values = lambda self, as_json=False, max_len=256, trim_values=True: _ITER_VALUES(
    self, as_json=as_json, max_len=max_len, trim_values=False)

COMPARED = {'REG_SZ', 'REG_EXPAND_SZ', 'REG_DWORD', 'REG_QWORD', 'REG_MULTI_SZ'}


def regf_side(path, plant):
    hive = regfprobe.Hive(path, recover=False)
    keys, values, planted = {}, defaultdict(list), None
    for key in hive.walk():
        if not key.path:
            continue
        keys[key.path.upper()] = (key.last_written,)   # a tuple: a FILETIME of 0 gives None
        for value in key.values():
            data = value.data
            if plant and planted is None and value.type == 1 and data:
                data, planted = data + 'X', f'{key.path} : {value.name}'
            values[(key.path.upper(), value.name.upper())].append(
                (value.type_name, data, 'data after the terminating NUL' in value.notes))
    return hive, keys, values, planted


def regipy_side(path):
    hive = RegistryHive(path)
    keys, values, corrupted = {}, defaultdict(list), 0
    for sub in hive.recurse_subkeys(as_json=False):
        rel = sub.path.lstrip('\\').upper()
        if not rel:
            continue
        keys[rel] = sub.timestamp
        for value in sub.values or []:
            corrupted += bool(value.is_corrupted)
            name = '' if value.name == '(default)' else value.name
            values[(rel, name.upper())].append((value.value_type, value.value))
    return keys, values, corrupted


def _same(kind, mine, theirs):
    if kind == 'REG_MULTI_SZ' and isinstance(theirs, list):
        return [s for s in mine if s] == [s for s in theirs if s]
    return mine == theirs


def compare(path, plant, details):
    hive, rkeys, rvalues, planted = regf_side(path, plant)
    pkeys, pvalues, corrupted = regipy_side(path)
    found, shown = Counter(), Counter()

    def report(kind, text):
        found[kind] += 1
        if shown[kind] < details:
            shown[kind] += 1
            print(f'    {kind}: {text[:180]}')

    print(path)
    for name in sorted(set(rkeys) | set(pkeys)):
        a, b = rkeys.get(name), pkeys.get(name)
        if a is None or b is None:
            report('key on one side only', f'{name} regfprobe={a is not None} regipy={b is not None}')
        elif a[0] is None or not hasattr(b, 'tzinfo'):
            if (a[0] is None) != (not hasattr(b, 'tzinfo') or b.year <= 1601):
                report('key time differs', f'{name} {a[0]} vs {b}')
        elif abs(a[0] - b) > timedelta(microseconds=1):
            report('key time differs', name)
    for name in sorted(set(rvalues) | set(pvalues)):
        a, b = rvalues.get(name), pvalues.get(name)
        label = f'{name[0]} : {name[1] or "(default)"}'
        if a is None or b is None:
            report('value on one side only', f'{label} regfprobe={a is not None} regipy={b is not None}')
            continue
        if len(a) != len(b):
            report('value name count differs', label)
            continue
        for (kind, mine, after_nul), (theirs_kind, theirs) in zip(a, b):
            if kind in regfprobe.REG_TYPES.values() and kind != theirs_kind:
                report('value type differs', f'{label} {kind} vs {theirs_kind}')
            elif kind in COMPARED and kind == theirs_kind and not _same(kind, mine, theirs):
                if after_nul:
                    # regfprobe stops a string at its first NUL and notes the rest; regipy keeps
                    # the rest, or returns bytes when it does not decode
                    report('bytes after the NUL kept by regipy', label)
                else:
                    report(f'decoded {kind} differs', label)
    print(f'  keys regfprobe {len(rkeys)}, regipy {len(pkeys)}; values regfprobe '
          f'{sum(map(len, rvalues.values()))}, regipy {sum(map(len, pvalues.values()))}; '
          f'regfprobe faults {dict(hive.faults) or "none"}; regipy corrupted values {corrupted}')
    if planted:
        print(f'  planted a change in {planted}')
    for kind, count in sorted(found.items()):
        print(f'  {kind}: {count}')
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('hives', nargs='+')
    parser.add_argument('--details', type=int, default=3)
    parser.add_argument('--plant', action='store_true')
    args = parser.parse_args()
    total = Counter()
    for path in args.hives:
        try:
            total.update(compare(path, args.plant, args.details))
        except Exception as error:  # pylint: disable=broad-exception-caught
            print(f'{path}\n  could not compare: {type(error).__name__}: {error}')
            total['could not compare'] += 1
    print('TOTAL', dict(total) or 'no differences')
    return 0


if __name__ == '__main__':
    sys.exit(main())
