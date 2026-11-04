#!/usr/bin/env python3
"""Read hives with regfprobe and with python-registry, and diff what each reports.

Records are keyed by name, never by position: a key by its path, a value by (key path, value
name). Compared per key: last-written time as each library's python-registry-shaped call returns
it (regfprobe's CompatKey.timestamp()), subkey and value counts. Per value: type and raw bytes,
then the decoded data from regfprobe's CompatValue.value() against python-registry's value(),
which is what a caller switching libraries would see change.

    python3 tools/compare_python_registry.py HIVE [HIVE ...] [--plant] [--details N]

--plant changes one raw value on regfprobe's side before the diff, a positive control: the run
must then report exactly one raw difference, or the diff cannot see what it claims to check.
Prints counts and paths only, never value data, so its output can be kept with the corpus key.
Logs are not replayed on either side (python-registry has no replay), so both read the same bytes.
"""

import argparse
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import regfprobe  # noqa: E402  pylint: disable=wrong-import-position

from Registry import Registry  # noqa: E402  pylint: disable=wrong-import-position


def regf_side(path, plant):
    hive = regfprobe.Hive(path, recover=False)
    keys, values = defaultdict(list), defaultdict(list)
    planted = None
    for key in hive.walk():
        ckey = regfprobe.CompatKey(key)
        keys[key.path.upper()].append((ckey.timestamp(), len(key.subkeys()), len(key.values())))
        for value in key.values():
            raw = value.raw
            if plant and planted is None and raw:
                raw = bytes([raw[0] ^ 0xFF]) + raw[1:]
                planted = (key.path, value.name)
            values[(key.path.upper(), value.name.upper())].append((value.type, raw, regfprobe.CompatValue(value).value(),
                                                                   'resident' if value.resident else 'big data' if value.big_data else 'cell'))
    return hive, keys, values, planted


def pyreg_side(path):
    reg = Registry.Registry(path)
    keys, values, errors = defaultdict(list), defaultdict(list), Counter()
    root = reg.root()
    stack = [(root, '')]
    while stack:
        key, rel = stack.pop()
        try:
            subkeys = key.subkeys()
        except Exception as error:  # pylint: disable=broad-exception-caught
            errors[f'subkeys: {type(error).__name__}'] += 1
            subkeys = []
        try:
            vals = key.values()
        except Exception as error:  # pylint: disable=broad-exception-caught
            errors[f'values: {type(error).__name__}'] += 1
            vals = []
        keys[rel.upper()].append((key.timestamp(), len(subkeys), len(vals)))
        for value in vals:
            name = value.name()
            name = '' if name == '(default)' and not value._vkrecord.has_name() else name  # pylint: disable=protected-access
            try:
                raw = value.raw_data()
            except Exception as error:  # pylint: disable=broad-exception-caught
                errors[f'raw_data: {type(error).__name__}'] += 1
                raw = None
            try:
                data = value.value()
            except Exception as error:  # pylint: disable=broad-exception-caught
                errors[f'value: {type(error).__name__}'] += 1
                data = ('<error>', type(error).__name__)
            values[(rel.upper(), name.upper())].append((value.value_type(), raw, data))
        for sub in reversed(subkeys):
            stack.append((sub, f'{rel}\\{sub.name()}' if rel else sub.name()))
    return keys, values, errors


def _same_decoded(mine, theirs):
    if mine == theirs:
        return True
    return False


def compare(path, plant, details):
    hive, rkeys, rvalues, planted = regf_side(path, plant)
    pkeys, pvalues, perrors = pyreg_side(path)
    out = Counter()
    shown = Counter()

    def show(kind, text):
        out[kind] += 1
        if shown[kind] < details:
            shown[kind] += 1
            print(f'    {kind}: {text}')

    print(f'{path}')
    for name in sorted(set(rkeys) | set(pkeys)):
        a, b = rkeys.get(name), pkeys.get(name)
        if a is None:
            show('key only in python-registry', name)
        elif b is None:
            show('key only in regfprobe', name)
        elif len(a) != len(b):
            show('key path count differs', f'{name} {len(a)} vs {len(b)}')
        else:
            for x, y in zip(sorted(a, key=repr), sorted(b, key=repr)):
                if x[0] != y[0]:
                    show('key time differs', name)
                if x[1:] != y[1:]:
                    show('key counts differ', f'{name} {x[1:]} vs {y[1:]}')
    for name in sorted(set(rvalues) | set(pvalues)):
        a, b = rvalues.get(name), pvalues.get(name)
        label = f'{name[0]} : {name[1] or "(default)"}'
        if a is None:
            show('value only in python-registry', label)
            continue
        if b is None:
            show('value only in regfprobe', label)
            continue
        if len(a) != len(b):
            show('value name count differs', f'{label} {len(a)} vs {len(b)}')
            continue
        for x, y in zip(a, b):
            if x[0] != y[0]:
                show('value type differs', label)
            if y[1] is None:
                show('raw unreadable in python-registry', label)
            elif x[1] != y[1]:
                show(f'raw differs, {x[3]} data', f'{label} ({len(x[1])} vs {len(y[1])} bytes, type {x[0]})')
            elif not _same_decoded(x[2], y[2]):
                show(f'decoded differs, type {x[0]}', label)
    print(f'  keys regfprobe {sum(map(len, rkeys.values()))}, python-registry {sum(map(len, pkeys.values()))}; '
          f'values regfprobe {sum(map(len, rvalues.values()))}, python-registry {sum(map(len, pvalues.values()))}')
    print(f'  regfprobe faults: {dict(hive.faults) or "none"}; python-registry errors: {dict(perrors) or "none"}')
    if planted:
        print(f'  planted a change in {planted[0]} : {planted[1] or "(default)"}')
    for kind, count in sorted(out.items()):
        print(f'  {kind}: {count}')
    if not out:
        print('  no differences')
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('hives', nargs='+')
    parser.add_argument('--plant', action='store_true')
    parser.add_argument('--details', type=int, default=5)
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
