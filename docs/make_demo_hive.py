"""Write docs/demo/SAM: a small, made-up SAM hive (fictional accounts) used for the manual's
screenshots. No real data: names, times and SIDs are invented.

    python docs/make_demo_hive.py
"""

import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'tests'))

import hivebuilder  # noqa: E402  pylint: disable=wrong-import-position
from hivebuilder import V  # noqa: E402  pylint: disable=wrong-import-position

DOMAIN = (2111111111, 3222222222, 1333333333)   # invented machine SID parts


def ft(year, month, day, hour=0, minute=0, second=0):
    from datetime import datetime, timezone  # pylint: disable=import-outside-toplevel
    stamp = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    return int((stamp - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)


def f_value(rid, flags, last_logon, pwd_set, logons, failed=0, last_failed=0):
    data = bytearray(80)
    struct.pack_into('<HH', data, 0, 3, 1)
    struct.pack_into('<Q', data, 0x08, last_logon)
    struct.pack_into('<Q', data, 0x18, pwd_set)
    struct.pack_into('<Q', data, 0x20, 0x7FFFFFFFFFFFFFFF)
    struct.pack_into('<Q', data, 0x28, last_failed)
    struct.pack_into('<I', data, 0x30, rid)
    struct.pack_into('<H', data, 0x38, flags)
    struct.pack_into('<HH', data, 0x40, failed, logons)
    return bytes(data)


def v_value(user, full='', comment='', profile=''):
    header = bytearray(0xCC)
    body = bytearray()
    for at, text in ((0x0C, user), (0x18, full), (0x24, comment), (0x6C, profile)):
        raw = text.encode('utf-16-le')
        struct.pack_into('<III', header, at, len(body), len(raw), 0)
        body += raw + b'\x00' * (-len(raw) % 4)
    struct.pack_into('<III', header, 0xA8, len(body), 4, 0)   # no NT hash stored
    return bytes(header + body)


def sid(*parts):
    authority, subs = parts[0], parts[1:]
    return bytes([1, len(subs)]) + authority.to_bytes(6, 'big') + b''.join(struct.pack('<I', s) for s in subs)


def alias_c(name, description, members):
    member_bytes = b''.join(members)
    name_raw, desc_raw = name.encode('utf-16-le'), description.encode('utf-16-le')
    head = bytearray(0x34)
    struct.pack_into('<II', head, 0x10, 0, len(name_raw))
    struct.pack_into('<II', head, 0x1C, len(name_raw), len(desc_raw))
    struct.pack_into('<III', head, 0x28, len(name_raw) + len(desc_raw), len(member_bytes), len(members))
    return bytes(head) + name_raw + desc_raw + member_bytes


def bmp(size=48):
    """A small picture: a blue circle on grey, standing in for an account picture."""
    rows = []
    for y in range(size):
        row = bytearray()
        for x in range(size):
            inside = (x - size / 2) ** 2 + (y - size / 2) ** 2 < (size / 2.6) ** 2
            row += bytes((200, 120, 40) if inside else (230, 230, 230))
        row += b'\x00' * (-len(row) % 4)
        rows.append(bytes(row))
    pixels = b''.join(rows)
    info = struct.pack('<IiiHHIIiiII', 40, size, size, 1, 24, 0, len(pixels), 2835, 2835, 0, 0)
    head = b'BM' + struct.pack('<IHHI', 14 + 40 + len(pixels), 0, 0, 54)
    return struct.pack('<IIII', 1, 3, 1, len(head + info + pixels)) + head + info + pixels


def account(rid, name, full, logon, pwd, logons, flags=0x0210, tile=False, extra=()):
    values = [V('F', 3, f_value(rid, flags, logon, pwd, logons)),
              V('V', 3, v_value(name, full, profile='' if rid < 1000 else f'C:\\Users\\{name}'))]
    values += list(extra)
    if tile:
        values.append(V('UserTile', 3, bmp()))
    return {'name': f'{rid:08X}', 'stamp': pwd, 'values': values}


def tree():
    t = ft(2025, 3, 14, 9, 30)
    users = [
        account(500, 'Administrator', '', 0, ft(2025, 1, 2, 8), 0, flags=0x0211),
        account(501, 'Guest', '', 0, 0, 0, flags=0x0215),
        account(1001, 'jdoe', 'Jordan Doe', ft(2025, 3, 14, 9, 12), ft(2025, 1, 2, 8, 41), 37, tile=True,
             extra=[V('InternetUserName', 3, 'jordan.doe@example.com'.encode('utf-16-le')),
                    V('ForcePasswordReset', 3, b'\x00\x00\x00\x00')]),
        account(1002, 'asmith', 'Alex Smith', ft(2025, 2, 27, 17, 5), ft(2025, 2, 1, 10), 6),
    ]
    names = [{'name': n, 'stamp': t, 'values': [V('', rid, b'')]}
             for n, rid in (('Administrator', 500), ('Guest', 501), ('jdoe', 1001), ('asmith', 1002))]
    members = [sid(5, 21, *DOMAIN, 500), sid(5, 21, *DOMAIN, 1001)]
    return {'name': 'ROOT', 'stamp': t, 'keys': [{'name': 'SAM', 'stamp': t, 'keys': [
        {'name': 'Domains', 'stamp': t, 'keys': [
            {'name': 'Account', 'stamp': t, 'values': [V('F', 3, bytes(64))], 'keys': [
                {'name': 'Users', 'stamp': t, 'keys': users + [{'name': 'Names', 'stamp': t, 'keys': names}]},
            ]},
            {'name': 'Builtin', 'stamp': t, 'keys': [
                {'name': 'Aliases', 'stamp': t, 'keys': [
                    {'name': '00000220', 'stamp': t, 'values': [V('C', 3, alias_c(
                        'Administrators', 'Administrators have complete and unrestricted access to the computer',
                        members))]},
                    {'name': '00000221', 'stamp': t, 'values': [V('C', 3, alias_c(
                        'Users', 'Users are prevented from making accidental or intentional system-wide changes',
                        [sid(5, 21, *DOMAIN, 1002)]))]},
                ]},
            ]},
        ]},
    ]}]}


def main():
    folder = os.path.join(HERE, 'demo')
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, 'SAM')
    with open(path, 'wb') as handle:
        handle.write(hivebuilder.build(tree(), name='\\SystemRoot\\System32\\Config\\SAM'
                                       ) if _takes_name() else hivebuilder.build(tree()))
    print(path, zlib.crc32(open(path, 'rb').read()))


def _takes_name():
    import inspect  # pylint: disable=import-outside-toplevel
    return 'name' in inspect.signature(hivebuilder.Builder.build).parameters


if __name__ == '__main__':
    main()
