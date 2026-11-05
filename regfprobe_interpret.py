"""Turn raw registry value bytes into readable fields for the HTML report.

interpret(key, value) returns a list of (label, text) pairs, or [] when nothing better than
regfprobe's own decoding is known. An optional ('__image__', data_uri) pair carries a picture.
Known layouts: SAM user F and V, SAM Names\\<user> default (RID), SAM UserTile, SAM alias C.
Generic: UTF-16LE text in binaries, SIDs, GUIDs, FILETIMEs, DWORD/QWORD binaries.
"""

import base64
import struct
import uuid
from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

ACB_FLAGS = {
    0x0001: 'Account disabled', 0x0002: 'Home directory required', 0x0004: 'Password not required',
    0x0008: 'Temporary duplicate account', 0x0010: 'Normal user account', 0x0020: 'MNS logon account',
    0x0040: 'Interdomain trust account', 0x0080: 'Workstation trust account',
    0x0100: 'Server trust account', 0x0200: 'Password does not expire', 0x0400: 'Account auto-locked',
}

WELL_KNOWN_RIDS = {500: 'Administrator', 501: 'Guest', 503: 'DefaultAccount', 504: 'WDAGUtilityAccount',
                   544: 'Administrators', 545: 'Users', 546: 'Guests', 547: 'Power Users',
                   551: 'Backup Operators', 555: 'Remote Desktop Users', 562: 'Distributed COM Users',
                   573: 'Event Log Readers', 578: 'Hyper-V Administrators', 580: 'Remote Management Users'}


def filetime(value):
    if value in (0, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
        return {0: 'Never / not set', 0x7FFFFFFFFFFFFFFF: 'Never (no expiry)'}.get(value, 'Never')
    try:
        return (_EPOCH + timedelta(microseconds=value // 10)).strftime('%Y-%m-%d %H:%M:%S UTC')
    except OverflowError:
        return f'out of range ({value})'


def sid(data):
    if len(data) < 8 or data[0] != 1 or len(data) < 8 + 4 * data[1]:
        return None
    count = data[1]
    authority = int.from_bytes(data[2:8], 'big')
    subs = struct.unpack_from(f'<{count}I', data, 8)
    return 'S-1-' + '-'.join([str(authority)] + [str(s) for s in subs])


def _utf16(data):
    if len(data) < 2 or len(data) % 2:
        return None
    try:
        text = data.decode('utf-16-le').rstrip('\x00')
    except UnicodeDecodeError:
        return None
    if text and all(c.isprintable() or c in '\r\n\t' for c in text):
        return text
    return None


def _f(data):
    if len(data) < 0x44:
        return []
    q = lambda o: struct.unpack_from('<Q', data, o)[0]  # noqa: E731
    flags = struct.unpack_from('<H', data, 0x38)[0]
    rid = struct.unpack_from('<I', data, 0x30)[0]
    names = [n for b, n in ACB_FLAGS.items() if flags & b]
    return [('Last logon', filetime(q(0x08))), ('Password last set', filetime(q(0x18))),
            ('Account expires', filetime(q(0x20))), ('Last failed logon', filetime(q(0x28))),
            ('RID', f'{rid} (0x{rid:x})' + (f' {WELL_KNOWN_RIDS[rid]}' if rid in WELL_KNOWN_RIDS else '')),
            ('Account flags', f'0x{flags:04x}: ' + (', '.join(names) or 'none')),
            ('Failed logon count', str(struct.unpack_from('<H', data, 0x40)[0])),
            ('Logon count', str(struct.unpack_from('<H', data, 0x42)[0]))]


_V_FIELDS = [(0x0C, 'User name'), (0x18, 'Full name'), (0x24, 'Comment'), (0x30, 'User comment'),
             (0x48, 'Home directory'), (0x54, 'Home directory drive'), (0x60, 'Logon script'),
             (0x6C, 'Profile path'), (0x78, 'Allowed workstations')]


def _v(data):
    if len(data) < 0xCC:
        return []
    out = []
    for at, label in _V_FIELDS:
        off, length = struct.unpack_from('<II', data, at)
        if length:
            text = data[0xCC + off:0xCC + off + length].decode('utf-16-le', 'replace')
            out.append((label, text))
    for at, label in ((0x9C, 'LM hash'), (0xA8, 'NT hash')):
        _off, length = struct.unpack_from('<II', data, at)
        out.append((label, f'stored, {length} bytes (encrypted; needs the SYSTEM boot key)'
                    if length > 4 else 'not stored'))
    return out


def _alias_c(data):
    if len(data) < 0x34:
        return []
    out = []
    try:
        name_off, name_len = struct.unpack_from('<II', data, 0x10)
        out.append(('Group name', data[0x34 + name_off:0x34 + name_off + name_len].decode('utf-16-le', 'replace')))
        com_off, com_len = struct.unpack_from('<II', data, 0x1C)
        if com_len:
            out.append(('Description', data[0x34 + com_off:0x34 + com_off + com_len].decode('utf-16-le', 'replace')))
        mem_off, _mem_len, count = struct.unpack_from('<III', data, 0x28)
        pos, members = 0x34 + mem_off, []
        for _ in range(count):
            s = sid(data[pos:])
            if not s:
                break
            members.append(s)
            pos += 8 + 4 * data[pos + 1]
        out.append(('Members', '\n'.join(members) if members else '(none)'))
    except (struct.error, IndexError):
        pass
    return out


def _image(data):
    for magic, mime in ((b'\x89PNG', 'image/png'), (b'BM', 'image/bmp'), (b'\xff\xd8\xff', 'image/jpeg')):
        at = data.find(magic, 0, 64)
        if at >= 0:
            pic = data[at:]
            info = mime.split('/')[1].upper()
            if mime == 'image/bmp' and len(pic) >= 26:
                w, h = struct.unpack_from('<ii', pic, 18)
                info += f' {w}x{abs(h)}'
            return [('Picture', info + f', {len(pic)} bytes'),
                    ('__image__', f'data:{mime};base64,' + base64.b64encode(pic).decode())]
    return []


def interpret(key, value):
    data = value.raw
    path = (key.path or '').lower()
    name = (value.name or '').lower()
    in_sam_users = '\\domains\\account\\users\\' in path + '\\'
    if in_sam_users and '\\names\\' in path + '\\' and not value.name:
        return [('RID', f'{value.type} (0x{value.type:x})' + (f' {WELL_KNOWN_RIDS[value.type]}'
                                                               if value.type in WELL_KNOWN_RIDS else '')
                 + ' (the RID is stored as the value type)')]
    if in_sam_users and name == 'f':
        return _f(data)
    if in_sam_users and name == 'v':
        return _v(data)
    if '\\aliases\\' in path and name == 'c':
        return _alias_c(data)
    if not data:
        return []
    if name == 'usertile' or data[:2] == b'BM' or data[:4] == b'\x89PNG':
        pic = _image(data)
        if pic:
            return pic
    if value.type_name not in ('REG_BINARY', 'REG_NONE') and not value.type_name.startswith('unknown'):
        return []   # regfprobe already decodes strings, numbers and multi-strings
    if name.endswith('guid') and len(data) == 16:
        return [('GUID', '{' + str(uuid.UUID(bytes_le=data)).upper() + '}')]
    s = sid(data) if 'sid' in name else None
    if s:
        return [('SID', s)]
    text = _utf16(data)
    if text:
        return [('Text', text)]
    if len(data) == 8 and any(w in name for w in ('time', 'date', 'last', 'install', 'stamp')):
        return [('Time', filetime(struct.unpack('<Q', data)[0]))]
    if len(data) == 4:
        n = struct.unpack('<I', data)[0]
        return [('Number', f'{n} (0x{n:x})')]
    if len(data) == 8:
        n = struct.unpack('<Q', data)[0]
        return [('Number', f'{n} (0x{n:x})')]
    if len(data) == 16 and 'guid' in name:
        return [('GUID', '{' + str(uuid.UUID(bytes_le=data)).upper() + '}')]
    return []
