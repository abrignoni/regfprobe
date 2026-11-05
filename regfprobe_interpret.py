"""Readable fields for the HTML report, for value layouts with a published source.

interpret(key, value) returns a list of (label, text) pairs, or [] when no layout is known for
the value; the report then falls back to regfprobe's own decoding. A ('__image__', data_uri)
pair carries a picture. Nothing here guesses a meaning from a value's name or from what its
bytes happen to look like.

Sources for the layouts:
  SAM Users\\<RID>\\F: last logon 0x08, password last set 0x18, account expires 0x20, last
    failed logon 0x28, RID 0x30, account flags 0x38, failed and total logon counts 0x40 and
    0x42; samparse.pl reports a logon or password time of 0 as never. RegRipper 3.0
    samparse.pl, parseF
    (github.com/keydet89/RegRipper3.0, commit ec96dd4a6a5c3ea70d8fece9b47a374f83582335).
  SAM account flag values: the USER_* constants in impacket's samr.py
    (github.com/fortra/impacket, commit 0b3ef2b979ba0f52dfc852dd41e0f90ce7b3bc42).
  SAM Users\\<RID>\\V: the offset/length pairs of USER_ACCOUNT_V in impacket's secretsdump.py
    (same commit), with the data area starting at 0xCC as samparse.pl reads it.
  SAM alias C: name, description and member SIDs as samparse.pl parseC and parseCUsers read them.
  SAM Users\\Names\\<user>: the RID is the default value's type, as regipy's samparse plugin
    reads it (github.com/mkorman90/regipy, commit c6de929abc37d8315d1c31aba5e937db636f3303).
  Well-known RIDs: Microsoft, "Security identifiers", which lists S-1-5-<domain>-500 and -501
    and the S-1-5-32 groups used here (learn.microsoft.com/en-us/windows-server/identity/ad-ds/
    manage/understand-security-identifiers).
"""

import base64
import struct
from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

ACB_FLAGS = {
    0x0001: 'Account disabled', 0x0002: 'Home directory required', 0x0004: 'Password not required',
    0x0008: 'Temporary duplicate account', 0x0010: 'Normal user account', 0x0020: 'MNS logon account',
    0x0040: 'Interdomain trust account', 0x0080: 'Workstation trust account',
    0x0100: 'Server trust account', 0x0200: 'Password does not expire', 0x0400: 'Account auto-locked',
}

WELL_KNOWN_RIDS = {500: 'Administrator', 501: 'Guest',
                   544: 'Administrators', 545: 'Users', 546: 'Guests', 547: 'Power Users',
                   551: 'Backup Operators', 555: 'Remote Desktop Users', 562: 'Distributed COM Users',
                   573: 'Event Log Readers', 578: 'Hyper-V Administrators', 580: 'Remote Management Users'}


def filetime(value, zero='Never (0)'):
    """A SAM time as UTC; 0 shows as `zero`, and a value no date can hold is shown as stored."""
    if value == 0:
        return zero
    try:
        return (_EPOCH + timedelta(microseconds=value // 10)).strftime('%Y-%m-%d %H:%M:%S UTC')
    except OverflowError:
        return f'not a date: stored as 0x{value:016X}'


def sid(data):
    if len(data) < 8 or data[0] != 1 or len(data) < 8 + 4 * data[1]:
        return None
    count = data[1]
    authority = int.from_bytes(data[2:8], 'big')
    subs = struct.unpack_from(f'<{count}I', data, 8)
    return 'S-1-' + '-'.join([str(authority)] + [str(s) for s in subs])


def _rid(rid):
    return f'{rid} (0x{rid:x})' + (f' {WELL_KNOWN_RIDS[rid]}' if rid in WELL_KNOWN_RIDS else '')


def _f(data):
    if len(data) < 0x44:
        return []
    q = lambda o: struct.unpack_from('<Q', data, o)[0]  # noqa: E731
    flags = struct.unpack_from('<H', data, 0x38)[0]
    names = [n for b, n in ACB_FLAGS.items() if flags & b]
    return [('Last logon', filetime(q(0x08))), ('Password last set', filetime(q(0x18))),
            ('Account expires', filetime(q(0x20), zero='stored as 0')), ('Last failed logon', filetime(q(0x28))),
            ('RID', _rid(struct.unpack_from('<I', data, 0x30)[0])),
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
            out.append((label, data[0xCC + off:0xCC + off + length].decode('utf-16-le', 'replace')))
    for at, label in ((0x9C, 'LM hash entry'), (0xA8, 'NT hash entry')):
        _off, length = struct.unpack_from('<II', data, at)
        out.append((label, f'{length} bytes (not decoded here)'))
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


def _picture(pic):
    """The MIME type of a PNG, JPEG or BMP file that starts at pic[0], checked on its header."""
    if pic[:8] == b'\x89PNG\r\n\x1a\n' and pic[12:16] == b'IHDR':
        return 'image/png', ''
    if pic[:3] == b'\xff\xd8\xff':
        return 'image/jpeg', ''
    if pic[:2] == b'BM' and len(pic) >= 26:
        size, _reserved, pixels = struct.unpack_from('<III', pic, 2)
        width, height = struct.unpack_from('<ii', pic, 18)
        if 26 <= size <= len(pic) and 14 < pixels < size and width > 0 and height:
            return 'image/bmp', f' {width}x{abs(height)}'
    return None


def _image(data, search):
    for at in (range(min(64, len(data))) if search else (0,)):
        found = _picture(data[at:])
        if found:
            mime, info = found
            pic = data[at:]
            return [('Picture', mime.split('/')[1].upper() + info + f', {len(pic)} bytes at offset {at}'),
                    ('__image__', f'data:{mime};base64,' + base64.b64encode(pic).decode())]
    return []


def interpret(key, value):
    data = value.raw
    path = (key.path or '').lower() + '\\'
    name = (value.name or '').lower()
    in_sam_users = '\\domains\\account\\users\\' in path
    if in_sam_users and '\\names\\' in path and not value.name:
        return [('RID', _rid(value.type) + ' (the RID is stored as the value type)')]
    if in_sam_users and name == 'f':
        return _f(data)
    if in_sam_users and name == 'v':
        return _v(data)
    if '\\aliases\\' in path and name == 'c':
        return _alias_c(data)
    if data and value.type_name in ('REG_BINARY', 'REG_NONE'):
        # UserTile holds a picture after a header; any other binary must start with one
        return _image(data, search=in_sam_users and name == 'usertile')
    return []
