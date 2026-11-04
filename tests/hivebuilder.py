"""Build small registry hives in memory, laid out as the format specification describes.

Used by the tests and by tools/make_fixtures.py. Written here because nothing else writes regf
offline; python-registry, which only reads, is the independent check that what this writes is a
hive. A key is a dict:

    {'name': 'Run', 'utf16': False, 'stamp': 0x01D..., 'class': 'cls', 'index': 'lh',
     'values': [V(...), ...], 'keys': [{...}, ...]}

index is 'lh', 'lf', 'li' or 'ri' (an ri over two lh lists). Values are made with V().
"""

import struct

PAGE = 4096
DEFAULT_STAMP = 133_000_000_000_000_015  # 2022-06-18; an odd microsecond count plus 5 tenths


def V(name, kind, data, utf16=False, resident=None, size=None):  # pylint: disable=invalid-name
    """A value. Data of one to four bytes is stored in the data offset field, as Windows stores
    it, unless resident=False puts it in a cell of its own. size overrides the stored data size,
    to build a value whose size and bytes disagree."""
    return {'name': name, 'type': kind, 'data': data, 'utf16': utf16, 'resident': resident,
            'size': size}


def sz(text, terminate=True):
    return (text + ('\x00' if terminate else '')).encode('utf-16-le')


def xor32(block):
    value = 0
    for (word,) in struct.iter_unpack('<I', bytes(block[:508])):
        value ^= word
    if value == 0xFFFFFFFF:
        return 0xFFFFFFFE
    return 1 if value == 0 else value


# Owner Administrators, group Local System, DACL with one ACCESS_ALLOWED ACE for Everyone.
def _sid(text):
    parts = [int(p) for p in text.split('-')[1:]]
    revision, authority, subs = parts[0], parts[1], parts[2:]
    return struct.pack('<BB', revision, len(subs)) + authority.to_bytes(6, 'big') + \
        b''.join(struct.pack('<I', s) for s in subs)


def security_descriptor():
    owner, group, everyone = _sid('S-1-5-32-544'), _sid('S-1-5-18'), _sid('S-1-1-0')
    ace = struct.pack('<BBHI', 0x00, 0x02, 8 + len(everyone), 0x000F003F) + everyone
    acl = struct.pack('<BBHHH', 2, 0, 8 + len(ace), 1, 0) + ace
    header = 20
    owner_at = header
    group_at = owner_at + len(owner)
    dacl_at = group_at + len(group)
    control = 0x8000 | 0x0004  # self-relative, DACL present
    return struct.pack('<BBHIIII', 1, 0, control, owner_at, group_at, 0, dacl_at) + owner + group + acl


class Builder:
    def __init__(self, minor=5):
        self.minor = minor
        self.cells = bytearray()
        self.sk = None

    def _offset(self):
        return 32 + len(self.cells)  # offsets count from the start of the hive bins data

    def alloc(self, data, free=False):
        size = (len(data) + 4 + 7) // 8 * 8
        offset = self._offset()
        self.cells += struct.pack('<i', size if free else -size) + data + b'\x00' * (size - 4 - len(data))
        return offset

    def patch(self, offset, fmt, at, *values):
        struct.pack_into(fmt, self.cells, offset - 32 + 4 + at, *values)

    def security(self):
        if self.sk is None:
            descriptor = security_descriptor()
            self.sk = self.alloc(b'sk' + struct.pack('<HIIII', 0, 0, 0, 1, len(descriptor)) + descriptor)
            self.patch(self.sk, '<II', 4, self.sk, self.sk)
        return self.sk

    def value(self, spec):
        name = spec['name'].encode('utf-16-le' if spec['utf16'] else 'latin-1')
        data = spec['data']
        size = len(data) if spec['size'] is None else spec['size']
        resident = spec['resident'] if spec['resident'] is not None else 0 < len(data) <= 4
        if resident:
            field = data.ljust(4, b'\x00')[:4]
            size_field, data_offset = size | 0x80000000, struct.unpack('<I', field)[0]
        elif not data and size == 0:
            size_field, data_offset = 0, 0xFFFFFFFF
        elif len(data) > 16344 and self.minor > 3:
            segments = [self.alloc(data[i:i + 16344]) for i in range(0, len(data), 16344)]
            listing = self.alloc(b''.join(struct.pack('<I', s) for s in segments))
            data_offset = self.alloc(b'db' + struct.pack('<HI', len(segments), listing))
            size_field = size
        else:
            data_offset, size_field = self.alloc(data), size
        flags = 0 if spec['utf16'] else 1
        return self.alloc(b'vk' + struct.pack('<HIIIHH', len(name), size_field, data_offset,
                                              spec['type'], flags, 0) + name)

    def key(self, spec, parent, root=False):
        name = spec['name'].encode('utf-16-le' if spec.get('utf16') else 'latin-1')
        flags = (0 if spec.get('utf16') else 0x20) | (0x4 if root else 0)
        children, values = spec.get('keys', []), spec.get('values', [])
        offset = self.alloc(b'nk' + struct.pack('<HQIIIIIIIIIIIIIIIHH', flags,
                                                spec.get('stamp', DEFAULT_STAMP), 0, parent,
                                                len(children), 0, 0xFFFFFFFF, 0xFFFFFFFF,
                                                len(values), 0xFFFFFFFF, self.security(),
                                                0xFFFFFFFF, 0, 0, 0, 0, 0,
                                                len(name), 0) + name)
        if spec.get('class'):
            raw = spec['class'].encode('utf-16-le')
            self.patch(offset, '<I', 48, self.alloc(raw))
            self.patch(offset, '<H', 74, len(raw))
        if values:
            vk = [self.value(v) for v in values]
            self.patch(offset, '<I', 40, self.alloc(b''.join(struct.pack('<I', o) for o in vk)))
        if children:
            nk = [self.key(child, offset) for child in children]
            self.patch(offset, '<I', 28, self.index(spec.get('index', 'lh'), nk))
        return offset

    def index(self, kind, offsets):
        if kind == 'li':
            return self.alloc(b'li' + struct.pack('<H', len(offsets)) + b''.join(struct.pack('<I', o) for o in offsets))
        if kind in ('lf', 'lh'):
            return self.alloc(kind.encode() + struct.pack('<H', len(offsets)) +
                              b''.join(struct.pack('<II', o, 0) for o in offsets))
        if kind == 'ri':
            half = max(1, len(offsets) // 2)
            lists = [self.index('lh', offsets[:half]), self.index('lh', offsets[half:])]
            return self.alloc(b'ri' + struct.pack('<H', len(lists)) + b''.join(struct.pack('<I', o) for o in lists))
        raise ValueError(kind)

    def build(self, tree, name='TESTHIVE', sequence=(1, 1), stamp=DEFAULT_STAMP):
        root = self.key(tree, 0xFFFFFFFF, root=True)
        used = 32 + len(self.cells)
        size = (used + 8 + PAGE - 1) // PAGE * PAGE
        free = size - used
        if free >= 8:
            self.cells += struct.pack('<i', free) + b'\x00' * (free - 4)
        bins = bytearray(b'hbin' + struct.pack('<IIQQI', 0, size, 0, stamp, 0)) + self.cells
        block = bytearray(PAGE)
        block[0:4] = b'regf'
        struct.pack_into('<IIQIIIIIII', block, 4, sequence[0], sequence[1], stamp, 1, self.minor,
                         0, 1, root, len(bins), 1)
        raw_name = name.encode('utf-16-le')[:64]
        block[48:48 + len(raw_name)] = raw_name
        struct.pack_into('<I', block, 508, xor32(block))
        return bytes(block) + bytes(bins)


def build(tree, **kwargs):
    minor = kwargs.pop('minor', 5)
    return Builder(minor).build(tree, **kwargs)


def sample_tree():
    """A small tree exercising every structure the reader handles."""
    return {
        'name': 'ROOT', 'stamp': DEFAULT_STAMP, 'index': 'lh',
        'keys': [
            {'name': 'Software', 'class': 'ClassText', 'index': 'ri', 'keys': [
                {'name': f'Sub{i}', 'stamp': DEFAULT_STAMP + i * 10_000_000} for i in range(5)]},
            {'name': 'Ünïcödé Ключ', 'utf16': True, 'index': 'li', 'keys': [
                {'name': 'Leaf', 'index': 'lf'}]},
            {'name': 'Café', 'values': [V('Größe', 1, sz('bytes ≥ 0x80'), utf16=False)]},
            {'name': 'Values', 'values': [
                V('', 1, sz('the default value')),
                V('Text', 1, sz('hello')),
                V('Expand', 2, sz('%SystemRoot%\\x')),
                V('NoTerminator', 1, sz('abc', terminate=False)),
                V('AfterNul', 1, sz('abc') + sz('junk')),
                V('OddLength', 1, sz('abc') + b'\x41'),
                V('Multi', 7, sz('one') + sz('two') + b'\x00\x00'),
                V('Dword', 4, struct.pack('<I', 0xDEADBEEF)),
                V('DwordBE', 5, struct.pack('>I', 0x01020304)),
                V('ShortDword', 4, b'\x01\x02'),
                V('LongDword', 4, b'\x01\x02\x03\x04\x05\x06\x07\x08'),
                V('Qword', 11, struct.pack('<Q', 0x0102030405060708)),
                V('Binary', 3, bytes(range(40))),
                V('None', 0, b''),
                V('ResidentSz', 1, sz('A'), resident=True),
                V('ResidentDword', 4, struct.pack('<I', 7), resident=True),
                V('Big', 3, bytes(i % 251 for i in range(40000))),
                V('Unknown', 0x20004, b'\x05\x00\x00\x00'),
                V('CellDword', 4, struct.pack('<I', 0x11223344), resident=False),
                V('Пароль', 1, sz('utf16 name'), utf16=True),
            ]},
        ],
    }
