"""The reader, on hives built by tests/hivebuilder.py, with python-registry as the outside check."""

import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, '..'), HERE]
import hivebuilder  # noqa: E402  pylint: disable=wrong-import-position
import regfprobe  # noqa: E402  pylint: disable=wrong-import-position
from hivebuilder import V, sz  # noqa: E402  pylint: disable=wrong-import-position

try:
    from Registry import Registry
except ImportError:  # python-registry is a test-only oracle
    if os.environ.get('REGFPROBE_REQUIRE_PYTHON_REGISTRY'):
        raise
    Registry = None


def sample():
    return hivebuilder.build(hivebuilder.sample_tree())


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = regfprobe.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class StructureTest(unittest.TestCase):
    def setUp(self):
        self.hive = regfprobe.Hive(sample())

    def test_every_key_is_reached_once_in_stored_order(self):
        paths = [k.path for k in self.hive.walk()]
        self.assertEqual(paths, ['', 'Software'] + [f'Software\\Sub{i}' for i in range(5)] +
                         ['Ünïcödé Ключ', 'Ünïcödé Ключ\\Leaf', 'Café', 'Values'])
        self.assertEqual(dict(self.hive.faults), {})

    def test_base_block(self):
        self.assertEqual(self.hive.version, '1.5')
        self.assertEqual(self.hive.header['file_name'], 'TESTHIVE')
        self.assertTrue(self.hive.header['checksum_ok'])
        self.assertEqual(self.hive.recovery['state'], 'clean')
        self.assertEqual(self.hive.root().name, 'ROOT')

    def test_index_kinds_ri_li_lf_lh_are_all_followed(self):
        self.assertEqual(len(self.hive.open_key('Software').subkeys()), 5)  # ri over two lh
        self.assertEqual(self.hive.open_key('Ünïcödé Ключ').subkeys()[0].name, 'Leaf')  # li
        self.assertEqual(len(self.hive.root().subkeys()), 4)  # lh

    def test_names_utf16_and_compressed_with_high_bytes(self):
        self.assertEqual(self.hive.open_key('ünïcödé ключ').name, 'Ünïcödé Ключ')
        self.assertEqual(self.hive.open_key('CAFÉ').name, 'Café')
        self.assertEqual(self.hive.open_key('Café').value('Größe').data, 'bytes ≥ 0x80')
        self.assertEqual(self.hive.open_key('Values').value('Пароль').data, 'utf16 name')

    def test_lookup_is_case_insensitive_and_takes_either_separator(self):
        self.assertEqual(self.hive.open_key('software/SUB3').name, 'Sub3')
        self.assertEqual(self.hive.open_key('Software\\Sub3').path, 'Software\\Sub3')
        with self.assertRaises(regfprobe.KeyNotFound):
            self.hive.open_key('Software\\Nope')
        with self.assertRaises(regfprobe.ValueNotFound):
            self.hive.open_key('Values').value('Nope')

    def test_class_name_and_times(self):
        key = self.hive.open_key('Software')
        self.assertEqual(key.class_name, 'ClassText')
        self.assertEqual(self.hive.open_key('Software\\Sub2').last_written_raw,
                         hivebuilder.DEFAULT_STAMP + 20_000_000)
        self.assertEqual(key.last_written.tzinfo, regfprobe.timezone.utc)

    def test_security_record(self):
        sk = self.hive.open_key('Software').security()
        self.assertEqual(sk['owner'], 'S-1-5-32-544')
        self.assertEqual(sk['group'], 'S-1-5-18')
        self.assertEqual(sk['dacl'], [{'type': 0, 'type_name': 'ACCESS_ALLOWED', 'flags': 2,
                                       'mask': 0x000F003F, 'sid': 'S-1-1-0'}])
        self.assertIsNone(sk['sacl'])


class ValueTest(unittest.TestCase):
    def setUp(self):
        self.key = regfprobe.Hive(sample()).open_key('Values')

    def v(self, name):
        return self.key.value(name)

    def test_default_value(self):
        self.assertTrue(self.v('').is_default)
        self.assertEqual(self.v(None).data, 'the default value')

    def test_strings_and_their_notes(self):
        self.assertEqual((self.v('Text').data, self.v('Text').notes), ('hello', []))
        self.assertEqual(self.v('Expand').data, '%SystemRoot%\\x')
        self.assertEqual((self.v('NoTerminator').data, self.v('NoTerminator').notes), ('abc', ['no terminating NUL']))
        self.assertEqual((self.v('AfterNul').data, self.v('AfterNul').notes), ('abc', ['data after the terminating NUL']))
        self.assertEqual(self.v('OddLength').data, 'abc')
        self.assertIn('odd length: the last byte is not part of the text', self.v('OddLength').notes)
        self.assertEqual(self.v('OddLength').raw[-1:], b'\x41')  # the stray byte stays in raw

    def test_multi_string(self):
        self.assertEqual(self.v('Multi').data, ['one', 'two'])

    def test_numbers(self):
        self.assertEqual(self.v('Dword').data, 0xDEADBEEF)
        self.assertEqual(self.v('DwordBE').data, 0x01020304)
        self.assertEqual(self.v('Qword').data, 0x0102030405060708)
        self.assertEqual(self.v('CellDword').data, 0x11223344)
        self.assertFalse(self.v('CellDword').resident)
        short = self.v('ShortDword')
        self.assertEqual((short.data, short.raw), (b'\x01\x02', b'\x01\x02'))
        self.assertEqual(short.notes, ['2 bytes, fewer than the four a DWORD needs'])
        long_ = self.v('LongDword')
        self.assertEqual(long_.data, 0x04030201)
        self.assertEqual(long_.notes, ['8 bytes, more than the four a DWORD holds'])

    def test_resident_data_keeps_its_stored_size(self):
        self.assertTrue(self.v('ResidentSz').resident)
        self.assertEqual(self.v('ResidentSz').raw, sz('A'))
        self.assertEqual(self.v('ResidentSz').data, 'A')
        self.assertEqual(self.v('ResidentDword').data, 7)

    def test_big_data_is_joined_from_its_segments(self):
        big = self.v('Big')
        self.assertTrue(big.big_data)
        self.assertEqual(big.raw, bytes(i % 251 for i in range(40000)))
        self.assertEqual(big.notes, [])

    def test_big_data_size_on_an_old_hive_is_a_plain_cell(self):
        tree = {'name': 'R', 'values': [V('Old', 3, bytes(20000))]}
        value = regfprobe.Hive(hivebuilder.build(tree, minor=3)).root().value('Old')
        self.assertFalse(value.big_data)
        self.assertEqual(len(value.raw), 20000)

    def test_unknown_type_is_kept_as_stored(self):
        value = self.v('Unknown')
        self.assertEqual((value.type, value.type_name, value.data), (0x20004, 'unknown type 0x20004', b'\x05\x00\x00\x00'))

    def test_empty_values(self):
        self.assertEqual((self.v('None').raw, self.v('None').data), (b'', b''))


def _patch(data, offset, fmt, at, *values):
    """Overwrite a field of the cell at offset (hive bins relative) in a built hive."""
    data = bytearray(data)
    struct.pack_into(fmt, data, 4096 + offset + 4 + at, *values)
    return bytes(data)


class FaultTest(unittest.TestCase):
    def test_a_damaged_key_loses_only_itself(self):
        data = sample()
        sub2 = regfprobe.Hive(data).open_key('Software\\Sub2').offset
        hive = regfprobe.Hive(_patch(data, sub2, '<2s', 0, b'XX'))
        names = [k.name for k in hive.open_key('Software').subkeys()]
        self.assertEqual(names, ['Sub0', 'Sub1', 'Sub3', 'Sub4'])
        self.assertEqual(hive.faults['nk'], 1)
        self.assertEqual(len(list(hive.walk())), 10)

    def test_a_list_that_points_back_up_the_tree_is_walked_once(self):
        data = sample()
        hive = regfprobe.Hive(data)
        node = hive.open_key('Ünïcödé Ключ')
        # its li list's one element is made to point at the root key
        data = _patch(data, node.subkeys_offset, '<I', 4, hive.root_offset)
        hive = regfprobe.Hive(data)
        paths = [k.path for k in hive.walk()]
        self.assertEqual(len(paths), len(set(paths)) + 0)
        self.assertEqual(hive.faults['cycle'], 1)

    def test_reading_a_damaged_structure_again_does_not_count_it_again(self):
        data = sample()
        hive = regfprobe.Hive(data)
        node = hive.open_key('Ünïcödé Ключ')
        hive = regfprobe.Hive(_patch(data, node.subkeys_offset, '<I', 4, hive.root_offset))
        for _ in range(3):
            list(hive.walk())
        key = regfprobe.Hive(data).open_key('Software')
        broken = regfprobe.Hive(_patch(data, key.offset, '<I', 44, 0x7FFFFFF8))
        for _ in range(3):
            broken.open_key('Software').security()
        self.assertEqual((hive.faults['cycle'], broken.faults['sk']), (1, 1))
        self.assertEqual(len(broken.fault_log), 1)

    def test_a_value_list_past_the_end_is_counted_and_the_key_still_reads(self):
        data = sample()
        key = regfprobe.Hive(data).open_key('Values')
        hive = regfprobe.Hive(_patch(data, key.offset, '<I', 40, 0x7FFFFFF8))
        self.assertEqual(hive.open_key('Values').values(), [])
        self.assertEqual(hive.faults['values'], 1)
        self.assertEqual(hive.open_key('Values').name, 'Values')

    def test_a_data_size_larger_than_its_cell_is_read_as_far_as_it_goes(self):
        data = sample()
        value = regfprobe.Hive(data).open_key('Values').value('Binary')
        hive = regfprobe.Hive(_patch(data, value.offset, '<I', 4, 400))
        broken = hive.open_key('Values').value('Binary')
        self.assertEqual(broken.raw[:40], bytes(range(40)))
        self.assertTrue(any(note.startswith('truncated') for note in broken.notes))

    def test_not_a_hive(self):
        with self.assertRaises(regfprobe.RegfError):
            regfprobe.Hive(b'\x00' * 8192)


@unittest.skipIf(Registry is None, 'python-registry not installed')
class PythonRegistryOracleTest(unittest.TestCase):
    """python-registry reads what hivebuilder writes, and agrees with regfprobe where both are right."""

    def test_same_tree_names_times_types_and_bytes(self):
        data = sample()
        mine = regfprobe.CompatRegistry(regfprobe.Hive(data))
        theirs = Registry.Registry(io.BytesIO(data))
        # python-registry 1.3.1 reads a REG_DWORD from the data offset field whatever its size
        # says, a REG_DWORD_BIG_ENDIAN from a cell even when it is resident, and masks the type
        # to its low 12 bits; those values are checked by regfprobe's own tests above instead.
        skip = {'CellDword', 'ShortDword', 'LongDword', 'DwordBE', 'Unknown'}

        def walk(a, b):
            self.assertEqual(a.path(), b.path())
            self.assertEqual(a.timestamp(), b.timestamp())
            self.assertEqual([k.name() for k in a.subkeys()], [k.name() for k in b.subkeys()])
            self.assertEqual([v.name() for v in a.values()], [v.name() for v in b.values()])
            for va, vb in zip(a.values(), b.values()):
                if va.name() in skip:
                    continue
                self.assertEqual(va.value_type(), vb.value_type(), va.name())
                self.assertEqual(va.raw_data(), vb.raw_data(), va.name())
                self.assertEqual(va.value(), vb.value(), va.name())
            for ka, kb in zip(a.subkeys(), b.subkeys()):
                walk(ka, kb)
        walk(mine.root(), theirs.root())


class CompatTest(unittest.TestCase):
    def setUp(self):
        self.reg = regfprobe.CompatRegistry(sample())

    def test_python_registry_shapes(self):
        key = self.reg.open('Values')
        self.assertEqual(key.path(), 'ROOT\\Values')
        self.assertEqual(key.value('(default)').name(), '(default)')
        self.assertEqual(key.value('Multi').value(), ['one', 'two', '', ''])
        self.assertEqual(key.value('Dword').value_type_str(), 'RegDWord')
        self.assertIsNone(key.timestamp().tzinfo)
        with self.assertRaises(regfprobe.CompatRegistry.RegistryKeyNotFoundException):
            self.reg.open('Nope')
        with self.assertRaises(regfprobe.CompatRegistry.RegistryValueNotFoundException):
            key.value('Nope')

    def test_constants_and_errors_python_registry_callers_use(self):
        reg = regfprobe.CompatRegistry
        self.assertEqual((reg.RegNone, reg.RegSZ, reg.RegExpandSZ, reg.RegBin, reg.RegDWord, reg.RegBigEndian,
                          reg.RegLink, reg.RegMultiSZ, reg.RegResourceList, reg.RegFullResourceDescriptor,
                          reg.RegResourceRequirementsList, reg.RegQWord), tuple(range(12)))
        self.assertTrue(issubclass(reg.RegistryKeyNotFoundException, reg.RegistryException))
        with self.assertRaises(reg.RegistryException):
            regfprobe.CompatRegistry(b'not a hive' * 100)

    @unittest.skipIf(Registry is None, 'python-registry not installed')
    def test_constants_match_python_registry(self):
        from Registry import RegistryParse  # pylint: disable=import-outside-toplevel
        for name in ('RegNone', 'RegSZ', 'RegExpandSZ', 'RegBin', 'RegDWord', 'RegBigEndian', 'RegLink',
                     'RegMultiSZ', 'RegResourceList', 'RegFullResourceDescriptor',
                     'RegResourceRequirementsList', 'RegQWord'):
            self.assertEqual(getattr(regfprobe.CompatRegistry, name), getattr(RegistryParse, name), name)

    def test_a_value_whose_data_cannot_be_read_raises_in_the_compat_layer(self):
        data = sample()
        value = regfprobe.Hive(data).open_key('Values').value('Binary')
        broken = bytearray(data)
        struct.pack_into('<I', broken, 4096 + value.offset + 4 + 8, 0x7FFFFFF8)   # data offset past the end
        hive = regfprobe.Hive(bytes(broken))
        native = hive.open_key('Values').value('Binary')
        self.assertEqual((native.raw, native.unreadable), (b'', True))   # the native API reads on
        compat = regfprobe.CompatRegistry(hive).open('Values').value('Binary')
        with self.assertRaises(regfprobe.CompatRegistry.RegistryException):
            compat.value()
        with self.assertRaises(regfprobe.CompatRegistry.RegistryException):
            compat.raw_data()
        self.assertEqual(hive.faults['data'], 1)

    def test_a_short_dword_is_still_an_int(self):
        key = self.reg.open('Values')
        self.assertEqual(key.value('ShortDword').value(), 0x0201)
        self.assertEqual(key.value('ShortDword').raw_data(), b'\x01\x02')

    def test_on_fault_reports_each_damaged_structure_once(self):
        data = sample()
        sub2 = regfprobe.Hive(data).open_key('Software\\Sub2').offset
        damaged = bytearray(data)
        damaged[4096 + sub2 + 4:4096 + sub2 + 6] = b'XX'
        seen = []
        hive = regfprobe.Hive(bytes(damaged), on_fault=lambda kind, offset, reason: seen.append((kind, offset)))
        for _ in range(2):
            list(hive.walk())
        self.assertEqual(seen, [('nk', sub2)])

    def test_timestamp_rounds_half_even_like_python_registry(self):
        stamp = self.reg.root().timestamp()  # DEFAULT_STAMP: an odd microsecond count and a 5
        whole = hivebuilder.DEFAULT_STAMP // 10
        self.assertEqual((hivebuilder.DEFAULT_STAMP % 10, whole % 2), (5, 1))
        expected = whole + 1  # half-even rounds an odd count up; truncation would not
        delta = stamp - regfprobe.datetime(1601, 1, 1)
        self.assertEqual((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds, expected)


class CommandLineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        cls.path = os.path.join(cls.folder.name, 'TEST.DAT')
        with open(cls.path, 'wb') as handle:
            handle.write(sample())

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def test_info(self):
        code, out, _err = run_cli('info', self.path)
        self.assertEqual(code, 0)
        self.assertIn('Format version:    1.5', out)
        self.assertIn('Keys / values:     11 / 21', out)

    def test_ls_and_cat(self):
        code, out, _err = run_cli('ls', self.path, 'Values')
        self.assertEqual(code, 0)
        self.assertIn('REG_SZ               Text = hello', out)
        code, out, _err = run_cli('cat', self.path, 'Values', 'Dword')
        self.assertIn('3735928559', out)
        self.assertIn('ef be ad de', out)

    def test_find(self):
        code, out, _err = run_cli('find', self.path, 'hello')
        self.assertEqual(code, 0)
        self.assertIn('value  Values\\Text  (data)', out)
        code, _out, _err = run_cli('find', self.path, 'no such text anywhere')
        self.assertEqual(code, 1)

    def test_timeline_newest_first(self):
        out_path = os.path.join(self.folder.name, 'timeline.csv')
        run_cli('timeline', self.path, '--out', out_path)
        with open(out_path, encoding='utf-8') as handle:
            lines = handle.read().splitlines()
        self.assertEqual(lines[1].split(',')[-1], 'Software\\Sub4')

    def test_export_json_csv_reg(self):
        for fmt in ('json', 'csv', 'reg'):
            out_path = os.path.join(self.folder.name, f'out.{fmt}')
            code, _out, _err = run_cli('export', self.path, '--format', fmt, '--out', out_path,
                                       '--prefix', 'HKEY_LOCAL_MACHINE\\TEST')
            self.assertEqual(code, 0)
            with open(out_path, encoding='utf-8') as handle:
                text = handle.read()
            if fmt == 'json':
                records = json.loads(text)
                self.assertEqual(len(records), 11)
                values = {v['name']: v for v in records[-1]['values']}
                self.assertEqual(values['NoTerminator']['notes'], ['no terminating NUL'])
            elif fmt == 'reg':
                self.assertTrue(text.startswith('Windows Registry Editor Version 5.00\n'))
                self.assertIn('[HKEY_LOCAL_MACHINE\\TEST\\Values]\n@="the default value"\n', text)
                self.assertIn('"Dword"=dword:deadbeef\n', text)
                self.assertIn('"NoTerminator"=hex(1):61,00,62,00,63,00\n', text)

    def test_logs(self):
        code, out, _err = run_cli('logs', self.path)
        self.assertEqual(code, 0)
        self.assertIn('clean as stored', out)

    def test_an_error_is_one_line_and_exit_2(self):
        code, _out, err = run_cli('ls', self.path, 'Nope')
        self.assertEqual(code, 2)
        self.assertTrue(err.startswith('regfprobe: '))


class WindowTest(unittest.TestCase):
    """The window is built in a child process: one Tk root per process (Tk 9 on macOS aborts
    the process when a second root is made after the first)."""

    def test_the_window_builds_and_shows_a_hive(self):
        import subprocess  # pylint: disable=import-outside-toplevel
        try:
            import tkinter  # pylint: disable=import-outside-toplevel
        except ImportError as error:
            if os.environ.get('REGFPROBE_REQUIRE_GUI'):
                raise
            self.skipTest(f'no Tk: {error}')
        if sys.platform == 'darwin' and tkinter.TkVersion >= 9 and not os.environ.get('REGFPROBE_REQUIRE_GUI'):
            # Tk 9.0.3 (python.org 3.14) aborts on macOS and pops a crash dialog on the desktop
            self.skipTest('Tk 9 on macOS; run this test with a Python that ships Tk 8.6')
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, 'TEST.DAT')
            with open(path, 'wb') as handle:
                handle.write(sample())
            done = subprocess.run([sys.executable, os.path.join(HERE, '..', 'regfprobe_gui.py'),
                                   '--selfcheck', path], capture_output=True, text=True,
                                  stdin=subprocess.DEVNULL, timeout=120, check=False)
        if done.returncode != 0:
            # only a display that cannot be opened is a reason to skip; a crash (a negative
            # return code, a signal) or any other error fails
            no_display = done.returncode > 0 and 'TclError' in done.stderr and 'display' in done.stderr
            if no_display and not os.environ.get('REGFPROBE_REQUIRE_GUI'):
                self.skipTest('no display')
            self.fail(f'window self-check failed ({done.returncode}): {done.stderr[-500:]}')
        self.assertEqual(json.loads(done.stdout), {
            'window': 'built', 'menus': 5 + (sys.platform == 'darwin'), 'logo': True, 'icon': True,
            'root_subkeys_shown': 4,
            'go_to_key': True, 'values_shown': 1, 'copied': True, 'missing_key_found': False,
            'timeline_rows': 11})


class _Walker:
    def __init__(self, data):
        self.data = data

    def read_file(self, _node, _size):
        return self.data


class ImageTest(unittest.TestCase):
    """read_from_image and the --image command line, with the image walk replaced by a fake."""

    def setUp(self):
        self.real = regfprobe._walk_image  # pylint: disable=protected-access
        hive = sample()
        files = [('vol1', 'Windows/System32/config/SYSTEM', hive), ('vol2', 'Windows/System32/config/SYSTEM', hive),
                 ('vol2', 'Windows/System32/config/SYSTEM.LOG1', b'not a log'), ('vol1', 'Users/a/NTUSER.DAT', hive)]

        def fake(_image, wanted, _password=None, cancel=None):
            for label, path, data in files:
                if cancel is not None and cancel():
                    raise regfprobe.RegfError('cancelled')
                if wanted(path):
                    yield label, path, _Walker(data), None, len(data)
        regfprobe._walk_image = fake  # pylint: disable=protected-access

    def tearDown(self):
        regfprobe._walk_image = self.real  # pylint: disable=protected-access

    def test_a_path_in_two_volumes_needs_a_volume(self):
        with self.assertRaises(regfprobe.RegfError) as caught:
            regfprobe.read_from_image('img', 'Windows/System32/config/SYSTEM')
        self.assertIn('vol1, vol2', str(caught.exception))
        hive = regfprobe.read_from_image('img', 'windows\\system32\\config\\system', volume='vol2')
        self.assertEqual(hive.path, 'img::vol2/Windows/System32/config/SYSTEM')
        self.assertEqual([name for name, _data in hive.logs], ['SYSTEM.LOG1'])  # the log of its own volume
        self.assertEqual(regfprobe.read_from_image('img', 'Users/a/NTUSER.DAT').logs, [])

    def test_a_refused_image_is_one_error_line(self):
        class Refused(Exception):
            pass

        class FakeQnx:
            @staticmethod
            def open_image(_image, password=None):  # pylint: disable=unused-argument
                raise Refused('it holds copies of files, not a disk')
        real_walk, real_qnx = regfprobe._walk_image, regfprobe._qnxprobe  # pylint: disable=protected-access
        regfprobe._walk_image = self.real  # pylint: disable=protected-access
        regfprobe._qnxprobe = lambda: FakeQnx  # pylint: disable=protected-access
        try:
            code, _out, err = run_cli('hives', '--image', 'case.ad1')
        finally:
            regfprobe._walk_image, regfprobe._qnxprobe = real_walk, real_qnx  # pylint: disable=protected-access
        self.assertEqual(code, 2)
        self.assertEqual(err, 'regfprobe: case.ad1: it holds copies of files, not a disk\n')

    def test_a_walk_can_be_cancelled(self):
        with self.assertRaises(regfprobe.RegfError) as caught:
            regfprobe.hives_in_image('img', cancel=lambda: True)
        self.assertEqual(str(caught.exception), 'cancelled')

    def test_commands_take_the_same_words_with_image(self):
        code, out, _err = run_cli('ls', '--image', 'img', '--path', 'Users/a/NTUSER.DAT', 'Values')
        self.assertEqual(code, 0)
        self.assertIn('Text = hello', out)
        code, out, _err = run_cli('cat', '--image', 'img', '--path', 'Users/a/NTUSER.DAT', 'Values', 'Text')
        self.assertIn('hello', out)
        code, out, _err = run_cli('find', '--image', 'img', '--path', 'Users/a/NTUSER.DAT', 'hello')
        self.assertIn('Values\\Text', out)
        code, _out, err = run_cli('info', '--image', 'img', '--path', 'Windows/System32/config/SYSTEM')
        self.assertEqual(code, 2)
        self.assertIn('--volume', err)


class SafeJoinTest(unittest.TestCase):
    def test_climbing_out_is_refused(self):
        with self.assertRaises(regfprobe.RegfError):
            regfprobe._safe_join('/tmp/x', 'vol', '../../etc/passwd')  # pylint: disable=protected-access
        self.assertEqual(regfprobe._safe_join('/tmp/x', 'vol', '/Windows/SYSTEM'),  # pylint: disable=protected-access
                         os.path.join('/tmp/x', 'vol', 'Windows', 'SYSTEM'))


if __name__ == '__main__':
    unittest.main()
