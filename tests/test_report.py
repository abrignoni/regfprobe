"""The HTML report and the value interpreters, on hives built by tests/hivebuilder.py."""

import io
import os
import re
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hivebuilder  # noqa: E402  pylint: disable=wrong-import-position
import regfprobe  # noqa: E402  pylint: disable=wrong-import-position
import regfprobe_interpret  # noqa: E402  pylint: disable=wrong-import-position
import regfprobe_report  # noqa: E402  pylint: disable=wrong-import-position


def _report(hive, entries, **kwargs):
    stream = io.StringIO()
    count = regfprobe_report.write_report(hive, entries, stream, **kwargs)
    return count, stream.getvalue()


class _Key:  # pylint: disable=too-few-public-methods
    def __init__(self, path):
        self.path = path


class _Value:  # pylint: disable=too-few-public-methods
    def __init__(self, name, raw, type_name='REG_BINARY', kind=3):
        self.name, self.raw, self.type_name, self.type = name, raw, type_name, kind


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.hive = regfprobe.Hive(hivebuilder.build(hivebuilder.sample_tree()))

    def test_every_key_under_the_root_is_written_once(self):
        count, text = _report(self.hive, [('', True), ('', False)])
        self.assertEqual(count, sum(1 for _ in self.hive.walk()))
        self.assertEqual(text.count('<section id='), count)

    def test_optional_columns_follow_the_choices(self):
        for show_data in (True, False):
            for show_raw in (True, False):
                _count, text = _report(self.hive, [('', True)], show_data=show_data, show_raw=show_raw)
                heads = re.findall(r'<th>([^<]*)</th>', text)
                self.assertEqual('regfprobe data' in heads, show_data)
                self.assertEqual('Raw bytes (hex)' in heads, show_raw)
                for row in re.findall(r'<tr><td>.*?</tr>', text):
                    self.assertEqual(row.count('<td'), 4 + show_data + show_raw)

    def test_strings_stay_readable_without_the_regfprobe_column(self):
        _count, text = _report(self.hive, [('', True)], show_data=False, show_raw=False)
        self.assertIn('hello', re.findall(r'<td class="interp">(.*?)</td>', text))

    def test_text_is_escaped(self):
        _count, text = _report(self.hive, [('', True)], title='<b>x</b>')
        self.assertIn('&lt;b&gt;x&lt;/b&gt;', text)
        self.assertNotIn('<b>x</b>', text)


class InterpretTest(unittest.TestCase):
    users = 'SAM\\Domains\\Account\\Users\\000003E9'

    def test_sam_f(self):
        data = bytearray(80)
        struct.pack_into('<Q', data, 0x18, 133136376335151712)
        struct.pack_into('<Q', data, 0x20, 0x7FFFFFFFFFFFFFFF)
        struct.pack_into('<I', data, 0x30, 1001)
        struct.pack_into('<H', data, 0x38, 0x0210)
        struct.pack_into('<HH', data, 0x40, 2, 7)
        got = dict(regfprobe_interpret.interpret(_Key(self.users), _Value('F', bytes(data))))
        self.assertEqual(got['Password last set'], '2022-11-23 00:40:33 UTC')
        self.assertEqual(got['Last logon'], 'Never (0)')
        self.assertEqual(got['Account expires'], 'not a date: stored as 0x7FFFFFFFFFFFFFFF')
        self.assertTrue(got['RID'].startswith('1001 '))
        self.assertIn('Password does not expire', got['Account flags'])
        self.assertEqual((got['Failed logon count'], got['Logon count']), ('2', '7'))

    def test_sam_v_user_name(self):
        name = 'borch'.encode('utf-16-le')
        data = bytearray(0xCC) + name
        struct.pack_into('<II', data, 0x0C, 0, len(name))
        got = dict(regfprobe_interpret.interpret(_Key(self.users), _Value('V', bytes(data))))
        self.assertEqual(got['User name'], 'borch')
        self.assertEqual(got['NT hash entry'], '0 bytes (not decoded here)')

    def test_rid_in_names_default_value_type(self):
        key = _Key('SAM\\Domains\\Account\\Users\\Names\\borch')
        got = regfprobe_interpret.interpret(key, _Value('', b'', 'unknown type 0x3e9', 0x3E9))
        self.assertTrue(got[0][1].startswith('1001 (0x3e9)'))

    def test_binaries_without_a_known_layout_are_not_guessed_at(self):
        key = _Key('Software\\X')
        for name, data in (('LastWrite', struct.pack('<Q', 133136376335151712)),   # FILETIME-shaped
                           ('Count', struct.pack('<I', 1033)),                       # decodes as U+0409
                           ('Mail', 'a@b.c'.encode('utf-16-le')),
                           ('OwnerSid', bytes([1, 2, 0, 0, 0, 0, 0, 5]) + struct.pack('<II', 32, 544)),
                           ('ProviderGUID', bytes.fromhex('8f88f9d7fce3b0499ea6a85b5f392a4f')),
                           ('Blob', b'BM' + bytes(40))):                              # not a BMP header
            self.assertEqual(regfprobe_interpret.interpret(key, _Value(name, data)), [], name)

    def test_pictures_need_a_valid_header(self):
        png = b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR' + bytes(17)
        got = regfprobe_interpret.interpret(_Key('Software\\X'), _Value('Logo', png))
        self.assertTrue(got[0][1].startswith('PNG,'))
        self.assertTrue(got[1][1].startswith('data:image/png;base64,'))
        bmp = b'BM' + struct.pack('<IIIIii', 70, 0, 54, 40, 2, 2) + bytes(70 - 26)
        tile = _Value('UserTile', b'\x01' * 16 + bmp)
        got = regfprobe_interpret.interpret(_Key(self.users), tile)
        self.assertEqual(got[0][1], 'BMP 2x2, 70 bytes at offset 16')
        # outside UserTile a picture must start the value
        self.assertEqual(regfprobe_interpret.interpret(_Key('Software\\X'), _Value('Logo', b'\x01' + png)), [])

    def test_times_that_no_date_holds_are_shown_as_stored(self):
        data = bytearray(0x44)
        struct.pack_into('<Q', data, 0x20, 0x7FFFFFFFFFFFFFFF)
        got = dict(regfprobe_interpret.interpret(_Key(self.users), _Value('F', bytes(data))))
        self.assertEqual(got['Account expires'], 'not a date: stored as 0x7FFFFFFFFFFFFFFF')
        self.assertEqual(got['Last logon'], 'Never (0)')

    def test_strings_are_left_to_regfprobe(self):
        self.assertEqual(regfprobe_interpret.interpret(_Key('X'), _Value('S', b'a\x00', 'REG_SZ', 1)), [])


if __name__ == '__main__':
    unittest.main()
