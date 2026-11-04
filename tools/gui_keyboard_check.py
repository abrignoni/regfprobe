#!/usr/bin/env python3
"""Walk through the window from the keyboard, with Tk's own key events, and report what happened.

    python3 tools/gui_keyboard_check.py

The window is shown for a few seconds. Keys are sent with event_generate to the widget that has
keyboard focus, so they go through the same bindings a person's keys do (the widgets' own and
the window's shortcuts). The hive is the synthetic one tests/hivebuilder.py makes. Copies are
caught by the script and never reach the clipboard; window settings are neither read nor saved.

Refuses to run on macOS with Tk 9 (python.org 3.14 ships Tk 9.0.3, which aborts Python here);
use a Python with Tk 8.6 (on this Mac, /usr/local/bin/python3.12).
"""

import json
import os
import sys
import tempfile
import time
import tkinter as tk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, '..'), os.path.join(HERE, '..', 'tests')]
import hivebuilder  # noqa: E402  pylint: disable=wrong-import-position
import regfprobe_gui  # noqa: E402  pylint: disable=wrong-import-position

MOD = regfprobe_gui._MOD  # pylint: disable=protected-access


def main():
    if sys.platform == 'darwin' and tk.TkVersion >= 9:
        print('refusing: Tk 9 on macOS aborts Python; run with a Tk 8.6 Python', file=sys.stderr)
        return 2
    folder = tempfile.mkdtemp()
    path = os.path.join(folder, 'TEST.DAT')
    with open(path, 'wb') as handle:
        handle.write(hivebuilder.build(hivebuilder.sample_tree()))
    root = tk.Tk()
    window = regfprobe_gui.Window(root, settings={})
    copies = []
    window._copy = lambda text, what: copies.append((what, text))  # pylint: disable=protected-access
    report = {}

    def pump(seconds=0.3):
        end = time.time() + seconds
        while time.time() < end:
            root.update()
            time.sleep(0.02)

    def key(sequence, widget=None):
        target = widget or root.focus_get() or root
        target.event_generate(sequence, when='tail')
        pump(0.15)

    def wait_idle(limit=10):
        end = time.time() + limit
        while window.busy and time.time() < end:
            pump(0.1)

    root.lift()
    root.focus_force()
    window.open_path(path)
    wait_idle()
    pump()
    tree = window.tree
    report['opened'] = window.hive is not None and root.focus_get() is tree

    key('<Down>', tree)
    report['down_selects'] = window.selected_key().path
    key('<Return>', tree)
    report['return_opens'] = bool(tree.item(tree.focus(), 'open'))
    key('<Down>', tree)
    report['down_into_child'] = window.selected_key().path

    key(f'<{MOD}-l>', tree)
    report['cmd_l_focuses_address'] = root.focus_get() is window.address_entry
    window.address.set('values')
    key('<Return>', window.address_entry)
    report['address_goes_to'] = window.selected_key().path
    report['values_listed'] = len(window.table.get_children())
    key(f'<{MOD}-l>', tree)
    window.address.set('Values\\Nope')
    key('<Return>', window.address_entry)
    report['bad_address_status'] = window.status.cget('text')

    window.table.focus_set()
    first = window.table.get_children()[0]
    window.table.selection_set(first)
    window.table.focus(first)
    pump()
    key(f'<{MOD}-c>', window.table)
    report['cmd_c_copies'] = copies[-1] if copies else None
    key(f'<{MOD}-C>', window.table)
    report['cmd_shift_c_copies'] = copies[-1] if copies else None

    window.sort(window.table, 'size')
    window.sort(window.table, 'size')
    sizes = [int(window.table.set(i, 'size')) for i in window.table.get_children()]
    report['size_sort_descending'] = sizes == sorted(sizes, reverse=True)

    key(f'<{MOD}-f>', window.table)
    report['cmd_f'] = (window.tabs.index('current'), root.focus_get() is window.search_entry)
    window.query.set('hello')
    key('<Return>', window.search_entry)
    wait_idle()
    pump()
    report['search_results'] = len(window.results.get_children())
    key('<Return>', window.results)
    report['result_return_jumps_to'] = window.selected_key().path

    key(f'<{MOD}-Key-4>', tree)
    report['cmd_4_tab'] = window.tabs.index('current')
    window.timeline()
    wait_idle()
    pump()
    report['timeline_rows'] = len(window.timeline_view.get_children())
    window.timeline_view.focus_set()
    row = window.timeline_view.get_children()[0]
    window.timeline_view.selection_set(row)
    window.timeline_view.focus(row)
    key('<Return>', window.timeline_view)
    report['timeline_return_jumps_to'] = window.selected_key().path

    tree.focus_set()
    pump()
    key('<Tab>', tree)
    report['tab_leaves_tree'] = root.focus_get() is not tree

    window._start_busy('test')  # pylint: disable=protected-access
    key('<Escape>', tree)
    report['escape_cancels'] = window.cancel_flag.is_set()
    window._stop_busy('Ready')  # pylint: disable=protected-access

    for pending in root.tk.splitlist(root.tk.call('after', 'info')):
        root.after_cancel(pending)
    root.destroy()
    print(json.dumps(report, ensure_ascii=False, indent=1))
    expected = {'opened': True, 'down_selects': 'Software', 'return_opens': True,
                'down_into_child': 'Software\\Sub0', 'cmd_l_focuses_address': True,
                'address_goes_to': 'Values', 'values_listed': 20,
                'bad_address_status': 'No key at Values\\Nope',
                'cmd_c_copies': ['data', 'the default value'], 'cmd_shift_c_copies': ['key path', 'Values'],
                'size_sort_descending': True, 'cmd_f': [2, True], 'search_results': 1,
                'result_return_jumps_to': 'Values', 'cmd_4_tab': 3, 'timeline_rows': 11,
                'timeline_return_jumps_to': 'Software\\Sub4', 'tab_leaves_tree': True, 'escape_cancels': True}
    got = json.loads(json.dumps(report))
    failed = sorted(name for name, want in expected.items() if got.get(name) != want)
    print('all keyboard checks passed' if not failed else f'FAILED: {", ".join(failed)}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
