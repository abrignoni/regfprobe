"""Theme switching, in a child process (one Tk root per process; see test_reader.WindowTest)."""

import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

_SCRIPT = r'''
import json, sys, tkinter as tk
from tkinter import ttk
sys.path.insert(0, sys.argv[1])
import regfprobe_theme
root = tk.Tk()
root.withdraw()
theme = regfprobe_theme.Theme(root)
box = ttk.Combobox(root, values=['a', 'b'], state='readonly')

def listbox():
    popdown = root.tk.call('ttk::combobox::PopdownWindow', box)   # what opening the list builds
    colour = root.tk.call(f'{popdown}.f.l', 'cget', '-background')
    return list(root.winfo_rgb(colour))   # 'white' and '#ffffff' are the same colour

light = listbox()                # opened once in light mode
theme.apply(True)
dark = listbox()                 # then in dark mode
theme.apply(False)
back = listbox()                 # and in light mode again
field = list(root.winfo_rgb(regfprobe_theme.DARK['field']))
root.destroy()
print(json.dumps({'light': light, 'dark': dark, 'back': back, 'field': field}))
'''


class ThemeTest(unittest.TestCase):
    def test_an_opened_dropdown_list_follows_the_theme(self):
        try:
            import tkinter  # pylint: disable=import-outside-toplevel
        except ImportError as error:
            if os.environ.get('REGFPROBE_REQUIRE_GUI'):
                raise
            self.skipTest(f'no Tk: {error}')
        if sys.platform == 'darwin' and tkinter.TkVersion >= 9 and not os.environ.get('REGFPROBE_REQUIRE_GUI'):
            self.skipTest('Tk 9 on macOS; run this test with a Python that ships Tk 8.6')
        done = subprocess.run([sys.executable, '-c', _SCRIPT, os.path.join(HERE, '..')], capture_output=True,
                              text=True, stdin=subprocess.DEVNULL, timeout=120, check=False)
        if done.returncode != 0:
            no_display = done.returncode > 0 and 'TclError' in done.stderr and 'display' in done.stderr
            if no_display and not os.environ.get('REGFPROBE_REQUIRE_GUI'):
                self.skipTest('no display')
            self.fail(f'theme check failed ({done.returncode}): {done.stderr[-500:]}')
        seen = json.loads(done.stdout)
        self.assertEqual(seen['dark'], seen['field'])
        self.assertEqual(seen['back'], seen['light'])
        self.assertNotEqual(seen['light'], seen['dark'])


if __name__ == '__main__':
    unittest.main()
