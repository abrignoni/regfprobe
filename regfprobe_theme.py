"""Light/dark colours for the regfprobe window.

ttk widgets are recoloured through ttk.Style on the 'clam' theme (Windows' native 'vista'
theme ignores colours). Classic Tk widgets (Text, Listbox, Menu, Toplevel) get colours both
directly and through the option database, so ones made later match. On Windows 10/11 the title
bars are switched with DwmSetWindowAttribute.
"""

import sys
import tkinter as tk
from tkinter import ttk

DARK = {'bg': '#1e1f22', 'panel': '#2b2d31', 'field': '#232428', 'fg': '#e3e5e8', 'muted': '#a0a4ab',
        'line': '#3a3c42', 'select': '#2f5fa8', 'select_fg': '#ffffff', 'button': '#34363c',
        'hover': '#40434a', 'heading': '#2b2d31'}


def _title_bar(window, dark):
    if sys.platform != 'win32':
        return
    try:
        import ctypes  # pylint: disable=import-outside-toplevel
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id()) or window.winfo_id()
        value = ctypes.c_int(1 if dark else 0)
        for attribute in (20, 19):   # DWMWA_USE_IMMERSIVE_DARK_MODE (newer, then older Windows 10)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(value),
                                                          ctypes.sizeof(value)) == 0:
                break
    except (AttributeError, OSError, tk.TclError):
        pass


def _walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


class Theme:
    def __init__(self, root):
        self.root = root
        self.style = ttk.Style(root)
        self.light_theme = self.style.theme_use()
        self.dark = False
        self._light_defaults = {}
        self._check_size = None
        self._check_images = ()
        root.bind_class('Toplevel', '<Map>', lambda e: _title_bar(e.widget, self.dark), add='+')

    def _remember(self, widget, keys):
        if widget not in self._light_defaults:
            saved = {}
            for k in keys:
                try:
                    saved[k] = widget.cget(k)
                except tk.TclError:
                    pass
            self._light_defaults[widget] = saved

    def apply(self, dark):
        self.dark = dark
        style, root = self.style, self.root
        if dark:
            c = DARK
            style.theme_use('clam')
            style.configure('.', background=c['bg'], foreground=c['fg'], fieldbackground=c['field'],
                            bordercolor=c['line'], darkcolor=c['bg'], lightcolor=c['line'],
                            troughcolor=c['panel'], insertcolor=c['fg'], selectbackground=c['select'],
                            selectforeground=c['select_fg'], arrowcolor=c['fg'])
            style.map('.', background=[('disabled', c['bg'])], foreground=[('disabled', c['muted'])])
            style.configure('TButton', background=c['button'], padding=(10, 3))
            style.map('TButton', background=[('pressed', c['select']), ('active', c['hover'])])
            style.configure('TEntry', fieldbackground=c['field'], foreground=c['fg'])
            style.configure('TCombobox', fieldbackground=c['field'], foreground=c['fg'], background=c['button'],
                            arrowcolor=c['fg'], selectbackground=c['field'], selectforeground=c['fg'])
            style.map('TCombobox', fieldbackground=[('readonly', c['field'])], foreground=[('readonly', c['fg'])],
                      background=[('active', c['hover']), ('readonly', c['button'])],
                      selectbackground=[('readonly', c['field'])], selectforeground=[('readonly', c['fg'])])
            root.option_add('*TCombobox*Listbox.background', c['field'])
            root.option_add('*TCombobox*Listbox.foreground', c['fg'])
            root.option_add('*TCombobox*Listbox.selectBackground', c['select'])
            root.option_add('*TCombobox*Listbox.selectForeground', c['select_fg'])
            style.configure('TCheckbutton', background=c['bg'], indicatorbackground=c['field'],
                            indicatorforeground=c['select_fg'], upperbordercolor=c['muted'],
                            lowerbordercolor=c['muted'])
            style.map('TCheckbutton', background=[('active', c['bg'])],
                      indicatorbackground=[('selected', c['select'])])
            self._checkbox_images(c)
            style.configure('TNotebook', background=c['bg'], bordercolor=c['line'])
            style.configure('TNotebook.Tab', background=c['panel'], foreground=c['muted'], padding=(10, 3))
            style.map('TNotebook.Tab', background=[('selected', c['bg'])], foreground=[('selected', c['fg'])])
            style.configure('Treeview', background=c['field'], fieldbackground=c['field'], foreground=c['fg'],
                            bordercolor=c['line'])
            style.map('Treeview', background=[('selected', c['select'])],
                      foreground=[('selected', c['select_fg'])])
            style.configure('Treeview.Heading', background=c['heading'], foreground=c['fg'],
                            bordercolor=c['line'])
            style.map('Treeview.Heading', background=[('active', c['hover'])])
            style.configure('TScrollbar', background=c['button'], troughcolor=c['bg'], bordercolor=c['bg'],
                            arrowcolor=c['muted'])
            style.map('TScrollbar', background=[('active', c['hover'])])
            style.configure('TPanedwindow', background=c['line'])
            style.configure('Sash', sashthickness=5, gripcount=0, background=c['line'])
            classic = {'background': c['field'], 'foreground': c['fg'], 'insertbackground': c['fg'],
                       'selectbackground': c['select'], 'selectforeground': c['select_fg'],
                       'highlightbackground': c['line'], 'highlightcolor': c['select']}
            menu = {'background': c['panel'], 'foreground': c['fg'], 'activebackground': c['select'],
                    'activeforeground': c['select_fg'], 'disabledforeground': c['muted']}
            root.option_add('*Text.background', c['field'])
            root.option_add('*Text.foreground', c['fg'])
            root.option_add('*Listbox.background', c['field'])
            root.option_add('*Listbox.foreground', c['fg'])
            root.option_add('*Listbox.selectBackground', c['select'])
            root.option_add('*Menu.background', c['panel'])
            root.option_add('*Menu.foreground', c['fg'])
            root.option_add('*Menu.activeBackground', c['select'])
            root.option_add('*Toplevel.background', c['bg'])
            self._remember(root, ['background'])   # before recolouring, so light can be restored
            root.configure(background=c['bg'])
        else:
            root.option_clear()
            style.theme_use(self.light_theme)
            classic = menu = None
        for widget in _walk(root):
            cls = widget.winfo_class()
            if cls in ('Text', 'Listbox'):
                if classic:
                    self._remember(widget, list(classic))
                self._recolour(widget, classic)
            elif cls == 'Menu':
                if menu:
                    self._remember(widget, list(menu))
                self._recolour(widget, menu)
            elif cls in ('Toplevel', 'Tk'):
                if dark:
                    self._remember(widget, ['background'])
                self._recolour(widget, {'background': DARK['bg']} if dark else None)
                _title_bar(widget, dark)

    def _checkbox_images(self, c):
        """Draw a ✓ checkbox (clam draws an ✕) at a size that follows the font, and use it in dark mode."""
        from tkinter import font as tkfont  # pylint: disable=import-outside-toplevel
        size = max(12, tkfont.nametofont('TkDefaultFont').metrics('linespace') * 2 // 3)
        if self._check_size != size:
            self._check_size = size
            self._check_images = (self._box(size, c, False), self._box(size, c, True))
            self.style.element_create('DarkCheck.indicator', 'image', self._check_images[0],
                                      ('selected', self._check_images[1]),
                                      ('alternate', self._check_images[0]), border=0, sticky='')
        self.style.layout('TCheckbutton', [('Checkbutton.padding', {'sticky': 'nswe', 'children': [
            ('DarkCheck.indicator', {'side': 'left', 'sticky': ''}),
            ('Checkbutton.focus', {'side': 'left', 'sticky': 'w', 'children': [
                ('Checkbutton.label', {'sticky': 'nswe'})]})]})])
        self.style.configure('TCheckbutton', padding=(2, 2), indicatormargin=0)

    def _box(self, n, c, checked):
        img = tk.PhotoImage(master=self.root, width=n + 6, height=n)   # 6px gap before the label
        fill = c['select'] if checked else c['field']
        edge = c['select'] if checked else c['muted']
        rows = []
        for y in range(n):
            row = []
            for x in range(n):
                corner = (x in (0, n - 1)) and (y in (0, n - 1))
                border = x in (0, 1, n - 2, n - 1) and n > 14 or x in (0, n - 1) or y in (0, n - 1)                     or (n > 14 and y in (1, n - 2))
                row.append(c['bg'] if corner else edge if border else fill)
            row += [c['bg']] * 6
            rows.append('{' + ' '.join(row) + '}')
        img.put(' '.join(rows))
        if checked:   # tick from about (22%, 52%) down to (42%, 72%) then up to (78%, 28%)
            t = max(2, n // 8)
            pts = [(0.22, 0.52), (0.42, 0.72), (0.78, 0.28)]
            for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
                steps = n * 2
                for i in range(steps + 1):
                    x = (x0 + (x1 - x0) * i / steps) * n
                    y = (y0 + (y1 - y0) * i / steps) * n
                    for dx in range(t):
                        for dy in range(t):
                            px, py = int(x - t / 2 + dx), int(y - t / 2 + dy)
                            if 1 < px < n - 2 and 1 < py < n - 2:
                                img.put(c['select_fg'], (px, py))
        return img

    def _recolour(self, widget, colours):
        colours = colours if colours is not None else self._light_defaults.get(widget, {})
        for key, value in colours.items():
            try:
                widget.configure(**{key: value})
            except tk.TclError:
                pass
