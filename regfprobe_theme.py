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
            style.configure('TCheckbutton', background=c['bg'], indicatorbackground=c['field'],
                            indicatorforeground=c['select_fg'], upperbordercolor=c['muted'],
                            lowerbordercolor=c['muted'])
            style.map('TCheckbutton', background=[('active', c['bg'])],
                      indicatorbackground=[('selected', c['select'])])
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

    def _recolour(self, widget, colours):
        colours = colours if colours is not None else self._light_defaults.get(widget, {})
        for key, value in colours.items():
            try:
                widget.configure(**{key: value})
            except tk.TclError:
                pass
