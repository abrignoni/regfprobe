#!/usr/bin/env python3
"""regfprobe GUI: a read-only tkinter window over regfprobe.py.

Standard library only, like the reader it drives. Everything it shows comes from the same
library calls the command line makes, so anything seen here can be reproduced there.

    python3 regfprobe_gui.py                      open the window
    python3 regfprobe_gui.py HIVE                 open it with this hive loaded
    python3 regfprobe_gui.py HIVE --key PATH      ... and that key selected
    python3 regfprobe_gui.py --image IMAGE        open it and pick a hive inside the image
    python3 regfprobe_gui.py --selfcheck [HIVE]   build the window, load the hive, exit (no window shown)

The hive is read into memory and never written. There are no edit controls. The only file the
window writes on its own is its size and position, in the user's settings folder.

Author: @AlexisBrignoni, Claude. MIT licence.
"""

import argparse
import csv
import json
import os
import queue
import sys
import threading
import tkinter as tk
from datetime import datetime, timezone
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import regfprobe  # noqa: E402  pylint: disable=wrong-import-position
import regfprobe_theme  # noqa: E402  pylint: disable=wrong-import-position
import regfprobe_profile  # noqa: E402  pylint: disable=wrong-import-position
import regfprobe_report  # noqa: E402  pylint: disable=wrong-import-position

_PLACEHOLDER = '\x00loading'
_MAC = sys.platform == 'darwin'
_MOD = 'Command' if _MAC else 'Control'          # the key Tk binds as the shortcut modifier
_MOD_LABEL = 'Cmd' if _MAC else 'Ctrl'           # the name shown in menus
_PAGE_ROWS = 1000                                # timeline rows shown at once
_SEARCH_LIMIT = 5000
_STRIPES = {'ok': '#2e7d32', 'info': '#1565c0', 'warn': '#ef6c00', 'bad': '#c62828'}


def _iso(raw):
    stamp = regfprobe.filetime_to_datetime(raw)
    return stamp.strftime('%Y-%m-%d %H:%M:%S.%f') if stamp else ''


def _hexdump(data, width=16):
    lines = []
    for start in range(0, len(data), width):
        chunk = data[start:start + width]
        text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{start:08x}  {chunk.hex(" "):<{width * 3}} {text}')
    return '\n'.join(lines)


def _filetime(text, end_of_day=False):
    """A FILETIME for a 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS' UTC string; None for ''.

    Raises ValueError for anything else."""
    text = text.strip()
    if not text:
        return None
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try:
            stamp = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        delta = stamp - datetime(1601, 1, 1, tzinfo=timezone.utc)
        ticks = (delta.days * 86400 + delta.seconds) * 10_000_000
        if fmt == '%Y-%m-%d' and end_of_day:
            ticks += 86400 * 10_000_000 - 1
        return ticks
    raise ValueError(f'not a date: {text!r} (use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS, UTC)')


def _settings_path():
    if _MAC:
        base = os.path.expanduser('~/Library/Application Support')
    elif os.name == 'nt':
        base = os.environ.get('APPDATA') or os.path.expanduser('~')
    else:
        base = os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config')
    return os.path.join(base, 'regfprobe', 'window.json')


def _load_settings():
    try:
        with open(_settings_path(), encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _short_hive(hive):
    """A short name for where a hive came from: 'SAM (CASE.E01)', 'Users/jdoe/NTUSER.DAT (CASE.E01)'."""
    source = str(hive.path or hive.name).replace('\\', '/')
    image, _sep, inside = source.rpartition('::')
    parts = inside.split('/')
    if len(parts) > 2 and parts[1].lower() == 'users':      # volume/Users/<name>/...: keep the user
        name = '/'.join(parts[1:4]) + ('/.../' + parts[-1] if len(parts) > 4 else '')
    else:
        name = parts[-1]
    return f'{name} ({os.path.basename(image)})' if image else name


def _save_settings(settings):
    path = _settings_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(settings, handle)
    except OSError:
        pass  # the window's size is a convenience, never worth an error


def _dpi_aware():
    """On Windows, ask to be drawn at the screen's own resolution instead of scaled up (blurry)."""
    if os.name != 'nt':
        return
    try:
        import ctypes  # pylint: disable=import-outside-toplevel
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            ctypes.windll.user32.SetProcessDPIAware()
    except (AttributeError, OSError, ImportError):
        pass


class Window:  # pylint: disable=too-many-instance-attributes,too-many-public-methods,attribute-defined-outside-init
    """The main window: key tree, values, hex, key info, security, search and timeline."""

    def __init__(self, root, settings=None):
        self.root = root
        self.hive = None
        self.keys = {}          # tree item id -> regfprobe.Key
        self.values = {}        # values table item id -> regfprobe.Value
        self.jobs = queue.Queue()
        self.cancel_flag = threading.Event()
        self.busy = False
        self.timeline_rows = []  # [(FILETIME, path)] after the date filter, in the shown order
        self.timeline_page = 0
        self.sorts = {}         # treeview -> (column, descending)
        self.settings = settings if settings is not None else {}
        self._menu_view = None   # the table a right-click menu was opened on
        root.title('regfprobe')
        width = min(1200, root.winfo_screenwidth() - 40)
        height = min(780, root.winfo_screenheight() - 200)   # title bar, menus, taskbar or Dock
        root.geometry(self.settings.get('geometry', f'{width}x{height}'))
        root.minsize(760, 480)
        self.fixed = 'TkFixedFont'
        self.report_entries = []   # (hive, key path, include subkeys) for the HTML report; can span hives
        self._banner_level = 'ok'
        self._build()
        self._menus()
        self._shortcuts()
        root.protocol('WM_DELETE_WINDOW', self.close)
        if self.dark_var.get():
            self.set_dark(True)
        root.after(100, self._drain)

    # -- layout -----------------------------------------------------------------------------

    def _build(self):
        self.theme = regfprobe_theme.Theme(self.root)
        self._base_styles()
        self._build_widgets()

    def _base_styles(self):
        """Styles regfprobe sets on whichever ttk theme is in use (re-run after a theme switch)."""
        style = ttk.Style(self.root)
        bold = tkfont.nametofont('TkDefaultFont').copy()
        bold.configure(weight='bold', size=bold.cget('size') + 2 if bold.cget('size') > 0 else bold.cget('size') - 2)
        self._bold = bold   # kept: Tk forgets a font whose Python object is collected
        style.configure('Banner.TLabel', padding=(8, 2, 8, 4))
        style.configure('BannerBold.TLabel', padding=(8, 4, 8, 0), font=bold)
        # Treeview rows default to a fixed ~20px; under DPI awareness fonts scale but rows
        # don't, so text is clipped on Windows at >100% scaling. Size rows from the font.
        line = max(tkfont.nametofont(f).metrics('linespace') for f in ('TkDefaultFont', 'TkTextFont'))
        style.configure('Treeview', rowheight=line + 6)
        # check and radio indicators are drawn at a fixed size by some themes (clam): scale them too
        style.configure('TCheckbutton', indicatorsize=max(12, line * 2 // 3))
        style.configure('TRadiobutton', indicatorsize=max(12, line * 2 // 3))

    def _build_widgets(self):

        # address bar
        bar = ttk.Frame(self.root, padding=(8, 6, 8, 2))
        bar.pack(fill='x')
        ttk.Label(bar, text='Key').pack(side='left')
        self.address = tk.StringVar()
        self.address_entry = ttk.Entry(bar, textvariable=self.address)
        self.address_entry.pack(side='left', fill='x', expand=True, padx=(6, 6))
        self.address_entry.bind('<Return>', lambda _e: self.go_to_address())
        self.address_entry.bind('<KP_Enter>', lambda _e: self.go_to_address())
        ttk.Button(bar, text='Go', command=self.go_to_address).pack(side='left')

        # banner: a coloured stripe says how much to trust what follows
        banner = ttk.Frame(self.root, padding=(8, 2))
        banner.pack(fill='x')
        self.stripe = tk.Frame(banner, width=6, background=_STRIPES['info'])
        self.stripe.pack(side='left', fill='y')
        text = ttk.Frame(banner)
        text.pack(side='left', fill='x', expand=True)
        self.banner_title = ttk.Label(text, text='No hive open', style='BannerBold.TLabel')
        self.banner_title.pack(fill='x')
        self.banner = ttk.Label(text, text=f'Open a hive file with {_MOD_LABEL}+O, or a hive inside '
                                f'a disk image with {_MOD_LABEL}+Shift+O.',
                                style='Banner.TLabel', justify='left', wraplength=1100)
        self.banner.pack(fill='x')

        # status bar (packed before the panes so it keeps its place at the bottom)
        status = ttk.Frame(self.root, padding=(8, 2, 8, 4))
        status.pack(side='bottom', fill='x')
        self.status = ttk.Label(status, text='Ready')
        self.status.pack(side='left', fill='x', expand=True)
        self.progress = ttk.Progressbar(status, mode='indeterminate', length=160)
        self.cancel_button = ttk.Button(status, text='Cancel', command=self.cancel)

        panes = ttk.PanedWindow(self.root, orient='horizontal')
        panes.pack(fill='both', expand=True, padx=8, pady=4)
        self.panes = panes

        left = ttk.Frame(panes)
        self.tree = ttk.Treeview(left, show='tree', selectmode='browse')
        self.tree.column('#0', width=600, minwidth=200, stretch=True)
        scroll = ttk.Scrollbar(left, orient='vertical', command=self.tree.yview)
        across = ttk.Scrollbar(left, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll.set, xscrollcommand=across.set)
        across.pack(side='bottom', fill='x')
        scroll.pack(side='right', fill='y')
        self.tree.pack(side='left', fill='both', expand=True)
        self.tree.bind('<<TreeviewOpen>>', self._on_open)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        panes.add(left, weight=1)

        right = ttk.Frame(panes)
        panes.add(right, weight=3)
        # place the split once the panes have their real width (before that, Windows ignores it)
        def place_sash(event):
            if event.width > 400:
                panes.unbind('<Configure>')
                panes.sashpos(0, min(int(self.settings.get('sash', 340)), event.width - 300))
        panes.bind('<Configure>', place_sash)
        self.info = ttk.Label(right, text='', padding=(4, 2), anchor='w', justify='left')
        self.info.pack(fill='x')
        self.tabs = ttk.Notebook(right)
        self.tabs.pack(fill='both', expand=True)
        self._values_tab()
        self.security = tk.Text(self.tabs, font=self.fixed, wrap='none', state='disabled',
                                borderwidth=0, highlightthickness=0)
        self.tabs.add(self.security, text='Security')
        self._search_tab()
        self._timeline_tab()

    def _table(self, parent, columns):
        """A Treeview with headings that sort when clicked, and a vertical scrollbar."""
        frame = ttk.Frame(parent)
        view = ttk.Treeview(frame, columns=[c for c, _l, _w in columns], show='headings', selectmode='browse')
        for column, label, width in columns:
            view.heading(column, text=label, command=lambda c=column, v=view: self.sort(v, c))
            view.column(column, width=width, stretch=width >= 300)
        scroll = ttk.Scrollbar(frame, orient='vertical', command=view.yview)
        view.configure(yscrollcommand=scroll.set)
        view.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        return frame, view

    def _values_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text='Values')
        split = ttk.PanedWindow(tab, orient='vertical')
        split.pack(fill='both', expand=True)
        frame, self.table = self._table(split, (('name', 'Name', 180), ('type', 'Type', 130),
                                                ('size', 'Size', 60), ('data', 'Data', 300),
                                                ('notes', 'Notes', 300)))
        self.table.column('notes', width=160)
        self.table.column('size', anchor='e')
        self.table.bind('<<TreeviewSelect>>', self._on_value)
        split.add(frame, weight=3)
        self.hex = tk.Text(split, height=10, font=self.fixed, wrap='none', state='disabled',
                           borderwidth=0, highlightthickness=0)
        split.add(self.hex, weight=2)

    def _search_tab(self):
        tab = ttk.Frame(self.tabs, padding=4)
        self.tabs.add(tab, text='Search')
        row = ttk.Frame(tab)
        row.pack(fill='x')
        self.query = tk.StringVar()
        self.search_entry = ttk.Entry(row, textvariable=self.query, width=40)
        self.search_entry.pack(side='left')
        self.search_entry.bind('<Return>', lambda _e: self.search())
        self.scope = tk.StringVar(value='names and data')
        ttk.Combobox(row, textvariable=self.scope, state='readonly', width=16,
                     values=('names and data', 'names', 'data')).pack(side='left', padx=4)
        ttk.Button(row, text='Search', command=self.search).pack(side='left')
        frame, self.results = self._table(tab, (('kind', 'Match', 80), ('path', 'Key path', 600),
                                                ('value', 'Value', 200)))
        frame.pack(fill='both', expand=True, pady=(4, 0))
        self.results.bind('<Double-1>', lambda _e: self._jump_from(self.results))
        self.results.bind('<Return>', lambda _e: self._jump_from(self.results))

    def _timeline_tab(self):
        tab = ttk.Frame(self.tabs, padding=4)
        self.tabs.add(tab, text='Timeline')
        top = ttk.Frame(tab)
        top.pack(fill='x')
        ttk.Label(top, text='From').pack(side='left')
        self.date_from = tk.StringVar()
        ttk.Entry(top, textvariable=self.date_from, width=19).pack(side='left', padx=(4, 8))
        ttk.Label(top, text='To').pack(side='left')
        self.date_to = tk.StringVar()
        ttk.Entry(top, textvariable=self.date_to, width=19).pack(side='left', padx=(4, 8))
        ttk.Button(top, text='Build', command=self.timeline).pack(side='left')
        ttk.Button(top, text='Save CSV...', command=self.save_timeline).pack(side='left', padx=4)
        ttk.Label(top, text='UTC; YYYY-MM-DD or YYYY-MM-DD HH:MM:SS; blank for no limit').pack(side='left', padx=8)
        frame, self.timeline_view = self._table(tab, (('time', 'Last written (UTC)', 210), ('path', 'Key path', 700)))
        frame.pack(fill='both', expand=True, pady=(4, 0))
        self.timeline_view.bind('<Double-1>', lambda _e: self._jump_from(self.timeline_view))
        self.timeline_view.bind('<Return>', lambda _e: self._jump_from(self.timeline_view))
        pager = ttk.Frame(tab)
        pager.pack(fill='x', pady=(4, 0))
        self.prev_button = ttk.Button(pager, text='Previous', command=lambda: self.show_page(self.timeline_page - 1))
        self.prev_button.pack(side='left')
        self.next_button = ttk.Button(pager, text='Next', command=lambda: self.show_page(self.timeline_page + 1))
        self.next_button.pack(side='left', padx=4)
        self.page_label = ttk.Label(pager, text='Every key by last-written time, newest first.')
        self.page_label.pack(side='left', padx=8)

    def _menus(self):
        # Shortcut labels are written Cmd+O / Ctrl+O. On macOS, Tk turns such a label into the
        # menu item's own key equivalent, drawn with the macOS symbols (tkMacOSXMenu.c,
        # ParseAccelerator, which accepts Cmd/Command/Shift and '-' or '+'), and leaves running
        # the command to the bindings made in _shortcuts (TKMenu performKeyEquivalent).
        menubar = tk.Menu(self.root, tearoff=False)   # a menu bar has no tear-off entry
        if _MAC:
            app = tk.Menu(menubar, name='apple')
            app.add_command(label='About regfprobe', command=self.about)
            menubar.add_cascade(menu=app)
        files = tk.Menu(menubar, tearoff=False)
        files.add_command(label='Open Hive...', accelerator=f'{_MOD_LABEL}+O', command=self.open_hive_dialog)
        files.add_command(label='Open Hive from Disk Image...', accelerator=f'{_MOD_LABEL}+Shift+O',
                          command=self.open_image_dialog)
        files.add_separator()
        files.add_command(label='Export Selected Key...', accelerator=f'{_MOD_LABEL}+E', command=self.export_dialog)
        files.add_command(label='Save Timeline as CSV...', command=self.save_timeline)
        files.add_command(label='Export HTML Report...', command=self.report_dialog)
        files.add_separator()
        self.replay = tk.BooleanVar(value=True)
        files.add_checkbutton(label='Replay Transaction Logs When Opening', variable=self.replay)
        if not _MAC:
            files.add_separator()
            files.add_command(label='Exit', command=self.close)
        menubar.add_cascade(label='File', menu=files)
        edit = tk.Menu(menubar, tearoff=False)
        edit.add_command(label='Copy Key Path', accelerator=f'{_MOD_LABEL}+Shift+C', command=self.copy_path)
        edit.add_command(label='Copy Value Name', command=self.copy_name)
        edit.add_command(label='Copy Value Data', accelerator=f'{_MOD_LABEL}+C', command=self.copy_data)
        edit.add_command(label='Copy Value Bytes as Hex', command=self.copy_hex)
        edit.add_separator()
        edit.add_command(label='Find...', accelerator=f'{_MOD_LABEL}+F', command=self.focus_search)
        menubar.add_cascade(label='Edit', menu=edit)
        report = tk.Menu(menubar, tearoff=False)
        report.add_command(label='Add Selected Key', accelerator=f'{_MOD_LABEL}+R',
                           command=lambda: self.report_add(False))
        report.add_command(label='Add Selected Key and Subkeys', command=lambda: self.report_add(True))
        report.add_command(label='Keys in Report...', command=self.report_manage)
        report.add_separator()
        report.add_command(label='Save Selections as Profile...', command=self.profile_save)
        report.add_command(label='Load Profile from Disk Image...', command=self.profile_load)
        report.add_separator()
        report.add_command(label='Export HTML Report...', command=self.report_dialog)
        menubar.add_cascade(label='Report', menu=report)
        view = tk.Menu(menubar, tearoff=False)
        view.add_command(label='Go to Key...', accelerator=f'{_MOD_LABEL}+L', command=self.focus_address)
        view.add_command(label='Values', accelerator=f'{_MOD_LABEL}+1', command=lambda: self.tabs.select(0))
        view.add_command(label='Security', accelerator=f'{_MOD_LABEL}+2', command=lambda: self.tabs.select(1))
        view.add_command(label='Search', accelerator=f'{_MOD_LABEL}+3', command=lambda: self.tabs.select(2))
        view.add_command(label='Timeline', accelerator=f'{_MOD_LABEL}+4', command=lambda: self.tabs.select(3))
        view.add_separator()
        self.dark_var = tk.BooleanVar(value=bool(self.settings.get('dark', False)))
        view.add_checkbutton(label='Dark Mode', variable=self.dark_var, command=self.toggle_dark)
        menubar.add_cascade(label='View', menu=view)
        helps = tk.Menu(menubar, tearoff=False, name='help')
        if not _MAC:
            helps.add_command(label='About regfprobe', command=self.about)
        helps.add_command(label='User Manual', accelerator='F1', command=self.open_manual)
        helps.add_command(label='Save Manual as PDF...', command=self.save_manual_pdf)
        helps.add_command(label='Keyboard Shortcuts', command=self.shortcuts_help)
        menubar.add_cascade(label='Help', menu=helps)
        self.root.configure(menu=menubar)
        self.menubar = menubar

        self.tree_menu = tk.Menu(self.root, tearoff=False)
        self.tree_menu.add_command(label='Copy Key Path', command=self.copy_path)
        self.tree_menu.add_command(label='Copy Key Name', command=self.copy_key_name)
        self.tree_menu.add_separator()
        self.tree_menu.add_command(label='Export Key...', command=self.export_dialog)
        self.tree_menu.add_separator()
        self.tree_menu.add_command(label='Add Key to Report', command=lambda: self.report_add(False))
        self.tree_menu.add_command(label='Add Key and Subkeys to Report', command=lambda: self.report_add(True))
        self.value_menu = tk.Menu(self.root, tearoff=False)
        self.value_menu.add_command(label='Copy Value Data', command=self.copy_data)
        self.value_menu.add_command(label='Copy Value Name', command=self.copy_name)
        self.value_menu.add_command(label='Copy Value Bytes as Hex', command=self.copy_hex)
        self.value_menu.add_command(label='Copy Key Path and Value Name', command=self.copy_value_path)
        self.result_menu = tk.Menu(self.root, tearoff=False)
        self.result_menu.add_command(label='Go to Key', command=lambda: self._jump_from(self._menu_view))
        self.result_menu.add_command(label='Copy Key Path', command=lambda: self._copy_row_path(self._menu_view))

    def _shortcuts(self):
        bind = self.root.bind_all
        bind(f'<{_MOD}-o>', lambda _e: self.open_hive_dialog())
        bind(f'<{_MOD}-O>', lambda _e: self.open_image_dialog())     # with Shift
        bind(f'<{_MOD}-e>', lambda _e: self.export_dialog())
        bind(f'<{_MOD}-r>', lambda _e: self.report_add(False))
        bind('<F1>', lambda _e: self.open_manual())
        bind(f'<{_MOD}-f>', lambda _e: self.focus_search())
        bind(f'<{_MOD}-l>', lambda _e: self.focus_address())
        bind(f'<{_MOD}-C>', lambda _e: self.copy_path())             # with Shift
        for number in range(4):
            bind(f'<{_MOD}-Key-{number + 1}>', lambda _e, n=number: self.tabs.select(n))
        bind('<Escape>', lambda _e: self.cancel())
        # Cmd/Ctrl+C copies the value's data from the tree or the table; in an entry it is left
        # to copy the entry's own text.
        for widget in (self.tree, self.table):
            widget.bind(f'<{_MOD}-c>', lambda _e: (self.copy_data(), 'break')[1])
        buttons = ('<Button-2>', '<Control-Button-1>') if _MAC else ('<Button-3>',)
        pairs = ((self.tree, self.tree_menu), (self.table, self.value_menu),
                 (self.results, self.result_menu), (self.timeline_view, self.result_menu))
        for view, menu in pairs:
            for button in buttons:
                view.bind(button, lambda e, v=view, m=menu: self._popup(e, v, m))
            # the right-click menu from the keyboard: Shift+F10, and the Menu key on Windows
            # (keysym App) and Linux (keysym Menu)
            for sequence in ('<Shift-F10>', '<Key-App>', '<Key-Menu>'):
                try:
                    view.bind(sequence, lambda _e, v=view, m=menu: self._popup_here(v, m))
                except tk.TclError:
                    pass  # a keysym this platform's Tk does not know
        self.tree.bind('<Return>', self._toggle)
        self.tree.bind('<Right>', self._expand_key)

    # -- status and background work ---------------------------------------------------------

    def set_status(self, text):
        self.status.configure(text=text)

    def _start_busy(self, text):
        self.busy = True
        self.cancel_flag.clear()
        self.set_status(text)
        self.progress.pack(side='left', padx=6)
        self.progress.start(12)
        self.cancel_button.pack(side='left')
        self.root.configure(cursor='watch')

    def _stop_busy(self, text):
        self.busy = False
        self.progress.stop()
        self.progress.pack_forget()
        self.cancel_button.pack_forget()
        self.root.configure(cursor='')
        self.set_status(text)

    def cancel(self):
        if self.busy:
            self.cancel_flag.set()
            self.set_status('Cancelling...')

    def _run(self, text, work, done):
        """Run work() off the main thread; done(result) runs on it. Tk is touched only by done."""
        if self.busy:
            self.set_status('Busy: wait for the current task, or press Esc to cancel it.')
            return
        self._start_busy(text)

        def runner():
            try:
                result = work()
            except (regfprobe.RegfError, OSError, ValueError) as error:
                result = error
            self.jobs.put((done, result))
        threading.Thread(target=runner, daemon=True).start()

    def _drain(self):
        try:
            while True:
                done, result = self.jobs.get_nowait()
                if isinstance(result, Exception):
                    cancelled = str(result) == 'cancelled'
                    self._stop_busy('Cancelled.' if cancelled else f'Error: {result}')
                    if not cancelled:
                        messagebox.showerror('regfprobe', str(result), parent=self.root)
                else:
                    self._stop_busy('Ready')
                    done(result)
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    # -- opening ----------------------------------------------------------------------------

    def open_hive_dialog(self):
        path = filedialog.askopenfilename(title='Open a registry hive', parent=self.root)
        if path:
            self.open_path(path)

    def open_path(self, path, then_key=None):
        replay = self.replay.get()

        def done(hive):
            self.show_hive(hive)
            if then_key:
                self.address.set(then_key)
                self.go_to_address()
        self._run(f'Opening {os.path.basename(path)}...', lambda: regfprobe.Hive(path, recover=replay), done)

    def open_image_dialog(self):
        image = filedialog.askopenfilename(title='Open a disk image (E01, raw)', parent=self.root)
        if image:
            self.open_image(image)

    def open_image(self, image):
        cancelled = self.cancel_flag.is_set

        def done(found):
            if not found:
                messagebox.showinfo('regfprobe', 'No file named like a hive was found in the image.', parent=self.root)
                return
            choice = self._pick(found)
            if choice:
                volume, path = choice
                replay = self.replay.get()
                self._run(f'Reading {path} from the image...',
                          lambda: regfprobe.read_from_image(image, path, recover=replay, volume=volume,
                                                            cancel=cancelled),
                          self.show_hive)
        self._run(f'Looking for hives in {os.path.basename(image)}...',
                  lambda: regfprobe.hives_in_image(image, cancel=cancelled), done)

    def _pick(self, found):
        dialog = tk.Toplevel(self.root)
        dialog.title('Hives in the image')
        dialog.geometry('820x440')
        ttk.Label(dialog, text='Choose a hive. Its .LOG1 and .LOG2 are read from the same volume.',
                  padding=8).pack(fill='x')
        frame, listing = self._table(dialog, (('volume', 'Volume', 180), ('path', 'Path', 520), ('size', 'Bytes', 90)))
        listing.column('size', anchor='e')
        for volume, path, size in found:
            listing.insert('', 'end', values=(volume, path, size))
        frame.pack(fill='both', expand=True, padx=8)
        chosen = {}

        def take(_event=None):
            selected = listing.selection()
            if selected:
                values = listing.item(selected[0], 'values')
                chosen['pick'] = (values[0], values[1])
            dialog.destroy()
        listing.bind('<Double-1>', take)
        listing.bind('<Return>', take)
        dialog.bind('<Escape>', lambda _e: dialog.destroy())
        buttons = ttk.Frame(dialog, padding=8)
        buttons.pack(fill='x')
        ttk.Button(buttons, text='Cancel', command=dialog.destroy).pack(side='right')
        ttk.Button(buttons, text='Open', command=take, default='active').pack(side='right', padx=6)
        first = listing.get_children()
        if first:
            listing.selection_set(first[0])
            listing.focus(first[0])
        listing.focus_set()
        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)
        return chosen.get('pick')

    def show_hive(self, hive):
        self.hive = hive
        self.keys.clear()
        self.tree.delete(*self.tree.get_children())
        self.results.delete(*self.results.get_children())
        self.timeline_view.delete(*self.timeline_view.get_children())
        self.timeline_rows = []
        self.page_label.configure(text='Every key by last-written time, newest first.')
        item = self._insert('', hive.root())
        self.tree.item(item, open=True)
        self._fill(item)
        self.tree.selection_set(item)
        self.tree.focus(item)
        self._on_select(None)
        self.tree.focus_set()
        self.root.title(f'regfprobe: {hive.path or hive.name}')
        self._banner()

    def _banner(self):
        if self.hive is None:
            return
        level, title, text = self._banner_info(self.hive)
        self._banner_level = level
        self.stripe.configure(background=_STRIPES[level])
        self.banner_title.configure(text=title)
        self.banner.configure(text=text)

    @staticmethod
    def _banner_info(hive):
        """(level, title, text) describing how far to trust a hive, as the banner shows it."""
        h = hive.header
        state = hive.recovery.get('state')
        if hive.faults:
            level, title = 'bad', 'Damaged structures were skipped'
        elif state == 'dirty, not recovered':
            level, title = 'warn', 'Dirty hive read as it is: the transaction logs were not applied'
        elif state == 'recovered':
            level, title = 'info', 'Dirty hive: transaction logs replayed in memory'
        elif state == 'not attempted':
            level, title = 'warn', 'Read without replaying transaction logs'
        else:
            level, title = 'ok', 'Clean hive'
        text = (f'{hive.path or hive.name}\nformat {hive.version}   embedded name "{h["file_name"]}"   '
                f'base block last written {_iso(h["last_written"])} UTC')
        if state != 'clean':
            text += f'\n{regfprobe.summarise_recovery(hive.recovery)}'
        if hive.faults:
            text += '\nSkipped so far: ' + ', '.join(f'{kind} {count}' for kind, count in sorted(hive.faults.items()))
        return level, title, text

    # -- tree -------------------------------------------------------------------------------

    def _insert(self, parent, key):
        label = key.name if key.parent is not None else f'{key.name}  (root)'
        item = self.tree.insert(parent, 'end', text=label)
        self.keys[item] = key
        if key.subkey_count:
            self.tree.insert(item, 'end', text=_PLACEHOLDER)
        return item

    def _fill(self, item):
        children = self.tree.get_children(item)
        if len(children) == 1 and self.tree.item(children[0], 'text') == _PLACEHOLDER:
            self.tree.delete(children[0])
            for sub in self.keys[item].subkeys():
                self._insert(item, sub)
            self._banner()

    def _on_open(self, _event):
        item = self.tree.focus()
        if item:
            self._fill(item)

    def _toggle(self, _event):
        item = self.tree.focus()
        if item:
            self._fill(item)
            self.tree.item(item, open=not self.tree.item(item, 'open'))
        return 'break'

    def _expand_key(self, _event):
        item = self.tree.focus()
        if item:
            self._fill(item)

    def _on_select(self, _event):
        key = self.selected_key()
        if key is None:
            return
        self.address.set(key.path)
        self.info.configure(text=(
            f'{key.path or "(root)"}\n'
            f'Last written {_iso(key.last_written_raw)} UTC   FILETIME {key.last_written_raw}\n'
            f'{key.subkey_count} subkeys, {key.value_count} values   class name "{key.class_name}"   '
            f'cell 0x{key.offset:x}{"   flags " + ", ".join(key.flag_names) if key.flag_names else ""}'))
        self.table.delete(*self.table.get_children())
        self.values.clear()
        self.sorts.pop(self.table, None)
        self._headings(self.table)
        for value in key.values():
            text = value.data_text()
            if len(text) > 300:
                text = text[:297] + '...'
            item = self.table.insert('', 'end', values=(
                value.name or '(default)', value.type_name, value.size, text, '; '.join(value.notes)))
            self.values[item] = value
        self._set_text(self.hex, 'Select a value to see its decoded data and bytes.' if key.values()
                       else 'This key has no values.')
        self._show_security(key)
        self._banner()

    def _on_value(self, _event):
        value = self.selected_value()
        if value is None:
            return
        head = (f'{value.name or "(default)"}   {value.type_name}   {value.size} bytes'
                f'{"   big data" if value.big_data else ""}{"   stored in the value record" if value.resident else ""}'
                f'   cell 0x{value.offset:x}\n')
        data = value.data
        if isinstance(data, list):
            head += ''.join(f'  [{i}] {s}\n' for i, s in enumerate(data))
        elif not isinstance(data, (bytes, bytearray)):
            head += f'  {data}\n'
        if value.notes:
            head += f'  notes: {"; ".join(value.notes)}\n'
        self._set_text(self.hex, head + '\n' + _hexdump(value.raw))

    def _show_security(self, key):
        sk = key.security()
        if sk is None:
            self._set_text(self.security, 'No readable security record.')
            return

        def sid(text):
            name = regfprobe.WELL_KNOWN_SIDS.get(text)
            return f'{text} ({name})' if name else str(text)
        lines = [f'Security record at cell 0x{sk["offset"]:x}, used by {sk["references"]} keys',
                 f'Owner: {sid(sk.get("owner"))}', f'Group: {sid(sk.get("group"))}',
                 f'Control: 0x{sk.get("control", 0):04x}', '']
        for label in ('dacl', 'sacl'):
            aces = sk.get(label)
            if aces is None:
                continue
            lines.append(f'{label.upper()}: {len(aces)} entries')
            for ace in aces:
                if 'sid' in ace:
                    lines.append(f'  {ace["type_name"]:24} flags 0x{ace["flags"]:02x}  '
                                 f'mask 0x{ace["mask"]:08x}  {sid(ace["sid"])}')
                else:
                    lines.append(f'  {ace["type_name"]:24} flags 0x{ace["flags"]:02x}  {ace["raw"].hex()}')
            lines.append('')
        self._set_text(self.security, '\n'.join(lines))

    @staticmethod
    def _set_text(widget, text):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')

    def selected_key(self):
        selected = self.tree.selection()
        return self.keys.get(selected[0]) if selected else None

    def selected_value(self):
        selected = self.table.selection()
        return self.values.get(selected[0]) if selected else None

    # -- navigation -------------------------------------------------------------------------

    def focus_address(self):
        self.address_entry.focus_set()
        self.address_entry.select_range(0, 'end')

    def focus_search(self):
        self.tabs.select(2)
        self.search_entry.focus_set()
        self.search_entry.select_range(0, 'end')

    def go_to_address(self):
        if self.hive is None:
            return
        path = self.address.get().strip().replace('/', '\\').strip('\\')
        root_name = self.hive.root().name
        if path.upper().startswith(root_name.upper() + '\\'):
            path = path[len(root_name) + 1:]
        elif path.upper() == root_name.upper():
            path = ''
        if self.jump_to(path):
            self.tree.focus_set()
        else:
            self.set_status(f'No key at {path}')
            self.root.bell()

    def jump_to(self, path):
        """Select the key at path, expanding the tree down to it. False when it is not there."""
        if self.hive is None:
            return False
        item = next(iter(self.tree.get_children('')), None)
        for part in [p for p in path.split('\\') if p]:
            self._fill(item)
            self.tree.item(item, open=True)
            match = None
            for child in self.tree.get_children(item):
                key = self.keys.get(child)
                if key is not None and key.name.upper() == part.upper():
                    match = child
                    break
            if match is None:
                return False
            item = match
        self.tree.selection_set(item)
        self.tree.focus(item)
        self.tree.see(item)
        self.tabs.select(0)
        return True

    def _jump_from(self, view):
        selected = view.selection() if view is not None else ()
        if selected:
            path = view.item(selected[0], 'values')[1]
            self.jump_to('' if path == '(root)' else path)
            self.tree.focus_set()

    def _popup_here(self, view, menu):
        """The right-click menu at the focused row, for the keyboard."""
        row = view.focus()
        box = view.bbox(row) if row else ''
        x, y = (box[0] + 20, box[1] + box[3]) if box else (20, 20)
        if row:
            view.selection_set(row)
        self._menu_view = view
        try:
            menu.tk_popup(view.winfo_rootx() + x, view.winfo_rooty() + y)
        finally:
            menu.grab_release()
        return 'break'

    def _popup(self, event, view, menu):
        row = view.identify_row(event.y)
        if row:
            view.selection_set(row)
            view.focus(row)
        self._menu_view = view
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return 'break'

    # -- copying ----------------------------------------------------------------------------

    def _copy(self, text, what):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        shown = text if len(text) <= 80 else text[:77] + '...'
        self.set_status(f'Copied {what}: {shown}')

    def copy_path(self):
        key = self.selected_key()
        if key is not None:
            self._copy(key.path, 'key path')

    def copy_value_path(self):
        key, value = self.selected_key(), self.selected_value()
        if key is not None and value is not None:
            self._copy(f'{key.path}\\{value.name or "(default)"}', 'path')

    def copy_key_name(self):
        key = self.selected_key()
        if key is not None:
            self._copy(key.name, 'key name')

    def copy_name(self):
        value = self.selected_value()
        if value is not None:
            self._copy(value.name or '(default)', 'value name')

    def copy_data(self):
        value = self.selected_value()
        if value is None:
            self.set_status('Select a value to copy its data.')
            return
        data = value.data
        if isinstance(data, list):
            text = '\n'.join(data)
        elif isinstance(data, (bytes, bytearray)):
            text = data.hex(' ')
        else:
            text = str(data)
        self._copy(text, 'data')

    def copy_hex(self):
        value = self.selected_value()
        if value is not None:
            self._copy(value.raw.hex(' '), 'bytes')

    def _copy_row_path(self, view):
        selected = view.selection() if view is not None else ()
        if selected:
            self._copy(view.item(selected[0], 'values')[1], 'path')

    # -- sorting ----------------------------------------------------------------------------

    def _headings(self, view):
        column, descending = self.sorts.get(view, (None, False))
        for name in view['columns']:
            label = view.heading(name, 'text').rstrip(' ▲▼')
            if name == column:
                label += ' ▼' if descending else ' ▲'
            view.heading(name, text=label)

    def sort(self, view, column):
        last, descending = self.sorts.get(view, (None, False))
        descending = not descending if last == column else False
        self.sorts[view] = (column, descending)
        self._headings(view)
        if view is self.timeline_view:
            index = 0 if column == 'time' else 1
            self.timeline_rows.sort(key=lambda row: row[index] if index == 0 else row[1].upper(), reverse=descending)
            self.show_page(0)
            return
        numeric = column == 'size'
        rows = [(view.set(item, column), item) for item in view.get_children('')]
        rows.sort(key=lambda r: (int(r[0]) if numeric and r[0].isdigit() else r[0].upper() if not numeric else -1),
                  reverse=descending)
        for position, (_text, item) in enumerate(rows):
            view.move(item, '', position)

    # -- search and timeline ----------------------------------------------------------------

    def search(self):
        text = self.query.get()
        if self.hive is None or not text:
            return
        scope, needle, hive, stop = self.scope.get(), text.casefold(), self.hive, self.cancel_flag

        def work():
            hits = []
            for key in hive.walk():
                if stop.is_set():
                    raise regfprobe.RegfError('cancelled')
                if scope != 'data' and needle in key.name.casefold():
                    hits.append(('key', key.path, ''))
                for value in key.values():
                    if scope != 'data' and needle in value.name.casefold():
                        hits.append(('name', key.path, value.name or '(default)'))
                    elif scope != 'names':
                        data = value.data
                        if isinstance(data, list):
                            data = ' '.join(data)
                        if isinstance(data, (bytes, bytearray)):
                            if text.encode('utf-16-le') in data:
                                hits.append(('data', key.path, value.name or '(default)'))
                        elif needle in str(data).casefold():
                            hits.append(('data', key.path, value.name or '(default)'))
                if len(hits) >= _SEARCH_LIMIT:
                    break
            return hits

        def done(hits):
            self.results.delete(*self.results.get_children())
            for hit in hits:
                self.results.insert('', 'end', values=hit)
            more = f' (stopped at {_SEARCH_LIMIT}; narrow the search)' if len(hits) >= _SEARCH_LIMIT else ''
            self.set_status(f'{len(hits)} matches for "{text}"{more}')
            first = self.results.get_children()
            if first:
                self.results.selection_set(first[0])
                self.results.focus(first[0])
                self.results.focus_set()
            self._banner()
        self._run(f'Searching for "{text}"...', work, done)

    def timeline(self):
        if self.hive is None:
            return
        try:
            low = _filetime(self.date_from.get())
            high = _filetime(self.date_to.get(), end_of_day=True)
        except ValueError as error:
            messagebox.showerror('regfprobe', str(error), parent=self.root)
            return
        hive, stop = self.hive, self.cancel_flag

        def work():
            rows = []
            for key in hive.walk():
                if stop.is_set():
                    raise regfprobe.RegfError('cancelled')
                stamp = key.last_written_raw
                if (low is None or stamp >= low) and (high is None or stamp <= high):
                    rows.append((stamp, key.path))
            rows.sort(reverse=True)
            return rows

        def done(rows):
            self.timeline_rows = rows
            self.sorts[self.timeline_view] = ('time', True)
            self._headings(self.timeline_view)
            self.show_page(0)
        self._run('Building the timeline...', work, done)

    def show_page(self, page):
        rows = self.timeline_rows
        pages = max(1, -(-len(rows) // _PAGE_ROWS))
        page = max(0, min(page, pages - 1))
        self.timeline_page = page
        self.timeline_view.delete(*self.timeline_view.get_children())
        start = page * _PAGE_ROWS
        for stamp, path in rows[start:start + _PAGE_ROWS]:
            self.timeline_view.insert('', 'end', values=(_iso(stamp), path or '(root)'))
        end = min(start + _PAGE_ROWS, len(rows))
        self.page_label.configure(text=(f'{start + 1 if rows else 0} to {end} of {len(rows)} keys, page '
                                        f'{page + 1} of {pages}. Double-click or Return opens a key.'))
        self.prev_button.state(['!disabled'] if page > 0 else ['disabled'])
        self.next_button.state(['!disabled'] if page < pages - 1 else ['disabled'])

    def save_timeline(self):
        if not self.timeline_rows:
            messagebox.showinfo('regfprobe', 'Build the timeline first (Timeline tab).', parent=self.root)
            return
        path = filedialog.asksaveasfilename(title='Save the timeline', defaultextension='.csv',
                                            filetypes=(('CSV', '*.csv'),), parent=self.root)
        if not path:
            return
        with open(path, 'w', encoding='utf-8', newline='') as handle:
            writer = csv.writer(handle)
            writer.writerow(['Last Written (UTC)', 'FILETIME', 'Key Path'])
            for stamp, key_path in self.timeline_rows:
                writer.writerow([_iso(stamp), stamp, key_path or '(root)'])
        self.set_status(f'Saved {len(self.timeline_rows)} rows to {path}')

    # -- export, about, closing -------------------------------------------------------------

    def export_dialog(self):
        key = self.selected_key()
        if key is None:
            return
        path = filedialog.asksaveasfilename(
            title='Export the selected key and everything under it', parent=self.root,
            filetypes=(('JSON', '*.json'), ('CSV', '*.csv'), ('Registry file', '*.reg')),
            defaultextension='.json')
        if not path:
            return
        fmt = os.path.splitext(path)[1].lower().lstrip('.')
        if fmt not in ('json', 'csv', 'reg'):
            fmt = 'json'
        hive = self.hive
        self._run(f'Exporting {key.path or "(root)"}...', lambda: export(hive, key, fmt, path),
                  lambda _r: self.set_status(f'Exported {key.path or "(root)"} to {path}'))

    # -- HTML report -------------------------------------------------------------------------

    def report_add(self, deep):
        key = self.selected_key()
        if key is None:
            return
        hive = self.hive
        self.report_entries = [e for e in self.report_entries
                               if not (e[0] is hive and e[1] == key.path)] + [(hive, key.path, deep)]
        hives = len({id(e[0]) for e in self.report_entries})
        self.set_status(f'Added {key.path or "(root)"}{" and subkeys" if deep else ""} to the report '
                        f'({len(self.report_entries)} selection(s) from {hives} hive(s))')

    def report_manage(self):
        top = tk.Toplevel(self.root)
        top.title('Keys in report')
        top.transient(self.root)
        top.geometry('980x380')
        frame = ttk.Frame(top, padding=8)
        frame.pack(fill='both', expand=True)
        box = tk.Listbox(frame, selectmode='extended', font=self.fixed, activestyle='none')
        box.pack(side='left', fill='both', expand=True)
        bar = ttk.Scrollbar(frame, orient='vertical', command=box.yview)
        bar.pack(side='left', fill='y')
        box.configure(yscrollcommand=bar.set)

        def refill():
            box.delete(0, 'end')
            for hive, path, deep in self.report_entries:
                box.insert('end', f'{_short_hive(hive)}  >  ' + (path or '(root)')
                           + ('   [+ subkeys]' if deep else ''))

        def remove():
            gone = set(box.curselection())
            self.report_entries = [e for i, e in enumerate(self.report_entries) if i not in gone]
            refill()

        def clear():
            self.report_entries = []
            refill()

        def go():
            sel = box.curselection()
            if sel:
                hive, path, _deep = self.report_entries[sel[0]]
                if hive is not self.hive:
                    self.show_hive(hive)
                self.jump_to(path)

        buttons = ttk.Frame(top, padding=(8, 0, 8, 8))
        buttons.pack(fill='x')
        ttk.Button(buttons, text='Go to Key', command=go).pack(side='left')
        ttk.Button(buttons, text='Remove', command=remove).pack(side='left', padx=6)
        ttk.Button(buttons, text='Clear All', command=clear).pack(side='left')
        ttk.Button(buttons, text='Export HTML Report...',
                   command=lambda: (top.destroy(), self.report_dialog())).pack(side='right')
        ttk.Button(buttons, text='Close', command=top.destroy).pack(side='right', padx=6)
        box.bind('<Double-1>', lambda _e: go())
        box.bind('<Delete>', lambda _e: remove())
        refill()

    def profile_save(self):
        if not self.report_entries:
            messagebox.showinfo('regfprobe', 'No keys chosen yet. Add keys to the report first; the profile '
                                'saves that list.', parent=self.root)
            return
        entries, skipped = [], []
        for hive, key_path, deep in self.report_entries:
            pattern = regfprobe_profile.hive_pattern(hive)
            if pattern is None:
                skipped.append(f'{hive.path or hive.name}: {key_path}')
            elif (pattern, key_path, deep) not in entries:
                entries.append((pattern, key_path, deep))
        if not entries:
            messagebox.showwarning('regfprobe', 'None of these hives can be named inside a disk image.',
                                   parent=self.root)
            return
        path = filedialog.asksaveasfilename(title='Save key profile', parent=self.root, defaultextension='.json',
                                            filetypes=(('regfprobe key profile', '*.json'),))
        if not path:
            return
        regfprobe_profile.save(path, entries)
        users = any('/*/' in e[0] for e in entries)
        message = (f'Saved {len(entries)} key selection(s) to {os.path.basename(path)}.'
                   + ('\n\nUser hives are saved as Users/*/..., so loading pulls them for every user.'
                      if users else ''))
        if skipped:
            message += '\n\nLeft out (hive path unknown):\n' + '\n'.join(skipped[:10])
        messagebox.showinfo('regfprobe', message, parent=self.root)

    def profile_load(self):
        profile = filedialog.askopenfilename(title='Choose a key profile', parent=self.root,
                                             filetypes=(('regfprobe key profile', '*.json'), ('All files', '*')))
        if not profile:
            return
        try:
            entries = regfprobe_profile.load(profile)
        except (OSError, ValueError, KeyError, TypeError) as error:
            messagebox.showerror('regfprobe', f'Could not read the profile: {error}', parent=self.root)
            return
        image = filedialog.askopenfilename(title='Choose the disk image (E01, raw) to pull the keys from',
                                           parent=self.root)
        if not image:
            return
        replay, cancelled = self.replay.get(), self.cancel_flag.is_set

        def done(result):
            found, missing = result
            added = 0
            for hive, keys in found:
                for key_path, deep in keys:
                    self.report_entries = [e for e in self.report_entries
                                           if not (e[0] is hive and e[1] == key_path)] + [(hive, key_path, deep)]
                    added += 1
            if found:
                self.show_hive(found[0][0])
            self.set_status(f'Profile {os.path.basename(profile)}: added {added} key selection(s) from '
                            f'{len(found)} hive(s) in {os.path.basename(image)}')
            message = f'Added {added} key selection(s) from {len(found)} hive(s).'
            if missing:
                message += f'\n\nNot found in this image ({len(missing)}):\n' + '\n'.join(missing[:25])
                if len(missing) > 25:
                    message += f'\n... and {len(missing) - 25} more'
            (messagebox.showwarning if missing else messagebox.showinfo)('regfprobe', message, parent=self.root)
            if added:
                self.report_manage()

        self._run(f'Pulling {len(entries)} key selection(s) from {os.path.basename(image)}...',
                  lambda: regfprobe_profile.pull(image, entries, recover=replay, cancel=cancelled), done)

    def _report_options(self):
        """Ask which optional columns go in the report; None when cancelled. Choices are remembered."""
        top = tk.Toplevel(self.root)
        top.title('HTML report columns')
        top.transient(self.root)
        top.resizable(False, False)
        frame = ttk.Frame(top, padding=14)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Always included: Name, Type, Size and Interpreted (readable) data.').pack(anchor='w')
        show_data = tk.BooleanVar(value=self.settings.get('report_show_data', True))
        show_raw = tk.BooleanVar(value=self.settings.get('report_show_raw', True))
        ttk.Checkbutton(frame, text='Include regfprobe data column (as regfprobe decodes it; hex for binary values)',
                        variable=show_data).pack(anchor='w', pady=(10, 2))
        ttk.Checkbutton(frame, text='Include raw bytes (hex) column (exactly as stored)',
                        variable=show_raw).pack(anchor='w')
        result = []

        def ok():
            result.append((show_data.get(), show_raw.get()))
            top.destroy()

        buttons = ttk.Frame(frame)
        buttons.pack(fill='x', pady=(14, 0))
        ttk.Button(buttons, text='Cancel', command=top.destroy).pack(side='right')
        ttk.Button(buttons, text='Continue...', command=ok).pack(side='right', padx=6)
        top.bind('<Return>', lambda _e: ok())
        top.bind('<Escape>', lambda _e: top.destroy())
        top.grab_set()
        self.root.wait_window(top)
        if not result:
            return None
        self.settings['report_show_data'], self.settings['report_show_raw'] = result[0]
        return result[0]

    def report_dialog(self):
        if not self.report_entries:
            messagebox.showinfo('regfprobe', 'No keys chosen yet. Select a key, then use Report > Add '
                                'Selected Key (or right-click it in the tree).', parent=self.root)
            return
        options = self._report_options()
        if options is None:
            return
        path = filedialog.asksaveasfilename(title='Save the HTML report', parent=self.root,
                                            defaultextension='.html', filetypes=(('HTML', '*.html'),))
        if not path:
            return
        groups = []   # one per hive, in the order hives were first added
        for hive, key_path, deep in self.report_entries:
            for group in groups:
                if group[0] is hive:
                    group[2].append((key_path, deep))
                    break
            else:
                groups.append((hive, self._banner_info(hive), [(key_path, deep)]))
        names = [os.path.basename(regfprobe_report.hive_label(g[0])) for g in groups]
        title = 'Registry report: ' + ', '.join(names)

        def work():
            with open(path, 'w', encoding='utf-8') as stream:
                return regfprobe_report.write_multi_report(groups, stream, title=title,
                                                           show_data=options[0], show_raw=options[1])

        self._run('Writing HTML report...', work,
                  lambda n: self.set_status(f'Wrote {n} key(s) to {path}'))

    def toggle_dark(self):
        self.set_dark(self.dark_var.get())
        self.settings['dark'] = self.dark_var.get()

    def set_dark(self, dark):
        self.theme.apply(dark)
        self._base_styles()   # banner fonts and row height belong to the theme just switched to

    def about(self):
        messagebox.showinfo('About regfprobe', (
            f'regfprobe {regfprobe.__version__}\n\nReads Windows registry hives offline and read-only.\n'
            'Python standard library only. MIT licence.\n\nhttps://github.com/abrignoni/regfprobe'),
            parent=self.root)

    @staticmethod
    def _docs(name):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'docs', name)

    def open_manual(self):
        """Open docs/manual.html in the default browser."""
        import pathlib  # pylint: disable=import-outside-toplevel
        import webbrowser  # pylint: disable=import-outside-toplevel
        path = self._docs('manual.html')
        if not os.path.exists(path):
            messagebox.showerror('regfprobe', f'The manual was not found at {path}. Keep the docs folder '
                                 'beside regfprobe_gui.py.', parent=self.root)
            return
        webbrowser.open(pathlib.Path(path).as_uri())
        self.set_status('Opened the manual in your browser.')

    def save_manual_pdf(self):
        """Copy docs/manual.pdf to a place the user chooses."""
        import shutil  # pylint: disable=import-outside-toplevel
        source = self._docs('manual.pdf')
        if not os.path.exists(source):
            messagebox.showerror('regfprobe', 'manual.pdf was not found in the docs folder. Open the manual '
                                 '(Help > User Manual) and use its Save as PDF button instead.', parent=self.root)
            return
        target = filedialog.asksaveasfilename(title='Save the regfprobe manual as PDF', parent=self.root,
                                              initialfile='regfprobe manual.pdf', defaultextension='.pdf',
                                              filetypes=(('PDF', '*.pdf'),))
        if not target:
            return
        try:
            shutil.copyfile(source, target)
        except OSError as error:
            messagebox.showerror('regfprobe', f'Could not save the PDF: {error}', parent=self.root)
            return
        self.set_status(f'Saved the manual to {target}')

    def shortcuts_help(self):
        m = _MOD_LABEL
        messagebox.showinfo('Keyboard shortcuts', '\n'.join((
            f'{m}+O  open a hive file', f'{m}+Shift+O  open a hive inside a disk image',
            f'{m}+L  go to a key by path', f'{m}+F  find', f'{m}+C  copy the selected value\'s data',
            f'{m}+Shift+C  copy the key path', f'{m}+E  export the selected key',
            f'{m}+1 to {m}+4  Values, Security, Search, Timeline', 'F1  open the user manual',
            'Esc  cancel a running task',
            'Arrows move in the tree; Return opens or closes a key; Tab moves between panes.')),
            parent=self.root)

    def close(self):
        try:
            self.settings['geometry'] = self.root.geometry()
            self.settings['sash'] = self.panes.sashpos(0)
            _save_settings(self.settings)
        except tk.TclError:
            pass
        self.root.destroy()


def export(hive, key, fmt, path):
    """Write key and its subtree with regfprobe.export_key, the code the command line runs."""
    with open(path, 'w', encoding='utf-8', newline='') as stream:
        regfprobe.export_key(hive, key, fmt, stream)
    return path


def selfcheck(hive_path):
    """Build the window, load the hive, and exercise what can be checked without showing it.

    It never runs Tk's event loop (no update(), no mainloop): python.org 3.14 on macOS ships
    Tk 9.0.3, which aborts the process in Tk_MacOSXGetTkWindow from the idle loop on a window
    that was never shown. Pending timers are cancelled before the root is destroyed. Settings
    are neither read nor written, and copies are caught here, never put on the clipboard.
    """
    root = tk.Tk()
    root.withdraw()
    window = Window(root, settings={})
    copies = []
    window._copy = lambda text, _what: copies.append(text)  # pylint: disable=protected-access
    report = {'window': 'built', 'menus': window.menubar.index('end') + 1}
    if hive_path:
        window.show_hive(regfprobe.Hive(hive_path))
        first = window.tree.get_children('')[0]
        children = window.tree.get_children(first)
        report['root_subkeys_shown'] = len(children)
        for child in children:
            if window.keys[child].value_count:
                path = window.keys[child].path
                report['go_to_key'] = window.jump_to(path)
                window._on_select(None)  # pylint: disable=protected-access
                report['values_shown'] = len(window.table.get_children())
                rows = window.table.get_children()
                if rows:
                    window.table.selection_set(rows[0])
                    window.copy_data()
                    report['copied'] = bool(copies)
                window.sort(window.table, 'name')
                break
        report['missing_key_found'] = window.jump_to('no such key at all')
        window.timeline_rows = sorted(((k.last_written_raw, k.path) for k in window.hive.walk()), reverse=True)
        window.show_page(0)
        report['timeline_rows'] = len(window.timeline_view.get_children())
    for pending in root.tk.splitlist(root.tk.call('after', 'info')):
        root.after_cancel(pending)
    root.destroy()
    print(json.dumps(report))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog='regfprobe_gui')
    parser.add_argument('hive', nargs='?')
    parser.add_argument('--image', help='pick a hive from inside this disk image')
    parser.add_argument('--key', help='open at this key (path below the root)')
    parser.add_argument('--selfcheck', action='store_true', help='build the window and exit')
    args = parser.parse_args(argv)
    if args.selfcheck:
        return selfcheck(args.hive)
    _dpi_aware()
    root = tk.Tk()
    window = Window(root, settings=_load_settings())
    if args.hive:
        root.after(200, lambda: window.open_path(args.hive, then_key=args.key))
    elif args.image:
        root.after(200, lambda: window.open_image(args.image))
    root.mainloop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
