#!/usr/bin/env python3
"""regfprobe GUI: a read-only tkinter window over regfprobe.py.

Standard library only, like the reader it drives. Everything it shows comes from the same
library calls the command line makes, so anything seen here can be reproduced there.

    python3 regfprobe_gui.py                      open the window
    python3 regfprobe_gui.py HIVE                 open it with this hive loaded
    python3 regfprobe_gui.py --image IMAGE        open it and pick a hive inside the image
    python3 regfprobe_gui.py --selfcheck [HIVE]   build the window, load the hive, exit (no window shown)

The hive is read into memory and never written. There are no edit controls.

Author: @AlexisBrignoni, Claude. MIT licence.
"""

import argparse
import json
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import regfprobe  # noqa: E402  pylint: disable=wrong-import-position

_PLACEHOLDER = '\x00loading'


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


class Window:
    """The main window: key tree, values, hex, key info, security, search and timeline."""

    def __init__(self, root):
        self.root = root
        self.hive = None
        self.keys = {}          # tree item id -> regfprobe.Key
        self.items = {}         # key cell offset -> tree item id
        self.values = {}        # values table item id -> regfprobe.Value
        self.jobs = queue.Queue()
        root.title('regfprobe')
        root.geometry('1200x760')
        self._build()
        root.after(100, self._drain)

    # -- layout -----------------------------------------------------------------------------

    def _build(self):
        bar = ttk.Frame(self.root, padding=(6, 4))
        bar.pack(fill='x')
        ttk.Button(bar, text='Open hive...', command=self.open_hive_dialog).pack(side='left')
        ttk.Button(bar, text='Open from image...', command=self.open_image_dialog).pack(side='left', padx=4)
        ttk.Button(bar, text='Export key...', command=self.export_dialog).pack(side='left', padx=4)
        ttk.Button(bar, text='Copy path', command=self.copy_path).pack(side='left')
        self.replay = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text='Replay transaction logs', variable=self.replay).pack(side='left', padx=12)

        self.banner = ttk.Label(self.root, text='No hive open.', padding=(8, 4), anchor='w',
                                relief='groove', wraplength=1150, justify='left')
        self.banner.pack(fill='x', padx=6)

        panes = ttk.PanedWindow(self.root, orient='horizontal')
        panes.pack(fill='both', expand=True, padx=6, pady=6)

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
        self.root.after(50, lambda: panes.sashpos(0, 340))
        self.info = ttk.Label(right, text='', padding=(4, 2), anchor='w', justify='left')
        self.info.pack(fill='x')
        self.tabs = ttk.Notebook(right)
        self.tabs.pack(fill='both', expand=True)

        # values tab
        values_tab = ttk.Frame(self.tabs)
        self.tabs.add(values_tab, text='Values')
        split = ttk.PanedWindow(values_tab, orient='vertical')
        split.pack(fill='both', expand=True)
        table = ttk.Frame(split)
        self.table = ttk.Treeview(table, columns=('name', 'type', 'size', 'data', 'notes'),
                                  show='headings', selectmode='browse')
        for column, label, width in (('name', 'Name', 200), ('type', 'Type', 150),
                                     ('size', 'Size', 70), ('data', 'Data', 420),
                                     ('notes', 'Notes', 200)):
            self.table.heading(column, text=label)
            self.table.column(column, width=width, stretch=column in ('data', 'notes'))
        tscroll = ttk.Scrollbar(table, orient='vertical', command=self.table.yview)
        self.table.configure(yscrollcommand=tscroll.set)
        self.table.pack(side='left', fill='both', expand=True)
        tscroll.pack(side='right', fill='y')
        self.table.bind('<<TreeviewSelect>>', self._on_value)
        split.add(table, weight=3)
        self.hex = tk.Text(split, height=10, font=('Courier', 11), wrap='none', state='disabled')
        split.add(self.hex, weight=2)

        # security tab
        self.security = tk.Text(self.tabs, font=('Courier', 11), wrap='none', state='disabled')
        self.tabs.add(self.security, text='Security')

        # search tab
        search_tab = ttk.Frame(self.tabs, padding=4)
        self.tabs.add(search_tab, text='Search')
        row = ttk.Frame(search_tab)
        row.pack(fill='x')
        self.query = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self.query, width=40)
        entry.pack(side='left')
        entry.bind('<Return>', lambda _e: self.search())
        self.scope = tk.StringVar(value='names and data')
        ttk.Combobox(row, textvariable=self.scope, state='readonly', width=16,
                     values=('names and data', 'names', 'data')).pack(side='left', padx=4)
        ttk.Button(row, text='Search', command=self.search).pack(side='left')
        self.search_status = ttk.Label(row, text='')
        self.search_status.pack(side='left', padx=8)
        self.results = ttk.Treeview(search_tab, columns=('kind', 'path', 'value'), show='headings')
        for column, label, width in (('kind', 'Match', 80), ('path', 'Key path', 600), ('value', 'Value', 200)):
            self.results.heading(column, text=label)
            self.results.column(column, width=width, stretch=column == 'path')
        self.results.pack(fill='both', expand=True, pady=(4, 0))
        self.results.bind('<Double-1>', self._jump_from_results)

        # timeline tab
        timeline_tab = ttk.Frame(self.tabs, padding=4)
        self.tabs.add(timeline_tab, text='Timeline')
        top = ttk.Frame(timeline_tab)
        top.pack(fill='x')
        ttk.Button(top, text='Build timeline', command=self.timeline).pack(side='left')
        self.timeline_status = ttk.Label(top, text='Every key by last-written time, newest first.')
        self.timeline_status.pack(side='left', padx=8)
        self.timeline_view = ttk.Treeview(timeline_tab, columns=('time', 'path'), show='headings')
        self.timeline_view.heading('time', text='Last written (UTC)')
        self.timeline_view.heading('path', text='Key path')
        self.timeline_view.column('time', width=210, stretch=False)
        self.timeline_view.column('path', width=700)
        self.timeline_view.pack(fill='both', expand=True, pady=(4, 0))
        self.timeline_view.bind('<Double-1>', self._jump_from_timeline)

    # -- opening ----------------------------------------------------------------------------

    def open_hive_dialog(self):
        path = filedialog.askopenfilename(title='Open a registry hive')
        if path:
            self.load(lambda: regfprobe.Hive(path, recover=self.replay.get()))

    def open_image_dialog(self):
        image = filedialog.askopenfilename(title='Open a disk image (E01, raw)')
        if not image:
            return
        self.banner.configure(text=f'Listing hives in {image} ...')
        self.root.update_idletasks()
        try:
            found = regfprobe.hives_in_image(image)
        except (regfprobe.RegfError, OSError) as error:
            messagebox.showerror('regfprobe', str(error))
            return
        if not found:
            messagebox.showinfo('regfprobe', 'No file named like a hive was found in the image.')
            return
        choice = self._pick(found)
        if choice:
            self.load(lambda: regfprobe.read_from_image(image, choice, recover=self.replay.get()))

    def _pick(self, found):
        dialog = tk.Toplevel(self.root)
        dialog.title('Hives in the image')
        dialog.geometry('760x420')
        listing = ttk.Treeview(dialog, columns=('volume', 'path', 'size'), show='headings')
        for column, label, width in (('volume', 'Volume', 160), ('path', 'Path', 480), ('size', 'Bytes', 90)):
            listing.heading(column, text=label)
            listing.column(column, width=width)
        for volume, path, size in found:
            listing.insert('', 'end', values=(volume, path, size))
        listing.pack(fill='both', expand=True)
        chosen = {}

        def take(_event=None):
            selected = listing.selection()
            if selected:
                chosen['path'] = listing.item(selected[0], 'values')[1]
            dialog.destroy()
        listing.bind('<Double-1>', take)
        ttk.Button(dialog, text='Open', command=take).pack(pady=4)
        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)
        return chosen.get('path')

    def load(self, opener):
        try:
            hive = opener()
        except (regfprobe.RegfError, OSError) as error:
            messagebox.showerror('regfprobe', str(error))
            return
        self.show_hive(hive)

    def show_hive(self, hive):
        self.hive = hive
        self.keys.clear()
        self.items.clear()
        self.tree.delete(*self.tree.get_children())
        self.results.delete(*self.results.get_children())
        self.timeline_view.delete(*self.timeline_view.get_children())
        root = hive.root()
        item = self._insert('', root)
        self.tree.item(item, open=True)
        self._fill(item)
        self.tree.selection_set(item)
        self.root.title(f'regfprobe - {hive.path or hive.name}')
        self._banner()

    def _banner(self):
        hive = self.hive
        h = hive.header
        text = (f'{hive.path or hive.name}   format {hive.version}   embedded name "{h["file_name"]}"   '
                f'last written {_iso(h["last_written"])} UTC\n'
                f'{regfprobe.summarise_recovery(hive.recovery)}')
        if hive.faults:
            text += '\nDamaged structures skipped: ' + ', '.join(
                f'{kind} {count}' for kind, count in sorted(hive.faults.items()))
        self.banner.configure(text=text)

    # -- tree -------------------------------------------------------------------------------

    def _insert(self, parent, key):
        label = key.name if key.parent is not None else f'{key.name}  (root)'
        item = self.tree.insert(parent, 'end', text=label)
        self.keys[item] = key
        self.items[key.offset] = item
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

    def _on_select(self, _event):
        selected = self.tree.selection()
        if not selected:
            return
        key = self.keys.get(selected[0])
        if key is None:
            return
        self.info.configure(text=(
            f'{key.path or "(root)"}\nLast written {_iso(key.last_written_raw)} UTC   '
            f'FILETIME {key.last_written_raw}   class name "{key.class_name}"   '
            f'cell 0x{key.offset:x}   {key.subkey_count} subkeys, {key.value_count} values'
            f'{"   flags " + ", ".join(key.flag_names) if key.flag_names else ""}'))
        self.table.delete(*self.table.get_children())
        self.values.clear()
        for value in key.values():
            text = value.data_text()
            if len(text) > 300:
                text = text[:297] + '...'
            item = self.table.insert('', 'end', values=(
                value.name or '(default)', value.type_name, value.size, text, '; '.join(value.notes)))
            self.values[item] = value
        self._set_text(self.hex, '')
        self._show_security(key)
        self._banner()

    def _on_value(self, _event):
        selected = self.table.selection()
        if selected and selected[0] in self.values:
            value = self.values[selected[0]]
            head = (f'{value.name or "(default)"}   {value.type_name}   {value.size} bytes'
                    f'{"   big data" if value.big_data else ""}{"   resident" if value.resident else ""}'
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

    def copy_path(self):
        key = self.selected_key()
        if key is None:
            return
        path = key.path
        selected = self.table.selection()
        if selected and selected[0] in self.values:
            path += f'\\{self.values[selected[0]].name or "(default)"}'
        self.root.clipboard_clear()
        self.root.clipboard_append(path)

    def jump_to(self, path):
        """Select the key at path, expanding the tree down to it."""
        if self.hive is None:
            return
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
                break
            item = match
        self.tree.selection_set(item)
        self.tree.see(item)
        self.tabs.select(0)

    # -- background work --------------------------------------------------------------------

    def _run(self, work, done):
        def runner():
            try:
                result = work()
            except (regfprobe.RegfError, OSError) as error:
                result = error
            self.jobs.put((done, result))
        threading.Thread(target=runner, daemon=True).start()

    def _drain(self):
        try:
            while True:
                done, result = self.jobs.get_nowait()
                done(result)
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def search(self):
        text = self.query.get()
        if self.hive is None or not text:
            return
        scope = self.scope.get()
        needle = text.casefold()
        hive = self.hive
        self.search_status.configure(text='Searching...')
        self.results.delete(*self.results.get_children())

        def work():
            hits = []
            for key in hive.walk():
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
                if len(hits) >= 5000:
                    break
            return hits

        def done(hits):
            if isinstance(hits, Exception):
                self.search_status.configure(text=str(hits))
                return
            for hit in hits:
                self.results.insert('', 'end', values=hit)
            more = ' (stopped at 5000)' if len(hits) >= 5000 else ''
            self.search_status.configure(text=f'{len(hits)} matches{more}')
            self._banner()
        self._run(work, done)

    def timeline(self):
        if self.hive is None:
            return
        hive = self.hive
        self.timeline_status.configure(text='Building...')

        def work():
            return sorted(((k.last_written_raw, k.path) for k in hive.walk()), reverse=True)

        def done(rows):
            if isinstance(rows, Exception):
                self.timeline_status.configure(text=str(rows))
                return
            self.timeline_view.delete(*self.timeline_view.get_children())
            for stamp, path in rows:
                self.timeline_view.insert('', 'end', values=(_iso(stamp), path or '(root)'))
            self.timeline_status.configure(text=f'{len(rows)} keys, newest first. Double-click to open.')
        self._run(work, done)

    def _jump_from_results(self, _event):
        selected = self.results.selection()
        if selected:
            self.jump_to(self.results.item(selected[0], 'values')[1])

    def _jump_from_timeline(self, _event):
        selected = self.timeline_view.selection()
        if selected:
            path = self.timeline_view.item(selected[0], 'values')[1]
            self.jump_to('' if path == '(root)' else path)

    # -- export -----------------------------------------------------------------------------

    def export_dialog(self):
        key = self.selected_key()
        if key is None:
            return
        path = filedialog.asksaveasfilename(
            title='Export the selected key and everything under it',
            filetypes=(('JSON', '*.json'), ('CSV', '*.csv'), ('Registry file', '*.reg')),
            defaultextension='.json')
        if not path:
            return
        fmt = os.path.splitext(path)[1].lower().lstrip('.')
        if fmt not in ('json', 'csv', 'reg'):
            fmt = 'json'
        export(self.hive, key, fmt, path)
        self.banner.configure(text=self.banner.cget('text') + f'\nExported {key.path or "(root)"} to {path}')


def export(hive, key, fmt, path):
    """Write key and its subtree with regfprobe.export_key, the code the command line runs."""
    with open(path, 'w', encoding='utf-8', newline='') as stream:
        regfprobe.export_key(hive, key, fmt, stream)


def selfcheck(hive_path):
    """Build the window, load the hive, show the first root subkey that has values, then exit.

    It never runs Tk's event loop (no update(), no mainloop): python.org 3.14 on macOS ships
    Tk 9.0.3, which aborts the process in Tk_MacOSXGetTkWindow from the idle loop on a window
    that was never shown. Pending timers are cancelled before the root is destroyed.
    """
    root = tk.Tk()
    root.withdraw()
    window = Window(root)
    report = {'window': 'built'}
    if hive_path:
        window.show_hive(regfprobe.Hive(hive_path))
        first = window.tree.get_children('')[0]
        window._fill(first)  # pylint: disable=protected-access
        children = window.tree.get_children(first)
        report['root_subkeys_shown'] = len(children)
        for child in children:
            if window.keys[child].value_count:
                window.tree.selection_set(child)
                window._on_select(None)  # pylint: disable=protected-access
                report['values_shown'] = len(window.table.get_children())
                break
    for pending in root.tk.splitlist(root.tk.call('after', 'info')):
        root.after_cancel(pending)
    root.destroy()
    print(json.dumps(report))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog='regfprobe_gui')
    parser.add_argument('hive', nargs='?')
    parser.add_argument('--image', help='pick a hive from inside this disk image')
    parser.add_argument('--selfcheck', action='store_true', help='build the window and exit')
    args = parser.parse_args(argv)
    if args.selfcheck:
        return selfcheck(args.hive)
    root = tk.Tk()
    window = Window(root)
    if args.hive:
        window.load(lambda: regfprobe.Hive(args.hive))
    elif args.image:
        found = regfprobe.hives_in_image(args.image)
        choice = window._pick(found) if found else None  # pylint: disable=protected-access
        if choice:
            window.load(lambda: regfprobe.read_from_image(args.image, choice))
    root.mainloop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
