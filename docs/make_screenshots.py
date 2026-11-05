"""Take the manual's screenshots of the regfprobe window, using docs/demo/SAM (made-up data).

Windows only (PIL ImageGrab). Run docs/make_demo_hive.py first. The window is driven by code;
leave the mouse and keyboard alone while it runs (about half a minute).

    python docs/make_screenshots.py
"""

import io
import os
import subprocess
import sys
import tkinter as tk

from PIL import ImageGrab

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import regfprobe  # noqa: E402  pylint: disable=wrong-import-position
import regfprobe_gui as gui  # noqa: E402  pylint: disable=wrong-import-position
import regfprobe_report  # noqa: E402  pylint: disable=wrong-import-position

IMG = os.path.join(HERE, 'img')
B = '\\'
USER = B.join(['SAM', 'Domains', 'Account', 'Users', '000003E9'])
EDGE = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'


def settle(widget, ms=400):
    widget.update()
    widget.after(ms)
    widget.update()


def grab(widget, name, pad=0, extra=None):
    settle(widget)
    x, y = widget.winfo_rootx() - pad, widget.winfo_rooty() - pad
    w, h = widget.winfo_width() + 2 * pad, widget.winfo_height() + 2 * pad
    if extra:
        x0, y0, x1, y1 = extra
        box = (min(x, x0), min(y, y0), max(x + w, x1), max(y + h, y1))
    else:
        box = (x, y, x + w, y + h)
    ImageGrab.grab(box, all_screens=True).save(os.path.join(IMG, name))
    print('saved', name)


def select_value(window, name):
    for item in window.table.get_children():
        if window.values[item].name == name:
            window.table.selection_set(item)
            window.table.see(item)
            window._on_value(None)  # pylint: disable=protected-access
            return


def main():  # pylint: disable=too-many-statements
    os.makedirs(IMG, exist_ok=True)
    gui._dpi_aware()  # pylint: disable=protected-access
    root = tk.Tk()
    root.geometry('1440x800+40+40')
    root.attributes('-topmost', True)
    window = gui.Window(root, settings={})
    window.set_dark(True)   # every screenshot is taken in dark mode
    hive = regfprobe.Hive(os.path.join(HERE, 'demo', 'SAM'))
    hive.path = r'E:\Cases\DEMO-001.E01::p3_lba239616_basic_data_partition/Windows/System32/config/SAM'
    window.show_hive(hive)
    window.jump_to(USER)
    window.panes.sashpos(0, 400)
    settle(root, 600)
    select_value(window, 'F')
    grab(root, 'main-window.png')

    # build a report list that spans two hives
    window.report_add(False)
    window.jump_to(B.join(['SAM', 'Domains', 'Account', 'Users', 'Names']))
    window.report_add(True)
    window.jump_to(B.join(['SAM', 'Domains', 'Builtin', 'Aliases', '00000220']))
    window.report_add(False)
    second = regfprobe.Hive(os.path.join(HERE, 'demo', 'SAM'))
    second.path = r'E:\Cases\DEMO-002.E01::p2_lba206848/Windows/System32/config/SAM'
    window.show_hive(second)
    window.jump_to(B.join(['SAM', 'Domains', 'Account', 'Users', '000003EA']))
    window.report_add(False)
    window.show_hive(hive)
    window.jump_to(USER)
    settle(root)
    window.report_manage()
    tops = [w for w in root.winfo_children() if isinstance(w, tk.Toplevel)]
    grab(tops[-1], 'keys-in-report.png')
    tops[-1].destroy()

    # the column choice dialog is modal: grab it from a timer, then cancel it
    def shoot_options():
        top = [w for w in root.winfo_children() if isinstance(w, tk.Toplevel)][-1]
        grab(top, 'report-columns.png')
        top.destroy()
    root.after(900, shoot_options)
    window._report_options()  # pylint: disable=protected-access

    # the hive picker (also modal)
    found = [('p1_lba2048_efi_system_partition', 'EFI/Microsoft/Boot/BCD', 49152),
             ('p3_lba239616_basic_data_partition', 'Windows/System32/config/SAM', 65536),
             ('p3_lba239616_basic_data_partition', 'Windows/System32/config/SECURITY', 32768),
             ('p3_lba239616_basic_data_partition', 'Windows/System32/config/SOFTWARE', 81002496),
             ('p3_lba239616_basic_data_partition', 'Windows/System32/config/SYSTEM', 16515072),
             ('p3_lba239616_basic_data_partition', 'Users/jdoe/NTUSER.DAT', 1835008),
             ('p3_lba239616_basic_data_partition',
              'Users/jdoe/AppData/Local/Microsoft/Windows/UsrClass.dat', 1310720)]

    def shoot_picker():
        top = [w for w in root.winfo_children() if isinstance(w, tk.Toplevel)][-1]
        grab(top, 'hive-picker.png')
        top.destroy()
    root.after(900, shoot_picker)
    window._pick(found)  # pylint: disable=protected-access

    # timeline tab
    window.tabs.select(3)
    window.timeline_rows = sorted(((k.last_written_raw, k.path) for k in hive.walk()), reverse=True)
    window.show_page(0)
    grab(root, 'timeline.png')

    # search tab
    window.tabs.select(2)
    try:
        window.search_entry.delete(0, 'end')
        window.search_entry.insert(0, 'jdoe')
        window.search()
        for _ in range(20):
            settle(root, 150)
    except AttributeError:
        pass
    grab(root, 'search.png')
    window.tabs.select(0)

    # the HTML report, rendered by Edge
    groups = [(hive, window._banner_info(hive), [(USER, False),  # pylint: disable=protected-access
                                                 (B.join(['SAM', 'Domains', 'Builtin', 'Aliases', '00000220']), False)])]
    html_path = os.path.join(HERE, 'demo', 'demo-report.html')
    stream = io.StringIO()
    regfprobe_report.write_multi_report(groups, stream, title='Registry report: SAM', show_data=False, show_raw=False)
    with open(html_path, 'w', encoding='utf-8') as handle:
        handle.write(stream.getvalue())
    if os.path.exists(EDGE):
        subprocess.run([EDGE, '--headless=new', '--disable-gpu', '--force-dark-mode', '--hide-scrollbars', '--force-device-scale-factor=1',
                        f'--screenshot={os.path.join(IMG, "html-report.png")}', '--window-size=1200,1250',
                        'file:///' + html_path.replace(os.sep, '/')], check=False, timeout=90,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print('saved html-report.png')
    for pending in root.tk.splitlist(root.tk.call('after', 'info')):
        root.after_cancel(pending)
    root.destroy()


if __name__ == '__main__':
    main()
