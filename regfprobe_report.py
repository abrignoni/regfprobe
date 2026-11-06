"""Write chosen registry keys from a regfprobe Hive as one self-contained HTML report.

Uses the same Value fields regfprobe's JSON/CSV export uses,
so decoded data, raw bytes and notes match what the tool shows.
"""

import html
from datetime import datetime, timezone

import regfprobe
import regfprobe_interpret

_CSS = """
:root{--bg:#fff;--fg:#1d1d1f;--muted:#5f6368;--line:#d9dce1;--head:#f3f4f6;--accent:#1f6feb;
--ok:#2e7d32;--warn:#b26a00;--bad:#c62828;--info:#1565c0}
@media (prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#e8eaed;--muted:#9aa0a6;--line:#30343a;
--head:#1f2228;--accent:#58a6ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0;word-break:break-all}
.meta{color:var(--muted);margin:0 0 16px}
.banner{border-left:5px solid var(--ok);background:var(--head);padding:10px 14px;margin:0 0 20px;
white-space:pre-wrap;font-size:13px}
.banner b{display:block;font-size:15px;margin-bottom:4px}
.banner.warn{border-color:var(--warn)}.banner.bad{border-color:var(--bad)}.banner.info{border-color:var(--info)}
nav{margin:0 0 24px}nav h3{font-size:14px;margin:14px 0 4px}nav .count{color:var(--muted);font-weight:400}
.hive{margin:0 0 32px}.hivehead{font-size:18px;margin:28px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--line)}
nav ol{margin:6px 0 0;padding-left:22px}nav .origin{color:var(--muted);font-size:12.5px}nav a{color:var(--accent);word-break:break-all}
section{border:1px solid var(--line);border-radius:6px;margin:0 0 18px;overflow:hidden}
section header{background:var(--head);padding:10px 14px;border-bottom:1px solid var(--line)}
section header p{margin:4px 0 0;color:var(--muted);font-size:12.5px}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;vertical-align:top;padding:6px 10px;border-bottom:1px solid var(--line)}
th{font-weight:600;color:var(--muted);white-space:nowrap}tr:last-child td{border-bottom:0}
td.interp{min-width:260px;white-space:pre-wrap}td.interp b{font-weight:600}td.interp img{max-width:128px;display:block;margin-top:4px;border:1px solid var(--line)}.none{color:var(--muted)}
td.data{white-space:pre-wrap;word-break:break-all;max-width:320px;font-size:12px;color:var(--muted)}
td.hex{font-family:Consolas,"Cascadia Mono",monospace;font-size:12px;word-break:break-all;max-width:360px;
color:var(--muted)}
.empty{padding:10px 14px;color:var(--muted);font-style:italic}
.note{color:var(--warn)}
footer{color:var(--muted);font-size:12px;margin-top:28px}
@media print{section{break-inside:avoid}nav{display:none}}
"""

_HEX_LIMIT = 4096  # bytes of raw data shown per value; longer values are cut with a note


def _e(text):
    return html.escape('' if text is None else str(text))


def _interp(key, value, show_data=True):
    try:
        pairs = regfprobe_interpret.interpret(key, value)
    except Exception as error:  # pylint: disable=broad-except
        return f'<span class="note">could not interpret: {_e(error)}</span>'
    out = []
    for label, text in pairs:
        if label == '__image__':
            out.append(f'<img src="{text}" alt="picture stored in the value">')
        else:
            out.append(f'<div><b>{_e(label)}:</b> {_e(text)}</div>')
    binary = value.type_name in ('REG_BINARY', 'REG_NONE') or value.type_name.startswith('unknown')
    if not out and value.raw and (not binary or not show_data):
        # no known layout: regfprobe's own decoding, so nothing is lost when its column is hidden
        out.append(_e(value.data_text()))
    return ''.join(out) or '<span class="none">-</span>'


def _value_rows(key, show_data=True, show_raw=True):
    rows = []
    for v in key.values():
        raw = v.raw
        hexed = raw[:_HEX_LIMIT].hex(' ')
        if len(raw) > _HEX_LIMIT:
            hexed += f' ... ({len(raw) - _HEX_LIMIT} more bytes not shown)'
        notes = '; '.join(v.notes)
        rows.append(
            f'<tr><td>{_e(v.name or "(default)")}</td><td>{_e(v.type_name)}</td><td>{v.size}</td>'
            f'<td class="interp">{_interp(key, v, show_data)}'
            + (f'<div class="note">{_e(notes)}</div>' if notes and not show_data else '') + '</td>'
            + (f'<td class="data">{_e(v.data_text())}'
               + (f'<div class="note">{_e(notes)}</div>' if notes else '') + '</td>' if show_data else '')
            + (f'<td class="hex">{_e(hexed)}</td>' if show_raw else '') + '</tr>')
    return rows


def _key_section(key, anchor, show_data=True, show_raw=True):
    path = key.path or '(root)'
    rows = _value_rows(key, show_data, show_raw)
    head = (f'<header><h2>{_e(path)}</h2><p>Last written {_e(regfprobe._iso(key.last_written_raw).rstrip("Z"))} UTC'  # pylint: disable=protected-access
            f' &middot; FILETIME {key.last_written_raw} &middot; {len(rows)} value(s)'
            f' &middot; cell 0x{key.offset:x}'
            + (f' &middot; class name "{_e(key.class_name)}"' if key.class_name else '')
            + '</p></header>')
    if rows:
        body = ('<div class="wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Size</th>'
                '<th>Interpreted</th>' + ('<th>regfprobe data</th>' if show_data else '')
                + ('<th>Raw bytes (hex)</th>' if show_raw else '') + '</tr></thead><tbody>'
                + ''.join(rows) + '</tbody></table></div>')
    else:
        body = '<div class="empty">No values.</div>'
    return f'<section id="{anchor}">{head}{body}</section>'


def hive_label(hive):
    """Where a hive came from, short: the part after '::' for a hive read from a disk image."""
    return str(hive.path or hive.name).split('::')[-1]


def _keys(hive, entries):
    keys, seen = [], set()
    for path, deep, *_origin in entries:
        start = hive.open_key(path)
        for key in (hive.walk(start) if deep else [start]):
            if key.offset not in seen:
                seen.add(key.offset)
                keys.append(key)
    return keys


def write_report(hive, entries, stream, title='regfprobe report', banner=('ok', '', ''), examiner='',
                 show_data=True, show_raw=True):
    """entries: list of (key path, include_subkeys). banner: (level, title, text) as the GUI shows it."""
    return write_multi_report([(hive, banner, entries)], stream, title=title, examiner=examiner,
                              show_data=show_data, show_raw=show_raw)


def write_multi_report(groups, stream, title='regfprobe report', examiner='', show_data=True, show_raw=True):
    """groups: list of (hive, banner, entries), one per hive, in the order they should appear.

    entries are (key path, include subkeys) or (key path, include subkeys, origin); origin, when
    not empty, is shown beside the selection (a key pulled through a key profile names the
    profile entry it came from).

    With one hive the page looks as it did before; with several, each hive gets its own heading,
    trust banner and contents list.
    """
    built = [(hive, banner, entries, _keys(hive, entries)) for hive, banner, entries in groups]
    total = sum(len(g[3]) for g in built)
    many = len(built) > 1
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    nav, body = [], []
    for g, (hive, (level, banner_title, banner_text), entries, keys) in enumerate(built):
        label = hive_label(hive)
        toc = ''.join(f'<li><a href="#h{g}k{i}">{_e(k.path or "(root)")}</a></li>' for i, k in enumerate(keys))
        chosen = ''.join(f'<li>{_e(p or "(root)")}{" and subkeys" if d else ""}'
                         + (f' <span class="origin">({_e(o[0])})</span>' if o and o[0] else '') + '</li>'
                         for p, d, *o in entries)
        nav.append((f'<h3><a href="#h{g}">{_e(label)}</a> <span class="count">{len(keys)} key(s)</span></h3>'
                    if many else '')
                   + f'<strong>Selected</strong><ul>{chosen}</ul><strong>Keys in this report</strong><ol>{toc}</ol>')
        body.append(f'<div class="hive" id="h{g}">'
                    + (f'<h2 class="hivehead">Hive: {_e(label)}</h2>' if many else '')
                    + f'<div class="banner {_e(level)}"><b>{_e(banner_title)}</b>{_e(banner_text)}</div>'
                    + ''.join(_key_section(k, f'h{g}k{i}', show_data, show_raw) for i, k in enumerate(keys))
                    + '</div>')
    stream.write(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{_e(title)}</title><style>{_CSS}</style></head><body><main>'
        f'<h1>{_e(title)}</h1>'
        f'<p class="meta">Generated {now} UTC by regfprobe {_e(regfprobe.__version__)}'
        + (f' &middot; Examiner: {_e(examiner)}' if examiner else '')
        + (f' &middot; {len(built)} hives' if many else '')
        + f' &middot; {total} key(s)</p>'
        + f'<nav>{"".join(nav)}</nav>' + ''.join(body)
        + '<footer>Key times are last-written times from the hive, in UTC. Interpreted fields come only '
        'from SAM layouts with a published source (listed in regfprobe_interpret.py) and from pictures '
        'whose file header checks out; every other value is shown as regfprobe decodes it. Raw bytes '
        'are shown as stored.</footer></main></body></html>\n')
    return total
