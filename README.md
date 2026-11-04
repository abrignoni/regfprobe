# regfprobe

Read Windows registry hive files offline: list keys, read values, search, build a timeline of
key last-written times, and export to JSON, CSV or a `.reg` file. When a hive is dirty, its
`.LOG1` and `.LOG2` transaction logs are replayed in memory first. It never writes to the hive
or its logs.

One file, `regfprobe.py`, Python 3.10 or later, standard library only. Nothing to install, no admin rights,
no mounting. It is meant to be copied into other tools as it is (vendored), the way qnxprobe and
ewfprobe are copied into the LEAPPs. A second, optional file, `regfprobe_gui.py`, puts a
read-only window over it. That one is standard library too.

The name comes from `regf`, the four bytes every hive file starts with.

## Quick start

    python3 regfprobe.py info SYSTEM
    python3 regfprobe.py ls SYSTEM Select
    python3 regfprobe.py cat SOFTWARE "Microsoft\Windows NT\CurrentVersion" ProductName
    python3 regfprobe.py find NTUSER.DAT "teamviewer"
    python3 regfprobe.py timeline SOFTWARE --out software_timeline.csv
    python3 regfprobe.py export SYSTEM ControlSet001\Services --format csv --out services.csv
    python3 regfprobe.py logs SYSTEM
    python3 regfprobe_gui.py SYSTEM

Key paths are given below the root key, with `\` or `/`, and names compare without case, the
way Windows compares them.

## Reading straight from a disk image

Put `qnxprobe.py` (and `ewfprobe.py` for E01) beside `regfprobe.py`, or anywhere Python can
import them, and a hive can be read without extracting anything first:

    python3 regfprobe.py hives --image case.E01
    python3 regfprobe.py info --image case.E01 --path Windows/System32/config/SYSTEM
    python3 regfprobe.py ls --image case.E01 --path Windows/System32/config/SYSTEM Select
    python3 regfprobe.py hives --image case.E01 --extract staged/

With `--image`, every command takes the same words as with a hive file, minus the file.
`hives` lists the files named like a hive (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT,
UsrClass.dat, Amcache.hve, settings.dat and the like). It goes by name, so a hive saved under
another name is not listed. `--path` reads that hive and the `.LOG1` and `.LOG2` beside it in
the same volume; when more than one volume holds a file at that path, name one with `--volume`. `--extract` copies the hives and their logs out, keeping their paths. The image is
only read.

## The window

    python3 regfprobe_gui.py
    python3 regfprobe_gui.py SOFTWARE --key "Microsoft\Windows NT\CurrentVersion"
    python3 regfprobe_gui.py --image case.E01

`regfprobe_gui.py` shows:

- a key bar at the top with the selected key's path; type or paste a path and press Return to go
  there (with or without the root key's name)
- a banner with a coloured stripe and a title saying how much to trust what follows: a clean
  hive, a dirty hive whose logs were replayed, a dirty hive read as it is (and why), or damaged
  structures that were skipped
- a key tree on the left, loaded as you open it
- the selected key's last-written time (UTC and the FILETIME), counts, class name, cell offset
  and flags
- its values: name, type, size, decoded data and any decoding notes, sortable by any column
- the decoded data and raw bytes of the selected value
- a Security tab with the key's owner, group and access entries
- a Search tab over key names, value names and data
- a Timeline tab with every key by last-written time, limited to a date range if you give one,
  shown 1000 rows at a time, and saved to CSV whole
- a status bar with a progress bar and a Cancel button while a hive is opened, an image is
  searched for hives, or a search or timeline runs; the window stays usable meanwhile

It has the usual menus (File, Edit, View, Help) and right-click menus on the tree, the values
and the result lists. Copy covers the key path, the value name, the value data and its bytes
as hex. The main actions have shortcuts, and the right-click menus also open from the keyboard:

| Keys (Ctrl on Windows and Linux, Cmd on macOS) | Does |
| --- | --- |
| Ctrl+O, Ctrl+Shift+O | open a hive file, or a hive inside a disk image |
| Ctrl+L | go to a key by path |
| Ctrl+F | find |
| Ctrl+C, Ctrl+Shift+C | copy the selected value's data, or the key path |
| Ctrl+E | export the selected key and everything under it (JSON, CSV, `.reg`) |
| Ctrl+1 to Ctrl+4 | Values, Security, Search, Timeline |
| Return | open or close a key in the tree; go to the key of a search or timeline row |
| Shift+F10, or the Menu key on Windows and Linux | the right-click menu of the selected row |
| Esc | cancel what is running |

There are no edit controls. Everything it shows comes from the same calls the command line
makes. The one file it writes on its own is its window size and position, in
`~/Library/Application Support/regfprobe/` (macOS), `%APPDATA%\regfprobe\` (Windows) or
`~/.config/regfprobe/` (Linux). On Windows it asks Windows to draw it at the screen's own
resolution instead of scaling it up.

What was checked, on 2026-11-04: `tools/gui_keyboard_check.py` sends Tk key events through the
window's own bindings (moving in the tree, the key bar, a bad path, copying, sorting, find,
the tab shortcuts, the timeline, Tab, Esc) and checks 22 results. The shortcuts that open a file
dialog, and Shift+F10, are checked only for being bound, since what they open waits for a person. All passed on macOS 27 with Python 3.12 (Tk
8.6) and on Windows 11 ARM64 with Python 3.11 (Tk 8.6), where the window was also captured on
the desktop. CI runs it on the Windows jobs.

The window does not work with a screen reader. Its accessibility tree was read with the
platform's own interface (no screen reader was run): on macOS 27 with Python 3.12 (Tk 8.6) it
held only the window's title and its three title-bar buttons, though the menu bar is the native
one and its items were listed. On Windows 11 ARM64 with Python 3.11 (Tk 8.6), UI Automation
showed 25 panes with no names and no menu. Tk 9.1 adds screen reader support to its widgets
(TIP 733); no Python available here ships it, so it is untested. With a screen reader, use the
command line, which prints the same keys and values as text.

On macOS, use a Python whose Tk is 8.6. The python.org installer for 3.14 ships Tk 9.0.3, and
on this Mac the window's `--selfcheck` (which builds the window without showing it) aborted
Python there. The test suite and `gui_keyboard_check.py` skip or refuse on that combination.

## Using it from code

```python
import regfprobe

hive = regfprobe.Hive('SYSTEM')            # logs beside it are found and replayed
print(hive.version, hive.recovery['state'])
key = hive.open_key('ControlSet001\\Services\\Tcpip\\Parameters')
print(key.last_written)                    # aware UTC datetime; key.last_written_raw is the FILETIME
for value in key.values():
    print(value.name or '(default)', value.type_name, value.data, value.notes)
    value.raw                              # the data bytes exactly as stored
print(hive.faults)                         # damaged structures skipped, by kind
```

`Hive` takes a path, bytes, or any file object with `read()`. `Value.data` is decoded by type:
`str` for REG_SZ, REG_EXPAND_SZ and REG_LINK, a list for REG_MULTI_SZ, `int` for the DWORD and
QWORD types, and `bytes` for everything else and for any value whose bytes do not fit its type.
`Value.raw` is always the stored bytes. `Value.notes` says what did not fit (no terminating NUL,
bytes after the NUL, an odd length, a DWORD that is not four bytes, a data cell shorter than the
size the value records). A note never stops a value from being read.

A cell that cannot be read loses that one key, value or list. It is counted in `hive.faults`
and described in `hive.fault_log`, and the rest of the hive reads normally.

### Code written for python-registry

`regfprobe.CompatRegistry` answers the calls that code written against python-registry 1.3.1
makes (`open`, `root`, `subkeys`, `subkey`, `values`, `value`, `name`, `path`, `timestamp`,
`value_type`, `raw_data` and its two not-found exceptions), with the same return shapes: naive
UTC datetimes rounded the same way, `(default)` for the default value's name, paths that begin
with the root key's name, and REG_MULTI_SZ lists that keep their trailing empty strings. It
carries python-registry's names for the REG_* numbers (`CompatRegistry.RegSZ`, `RegBin`,
`RegDWord` and the rest), and `CompatRegistry.RegistryException`, the base of every error
regfprobe raises, for a file that is not a hive. A REG_DWORD or REG_QWORD stored with fewer
bytes than it needs comes back as the number those bytes make, zero-padded, so arithmetic on it
still works (`Value.data` keeps the bytes and a note). When a value's data cell cannot be read,
`value()` and `raw_data()` raise `RegistryException`, as python-registry raises, so a caller's
error handling sees the damaged value; the native `Value` reads on with empty bytes, a note and
`Value.unreadable` set. Where the two libraries return different data for the same bytes, see the
next section.

`Hive(..., on_fault=callback)` calls `callback(kind, offset, reason)` the first time each
damaged structure is skipped, so a caller can log it when it happens.

## How it was checked

Measured on 2026-11-04.

**Against Windows itself.** `tools/known-data/make_known_hive.ps1` builds a key on Windows 11
build 26200 (ARM64) through the Win32 API, with UTF-16 and Latin-1 names, a key with 2000
subkeys, a class name, every REG_* type, three type numbers outside them, odd-length and
unterminated strings, and binary values from 0 to 100,000 bytes. It saves the key with
`reg save` (hive format 1.3) and with `RegSaveKeyEx` in the latest format (1.5, where four of
the values are stored as big data), and has Windows list every key and value through
`RegEnumKeyEx` and `RegEnumValue`. `tools/known-data/compare_known.py` matched regfprobe to
that list on both hives: all 2015 keys and 37 values, with the same last-written FILETIMEs to
the 100 ns, class names, counts, type numbers and data bytes. With one planted byte change it
reported exactly that one value. Corpus key: `windows11_arm_regfprobe_known_20261104`.

**Against python-registry, on real hives.** `tools/compare_python_registry.py` read 921 hives
with both libraries, out of ten Windows images in the corpus: CFReDS Data Leakage (Windows 7),
CFReDS Hacking Case (Windows XP), PC-MUS-001 (Windows 11), AF-Case2 and LoneWolf (Windows 10),
the Szechuan Sauce desktop and domain controller, the OU Server 2022 image and Ali Hadi's
Challenge 3 (Windows 8.1) and ThreatSim server (corpus keys `cfreds_leakage_win7`,
`cfreds_hacking_case_winxp`, `pc_mus_001_win11`, `af_case2_win10`, `lonewolf_win10`,
`szechuan_win10`, `szechuan_dc01_server2012r2`, `ou_ransomware_server2022`,
`alihadi_challenge3_win81`, `alihadi_threatsim_server2019`). That is 4,135,804 keys and
8,452,433 values. Both found the same keys, with the same last-written times. They found the
same values in every hive but one: in the BBI hive of the Szechuan desktop, which is dirty, two
value lists point at cells that only its logs hold. Read without the logs, python-registry
drops both lists, and regfprobe reads 12 of their 16 values (one of them without its data) and
counts the 4 values and the 1 data cell it cannot read as damaged. With the logs replayed,
regfprobe reads all 16 with their data. Matched by key path and value name,
never by position.

**Against RECmd.** `tools/compare_recmd.py` compared regfprobe with Eric Zimmerman's RECmd
2026.10.3 (`--kn ROOT --recover false --json`) on 60 of those hives: SYSTEM, SAM, SECURITY, one
user's NTUSER.DAT and UsrClass.dat, and Amcache.hve from each image, and the Windows 7 and XP
SOFTWARE hives. 789,559 keys and 2,058,352 values: the same keys, the same last-write times to
the 100 ns, the same values and the same bytes for every one of them. On the format 1.5
known-data hive it agreed on all 2015 keys and 37 values too. RECmd reports a type number with bits above the low
12 as the low type (15,684 values on these hives), the way python-registry does. In Amcache.hve
RECmd's `--kn ROOT` dumps the subkey named Root, so for those eight hives that subtree is what
was compared.

**Against regipy.** `tools/compare_regipy.py` compared regipy 6.5.0 on 186 of the 187 hives from
the first three images (it ran out of memory on the PC-MUS-001 SYSTEM hive) and on both
known-data hives. 957,873 keys: the same keys with the same last-written times, except where a key or value
name holds a byte above 0x7F. regipy decodes those bytes as U+FFFD, where Windows' own listing
of the known data and regfprobe give the character. regipy keeps the bytes after a string's
terminating NUL (85 values), and 70 more values decode differently in ways not examined one by
one. regipy trims values to 256 characters by default; the comparison turns that off.

**Log replay.** The replay code is copied from DLEAPP's `scripts/registry_recovery.py` (DLEAPP
commit dc77aab), which DLEAPP still uses for now. On the 61 dirty hives among those 921,
regfprobe and DLEAPP produced byte-identical hives and the same summary: 53 replayed and 8 read
as they are. One of the 8, the PC-MUS-001 SYSTEM hive, was refused because its logs would have
given 3 keys an earlier last-written time than the hive holds. DLEAPP's 23 tests of the replay
itself run here with only their imports changed; its tests of `open_hive`, which belongs to
DLEAPP, stayed there.

**Unit tests.** `tests/hivebuilder.py` builds hives in memory the way the specification lays
them out, and python-registry reading them is the check that they are hives. The tests cover
every index kind, both name encodings, big data, data stored in the value record itself,
security records, damaged cells, a subkey list that loops back up the tree, the command line
and the window.

## Where it differs from python-registry 1.3.1

Each of these was seen on the corpus hives and again on the Windows-made known data. The counts
are from the first 187 hives (the Windows 7, XP and PC-MUS-001 images).

| What | python-registry | regfprobe |
| --- | --- | --- |
| Data of four bytes or fewer, kept in the value record itself | bytes other than the stored ones for 33,716 values: 29,654 REG_SZ, 637 REG_EXPAND_SZ, 435 REG_MULTI_SZ, 39 REG_DWORD, 1 REG_DWORD_BIG_ENDIAN and 2,950 of other type numbers. Its code returns four bytes for a REG_SZ whatever the stored size, and none for a REG_MULTI_SZ | the stored number of bytes |
| A REG_DWORD whose data is in a cell of its own | reads the record's offset field as the data, so the DWORD is the cell's offset (1 value, an 8-byte DWORD on PC-MUS-001) | reads the cell |
| Type numbers with bits above the low 12 | masks them off, so 0x20004 is reported as 4 (19,146 values: 16,396 with a high word of 0xFFFF, 1,547 numbered 100,000,000 and up, 1,203 others) | the type number as stored |

regfprobe does not decode the `settings.dat` composite types. A tool that needs them decodes
`Value.raw` itself.

## What it does not do

- Deleted keys and values in unallocated cells are not recovered.
- Windows 9x (`CREG`) and Windows 3.1 (`SHCC`) registry files are not read.
- A lone `.LOG` file (the Windows XP log) is not read; only `.LOG1` and `.LOG2` are replayed.
- Transactional registry files (`.blf`, `.regtrans-ms`) are not read.
- `--image` reads disk images (E01, raw, and what qnxprobe opens). Logical evidence such as an
  FTK AD1 holds copies of files, not a disk: export the hive with ewfprobe and open the file.
- Layered keys (Windows containers) are read as ordinary keys; the tombstone flag is exposed as
  `Value.tombstone` and not interpreted.
- Nothing is ever written: no edits, no saving a replayed hive back over the original.

## Vendoring

Copy `regfprobe.py` verbatim (and `regfprobe_gui.py` if you want the window), keep `LICENSE`
beside it as `LICENSE-regfprobe`, and record the commit and SHA-256 you copied. Fix problems
here and copy again, so the copies do not drift.

## Sources

- Maxim Suhanov, "Windows registry file format specification",
  [commit 88e878d](https://github.com/msuhanov/regf/blob/88e878de51bae393143b0ac8daae6c2dfc256bf7/Windows%20registry%20file%20format%20specification.md):
  the base block, hive bins, cells, key nodes, values, big data, index lists, security records
  and both transaction log formats.
- Microsoft [MS-DTYP] sections 2.4.2 (SID), 2.4.4 (ACE), 2.4.5 (ACL) and 2.4.6 (security
  descriptor), and the REG_* type numbers of `winnt.h`.
- Marvin32 follows Microsoft's SymCrypt, `lib/marvin32.c` at commit 286762b, and reproduces its
  known answer.

No code was taken from another registry reader.

## Licence

MIT. See `LICENSE`.

Author: Alexis Brignoni (@AlexisBrignoni), with Claude.
