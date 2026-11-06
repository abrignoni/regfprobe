"""Key profiles: a saved list of (hive, key, subkeys) that can be pulled again from any disk image.

A profile names hives by their path inside the image, not by case: Windows/System32/config/SAM,
or Users/*/NTUSER.DAT, where * stands for one folder name, so a user hive matches every user.
Loading walks the image once, reads each matching hive with its .LOG1/.LOG2, and reports
what the profile asked for that the image does not have.
"""

import json
import os
import re

import regfprobe

FORMAT = 1

_BY_NAME = {   # where a hive opened as a loose file is usually found inside an image
    'SAM': 'Windows/System32/config/SAM', 'SYSTEM': 'Windows/System32/config/SYSTEM',
    'SOFTWARE': 'Windows/System32/config/SOFTWARE', 'SECURITY': 'Windows/System32/config/SECURITY',
    'DEFAULT': 'Windows/System32/config/DEFAULT', 'NTUSER.DAT': 'Users/*/NTUSER.DAT',
    'USRCLASS.DAT': 'Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat',
    'AMCACHE.HVE': 'Windows/appcompat/Programs/Amcache.hve',
}


def hive_pattern(hive):
    """The profile name for a hive: its path inside the image, with the user folder made '*'.

    None when it cannot be told (a loose file under a name that is not a usual hive name).
    """
    source = str(hive.path or hive.name).replace('\\', '/')
    if '::' in source:
        inside = source.split('::', 1)[1]
        inside = inside.split('/', 1)[1] if '/' in inside else inside   # drop the volume label
    else:
        inside = _BY_NAME.get(os.path.basename(source).upper())
        if inside is None:
            return None
    parts = inside.strip('/').split('/')
    if len(parts) > 2 and parts[0].lower() == 'users':
        parts[1] = '*'
    return '/'.join(parts)


def _regex(pattern):
    body = '/'.join('[^/]+' if part == '*' else re.escape(part.upper())
                    for part in pattern.strip('/').split('/'))
    return re.compile(body + r'(\.LOG1|\.LOG2)?')


_SAM_USERS = ('SAM', 'DOMAINS', 'ACCOUNT', 'USERS')


def general_key(pattern, key_path, hive=None):
    r"""A key path with its account-specific part made '*', so a profile fits any machine.

    SAM\Domains\Account\Users\<RID> and ...\Users\Names\<name> name one account; they become
    Users\* and Users\Names\* (every account). In SYSTEM, ControlSet001 (or 002...) becomes
    CurrentControlSet only when hive is given and its Select\Current names that same set, so a
    control set picked on purpose (not the current one) is kept as picked. Other keys are kept.
    """
    if pattern.upper().endswith('/SYSTEM'):
        first, _sep, rest = key_path.partition('\\')
        if re.fullmatch(r'ControlSet\d{3}', first, re.IGNORECASE) and hive is not None \
                and first.upper() == (current_control_set(hive) or '').upper():
            return 'CurrentControlSet' + ('\\' + rest if rest else '')
        return key_path
    if not pattern.upper().endswith('/SAM'):
        return key_path
    parts = key_path.split('\\')
    upper = [x.upper() for x in parts]
    if len(parts) >= 5 and tuple(upper[:4]) == _SAM_USERS:
        if upper[4] == 'NAMES':
            if len(parts) >= 6:
                parts[5] = '*'
        elif upper[4] != '*':
            parts[4] = '*'
    return '\\'.join(parts)


def profile_entries(report_entries):
    """[(hive, key path, include subkeys)] from the report -> (entries, skipped) for save().

    entries are (hive pattern, general key path, include subkeys), each once; skipped lists the
    selections whose hive cannot be named inside a disk image.
    """
    entries, skipped = [], []
    for hive, key_path, deep in report_entries:
        pattern = hive_pattern(hive)
        if pattern is None:
            skipped.append(f'{hive.path or hive.name}: {key_path}')
            continue
        item = (pattern, general_key(pattern, key_path, hive), bool(deep))
        if item not in entries:
            entries.append(item)
    return entries, skipped


def current_control_set(hive):
    r"""'ControlSet00N' that SYSTEM's Select\Current names, or None when the hive has none."""
    try:
        number = hive.open_key('Select').value('Current').data
    except (regfprobe.RegfError, AttributeError):
        return None
    return f'ControlSet{int(number):03d}' if isinstance(number, int) else None


def expand(hive, key_path):
    r"""Every key path in hive that key_path names; '*' stands for any one subkey.

    Under SAM\Domains\Account\Users, '*' leaves out the Names folder (it is not an account).
    A leading CurrentControlSet is the control set Select\Current names in that hive.
    """
    parts = [x for x in key_path.split('\\') if x] if key_path else []
    if parts and parts[0].upper() == 'CURRENTCONTROLSET':
        resolved = current_control_set(hive)
        if resolved is None:
            return []
        parts[0] = resolved
    current = [hive.root()]
    for depth, part in enumerate(parts):
        nxt = []
        for key in current:
            if part == '*':
                for sub in key.subkeys():
                    if depth == 4 and tuple(x.upper() for x in parts[:4]) == _SAM_USERS \
                            and sub.name.upper() == 'NAMES':
                        continue
                    nxt.append(sub)
            else:
                try:
                    nxt.append(key.subkey(part))
                except regfprobe.KeyNotFound:
                    pass
        current = nxt
    return [key.path for key in current]


def save(path, entries, name=''):
    """entries: [(hive pattern, key path, include subkeys)], written as given (see profile_entries)."""
    data = {'regfprobe_profile': FORMAT, 'name': name or os.path.splitext(os.path.basename(path))[0],
            'entries': [{'hive': h, 'key': k, 'subkeys': bool(d)} for h, k, d in entries]}
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.write('\n')


def load(path):
    """[(hive pattern, key path, include subkeys)] from a profile file, as written there.

    Keys are not rewritten on load, so a profile can name one control set or one account.
    """
    with open(path, encoding='utf-8') as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or data.get('regfprobe_profile') != FORMAT:
        raise ValueError(f'{os.path.basename(path)} is not a regfprobe key profile')
    out = []
    for e in data.get('entries', []):
        item = (e['hive'], e.get('key', ''), bool(e.get('subkeys')))
        if item not in out:
            out.append(item)
    return out


def pull(image, entries, recover=True, password=None, cancel=None):
    """Read every hive the profile names from the image and check its keys.

    Returns (found, missing, resolved): found is [(hive, [(key path, subkeys, origin)])] in profile
    order (origin is '' when the key is the profile's own path, else the profile entry it came from),
    one item per hive file (so one per user for a Users/* pattern); missing is [str] describing
    what the profile asked for and the image does not have; resolved is [str] naming the control
    set CurrentControlSet stood for in each hive, as Select\\Current gives it.
    """
    patterns = []
    for pattern, _key, _deep in entries:
        if pattern not in patterns:
            patterns.append(pattern)
    regexes = [(p, _regex(p)) for p in patterns]
    files = {}   # (volume, directory, upper base name) -> (path, bytes)
    order = []   # (pattern, volume, path) of each hive file, in walk order

    def wanted(path):
        upper = path.replace('\\', '/').strip('/').upper()
        return any(rx.fullmatch(upper) for _p, rx in regexes)

    for label, path, walker, node, size in regfprobe._walk_image(image, wanted, password, cancel):  # pylint: disable=protected-access
        clean = path.replace('\\', '/').strip('/')
        folder, base = clean.rsplit('/', 1) if '/' in clean else ('', clean)
        files[(label, folder.upper(), base.upper())] = (clean, regfprobe._read_node(walker, node, size))  # pylint: disable=protected-access
        if not base.upper().endswith(('.LOG1', '.LOG2')):
            for pattern, rx in regexes:
                if rx.fullmatch(clean.upper()):
                    order.append((pattern, label, clean))
                    break

    found, missing, resolved = [], [], []
    by_pattern = {}
    for pattern, label, clean in order:
        folder, base = clean.rsplit('/', 1) if '/' in clean else ('', clean)
        _p, data = files[(label, folder.upper(), base.upper())]
        logs = []
        for suffix in ('.LOG1', '.LOG2'):
            log = files.get((label, folder.upper(), base.upper() + suffix))
            if log:
                logs.append((log[0].rsplit('/', 1)[-1], log[1]))
        try:
            hive = regfprobe.Hive(data, logs=logs, recover=recover, name=base)
        except regfprobe.RegfError as error:
            missing.append(f'{label}/{clean}: not readable as a hive ({error})')
            continue
        hive.path = f'{image}::{label}/{clean}'
        by_pattern.setdefault(pattern, []).append(hive)

    for pattern in patterns:
        hives = by_pattern.get(pattern, [])
        if not hives:
            missing.append(f'{pattern}: no such hive in the image')
            continue
        for hive in hives:
            keys = []
            for p, key_path, deep in entries:
                if p != pattern:
                    continue
                current = None
                if key_path.upper().split('\\', 1)[0] == 'CURRENTCONTROLSET':
                    current = current_control_set(hive)
                    note = (f'{hive.path.split("::")[-1]}: CurrentControlSet is {current}, from Select\\Current'
                            if current else f'{hive.path.split("::")[-1]}: no Select\\Current, so CurrentControlSet '
                            'names no control set')
                    if note not in resolved:
                        resolved.append(note)
                try:
                    paths = expand(hive, key_path)
                except regfprobe.RegfError:
                    paths = []
                if not paths:
                    missing.append(f'{hive.path.split("::")[-1]}: no key {key_path or "(root)"}')
                    continue
                for path in paths:
                    if any(k[0] == path and k[1] == deep for k in keys):
                        continue
                    origin = ''
                    if path.upper() != key_path.upper():
                        origin = f'profile entry {key_path}' + (
                            f'; CurrentControlSet is {current}, from Select\\Current' if current else '')
                    keys.append((path, deep, origin))
            if keys:
                found.append((hive, keys))
    return found, missing, resolved
