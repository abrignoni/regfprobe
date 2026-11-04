"""Check a frozen regfprobe build against the source it was frozen from.

    python tools/smoke_binary.py --cli dist/regfprobe [--gui PATH] [--version 0.2.0]

The CLI binary must print the expected version, give the same output as `python regfprobe.py`
for info, ls and export on a hive written by tests/hivebuilder.py, and open a disk image
(so qnxprobe and ewfprobe were bundled). The window binary must pass --selfcheck on that
hive. A windowed Windows build has no stdout, so only its exit code is checked there.
Run it from the repository root; on Linux, run it under a virtual display.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, 'tests'))
import hivebuilder  # noqa: E402  pylint: disable=wrong-import-position,import-error

FAILED = []


def check(ok, what):
    print(('ok    ' if ok else 'FAIL  ') + what)
    if not ok:
        FAILED.append(what)


def run(cmd):
    done = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL, check=False,
                          env=dict(os.environ, PYTHONIOENCODING='utf-8'))
    return done.returncode, done.stdout.decode('utf-8', 'replace'), done.stderr.decode('utf-8', 'replace')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cli', required=True)
    parser.add_argument('--gui')
    parser.add_argument('--version')
    args = parser.parse_args()
    source = [sys.executable, os.path.join(HERE, 'regfprobe.py')]
    binary = [os.path.abspath(args.cli)]
    with tempfile.TemporaryDirectory() as folder:
        hive = os.path.join(folder, 'SAMPLE')
        with open(hive, 'wb') as handle:
            handle.write(hivebuilder.build(hivebuilder.sample_tree()))
        image = os.path.join(folder, 'zero.img')
        with open(image, 'wb') as handle:
            handle.write(b'\x00' * 4096)

        code, out, err = run(binary + ['--version'])
        expected = run(source + ['--version'])[1].strip()
        check(code == 0 and out.strip() == expected, f'--version prints {expected!r} (got {out.strip()!r}{err.strip()})')
        if args.version:
            check(out.strip() == f'regfprobe {args.version}', f'version is {args.version}')

        for sub in (['info', hive], ['ls', hive], ['export', hive, '--format', 'json'],
                    ['export', hive, '--format', 'reg']):
            want, got = run(source + sub), run(binary + sub)
            check(want[0] == 0 and got == want, f'{sub[0]} {" ".join(sub[2:])} matches the source'
                  f'{"" if got == want else f" (exit {got[0]} vs {want[0]}; {got[2].strip()[:200]})"}')

        code, out, err = run(binary + ['hives', '--image', image])
        check(code == 0 and 'needs qnxprobe' not in out + err,
              f'opens a disk image (exit {code}{"; " + err.strip()[:200] if err.strip() else ""})')

        if args.gui:
            code, out, err = run([os.path.abspath(args.gui), '--selfcheck', hive])
            check(code == 0, f'window --selfcheck exits 0 (got {code}; {err.strip()[:300]})')
            if out.strip():
                report = json.loads(out)
                check(report.get('window') == 'built' and report.get('root_subkeys_shown', 0) > 0
                      and report.get('values_shown', 0) > 0, f'window loaded the hive: {report}')
            else:
                print('note  the window printed nothing (a windowed Windows build has no stdout)')
    print(f'{len(FAILED)} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
