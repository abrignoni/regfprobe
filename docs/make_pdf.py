"""Build docs/manual.pdf from docs/manual.html with Microsoft Edge (or Chrome) in headless mode.

    python docs/make_pdf.py
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = [
    r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    r'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
    r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
]


def browser():
    for path in CANDIDATES:
        if os.path.exists(path):
            return path
    for name in ('msedge', 'google-chrome', 'chromium', 'chromium-browser', 'chrome'):
        found = shutil.which(name)
        if found:
            return found
    return None


def build(out=None):
    exe = browser()
    if exe is None:
        raise RuntimeError('no Edge or Chrome found to print the PDF with; open docs/manual.html and print it to PDF')
    source = os.path.join(HERE, 'manual.html')
    out = out or os.path.join(HERE, 'manual.pdf')
    subprocess.run([exe, '--headless=new', '--disable-gpu', '--no-pdf-header-footer', '--generate-pdf-document-outline',
                    f'--print-to-pdf={out}', 'file:///' + source.replace(os.sep, '/')],
                   check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return out


if __name__ == '__main__':
    made = build(sys.argv[1] if len(sys.argv) > 1 else None)
    print(made, os.path.getsize(made), 'bytes')
