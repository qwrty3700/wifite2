#!/usr/bin/env python

# Note: This script runs Wifite from within a cloned git repo.
# The script `bin/wifite` is designed to be run after installing (from /usr/sbin), not from the cwd.

import os
import sys


def _is_termux() -> bool:
    if os.environ.get("TERMUX_VERSION") or os.environ.get("TERMUX_APP_PID"):
        return True
    prefix = str(os.environ.get("PREFIX", "") or "")
    if prefix.startswith("/data/data/com.termux/"):
        return True
    return os.path.exists("/data/data/com.termux/files/usr/bin/termux-usb")


if _is_termux() and len(sys.argv) > 1 and sys.argv[-1].isdigit():
    os.environ.setdefault("RTWMON_TERMUX_USB_FD", sys.argv[-1])
    sys.argv.pop()

from wifite import wifite
wifite.main()
