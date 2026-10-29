"""Make one harmless GetAsyncKeyState call, discard its result, and wait.

This script never loops over keys, prints key state, records input, creates files,
sets hooks, or connects to the network. Python resolves this API dynamically, so
the companion C probe is the end-to-end fixture for static PE import detection.
"""

import ctypes
import os
import time
from ctypes import wintypes


def main() -> int:
    """Call one modifier-state API once and keep the process available for inspect."""
    if os.name != "nt":
        print("This benign probe requires Windows.")
        return 2
    api = ctypes.WinDLL("user32", use_last_error=True).GetAsyncKeyState
    api.argtypes = [wintypes.INT]
    api.restype = wintypes.SHORT
    api(0x10)  # VK_SHIFT; return value is deliberately discarded.
    print(f"Benign probe PID: {os.getpid()}. One call completed; no input retained. Ctrl+C to exit.")
    try:
        time.sleep(300)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
