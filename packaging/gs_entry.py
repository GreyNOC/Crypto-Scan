"""PyInstaller entry point for the portable `gs` executable.

Thin launcher so the one-file build has a concrete script to bundle; all logic
lives in cryptoscan.cli. Build: see packaging/build_portable.py.
"""

import sys

from cryptoscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
