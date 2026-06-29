"""Build the portable single-file `gs` executable with PyInstaller.

    python -m pip install -e . pyinstaller
    python packaging/build_portable.py

Output: ./portable/gs(.exe) — a self-contained binary that needs no Python.
"""

from pathlib import Path

import PyInstaller.__main__

ROOT = Path(__file__).resolve().parents[1]

PyInstaller.__main__.run([
    str(ROOT / "packaging" / "gs_entry.py"),
    "--onefile",
    "--name", "gs",
    "--console",
    "--noconfirm",
    # Point at the repo root so the cryptoscan/ source is found directly — an
    # editable (PEP 660) install isn't statically analyzable by PyInstaller.
    "--paths", str(ROOT),
    "--collect-submodules", "cryptoscan",
    "--distpath", str(ROOT / "portable"),
    "--workpath", str(ROOT / "build" / "pyi"),
    "--specpath", str(ROOT / "build"),
])
