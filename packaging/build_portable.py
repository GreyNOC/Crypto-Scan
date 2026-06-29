"""Build the portable single-file `gs` executable with PyInstaller.

    python -m pip install -e . pyinstaller
    python packaging/build_portable.py

Output: ./portable/gs(.exe) — a self-contained binary that needs no Python.
"""

import shutil
from pathlib import Path

import PyInstaller.__main__

ROOT = Path(__file__).resolve().parents[1]
PORTABLE = ROOT / "portable"

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
    "--distpath", str(PORTABLE),
    "--workpath", str(ROOT / "build" / "pyi"),
    "--specpath", str(ROOT / "build"),
])

# Bundle the usage note alongside the binary so the archive is self-documenting.
shutil.copyfile(ROOT / "packaging" / "README-PORTABLE.txt",
                PORTABLE / "README-PORTABLE.txt")
print(f"portable build ready in {PORTABLE}")
