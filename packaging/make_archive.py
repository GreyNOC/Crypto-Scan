"""Cross-platform release archiver (stdlib only).

    python packaging/make_archive.py <out_base> <zip|gztar> <root_dir>

Archives the *contents* of <root_dir> into <out_base>.<ext>. Used by the
release workflow to package the portable binary + its README on every OS.
"""

import shutil
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    out_base, fmt, root_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    path = shutil.make_archive(out_base, fmt, root_dir=root_dir)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
