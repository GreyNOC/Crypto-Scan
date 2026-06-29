"""Print the CHANGELOG.md section for a given version (for release notes).

    python packaging/changelog_section.py 0.2.1

Emits the body between the matching '## ... <version> ...' heading and the next
'## ' heading. Falls back to a generic line if the version isn't found.
"""

import re
import sys
from pathlib import Path


def section(version: str, changelog: str) -> str:
    out: list[str] = []
    capturing = False
    for line in changelog.splitlines():
        if re.match(r"^## ", line):
            if capturing:
                break
            if version in line:
                capturing = True
            continue
        if capturing:
            out.append(line)
    body = "\n".join(out).strip()
    return body or f"GreyNOC CryptoScan {version}."


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    version = sys.argv[1]
    path = Path(__file__).resolve().parents[1] / "CHANGELOG.md"
    text = section(version, path.read_text(encoding="utf-8"))
    # Emit UTF-8 regardless of the platform console codepage (the changelog uses
    # '·' and '→'); a cp1252 stdout would otherwise raise UnicodeEncodeError.
    sys.stdout.buffer.write((text + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
