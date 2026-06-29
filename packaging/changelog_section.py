"""Print the CHANGELOG.md section for a given version (for release notes).

    python packaging/changelog_section.py 0.2.1

Emits the body between the '## [<version>] ...' heading and the next '## '
heading. Exits 3 (and writes nothing to stdout) if no matching section exists,
so a release workflow can refuse to publish a release with placeholder notes.
"""

import re
import sys
from pathlib import Path


def section(version: str, changelog: str) -> str | None:
    """Return the section body, or None if there is no matching heading.

    Matches the bracketed form '## [<version>]' exactly, so '0.2.1' does not
    accidentally match a '## [0.2.10]' heading.
    """
    out: list[str] = []
    capturing = False
    for line in changelog.splitlines():
        if re.match(r"^## ", line):
            if capturing:
                break
            if f"[{version}]" in line:
                capturing = True
            continue
        if capturing:
            out.append(line)
    body = "\n".join(out).strip()
    return body or None


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    version = sys.argv[1]
    path = Path(__file__).resolve().parents[1] / "CHANGELOG.md"
    body = section(version, path.read_text(encoding="utf-8"))
    if body is None:
        sys.stderr.write(f"no CHANGELOG.md section for [{version}]\n")
        return 3
    # Emit UTF-8 regardless of the platform console codepage (the changelog uses
    # '·' and '→'); a cp1252 stdout would otherwise raise UnicodeEncodeError.
    sys.stdout.buffer.write((body + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
