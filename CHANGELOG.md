# Changelog

All notable changes to GreyNOC CryptoScan are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed
- **Reproducible fingerprints across operating systems.** Source and dependency
  locators are now normalized to POSIX (`/`) separators, so the SHA-256
  `fingerprint` of a finding is identical whether the scan runs on Windows or
  Linux. Previously a Windows scan produced `src\auth.py:6` and a Linux scan
  `src/auth.py:6`, silently breaking the "reproducible / diffable across scans"
  guarantee.
- **No-fabrication classification for ChaCha20 and SHA-3.** ChaCha20 /
  ChaCha20-Poly1305 are now reported as `ChaCha20` (a stream cipher) instead of
  being mislabeled `AES-256`; SHA-3 (`sha3-256`, `sha3-512`) is reported as its
  own primitive instead of being folded into `SHA-512`.
- **UTF-8 output on legacy Windows consoles.** The CLI now forces UTF-8 on
  stdout/stderr and writes all report/CBOM/JSON files as UTF-8 with a trailing
  newline, fixing mojibake (`·` rendered as `?`) and potential
  `UnicodeEncodeError` on cp1252 terminals.
- **Source/manifest files are read as UTF-8** regardless of the host locale.
- Use `re.split(..., maxsplit=1)` (keyword) to avoid the Python 3.13
  positional-`maxsplit` deprecation, and guard `package.json` parsing against
  non-object top-level JSON.

### Added
- **`--fail-on {critical,high,medium,low,none}`** CLI flag to control the CI
  gating threshold (default `critical`, preserving prior behavior). `none`
  disables the non-zero exit entirely.
- GitHub Actions CI: pytest on Linux + Windows across Python 3.10 and 3.13,
  plus a smoke test and an OS-independent-locator assertion.
- Repository hygiene: `.gitignore`, `LICENSE`, `CHANGELOG.md`.
- Tests for ChaCha20/SHA-3 classification, locator portability, and the
  `--fail-on` gate.

## [0.1.0]

- Initial MVP: TLS/certificate discovery, source + dependency discovery,
  quantum-risk classification, CycloneDX 1.6 CBOM emission, Markdown posture
  report + migration roadmap, and a deliberately mixed-crypto sample target.
