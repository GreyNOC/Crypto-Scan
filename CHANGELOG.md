# Changelog

All notable changes to GreyNOC CryptoScan are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.1] — packaging, QA hardening

Adds the `gs` CLI and per-OS portable releases, and lands the fixes from a full
multi-agent QA/QC pass. No change to scan semantics except the bug fixes below.

### Added
- **`gs` and `gscan` CLI commands** (short GreyNOC-Scan syntax) alongside
  `cryptoscan`, and a self-contained **portable `gs` executable** (PyInstaller,
  no Python required).
- **Release workflow** (`.github/workflows/release.yml`): on a `v*` tag, builds
  the wheel + sdist and a portable for linux-x64 / macos-arm64 / windows-x64,
  smoke-tests each binary, and publishes them with `SHA256SUMS.txt`. Refuses to
  publish if the tag doesn't match the package version or the CHANGELOG has no
  matching section.
- A ruff lint config; the tree is lint-clean.

### Fixed
- **Posture-diff assurance gate.** A relocated source finding that *also*
  escalates (higher severity, or newly HNDL-exposed) is now reported as a
  REGRESSION instead of being absorbed as a posture-neutral move — so
  `gs diff` exits 2 on a genuine regression.
- **CBOM `nistQuantumSecurityLevel` for hybrid groups.** SecP384r1MLKEM1024 now
  maps to category 5 (was 3); category is derived from the fact's quantum
  strength when no parameter-set token is present.
- **Robustness / hardening:** reject `pom.xml` declaring a DTD/entities
  (billion-laughs DoS) and cap manifest size; skip special files (FIFO/device)
  in both scan passes; clamp the TLS SNI and make the TLS 1.3 probe never raise;
  tolerate a partial Mosca `secrecy_years` override.

## [0.2.0] — the decision-engine release

The leap from inventory tool to decision engine. Default output (no new flags)
stays v0.1.0-shaped except for the enriched CBOM; all new analysis is opt-in.
The 15 v0.1.0 regression tests stay green, with a broad v0.2.0 suite on top.

### Added
- **Mosca Risk Engine** (`mosca.py`, `--mosca`). Applies Mosca's inequality
  `X + Y > Z` (data secrecy lifetime + migration time vs years-to-CRQC) per
  finding and as an aggregate, with PLAN/MONITOR/ACT-NOW urgency, scenario
  sensitivity, and a cited, fully overridable parameter set (`.basis()`).
- **Live TLS 1.3 key-exchange group probe** (`tls13_probe.py`). Hand-built
  ClientHello + ServerHello/HelloRetryRequest parser captures the negotiated
  group and detects PQC hybrids (X25519MLKEM768, SecP256r1MLKEM768, …) — closing
  the v0.1.0 "TLS 1.3 KEX group not captured" limitation. No new dependency
  (dummy key shares; only the 2-byte selected group is read). Verified live
  against Cloudflare/Google (→ X25519MLKEM768).
- **SARIF 2.1.0 output** (`sarif.py`, `--sarif`) for GitHub code scanning;
  schema-conformant (validated with the SARIF 2.1.0 JSON schema when the
  optional `jsonschema` dependency and network are available).
- **Posture diffing** (`diff.py`, `cryptoscan diff OLD NEW`). Fingerprint match
  with source move-detection; MIGRATION_LANDED / REGRESSION / PARTIAL / NO_CHANGE
  verdict; exits 2 on regression.
- **Parameter-aware severity**: a sub-112-bit key/curve (RSA-1024, secp192r1) is
  flagged `classically_weak` on top of its quantum risk (NIST SP 800-57 strength
  tables, curve facts).
- **Knowledge-base expansion**: per-group hybrid KEX facts, HMAC MAC fact, JOSE/
  COSE algorithm map (`jose_alg`), PQC parameter-set → NIST category table, more
  curves. `strength_for` / `curve_fact` / `pqc_category` helpers.
- **Seven-ecosystem dependency discovery**: Maven `pom.xml`, Gradle, Ruby
  `Gemfile`(`.lock`), PHP `composer.json`, `go.sum`, plus JOSE/JWT/JCA/WebCrypto
  source patterns — each manifest parser isolates its own parse errors.
- **Enriched CBOM**: TLS leaf certs as CycloneDX `certificate` assets (validity,
  subject/issuer) and TLS endpoints as `protocol` assets (version + cipher
  suites); param/shape-aware `nistQuantumSecurityLevel`. Validated against the
  CycloneDX 1.6 **strict** schema in CI.

### Fixed
- **CBOM emitted an invalid `key-agreement` cryptoFunctions token** — corrected
  to the schema's `keyderive`; `nistQuantumSecurityLevel` no longer hardcoded to
  3 for every PQ-safe asset.
- **Mis-aliased `x25519kyber768`** sat on the X25519 (Shor) fact; relocated to a
  proper PQ-safe hybrid fact. Corrected the `RFC 9370` citation (an IKEv2 doc) to
  `draft-ietf-tls-ecdhe-mlkem`.
- Version is now single-sourced in `_version.py` (no more 0.1.0 split-brain).

## [0.1.x]

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
