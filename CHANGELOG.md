# Changelog

All notable changes to GreyNOC CryptoScan are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.5] — QAQC hardening pass (no-fabrication, safety, fidelity)

A multi-surface adversarial review (correctness + no-fabrication + schema-validity
+ safety) with a verified fix and a regression test for every finding. No new
scan surfaces; the existing ones report more faithfully and fail safe.

### Fixed — no-fabrication (the cardinal rule)
- **IKEv2 AES key size is never invented.** A negotiated AES transform whose Key
  Length attribute could not be recovered was reported as a fabricated
  `AES-128`; it is now reported as generic `AES` (Grover-class, size unknown,
  no invented strength/NIST level). The transform parser also scans *all*
  attributes for Key Length (RFC 7296 does not require it to be first), so a real
  AES-256 gateway is no longer mislabeled AES-128.
- **IKEv2 ML-KEM groups keep their parameter set.** Groups 35/36/37 now report as
  `ML-KEM-512` / `ML-KEM-768` / `ML-KEM-1024` (NIST cat 1/3/5) instead of a bare
  `ML-KEM` — the same fidelity discipline the TLS/SSH hybrid groups already follow.
- **Ed448 is reported by name at ~224-bit strength**, not folded into the 128-bit
  Ed25519 fact (which contradicted the curve table and under-reported it). Every
  surface was updated — TLS/PKI key files, SSH `ssh-ed448` host keys, and source.
  The generic `EdDSA` note stays curve-agnostic for JOSE `EdDSA` (no curve named).
- **CBOM protocol `bom-ref`s are hashed**, not raw `host:port` strings, so they
  are guaranteed unique per the CycloneDX 1.6 constraint (locator kept in props).

### Fixed — false negatives (silent misses)
- **Certificate signature algorithms are no longer silently dropped.** An
  unrecognized digest suffix (`ecdsa-with-SHA512`, `dsa-with-sha256`,
  `sha3-256WithRSAEncryption`, SHA-224…) previously yielded *zero* signature
  findings; it now falls back to the asymmetric family so the Shor-broken
  signature always surfaces.
- **RSA key-establishment is now HNDL-assessed.** A cert whose KeyUsage asserts
  keyEncipherment/dataEncipherment/keyAgreement, and any standalone *private* RSA
  key file, is flagged key-establishment → HNDL-exposed and seen by the Mosca
  engine (a directory of RSA private keys previously reported zero HNDL risk).
  Auth-only certs (e.g. TLS 1.3 digitalSignature) stay HIGH, not HNDL CRITICAL.
- **Minified/bundled single-line source is scanned** (per-line cap raised from
  1 KB to 50 KB), so crypto calls buried past column 1000 are no longer missed.

### Fixed — safety / CI integrity
- **Directory-link traversal is contained.** Scans walk with `followlinks=False`
  and prune reparse-point subdirectories — covering both POSIX directory symlinks
  and **Windows junctions** (which are not symlinks, so an `is_symlink` check
  alone missed them) — so a directory link can neither escape the scan root nor
  spin an unbounded loop (DoS). Symlinked *files* are still followed, so
  symlink-based cert stores (e.g. `/etc/ssl/certs`) scan as before.
- **A scan that could not measure its target no longer reports a clean `0/100`.**
  Incompleteness is now judged by reachability, not by an empty finding set — a
  reachable endpoint that negotiates nothing (e.g. IKE `NO_PROPOSAL_CHOSEN`) is
  complete, but a run where *no* target responded, or a nonexistent `code`/`scan`
  path, exits **3** ("scan incomplete"). The `--json` envelope carries a
  `scan_status` field so a downstream diff/dashboard sees it too. `--fail-on none`
  suppresses the endpoint-incomplete exit 3 (a nonexistent path still exits 3).
- **Release publish fails loudly.** The `gh release create || upload --clobber`
  fallback (which masked a genuine create failure) is now an explicit
  exists-check branch; the CHANGELOG-section check is a first-class release gate;
  the PyInstaller major is pinned; `changelog_section` anchors on the version's
  own heading (no mid-line/backport-mention false match).
- **IPv6 targets parse correctly.** `[host]:port` now honors the explicit port
  (previously dropped) and bare/bracketed IPv6 is treated as a literal host.

### Fixed — determinism
- **Posture-diff MOVED pairing is deterministic** (candidates and the rendered
  from→to rows are sorted), so diff output stays byte-stable across runs.

## [0.2.4] — post-scan analysis pass (perf, UX, guards)

Polish from a full analyze-and-improve pass over the mature codebase. No new
surfaces; sharper output and fewer round-trips.

### Added
- **Post-quantum readiness section** in the Markdown report + a console line —
  surfaces which endpoints have a PQ-hybrid key exchange *observed* vs merely
  *offered* (a server can advertise a hybrid yet negotiate a classical group).
  This CNSA-2.0 headline was collected but previously discarded.
- **`gs assess <host>`** — scan one host across TLS + SSH + IKEv2 in one command.
- **`--json` envelope is versioned** (`schema_version` / `scanner_version`), like
  the CBOM/SARIF outputs; still timestamp-free so identical scans stay
  byte-identical.

### Changed / Fixed
- **Network targets are probed once, not twice.** `tls/ssh/ike` `scan()` accept a
  pre-fetched observation, so the CLI no longer re-probes each host after its
  status line — halving handshakes/latency per host.
- **`ecdsa-with-sha1` / `dsa-with-sha1` cert signatures** now surface the SHA-1
  LEGACY finding (previously a SHA-1-signed ECDSA cert dropped that signal).
- Corrected the stale CLI module docstring (all subcommands documented).

## [0.2.3] — IPsec/IKEv2 surface (roadmap complete)

The last planned discovery surface. All roadmap items are now implemented.

### Added
- **IPsec / IKEv2 endpoint scanning** (`gs ike`, `ike_scanner.py`). Sends an
  authorized `IKE_SA_INIT` (RFC 7296) over UDP and parses the responder's chosen
  SA — or its `INVALID_KE_PAYLOAD` preferred group — to classify the negotiated
  encryption / PRF / integrity and, critically, the **Diffie-Hellman group**
  (the HNDL key-exchange signal). Weak MODP-768/1024 and ECP-192 groups escalate
  to classically-weak; the PQ ML-KEM groups (codepoints 35/36/37,
  draft-ietf-ipsecme-ikev2-mlkem) are detected as PQ-safe. New `ike-endpoint`
  asset type + `--ike` on the combined `scan`. Verified live against a strongSwan
  gateway.
- New primitives: `AES-XCBC` (IKE/IPsec AES MAC) and `NULL-ENCRYPTION`
  (ENCR_NULL — plaintext IPsec is itself a HIGH finding).

### Notes
- All transform IDs and the IKEv2 wire layout were fact-verified before
  implementation; the binary response parser is fuzzed (20k random + adversarial
  inputs) to never hang or raise.

## [0.2.2] — cipher enumeration + SSH & PKI surfaces

Closes the single-handshake cipher limitation and expands coverage beyond
TLS + code/deps to SSH and certificate/key files.

### Added
- **Full TLS cipher-suite enumeration.** TLS 1.3 via the raw probe (each suite
  offered alone) and TLS ≤1.2 via an `ssl.set_ciphers` exclusion loop. The scan
  flags every primitive in the server's *accepted* set — so an accepted AES-128
  or legacy SHA-1/3DES suite is reported even when a stronger suite is
  negotiated — and the CBOM `protocol` asset lists the full set.
- **SSH endpoint scanning** (`gs ssh`, `ssh_scanner.py`). Reads the cleartext
  `SSH_MSG_KEXINIT` to enumerate the server's entire offered key-exchange /
  host-key / cipher / MAC set, classifying each — including PQ hybrids
  `sntrup761x25519` (RFC 9941), `mlkem768x25519`, `mlkem768nistp256`,
  `mlkem1024nistp384`. Flags HNDL-exposed classical KEX, `ssh-rsa`→SHA-1, and
  sub-112-bit DH groups. New `ssh-endpoint` asset type.
- **PKI / certificate-file scanning** (`pki_scanner.py`, folded into `gs code`/
  `gs scan`). Parses X.509 / PKCS#7 / private+public key files and classifies
  each key + signature algorithm (e.g. an RSA-1024 cert → classically-weak).
- New primitives: SNTRUP761X25519, MLKEM768NISTP256, MLKEM1024NISTP384 (SSH PQ
  hybrids), UMAC and Poly1305 MACs; `--ssh` on the combined `scan`.

### Notes
- The `@amazon.com` Kyber draft KEX string was deliberately omitted after fact
  verification flagged it as unattested — only IANA/RFC-attested SSH hybrids ship.

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
