# GreyNOC CryptoScan

[![CI](https://github.com/GreyNOC/Crypto-Scan/actions/workflows/ci.yml/badge.svg)](https://github.com/GreyNOC/Crypto-Scan/actions/workflows/ci.yml)

**Cryptographic Posture Management & PQC migration scanner.**
Discovers the cryptography actually in use across TLS endpoints and
source/dependency trees, classifies each primitive's quantum risk, and emits a
**CycloneDX 1.6 CBOM** (Cryptographic Bill of Materials) plus a CISO-readable
migration roadmap.

> Authorized testing only · reproducible findings · no fabrication.

GreyNOC · `GN-TOOL-CRYPTOSCAN-001` · v0.1.0

---

## Why this exists

NIST finalized the first post-quantum standards in 2024 — **ML-KEM (FIPS 203)**,
**ML-DSA (FIPS 204)**, **SLH-DSA (FIPS 205)** — and CNSA 2.0 / federal mandates
put migration on a clock. The hard part isn't choosing the new algorithms; it's
that almost no organization knows *where their current cryptography lives*. RSA,
ECC, and finite-field Diffie-Hellman are "harvest now, decrypt later" (HNDL)
liabilities: traffic captured today is decryptable the day a
cryptographically-relevant quantum computer exists.

CryptoScan answers the discovery-and-inventory question first, then prioritizes
remediation by HNDL exposure.

## What it does

- **TLS / certificate discovery** — performs an authorized handshake, reads the
  negotiated protocol + cipher suite and the leaf certificate's key algorithm,
  size, curve, and signature algorithm.
- **Source + dependency discovery** — static, read-only scan of source files for
  direct crypto API usage (file:line provenance) and of manifests
  (`requirements.txt`, `package.json`, `Cargo.toml`, `go.mod`) for crypto-bearing
  packages.
- **Quantum-risk classification** — every primitive is mapped to a defensible
  public position (NIST FIPS 203/204/205, SP 800-131A, CNSA 2.0):
  - `shor-broken` — RSA / ECC / DH, broken outright by Shor.
  - `grover-weakened` — symmetric strength ~halved; only a problem below floor.
  - `pq-safe` — standardized PQC, or AES-256 / SHA-384+ class.
  - `classically-weak` — already broken pre-quantum (MD5, SHA-1, 3DES, RC4).
- **CBOM emission** — schema-valid **CycloneDX 1.6** with `cryptoProperties`,
  validated against the official CycloneDX validator.
- **Migration roadmap** — vulnerable primitives grouped, severity-ranked, and
  mapped to their NIST PQC target with locations.

## Risk model

| Class | Severity floor | HNDL? | Examples |
|---|---|---|---|
| Shor-broken, key establishment | CRITICAL | yes | ECDHE, X25519, RSA key transport |
| Shor-broken, signature / auth | HIGH | no | ECDSA cert, RSA auth cert, EdDSA |
| classically-weak | HIGH | no | MD5, SHA-1, 3DES, RC4 |
| Grover-weakened (< 112-bit eff.) | MEDIUM | no | AES-128, AES-192 |
| pq-safe | INFO | no | ML-KEM, ML-DSA, AES-256, SHA-384 |

HNDL flagging is **role-accurate**: an RSA certificate used purely for
authentication (e.g. TLS 1.3) is HIGH, not a HNDL CRITICAL — only key-establishment
uses are harvestable.

## Install

```bash
pip install cryptography                 # required
pip install "cyclonedx-python-lib[json-validation]"   # optional, for CBOM self-validation
```

## Usage

```bash
# TLS endpoint(s)
python -m cryptoscan.cli tls example.com:443 api.example.com:443 \
    --cbom cbom.json --report report.md

# Source / dependency tree
python -m cryptoscan.cli code ./my-repo --report report.md --json findings.json

# Combined
python -m cryptoscan.cli scan ./my-repo --tls example.com:443 \
    --cbom cbom.json --report report.md --json findings.json

# Gate CI on a chosen severity (default: critical)
python -m cryptoscan.cli code ./my-repo --fail-on high      # fail on HIGH or worse
python -m cryptoscan.cli code ./my-repo --fail-on none      # never fail (inventory only)
```

Exit code is **2** when findings at or above `--fail-on` (default **critical**)
are present, so it gates CI; pass `--fail-on none` to only inventory.

## Outputs

- `--cbom`   CycloneDX 1.6 CBOM (drops into Dependency-Track / SBOM tooling)
- `--report` Markdown posture report + migration roadmap
- `--json`   raw findings with fingerprints + provenance

Each finding carries a stable `fingerprint` (sha256 of asset+locator+algo+evidence)
and a `locator`, so results are reproducible and diffable across scans.

## Known limitations (v0.1.0 MVP)

Stated plainly, because the no-fabrication standard cuts both ways:

- **TLS 1.3 KEX group is not yet captured.** The negotiated cipher suite name
  (`TLS_AES_256_GCM_SHA384`) doesn't encode the key-agreement group, so the
  ECDHE/X25519 HNDL exposure on a TLS 1.3 endpoint is currently inferred from the
  certificate, not the live group. Capturing the actual group needs a
  `key_share`/`supported_groups` probe — next on the roadmap.
- **Cipher-suite enumeration is single-handshake.** It reports the *negotiated*
  suite, not the server's full accepted set. Full enumeration is a planned pass.
- **Source scan is pattern-based**, so it favors recall over precision; treat
  source findings as leads to confirm, not proof of exploitable config.
- Coverage is TLS + code/deps. HSM, firmware, IPsec/SSH, and traffic-capture
  surfaces are out of scope for this MVP.

## Roadmap

1. TLS 1.3 `supported_groups` probe + full cipher enumeration.
2. SSH / IPsec / S-MIME surfaces.
3. Continuous re-scan + posture diffing (assurance layer — proves a migration
   landed and held).
4. Hybrid-readiness checks (X25519MLKEM768).

## Layout

```
cryptoscan/
  primitives.py   crypto knowledge base (single source of risk truth)
  classifier.py   Finding model + context-aware severity
  tls_scanner.py  TLS/cert discovery
  code_scanner.py source + dependency discovery
  cbom.py         CycloneDX 1.6 CBOM emitter
  report.py       Markdown posture report + roadmap
  cli.py          command-line entrypoint
tests/            unit tests (logic + CBOM shape + live sample scan)
sample-target/    deliberately mixed-crypto fixture
```

## Development

```bash
pip install -e .          # installs the package + `cryptography`
pip install pytest
pytest -q tests/          # or: python tests/test_core.py
```

CI (GitHub Actions) runs the suite on Linux and Windows across Python 3.10 and
3.13, smoke-tests the CLI against `sample-target/`, and asserts that finding
locators stay OS-independent so fingerprints remain reproducible.

See [CHANGELOG.md](CHANGELOG.md) for notable changes.
